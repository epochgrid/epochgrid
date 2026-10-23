//! NATS Auth Callout adapter. Registry/policy own identity; NATS enforces grants.
use crate::secrets::{Kind, SecretRef};
use crate::{
    identity_model::{AuthRegistry, now},
    wire,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nats_jwt_rs::{Claim, Claims, authorization::AuthResponse, user::User};
use nkeys::{KeyPair, KeyPairType, XKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};
use zeroize::Zeroizing;

pub const SUBJECT: &str = "$SYS.REQ.USER.AUTH";
pub const ENROLL: &str = "epochgrid.v1.identity.enroll";
/// Operator-owned public JWT configuration. Private signing keys stay in Secret Service.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorJwt {
    pub auth_account: String,
    pub connection_jwt: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub issuer: SecretRef,
    pub encryption: SecretRef,
    pub connection: SecretRef,
    pub target_account: String,
    pub control_nkey: String,
    pub authorization_ttl_seconds: u64,
    pub development_plaintext: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_jwt: Option<OperatorJwt>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_inner(path, false)
    }
    /// Setup/export may inspect an explicitly pending operator configuration.
    /// Runtime callers must use `load`, which rejects an absent service JWT.
    pub fn load_for_export(path: &Path) -> Result<Self> {
        Self::load_inner(path, true)
    }
    fn load_inner(path: &Path, allow_pending: bool) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            value.get("version").and_then(|v| v.as_u64()) == Some(2),
            "pre-Milestone-24 or unsupported callout configuration; initialize a fresh backend"
        );
        let config: Self = serde_json::from_value(value)?;
        ensure!(
            config.version == 2,
            "unsupported callout configuration version"
        );
        ensure!(
            (2..=60).contains(&config.authorization_ttl_seconds),
            "authorization TTL must be 2–60 seconds"
        );
        ensure!(
            !config.target_account.is_empty()
                && config.target_account.len() <= 64
                && config
                    .target_account
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid target account name"
        );
        ensure!(
            config.issuer.kind == Kind::Account
                && config.encryption.kind == Kind::XKey
                && config.connection.kind == Kind::User,
            "invalid callout credential types"
        );
        if let Some(operator) = &config.operator_jwt {
            for account in [&operator.auth_account, &config.target_account] {
                ensure!(
                    KeyPair::from_public_key(account)?.key_pair_type() == KeyPairType::Account,
                    "operator mode requires account public keys"
                );
            }
            ensure!(
                operator.auth_account != config.target_account,
                "authentication and application accounts must be separate"
            );
            if operator.connection_jwt.is_empty() {
                ensure!(
                    allow_pending,
                    "operator setup incomplete: supply the signed non-bearer auth service JWT in auth.json.operator_jwt.connection_jwt"
                );
                return Ok(config);
            }
            let jwt = Claims::<User>::decode(&operator.connection_jwt)
                .context("invalid auth service user JWT")?;
            ensure!(
                matches!(
                    jwt.nats.generic_fields.claim_type,
                    nats_jwt_rs::ClaimType::User
                ) && jwt.nats.generic_fields.version == 2,
                "expected a version-2 user JWT"
            );
            ensure!(
                jwt.sub == config.connection.public_key
                    && jwt.nats.issuer_account.as_ref().unwrap_or(&jwt.iss)
                        == &operator.auth_account
                    && jwt.nats.permissions.bearer_token != Some(true),
                "auth service JWT must bind the connection key and authentication account"
            );
            let timestamp = now()?;
            ensure!(
                jwt.exp.is_none_or(|expiry| expiry > timestamp)
                    && jwt.nbf.is_none_or(|start| start <= timestamp),
                "auth service JWT is not current"
            );
        }
        Ok(config)
    }
    pub fn check_transport(&self, url: &str) -> Result<()> {
        let tls = crate::tls::TlsConfig::from_env()?;
        tls.validate_endpoint(url)?;
        ensure!(
            !self.development_plaintext || tls.profile == crate::tls::Profile::Development,
            "development_plaintext requires EPOCHGRID_PROFILE=development"
        );
        ensure!(
            self.development_plaintext || url.starts_with("tls://"),
            "TLS required; development_plaintext is a development-only bypass"
        );
        Ok(())
    }
    pub async fn connect(&self, url: &str) -> Result<async_nats::Client> {
        Ok(self.connection_options(url)?.connect(url).await?)
    }
    /// Shared credential/TLS connector; callers may restrict discovery for inspection.
    pub fn connection_options(&self, url: &str) -> Result<async_nats::ConnectOptions> {
        self.check_transport(url)?;
        let seed = self.connection.read()?;
        let mut options = async_nats::ConnectOptions::with_nkey(seed.to_string());
        if let Some(operator) = &self.operator_jwt {
            let key = std::sync::Arc::new(KeyPair::from_seed(&seed)?);
            options = options.jwt(operator.connection_jwt.clone(), move |nonce| {
                let key = key.clone();
                async move { key.sign(&nonce).map_err(async_nats::AuthError::new) }
            });
        }
        crate::tls::TlsConfig::from_env()?.apply(
            url,
            options
                .connection_timeout(Duration::from_secs(5))
                .request_timeout(Some(Duration::from_secs(2))),
        )
    }
}
// Deliberately no Debug: CONNECT can contain enrollment secrets.
#[derive(Clone, Serialize, Deserialize)]
struct Request {
    server_id: Server,
    user_nkey: String,
    client_info: ClientInfo,
    connect_opts: Connect,
    #[serde(default)]
    client_tls: Option<serde_json::Value>,
    #[serde(rename = "type")]
    kind: String,
    version: u16,
}
impl Claim for Request {
    fn validate() {}
}
#[derive(Clone, Serialize, Deserialize)]
struct Server {
    id: String,
    xkey: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct ClientInfo {
    nonce: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Connect {
    nkey: String,
    sig: String,
    #[serde(default)]
    auth_token: Option<wire::EnrollmentToken>,
}
pub struct Callout {
    issuer: KeyPair,
    encryption: XKey,
    config: Config,
    seen: BTreeMap<String, i64>,
    worker: Option<String>,
}
impl Callout {
    pub fn new(config: Config) -> Result<Self> {
        let issuer = KeyPair::from_seed(&config.issuer.read()?)?;
        ensure!(
            issuer.key_pair_type() == KeyPairType::Account,
            "callout issuer must be an account key"
        );
        let encryption = XKey::from_seed(&config.encryption.read()?)?;
        Ok(Self {
            issuer,
            encryption,
            config,
            seen: BTreeMap::new(),
            worker: None,
        })
    }
    /// Bind a distinct forwarding identity. Only the authority selects this key.
    pub fn with_worker(mut self, worker: String) -> Result<Self> {
        ensure!(
            KeyPair::from_public_key(&worker)?.key_pair_type() == KeyPairType::User
                && worker != self.config.control_nkey,
            "invalid worker identity"
        );
        self.worker = Some(worker);
        Ok(self)
    }
    pub fn respond(
        &mut self,
        registry: &AuthRegistry,
        server_xkey: &str,
        encrypted: &[u8],
        devices_ready: bool,
    ) -> Result<Vec<u8>> {
        ensure!(
            encrypted.len() <= wire::MAX_WIRE,
            "oversized callout request"
        );
        let peer = XKey::from_public_key(server_xkey)?;
        let plaintext = Zeroizing::new(self.encryption.open(encrypted, &peer)?);
        let request = Claims::<Request>::decode(std::str::from_utf8(&plaintext)?)
            .context("invalid signed NATS request encoding")?;
        let timestamp = now()?;
        let expires = request.exp.context("missing request expiry")?;
        ensure!(
            request.aud.as_deref() == Some("nats-authorization-request")
                && request.sub
                    == self
                        .config
                        .operator_jwt
                        .as_ref()
                        .map(|operator| operator.auth_account.clone())
                        .unwrap_or_else(|| self.issuer.public_key()),
            "invalid callout audience/subject"
        );
        ensure!(
            request.nats.kind == "authorization_request" && request.nats.version == 2,
            "unsupported callout request type"
        );
        ensure!(
            request.iss == request.nats.server_id.id
                && KeyPair::from_public_key(&request.iss)?.key_pair_type() == KeyPairType::Server
                && request.nats.server_id.xkey == server_xkey,
            "callout server binding mismatch"
        );
        ensure!(
            expires > timestamp
                && expires <= timestamp + 60
                && request.iat <= timestamp as u64 + 2
                && request.iat + 60 >= timestamp as u64
                && request.nbf.is_none_or(|v| v <= timestamp),
            "stale callout request"
        );
        ensure!(
            KeyPair::from_public_key(&request.nats.user_nkey)?.key_pair_type() == KeyPairType::User,
            "invalid connection key"
        );
        self.seen.retain(|_, expires| *expires > timestamp);
        let connection = format!("{}:{}", request.iss, request.nats.user_nkey);
        ensure!(
            self.seen.len() < 4096 && !self.seen.contains_key(&connection),
            "replayed connection request or capacity exceeded"
        );
        self.seen.insert(connection, expires);
        let result = (|| -> Result<Claims<User>> {
            let connect = &request.nats.connect_opts;
            ensure!(
                self.config.development_plaintext || request.nats.client_tls.is_some(),
                "TLS required for device admission"
            );
            ensure!(
                devices_ready
                    || connect.nkey == self.config.control_nkey
                    || self.worker.as_ref() == Some(&connect.nkey),
                "revocation reconciliation pending"
            );
            let device = KeyPair::from_public_key(&connect.nkey)?;
            ensure!(
                device.key_pair_type() == KeyPairType::User
                    && !request.nats.client_info.nonce.is_empty()
                    && request.nats.client_info.nonce.len() <= 256,
                "invalid device possession proof"
            );
            device.verify(
                request.nats.client_info.nonce.as_bytes(),
                &URL_SAFE_NO_PAD.decode(&connect.sig)?,
            )?;
            let mut user =
                User::new_claims("EpochGrid device".into(), request.nats.user_nkey.clone());
            if self.config.operator_jwt.is_some() {
                user.nats.issuer_account = Some(self.config.target_account.clone());
            } else {
                user.aud = Some(self.config.target_account.clone());
            }
            user.exp = Some(timestamp + self.config.authorization_ttl_seconds as i64);
            user.nats.generic_fields.version = 2;
            user.nats.permissions.permissions.subscribe.allow =
                vec![format!("_INBOX.{}.>", connect.nkey)];
            if let Some(token) = &connect.auth_token {
                registry.enrollment_admission(token.as_str(), &connect.nkey)?;
                user.name = Some("EpochGrid enrollment".into());
                user.nats.permissions.permissions.publish.allow = vec![ENROLL.into()];
            } else if self.worker.as_ref() == Some(&connect.nkey) {
                user.name = Some("EpochGrid control worker".into());
                user.exp = Some(timestamp + 60);
                user.nats.permissions.permissions.publish.allow =
                    crate::backend_roles::worker_publish();
                user.nats
                    .permissions
                    .permissions
                    .subscribe
                    .allow
                    .extend(crate::backend_roles::worker_subscribe());
            } else if connect.nkey == self.config.control_nkey {
                user.name = Some("EpochGrid control service".into());
                // The operator-managed control role renews on a bounded 60-second
                // lease, independently of deliberately short device leases.
                user.exp = Some(timestamp + 60);
                user.nats.permissions.permissions.publish.allow = vec![
                    "$JS.API.>".into(),
                    "$KV.IDENTITIES.>".into(),
                    "$KV.CHANNELS.>".into(),
                    "$KV.TRANSPARENCY.>".into(),
                    "_INBOX.>".into(),
                    wire::AUDIT.into(),
                    wire::REVOCATIONS.into(),
                    wire::REVOKE.into(),
                    "epochgrid.v1.user.*.*.inbox".into(),
                ];
                user.nats
                    .permissions
                    .permissions
                    .subscribe
                    .allow
                    .push("epochgrid.v1.identity.*".into());
                user.nats
                    .permissions
                    .permissions
                    .subscribe
                    .allow
                    .push("epochgrid.v1.channel.*".into());
                if self.worker.is_some() {
                    user.nats.permissions.permissions.publish.allow =
                        crate::backend_roles::authority_publish();
                    user.nats.permissions.permissions.subscribe.allow =
                        vec![format!("_INBOX.{}.>", connect.nkey)];
                }
            } else {
                let authorization = registry.authorize(&connect.nkey)?;
                user.nats
                    .permissions
                    .permissions
                    .subscribe
                    .allow
                    .push(format!(
                        "epochgrid.v1.user.{}.{}.inbox",
                        authorization.user.as_str(),
                        authorization.device
                    ));
                user.name = Some(format!(
                    "{}/{}@{}",
                    authorization.user.as_str(),
                    authorization.device,
                    authorization.generation
                ));
                user.nats.permissions.permissions.publish.allow = [
                    ENROLL,
                    crate::authorization::SUBJECT,
                    crate::authorization::RELAY,
                    wire::KEYPACKAGE,
                    wire::REGISTER,
                    wire::LOOKUP,
                    wire::DEVICES,
                    wire::AUDIT,
                    wire::REVOCATIONS,
                    wire::REVOKE,
                ]
                .into_iter()
                .map(str::to_owned)
                .collect();
                for gid in registry.authorized_groups(&connect.nkey)? {
                    crate::authorization::validate_gid(&gid)?;
                    for kind in ["message", "handshake", "ephemeral"] {
                        let subject = format!("epochgrid.v1.group.{gid}.{kind}");
                        user.nats
                            .permissions
                            .permissions
                            .publish
                            .allow
                            .push(subject.clone());
                        user.nats
                            .permissions
                            .permissions
                            .subscribe
                            .allow
                            .push(subject);
                    }
                }
                for stream in ["CHAT", "MAILBOX"] {
                    for subject in [
                        format!("$JS.API.CONSUMER.INFO.{stream}.device_{}", connect.nkey),
                        format!("$JS.API.CONSUMER.MSG.NEXT.{stream}.device_{}", connect.nkey),
                        format!("$JS.ACK.{stream}.device_{}.>", connect.nkey),
                    ] {
                        user.nats
                            .permissions
                            .permissions
                            .publish
                            .allow
                            .push(subject);
                    }
                }
                // Only service-owned filtered consumers; no stream reads/create authority.
            }
            if let Some(limits) = &mut user.nats.permissions.limits
                && let Some(nats) = &mut limits.nats_limits
            {
                nats.payload = Some(wire::MAX_WIRE as i64);
                nats.subs = Some(128);
            }
            Ok(user)
        })();
        let mut response = AuthResponse::generic_claim(request.nats.user_nkey);
        response.aud = Some(request.iss);
        response.exp = Some(expires);
        match result {
            Ok(user) => response.nats.jwt = user.encode(&self.issuer)?,
            Err(_) => response.nats.error = "EpochGrid admission denied".into(),
        }
        self.encryption
            .seal(response.encode(&self.issuer)?.as_bytes(), &peer)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
