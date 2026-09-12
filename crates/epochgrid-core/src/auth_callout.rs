//! NATS Auth Callout adapter. Registry/policy own identity; NATS enforces grants.
use crate::{
    identity_model::{AuthRegistry, now},
    wire,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nats_jwt_rs::{Claim, Claims, authorization::AuthResponse, user::User};
use nkeys::{KeyPair, KeyPairType, XKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

pub const SUBJECT: &str = "$SYS.REQ.USER.AUTH";
pub const ENROLL: &str = "epochgrid.v1.identity.enroll";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u16,
    pub issuer_seed: PathBuf,
    pub encryption_seed: PathBuf,
    pub connection_seed: PathBuf,
    pub target_account: String,
    pub control_nkey: String,
    pub authorization_ttl_seconds: u64,
    pub development_plaintext: bool,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            config.version == 1,
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
        let parent = path.parent().context("configuration parent")?;
        for key in [
            &mut config.issuer_seed,
            &mut config.encryption_seed,
            &mut config.connection_seed,
        ] {
            if key.is_relative() {
                *key = parent.join(&*key);
            }
        }
        Ok(config)
    }
    pub fn check_transport(&self, url: &str) -> Result<()> {
        ensure!(
            self.development_plaintext || url.starts_with("tls://"),
            "TLS required; development_plaintext is a development-only bypass"
        );
        Ok(())
    }
    pub async fn connect(&self, url: &str) -> Result<async_nats::Client> {
        self.check_transport(url)?;
        let seed = read_seed(&self.connection_seed)?;
        Ok(async_nats::ConnectOptions::with_nkey(seed.to_string())
            .connection_timeout(Duration::from_secs(5))
            .request_timeout(Some(Duration::from_secs(2)))
            .connect(url)
            .await?)
    }
}
pub fn read_seed(path: &Path) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        std::fs::read_to_string(path)?.trim().to_owned(),
    ))
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
}
impl Callout {
    pub fn new(config: Config) -> Result<Self> {
        let issuer = KeyPair::from_seed(&read_seed(&config.issuer_seed)?)?;
        ensure!(
            issuer.key_pair_type() == KeyPairType::Account,
            "callout issuer must be an account key"
        );
        let encryption = XKey::from_seed(&read_seed(&config.encryption_seed)?)?;
        Ok(Self {
            issuer,
            encryption,
            config,
            seen: BTreeMap::new(),
        })
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
                && request.sub == self.issuer.public_key(),
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
                devices_ready || connect.nkey == self.config.control_nkey,
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
            user.aud = Some(self.config.target_account.clone());
            user.exp = Some(timestamp + self.config.authorization_ttl_seconds as i64);
            user.nats.generic_fields.version = 2;
            user.nats.permissions.permissions.subscribe.allow =
                vec![format!("_INBOX.{}.>", connect.nkey)];
            if let Some(token) = &connect.auth_token {
                registry.enrollment_admission(token.as_str(), &connect.nkey)?;
                user.name = Some("EpochGrid enrollment".into());
                user.nats.permissions.permissions.publish.allow = vec![ENROLL.into()];
            } else if connect.nkey == self.config.control_nkey {
                user.name = Some("EpochGrid control service".into());
                user.nats.permissions.permissions.publish.allow = vec![
                    "$JS.API.>".into(),
                    "$KV.IDENTITIES.>".into(),
                    "$KV.CHANNELS.>".into(),
                    "$KV.TRANSPARENCY.>".into(),
                    "_INBOX.>".into(),
                    wire::AUDIT.into(),
                    wire::REVOCATIONS.into(),
                    wire::REVOKE.into(),
                ];
                user.nats
                    .permissions
                    .permissions
                    .subscribe
                    .allow
                    .push("epochgrid.v1.identity.*".into());
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
                // Group grants and consumers require explicit membership policy (M22).
                // No default group/attachment/other-device mailbox access.
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
