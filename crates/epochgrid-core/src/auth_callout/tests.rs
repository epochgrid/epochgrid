use super::*;
use crate::identity::IdentityStore;
#[derive(Clone, Serialize, Deserialize)]
struct Response {
    jwt: String,
    #[serde(default)]
    error: String,
}
impl Claim for Response {
    fn validate() {}
}

struct Fixture {
    _root: tempfile::TempDir,
    config: Config,
    callout: Callout,
    registry: AuthRegistry,
    server: KeyPair,
    server_x: XKey,
    auth_x: XKey,
    device: KeyPair,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let issuer = KeyPair::new_account();
        let auth_x = XKey::new();
        std::fs::write(root.path().join("issuer"), issuer.seed()?)?;
        std::fs::write(root.path().join("xkey"), auth_x.seed()?)?;
        let config = Config {
            version: 1,
            issuer_seed: root.path().join("issuer"),
            encryption_seed: root.path().join("xkey"),
            connection_seed: root.path().join("unused"),
            control_nkey: KeyPair::new_user().public_key(),
            target_account: "EPOCHGRID".into(),
            authorization_ttl_seconds: 30,
            development_plaintext: true,
        };
        let mut registry = AuthRegistry::open(&root.path().join("registry"))?;
        let token = registry.invite("alice", 60)?;
        let mut identity = IdentityStore::open(&root.path().join("alice"))?;
        let registration = identity.init(
            crate::identity_model::token_user(&token)?.as_str(),
            "laptop",
        )?;
        let device = identity.nkey()?;
        registry.enroll(&token, &registration)?;
        registry.activate(&device.public_key())?;
        Ok(Self {
            callout: Callout::new(config.clone())?,
            registry,
            config,
            server: KeyPair::new_server(),
            server_x: XKey::new(),
            auth_x,
            device,
            _root: root,
        })
    }
    fn request(&self) -> Result<Claims<Request>> {
        Ok(serde_json::from_value(
            serde_json::json!({"iat":0,"iss":"","jti":"","sub":KeyPair::from_seed(&read_seed(&self.config.issuer_seed)?)?.public_key(),"aud":"nats-authorization-request","exp":now()?+2,"nats":{"type":"authorization_request","version":2,"server_id":{"id":self.server.public_key(),"xkey":self.server_x.public_key()},"user_nkey":KeyPair::new_user().public_key(),"client_info":{"nonce":"test-challenge"},"connect_opts":{"nkey":self.device.public_key(),"sig":URL_SAFE_NO_PAD.encode(self.device.sign(b"test-challenge")?)}}}),
        )?)
    }
    fn send(&mut self, request: &Claims<Request>, ready: bool) -> Result<Claims<Response>> {
        let encrypted = self
            .server_x
            .seal(request.encode(&self.server)?.as_bytes(), &self.auth_x)?;
        let response = self.callout.respond(
            &self.registry,
            &self.server_x.public_key(),
            &encrypted,
            ready,
        )?;
        Claims::<Response>::decode(std::str::from_utf8(
            &self.server_x.open(&response, &self.auth_x)?,
        )?)
    }
}
#[test]
fn encrypted_claim_binding_and_negative_admission() -> Result<()> {
    let mut f = Fixture::new()?;
    let request = f.request()?;
    let response = f.send(&request, true)?;
    assert_eq!(response.sub, request.nats.user_nkey);
    assert_eq!(
        response.aud.as_deref(),
        Some(f.server.public_key().as_str())
    );
    let user = Claims::<User>::decode(&response.nats.jwt)?;
    assert_eq!(user.sub, request.nats.user_nkey);
    assert_eq!(user.aud.as_deref(), Some("EPOCHGRID"));
    assert!(user.exp.context("expiry")? <= now()? + 30);
    assert!(
        !user
            .nats
            .permissions
            .permissions
            .publish
            .allow
            .iter()
            .any(|s| s == ">" || s.contains("group.*"))
    );
    assert!(f.send(&request, true).is_err());
    let mut bad = f.request()?;
    bad.nats.connect_opts.sig =
        URL_SAFE_NO_PAD.encode(KeyPair::new_user().sign(b"test-challenge")?);
    assert!(!f.send(&bad, true)?.nats.error.is_empty());
    let mut bad = f.request()?;
    bad.aud = Some("wrong".into());
    assert!(f.send(&bad, true).is_err());
    let mut bad = f.request()?;
    bad.exp = Some(now()? - 1);
    assert!(f.send(&bad, true).is_err());
    let mut bad = f.request()?;
    bad.nats.server_id.id = KeyPair::new_server().public_key();
    assert!(f.send(&bad, true).is_err());
    let request = f.request()?;
    assert!(!f.send(&request, false)?.nats.error.is_empty());
    f.registry.revoke(&f.device.public_key())?;
    let request = f.request()?;
    assert!(!f.send(&request, true)?.nats.error.is_empty());
    Ok(())
}
#[test]
fn enrollment_grants_only_enrollment_and_tampering_fails() -> Result<()> {
    let mut f = Fixture::new()?;
    let token = f.registry.invite("bob", 60)?;
    let mut request = f.request()?;
    request.nats.connect_opts.auth_token = Some(wire::EnrollmentToken::new(&token));
    let response = f.send(&request, true)?;
    let user = Claims::<User>::decode(&response.nats.jwt)?;
    assert_eq!(
        user.nats.permissions.permissions.publish.allow,
        vec![ENROLL]
    );
    assert_eq!(
        user.nats.permissions.permissions.subscribe.allow,
        vec![format!("_INBOX.{}.>", f.device.public_key())]
    );
    let bytes = f
        .server_x
        .seal(f.request()?.encode(&f.server)?.as_bytes(), &f.auth_x)?;
    let mut tampered = bytes.clone();
    tampered[40] ^= 1;
    assert!(
        f.callout
            .respond(&f.registry, &f.server_x.public_key(), &tampered, true)
            .is_err()
    );
    assert!(
        f.callout
            .respond(&f.registry, &XKey::new().public_key(), &bytes, true)
            .is_err()
    );
    f.callout.config.development_plaintext = false;
    let request = f.request()?;
    assert!(!f.send(&request, true)?.nats.error.is_empty());
    assert!(!format!("{:?}", wire::EnrollmentToken::new(&token)).contains(token.as_str()));
    Ok(())
}

#[test]
fn group_claims_are_exact_and_revocation_invalidates_reconnect() -> Result<()> {
    use crate::authorization::{Member, PolicyUpdate};
    let mut f = Fixture::new()?;
    let gid = "a".repeat(32);
    let policy = PolicyUpdate {
        version: 1,
        gid: gid.clone(),
        expected_generation: 0,
        epoch: 0,
        signer: f.device.public_key(),
        members: vec![Member {
            nkey: f.device.public_key(),
            leaf: 0,
        }],
    }
    .sign(&f.device)?;
    f.registry.apply_policy(&policy)?;
    let response = f.send(&f.request()?, true)?;
    let user = Claims::<User>::decode(&response.nats.jwt)?;
    let permissions = user.nats.permissions.permissions;
    let expected: Vec<_> = ["message", "handshake", "ephemeral"]
        .into_iter()
        .map(|kind| format!("epochgrid.v1.group.{gid}.{kind}"))
        .collect();
    for subjects in [&permissions.publish.allow, &permissions.subscribe.allow] {
        let groups: Vec<_> = subjects
            .iter()
            .filter(|s| s.starts_with("epochgrid.v1.group."))
            .cloned()
            .collect();
        assert_eq!(groups, expected);
        assert!(
            !subjects
                .iter()
                .any(|s| s.starts_with("$JS.API.CONSUMER.CREATE"))
        );
    }
    f.registry.revoke(&f.device.public_key())?;
    assert!(!f.send(&f.request()?, true)?.nats.error.is_empty());
    Ok(())
}
