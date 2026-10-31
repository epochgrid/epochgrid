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
        let vault = crate::secrets::Vault::new(root.path());
        let config = Config {
            version: 2,
            issuer: vault.import("issuer", Kind::Account, &issuer.seed()?)?,
            encryption: vault.import("encryption", Kind::XKey, &auth_x.seed()?)?,
            connection: vault.provision("connection", Kind::User)?,
            control_nkey: KeyPair::new_user().public_key(),
            target_account: "EPOCHGRID".into(),
            authorization_ttl_seconds: 30,
            development_plaintext: true,
            operator_jwt: None,
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
            serde_json::json!({"iat":0,"iss":"","jti":"","sub":self.config.issuer.public_key,"aud":"nats-authorization-request","exp":now()?+2,"nats":{"type":"authorization_request","version":2,"server_id":{"id":self.server.public_key(),"xkey":self.server_x.public_key()},"user_nkey":KeyPair::new_user().public_key(),"client_info":{"nonce":"test-challenge"},"connect_opts":{"nkey":self.device.public_key(),"sig":URL_SAFE_NO_PAD.encode(self.device.sign(b"test-challenge")?)}}}),
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
fn isolated_worker_cannot_gain_authority_grants() -> Result<()> {
    let mut f = Fixture::new()?;
    let authority = KeyPair::new_user();
    let worker = KeyPair::new_user();
    f.config.control_nkey = authority.public_key();
    f.callout = Callout::new(f.config.clone())?.with_worker(worker.public_key())?;
    for (key, expected) in [
        (&worker, crate::backend_roles::worker_publish()),
        (&authority, crate::backend_roles::authority_publish()),
    ] {
        let mut request = f.request()?;
        request.nats.connect_opts.nkey = key.public_key();
        request.nats.connect_opts.sig = URL_SAFE_NO_PAD.encode(key.sign(b"test-challenge")?);
        let response = f.send(&request, false)?;
        assert!(response.nats.error.is_empty());
        let user = Claims::<User>::decode(&response.nats.jwt)?;
        assert_eq!(user.nats.permissions.permissions.publish.allow, expected);
        assert!(user.exp.context("expiry")? <= now()? + 60);
    }
    let request = f.request()?;
    assert!(!f.send(&request, false)?.nats.error.is_empty());
    let mut forged = f.request()?;
    forged.nats.connect_opts.nkey = worker.public_key();
    assert!(!f.send(&forged, true)?.nats.error.is_empty());
    Ok(())
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

#[test]
fn control_role_lease_is_bounded_independently_of_device_ttl() -> Result<()> {
    let mut fixture = Fixture::new()?;
    fixture.callout.config.control_nkey = fixture.device.public_key();
    fixture.callout.config.authorization_ttl_seconds = 3;
    let response = fixture.send(&fixture.request()?, false)?;
    let user = Claims::<User>::decode(&response.nats.jwt)?;
    let expiry = user
        .exp
        .context("control role must not receive an unlimited lease")?;
    assert!((now()? + 59..=now()? + 60).contains(&expiry));
    Ok(())
}

#[test]
fn operator_account_binding_and_signed_service_credential() -> Result<()> {
    let mut f = Fixture::new()?;
    let auth = KeyPair::new_account();
    let target = KeyPair::new_account();
    let mut service = User::new_claims(
        "auth service".into(),
        f.config.connection.public_key.clone(),
    );
    service.nats.generic_fields.version = 2;
    f.config.target_account = target.public_key();
    f.config.operator_jwt = Some(OperatorJwt {
        auth_account: auth.public_key(),
        connection_jwt: service.encode(&auth)?,
    });
    let path = f._root.path().join("auth.json");
    std::fs::write(&path, serde_json::to_vec(&f.config)?)?;
    f.callout = Callout::new(Config::load(&path)?)?;
    let mut request = f.request()?;
    // Configuration-mode issuer is not the operator-mode request subject.
    assert!(f.send(&request, true).is_err());
    request.sub = auth.public_key();
    let response = f.send(&request, true)?;
    let admitted = Claims::<User>::decode(&response.nats.jwt)?;
    assert_eq!(admitted.nats.issuer_account, Some(target.public_key()));
    assert!(admitted.aud.is_none());
    assert_eq!(admitted.iss, f.config.issuer.public_key);
    assert_eq!(admitted.sub, request.nats.user_nkey);
    let mut other_account = f.request()?;
    other_account.sub = KeyPair::new_account().public_key();
    assert!(f.send(&other_account, true).is_err());
    for kind in ["wrong-key", "wrong-account", "expired", "future", "bearer"] {
        let mut bad = service.clone();
        let mut signer = &auth;
        match kind {
            "wrong-key" => bad.sub = KeyPair::new_user().public_key(),
            "wrong-account" => signer = &target,
            "expired" => bad.exp = Some(now()? - 1),
            "future" => bad.nbf = Some(now()? + 60),
            "bearer" => bad.nats.permissions.bearer_token = Some(true),
            _ => unreachable!(),
        }
        f.config.operator_jwt.as_mut().unwrap().connection_jwt = bad.encode(signer)?;
        std::fs::write(&path, serde_json::to_vec(&f.config)?)?;
        assert!(Config::load(&path).is_err(), "{kind}");
    }
    Ok(())
}

#[test]
fn maximum_group_grant_fits_signed_encrypted_response_budget() -> Result<()> {
    let mut fixture = Fixture::new()?;
    for i in 0..16 {
        let gid = format!("{i:032x}");
        fixture.registry.db.execute(
            "INSERT INTO authorization_groups VALUES(?1,1,0,?2,X'')",
            rusqlite::params![gid, fixture.device.public_key()],
        )?;
        fixture.registry.db.execute(
            "INSERT INTO authorization_members VALUES(?1,?2,0)",
            rusqlite::params![gid, fixture.device.public_key()],
        )?;
    }
    fixture
        .registry
        .capacity
        .check_registry(&fixture.registry.db)?;
    let request = fixture.request()?;
    let response = fixture.send(&request, true)?;
    assert!(response.nats.error.is_empty());
    let user = Claims::<User>::decode(&response.nats.jwt)?;
    assert_eq!(user.nats.permissions.permissions.subscribe.allow.len(), 50);
    let issuer = KeyPair::from_seed(&fixture.config.issuer.read()?)?;
    let encoded = response.encode(&issuer)?;
    // Includes a generous envelope/name/generation allowance beyond this fixture.
    assert!(encoded.len() + 2048 < wire::MAX_WIRE);
    eprintln!(
        "capacity grant fixture: groups=16, signed_response_bytes={}",
        encoded.len()
    );
    Ok(())
}
