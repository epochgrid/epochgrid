use super::*;

fn defaults() -> InitOptions {
    InitOptions {
        auth_mode: AuthMode::Configuration,
        target_account: None,
        auth_account: None,
        replicas: 1,
    }
}

#[test]
fn invalid_choices_leave_no_home() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("absent");
    let account = nkeys::KeyPair::new_account();
    for options in [
        InitOptions {
            replicas: 2,
            ..defaults()
        },
        InitOptions {
            target_account: Some(account.seed()?),
            ..defaults()
        },
        InitOptions {
            target_account: Some("BAD\nACCOUNT".into()),
            ..defaults()
        },
        InitOptions {
            target_account: Some("EPOCHGRID_AUTH".into()),
            ..defaults()
        },
        InitOptions {
            auth_account: Some(account.public_key()),
            ..defaults()
        },
        InitOptions {
            auth_mode: AuthMode::OperatorJwt,
            ..defaults()
        },
        InitOptions {
            auth_mode: AuthMode::OperatorJwt,
            target_account: Some(account.public_key()),
            auth_account: Some(account.public_key()),
            ..defaults()
        },
        InitOptions {
            auth_mode: AuthMode::OperatorJwt,
            target_account: Some(account.seed()?),
            auth_account: Some(nkeys::KeyPair::new_account().public_key()),
            ..defaults()
        },
    ] {
        assert!(initialize(&home, &options).is_err());
        assert!(!home.exists());
    }
    Ok(())
}

#[test]
fn atomic_publication_preserves_edits_and_rejects_symlinks() -> Result<()> {
    let root = tempfile::tempdir()?;
    let output = root.path().join("bundle");
    let artifacts = BTreeMap::from([
        ("a.json".into(), "first".into()),
        ("b.json".into(), "second".into()),
    ]);
    publish_bundle(&output, &artifacts)?;
    publish_bundle(&output, &artifacts)?;
    fs::write(output.join("a.json"), "operator edit")?;
    assert!(publish_bundle(&output, &artifacts).is_err());
    assert_eq!(fs::read_to_string(output.join("a.json"))?, "operator edit");
    assert!(publish_file(&output.join("a.json"), b"first").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(output.join("b.json"))?.permissions().mode() & 0o777,
            0o600
        );
        symlink(output.join("b.json"), root.path().join("link"))?;
        assert!(publish_file(&root.path().join("link"), b"second").is_err());
        symlink(&output, root.path().join("linked-bundle"))?;
        assert!(publish_bundle(&root.path().join("linked-bundle"), &artifacts).is_err());
    }
    Ok(())
}

#[test]
fn setup_lock_precedes_secrets_and_database_creation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let _lock = lock(root.path())?;
    assert!(
        initialize(root.path(), &defaults())
            .unwrap_err()
            .to_string()
            .contains("already in progress")
    );
    assert_eq!(fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn initialization_export_and_interrupted_retry_preserve_identity() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path();
    let options = InitOptions {
        target_account: Some("CUSTOM_APP".into()),
        replicas: 3,
        ..defaults()
    };
    // Simulate interruption after durable credentials/databases but before auth.json.
    fs::create_dir(home.join("deployment-artifacts"))?;
    fs::write(home.join("deployment-artifacts/operator-note"), "keep")?;
    assert!(initialize(home, &options).is_err());
    assert!(!home.join("auth.json").exists());
    let credentials = fs::read(home.join("credentials.json"))?;
    let control_credentials = fs::read(home.join("control/credentials.json"))?;
    let registration = IdentityStore::open(&home.join("control"))?.registration()?;
    assert!(initialize(home, &defaults()).is_err());
    fs::remove_file(home.join("deployment-artifacts/operator-note"))?;
    fs::remove_dir(home.join("deployment-artifacts"))?;
    initialize(home, &options)?;
    assert_eq!(fs::read(home.join("credentials.json"))?, credentials);
    assert_eq!(
        fs::read(home.join("control/credentials.json"))?,
        control_credentials
    );
    assert_eq!(
        IdentityStore::open(&home.join("control"))?.registration()?,
        registration
    );
    assert!(initialize(home, &options).is_err());
    let path = home.join("auth.json");
    let auth_bytes = fs::read(&path)?;
    let config = Config::load(&path)?;
    assert_eq!(config.target_account, "CUSTOM_APP");
    let manifest: DeploymentManifest =
        serde_json::from_slice(&fs::read(home.join(MANIFEST_FILE))?)?;
    assert_eq!(manifest.replicas(), 3);
    assert!(
        fs::read_to_string(home.join("nats-reference.conf"))?
            .contains("allowed_accounts: [\"CUSTOM_APP\"]")
    );
    for reference in [&config.issuer, &config.encryption, &config.connection] {
        let secret = reference.read()?;
        for contents in artifacts(&config, &manifest)?.values() {
            assert!(!contents.contains(secret.as_str()));
        }
    }
    export(home, &path, None, None)?;
    assert!(export(home, &path, Some(1), None).is_err());
    // Export an established M26 home without a manifest; explicit replicas required.
    fs::remove_file(home.join(MANIFEST_FILE))?;
    let output = home.join("second-export");
    assert!(export(home, &path, None, Some(&output)).is_err());
    assert!(!output.exists());
    export(home, &path, Some(3), Some(&output))?;
    assert_eq!(fs::read(&path)?, auth_bytes);
    assert_eq!(fs::read(home.join("credentials.json"))?, credentials);
    fs::write(output.join("CHAT.json"), "edited")?;
    assert!(export(home, &path, None, Some(&output)).is_err());
    assert_eq!(fs::read_to_string(output.join("CHAT.json"))?, "edited");
    Ok(())
}

#[test]
fn operator_setup_is_explicitly_incomplete_until_external_signing() -> Result<()> {
    use nats_jwt_rs::user::User;
    let root = tempfile::tempdir()?;
    let auth = nkeys::KeyPair::new_account();
    let app = nkeys::KeyPair::new_account();
    let options = InitOptions {
        auth_mode: AuthMode::OperatorJwt,
        target_account: Some(app.public_key()),
        auth_account: Some(auth.public_key()),
        replicas: 3,
    };
    initialize(root.path(), &options)?;
    let path = root.path().join("auth.json");
    assert!(
        Config::load(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("setup incomplete")
    );
    let mut config = Config::load_for_export(&path)?;
    let report = epochgrid_core::validation::offline(root.path(), &path, None);
    assert!(!report.success);
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.observed == serde_json::json!("operator_setup_incomplete"))
    );
    assert!(
        config
            .operator_jwt
            .as_ref()
            .unwrap()
            .connection_jwt
            .is_empty()
    );
    assert!(!root.path().join("nats-reference.conf").exists());
    export(root.path(), &path, None, None)?;
    let delegation: serde_json::Value = serde_json::from_slice(&fs::read(
        root.path()
            .join("deployment-artifacts/operator-delegation.json"),
    )?)?;
    assert_eq!(
        delegation["external_authorization"]["allowed_accounts"][0],
        app.public_key()
    );
    let mut user = User::new_claims("service".into(), config.connection.public_key.clone());
    user.nats.generic_fields.version = 2;
    config.operator_jwt.as_mut().unwrap().connection_jwt = user.encode(&auth)?;
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    Config::load(&path)?;
    assert!(epochgrid_core::validation::offline(root.path(), &path, None).success);
    export(root.path(), &path, None, None)?;
    // Neither root seeds nor the signed service JWT belong in exported artifacts.
    for contents in artifacts(&config, &DeploymentManifest::new(3)?)?.values() {
        assert!(!contents.contains(&auth.seed()?));
        assert!(!contents.contains(&app.seed()?));
        assert!(!contents.contains(&config.operator_jwt.as_ref().unwrap().connection_jwt));
    }
    Ok(())
}

#[test]
fn export_rejects_wrong_bindings_before_publishing() -> Result<()> {
    let root = tempfile::tempdir()?;
    initialize(root.path(), &defaults())?;
    let path = root.path().join("auth.json");
    let original = fs::read(&path)?;
    let credentials = fs::read(root.path().join("credentials.json"))?;
    let mut config = Config::load(&path)?;
    config.control_nkey = nkeys::KeyPair::new_user().public_key();
    fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    let output = root.path().join("not-created");
    assert!(export(root.path(), &path, None, Some(&output)).is_err());
    assert!(!output.exists());
    assert_eq!(fs::read(root.path().join("credentials.json"))?, credentials);
    fs::write(&path, original)?;
    let absent = root.path().join("absent");
    assert!(export(&absent, &absent.join("auth.json"), Some(1), None).is_err());
    assert!(!absent.exists());
    Ok(())
}

#[test]
fn offline_validation_accepts_established_state_and_rejects_unsafe_inputs() -> Result<()> {
    use epochgrid_core::validation::{Status, offline};
    let root = tempfile::tempdir()?;
    initialize(root.path(), &defaults())?;
    let path = root.path().join("auth.json");
    let auth = fs::read(&path)?;
    let credentials = fs::read(root.path().join("credentials.json"))?;
    let report = offline(root.path(), &path, Some("tls://127.0.0.1:1"));
    assert!(report.success, "{}", report.human());
    assert_eq!(fs::read(&path)?, auth);
    assert_eq!(fs::read(root.path().join("credentials.json"))?, credentials);
    let bad_url = offline(
        root.path(),
        &path,
        Some("tls://secret-user:PRIVATE_PASSWORD@localhost"),
    );
    assert!(!bad_url.success);
    assert!(!serde_json::to_string(&bad_url)?.contains("PRIVATE_PASSWORD"));
    assert!(
        bad_url
            .checks
            .iter()
            .any(|check| check.id == "local.transport.endpoint" && check.status == Status::Failed)
    );
    fs::write(root.path().join("deployment.json"), b"{invalid}")?;
    assert!(!offline(root.path(), &path, None).success);
    assert_eq!(fs::read(root.path().join("deployment.json"))?, b"{invalid}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let report = offline(root.path(), &path, None);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.observed == serde_json::json!("permissions_too_open"))
        );
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o644);
    }
    Ok(())
}

#[test]
fn stopped_capacity_upgrade_preserves_state_and_rejects_lower_usage_and_edits() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("backend");
    initialize(&home, &defaults())?;
    let auth = home.join("auth.json");
    let mut registry = AuthRegistry::open(&home)?;
    registry.invite("alice", 60)?;
    registry.invite("bob", 60)?;
    drop(registry);
    let original_manifest = fs::read(home.join(MANIFEST_FILE))?;
    let original_credentials = fs::read(home.join("credentials.json"))?;
    let original_auth = fs::read(&auth)?;
    // Model an established M28 home, retaining its original replica manifest.
    fs::remove_file(home.join(epochgrid_core::capacity::FILE))?;
    let policy_path = root.path().join("policy.json");
    let policy = epochgrid_core::capacity::Capacity::default();
    fs::write(&policy_path, serde_json::to_vec(&policy)?)?;
    let output = root.path().join("capacity-artifacts");
    let runtime = crate::roles::runtime_lock(&home)?;
    assert!(capacity_export(&home, &auth, &policy_path, &output, false).is_err());
    assert!(!output.exists());
    drop(runtime);
    capacity_export(&home, &auth, &policy_path, &output, false)?;
    capacity_export(&home, &auth, &policy_path, &output, false)?;
    assert_eq!(fs::read(home.join(MANIFEST_FILE))?, original_manifest);
    assert_eq!(
        fs::read(home.join("credentials.json"))?,
        original_credentials
    );
    assert_eq!(fs::read(&auth)?, original_auth);
    let installed = fs::read(home.join(epochgrid_core::capacity::FILE))?;
    let mut lower = policy.clone();
    lower.retained_users = 1;
    fs::write(&policy_path, serde_json::to_vec(&lower)?)?;
    assert!(capacity_export(&home, &auth, &policy_path, &root.path().join("lower"), true).is_err());
    assert_eq!(
        fs::read(home.join(epochgrid_core::capacity::FILE))?,
        installed
    );
    fs::write(&policy_path, serde_json::to_vec(&policy)?)?;
    fs::write(output.join("CHAT.json"), "operator edit")?;
    assert!(capacity_export(&home, &auth, &policy_path, &output, false).is_err());
    assert_eq!(
        fs::read_to_string(output.join("CHAT.json"))?,
        "operator edit"
    );
    let mut raised = policy;
    raised.chat_bytes *= 2;
    fs::write(&policy_path, serde_json::to_vec(&raised)?)?;
    capacity_export(
        &home,
        &auth,
        &policy_path,
        &root.path().join("raised"),
        true,
    )?;
    assert_eq!(epochgrid_core::capacity::Capacity::load(&home)?, raised);
    Ok(())
}
