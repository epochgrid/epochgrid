use super::*;

#[test]
fn missing_home_is_never_initialized_and_reports_roundtrip() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("missing");
    let report = offline(&home, &home.join("auth.json"), None);
    assert!(!report.success);
    assert!(!home.exists());
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "coverage.network" && check.status == Status::NotChecked)
    );
    let encoded = serde_json::to_vec(&report)?;
    assert!(!Report::parse(&encoded)?.success);
    let mut value = serde_json::to_value(&report)?;
    value["version"] = json!(2);
    assert!(Report::parse(&serde_json::to_vec(&value)?).is_err());
    value["version"] = json!(1);
    value["success"] = json!(true);
    assert!(Report::parse(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn raw_errors_never_enter_reports() {
    let mut report = Report {
        version: 1,
        mode: "offline".into(),
        success: false,
        checks: Vec::new(),
    };
    report.check::<()>(
        "local.test",
        "valid",
        "invalid",
        "Review configuration.",
        || anyhow::bail!("PRIVATE_TOKEN_JWT_SEED_DATABASE_RECORD"),
    );
    let output = serde_json::to_string(&report).unwrap();
    assert!(!output.contains("PRIVATE_TOKEN"));
    assert!(!report.human().contains("PRIVATE_TOKEN"));
    assert_eq!(report.checks[0].observed, json!("invalid"));
}

#[test]
fn keyring_errors_have_distinct_safe_diagnostics() {
    for (error, code) in [
        (crate::secrets::Error::Missing, "credential_missing"),
        (crate::secrets::Error::Locked, "keyring_locked"),
        (crate::secrets::Error::Duplicate, "credential_duplicate"),
        (
            crate::secrets::Error::Binding,
            "credential_binding_mismatch",
        ),
        (crate::secrets::Error::Unavailable, "keyring_unavailable"),
    ] {
        assert_eq!(diagnostic(&error.into(), "fallback", "remedy").0, code);
    }
}

#[test]
#[ignore = "locks its disposable Secret Service collection; verify.sh secrets"]
fn live_validation_duplicate_swapped_and_locked_credentials() -> Result<()> {
    use crate::{identity::IdentityStore, identity_model::AuthRegistry, secrets::save};
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    let root = tempfile::tempdir()?;
    drop(AuthRegistry::open(root.path())?);
    let mut control = IdentityStore::open(&root.path().join("control"))?;
    let control_nkey = control.init("service", "laptop")?.payload.nats_public_key;
    drop(control);
    let vault = Vault::new(root.path());
    let config = Config {
        version: 2,
        issuer: vault.provision("issuer", Kind::Account)?,
        encryption: vault.provision("encryption", Kind::XKey)?,
        connection: vault.provision("connection", Kind::User)?,
        target_account: "EPOCHGRID".into(),
        control_nkey,
        authorization_ttl_seconds: 30,
        development_plaintext: false,
        operator_jwt: None,
    };
    let path = root.path().join("auth.json");
    save(&path, &config)?;
    save(
        &root.path().join("deployment.json"),
        &DeploymentManifest::new(1)?,
    )?;
    let metadata = std::fs::read(root.path().join("credentials.json"))?;
    let database = std::fs::read(root.path().join("auth.sqlite"))?;
    assert!(offline(root.path(), &path, None).success);
    let secret = config.issuer.read()?;
    let swapped = zeroize::Zeroizing::new(nkeys::KeyPair::new_account().seed()?);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let service = SecretService::connect(EncryptionType::Dh).await?;
        let collection = service.get_default_collection().await?;
        let attributes = HashMap::from([
            ("application", "org.epochgrid.credentials.v1"),
            ("id", config.issuer.id.as_str()),
        ]);
        let original = service
            .search_items(attributes.clone())
            .await?
            .unlocked
            .remove(0);
        let duplicate = collection
            .create_item(
                "duplicate validation fixture",
                attributes,
                secret.as_bytes(),
                false,
                "text/plain",
            )
            .await?;
        let report = offline(root.path(), &path, None);
        assert!(!report.success);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.observed == json!("credential_duplicate"))
        );
        duplicate.delete().await?;
        original
            .set_secret(swapped.as_bytes(), "text/plain")
            .await?;
        let report = offline(root.path(), &path, None);
        assert!(!report.success);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.observed == json!("credential_binding_mismatch"))
        );
        let encoded = serde_json::to_string(&report)?;
        assert!(!encoded.contains(secret.as_str()) && !encoded.contains(swapped.as_str()));
        original.set_secret(secret.as_bytes(), "text/plain").await?;
        assert!(offline(root.path(), &path, None).success);
        collection.lock().await?;
        let report = offline(root.path(), &path, None);
        assert!(!report.success);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.observed == json!("keyring_locked"))
        );
        Result::<()>::Ok(())
    })?;
    // No live SQLite handles exist while byte-preservation is checked.
    assert_eq!(
        std::fs::read(root.path().join("credentials.json"))?,
        metadata
    );
    assert_eq!(std::fs::read(root.path().join("auth.sqlite"))?, database);
    Ok(())
}
