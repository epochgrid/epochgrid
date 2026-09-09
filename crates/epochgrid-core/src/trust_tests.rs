use crate::{
    identity::IdentityStore,
    transparency::{self, Snapshot},
    trust,
    wire::{self, Body},
};
use anyhow::{Context, Result};
use openmls::prelude::{KeyPackage, tls_codec::Serialize as _};

#[test]
fn fingerprints_verification_key_change_and_restart() -> Result<()> {
    let a = tempfile::tempdir()?;
    let b = tempfile::tempdir()?;
    let replacement = tempfile::tempdir()?;
    let alice = IdentityStore::open(a.path())?;
    let mut bob = IdentityStore::open(b.path())?;
    let original = bob.init("bob", "laptop")?;
    let fingerprint = trust::fingerprint(&original)?;
    alice.observe_device(&original)?;
    assert_eq!(
        alice
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state,
        "unverified"
    );
    assert!(
        alice
            .verify_device("bob", "laptop", &"0".repeat(64))
            .is_err()
    );
    alice.verify_device(
        "bob",
        "laptop",
        &trust::display_fingerprint(&fingerprint.to_ascii_lowercase()),
    )?;
    // Renewing HPKE/package material with the same identity keys has a stable fingerprint.
    let (signer, credential) = bob.signer()?;
    let bundle = KeyPackage::builder()
        .build(crate::identity::SUITE, &bob.provider, &signer, credential)
        .map_err(|e| anyhow::anyhow!("build package: {e:?}"))?;
    let mut renewed = original.clone();
    renewed.payload.mls_key_package = bundle.key_package().tls_serialize_detached()?;
    renewed.payload.created_at += 1;
    renewed.signature = bob.nkey()?.sign(&renewed.payload.signing_bytes()?)?;
    assert_ne!(
        renewed.payload.mls_key_package,
        original.payload.mls_key_package
    );
    assert_eq!(trust::fingerprint(&renewed)?, fingerprint);
    alice.observe_device(&renewed)?;
    drop(alice);
    let alice = IdentityStore::open(a.path())?;
    assert_eq!(
        alice
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state,
        "verified"
    );
    // Change only MLS identity material, retaining Bob's NKey and a valid signature.
    let mut fake = IdentityStore::open(replacement.path())?.init("bob", "laptop")?;
    fake.payload.nats_public_key = original.payload.nats_public_key.clone();
    fake.signature = bob.nkey()?.sign(&fake.payload.signing_bytes()?)?;
    crate::identity::verify(&fake)?;
    assert_ne!(trust::fingerprint(&fake)?, fingerprint);
    let fake_fingerprint = trust::fingerprint(&fake)?;
    assert!(alice.observe_device(&fake).is_err());
    let changed = alice
        .device_trust("bob", "laptop")?
        .context("trust missing")?;
    assert_eq!(changed.state, "changed");
    assert_eq!(changed.fingerprint, fingerprint);
    assert!(
        alice
            .verify_device("bob", "laptop", &changed.latest_fingerprint)
            .is_err()
    );
    drop(alice);
    let alice = IdentityStore::open(a.path())?;
    assert!(
        alice
            .trust_warning()?
            .context("warning missing")?
            .contains("CHANGED")
    );
    assert!(
        alice.observe_device(&original).is_err(),
        "changes remain sticky"
    );
    assert_eq!(
        alice
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .latest_fingerprint,
        fake_fingerprint
    );
    Ok(())
}

#[test]
fn merkle_prefixes_tamper_signer_rollback_and_wire() -> Result<()> {
    let root = tempfile::tempdir()?;
    let local = IdentityStore::open(&root.path().join("local"))?;
    let key = nkeys::KeyPair::new_user();
    let mut registrations = Vec::new();
    for user in ["alice", "bob", "charlie", "dana", "evan"] {
        registrations.push(IdentityStore::open(&root.path().join(user))?.init(user, "laptop")?);
    }
    assert_eq!(
        transparency::root(&[])?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    local.pin_directory(&key.public_key())?;
    for length in 0..=registrations.len() {
        let snapshot = Snapshot::signed(registrations[..length].to_vec(), &key)?;
        local.accept_checkpoint(&snapshot)?;
        let encoded = wire::encode(Body::AuditLog(snapshot.clone()))?;
        assert_eq!(&encoded[..2], &[1, 11]);
        assert_eq!(transparency::decode(&encoded)?, snapshot);
    }
    assert_eq!(wire::encode(Body::Audit)?, vec![1, 10]);
    let checkpoint = local.checkpoint()?.context("checkpoint missing")?;
    let complete = Snapshot::signed(registrations.clone(), &key)?;
    let old = Snapshot::signed(registrations[..2].to_vec(), &key)?;
    assert!(local.accept_checkpoint(&old).is_err());
    let mut reorder = registrations.clone();
    reorder.swap(1, 2);
    assert!(
        local
            .accept_checkpoint(&Snapshot::signed(reorder, &key)?)
            .is_err()
    );
    assert!(
        local
            .accept_checkpoint(&Snapshot::signed(
                registrations.clone(),
                &nkeys::KeyPair::new_user()
            )?)
            .is_err()
    );
    let mut altered = complete.clone();
    altered.checkpoint.signature[0] ^= 1;
    assert!(altered.validate().is_err());
    let mut altered = complete;
    altered.entries[0].payload.created_at += 1;
    assert!(altered.validate().is_err());
    assert!(
        Snapshot::signed(altered.entries, &key).is_err(),
        "log signer cannot forge device signature"
    );
    let mut duplicate = registrations;
    duplicate.push(duplicate[0].clone());
    assert!(Snapshot::signed(duplicate, &key).is_err());
    assert_eq!(local.checkpoint()?, Some(checkpoint));
    Ok(())
}

#[test]
fn expired_packages_remain_auditable_but_cannot_be_used_for_discovery() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut bob = IdentityStore::open(&dir.path().join("bob"))?;
    let mut record = bob.init("bob", "laptop")?;
    let (signer, credential) = bob.signer()?;
    let package = KeyPackage::builder()
        .key_package_lifetime(openmls::prelude::Lifetime::init(1, 2))
        .build(crate::identity::SUITE, &bob.provider, &signer, credential)
        .map_err(|e| anyhow::anyhow!("build expired package: {e:?}"))?;
    record.payload.mls_key_package = package.key_package().tls_serialize_detached()?;
    record.signature = bob.nkey()?.sign(&record.payload.signing_bytes()?)?;
    assert!(crate::identity::verify(&record).is_err());
    let historic = Snapshot::signed(vec![record], &nkeys::KeyPair::new_user())?;
    let local = IdentityStore::open(&dir.path().join("alice"))?;
    local.accept_checkpoint(&historic)?;
    assert_eq!(local.checkpoint()?, Some(historic.checkpoint));
    Ok(())
}

#[test]
fn migration_preserves_state_and_rolls_back_on_failure() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut local = IdentityStore::open(dir.path())?;
    let registration = local.init("alice", "laptop")?;
    let group = local.create_group("engineering")?;
    local.connection.execute_batch("DROP TABLE device_trust; DROP TABLE transparency_state; DROP TABLE trust_alert; DELETE FROM epochgrid_migrations WHERE version=2;
        CREATE TRIGGER fail_migration BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=2 BEGIN SELECT RAISE(ABORT,'injected migration failure'); END;")?;
    drop(local);
    assert!(IdentityStore::open(dir.path()).is_err());
    let connection = rusqlite::Connection::open(dir.path().join("identity.sqlite"))?;
    let tables: u64 = connection.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('device_trust','transparency_state','trust_alert')", [], |r| r.get(0))?;
    assert_eq!(tables, 0, "partial migration rolled back");
    connection.execute_batch("DROP TRIGGER fail_migration")?;
    drop(connection);
    let local = IdentityStore::open(dir.path())?;
    assert_eq!(local.registration()?, registration);
    assert_eq!(local.group("engineering")?, group);
    assert_eq!(local.group_epoch("engineering")?, 0);
    assert!(local.checkpoint()?.is_none());
    assert!(local.trust_warning()?.is_none());
    Ok(())
}
