use super::*;
use crate::{identity::SUITE, transparency::Snapshot};
use openmls::prelude::{KeyPackageIn, tls_codec::Deserialize as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

#[test]
fn encrypted_recovery_preserves_control_and_trust_but_no_mls_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let registration = alice.init("alice", "laptop")?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let bob_registration = bob.init("bob", "laptop")?;
    let operator = nkeys::KeyPair::new_user();
    let snapshot = Snapshot::signed(
        vec![registration.clone(), bob_registration.clone()],
        &operator,
    )?;
    alice.accept_checkpoint(&snapshot)?;
    alice.verify_device("bob", "laptop", &trust::fingerprint(&bob_registration)?)?;
    alice.transparency_failure("EPOCHGRID_RECOVERY_SECRET_91F3")?;
    let group = alice.create_group("engineering")?;
    let seed = Zeroizing::new(alice.nkey()?.seed()?);
    let (bytes, secret) = alice.export_recovery()?;
    for value in [
        seed.as_bytes(),
        b"EPOCHGRID_RECOVERY_SECRET_91F3",
        b"engineering",
        b"alice",
        b"bob",
    ] {
        assert!(!bytes.windows(value.len()).any(|w| w == value));
    }
    let (other, other_secret) = alice.export_recovery()?;
    assert_ne!(bytes, other);
    assert!(RecoveryArchive::decrypt(&bytes, &other_secret).is_err());
    let parsed = RecoverySecret::parse(&secret.encode())?;
    let archive = RecoveryArchive::decrypt(&bytes, &parsed)?;
    drop(alice);
    std::fs::remove_dir_all(root.path().join("alice"))?;
    let restored_path = root.path().join("restored");
    let restored = IdentityStore::open(&restored_path)?;
    let status = archive.restore(&restored)?;
    assert_eq!(
        status.groups,
        vec![GroupHint {
            name: group.name,
            gid: group.gid
        }]
    );
    assert_eq!(
        restored.nkey()?.public_key(),
        registration.payload.nats_public_key
    );
    assert_eq!(restored.registration()?, registration);
    assert_eq!(
        restored
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state,
        "verified"
    );
    assert_eq!(restored.checkpoint()?, Some(snapshot.checkpoint.clone()));
    assert_eq!(
        restored.trust_warning()?.as_deref(),
        Some("EPOCHGRID_RECOVERY_SECRET_91F3")
    );
    assert!(restored.groups()?.is_empty());
    assert!(restored.create_group("unsafe").is_err());
    assert!(restored.export_recovery().is_err());
    assert!(archive.restore(&restored).is_err());
    let credential = KeyPackageIn::tls_deserialize_exact(&registration.payload.mls_key_package)?
        .unverified_credential();
    assert!(
        SignatureKeyPair::read(
            restored.provider.storage(),
            credential.signature_key.as_slice(),
            SUITE.signature_algorithm()
        )
        .is_none()
    );
    for table in [
        "groups",
        "outbox",
        "welcomes",
        "transcript",
        "chat_deliveries",
    ] {
        assert_eq!(
            restored
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
    }
    drop(restored);
    let restored = IdentityStore::open(&restored_path)?;
    assert_eq!(restored.recovery_status()?, Some(status));
    assert!(restored.ensure_messaging_identity().is_err());
    let older = Snapshot::signed(vec![registration], &operator)?;
    assert!(restored.accept_checkpoint(&older).is_err());
    Ok(())
}

#[test]
fn rejects_tamper_truncation_versions_trailing_bytes_and_invalid_secrets() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut store = IdentityStore::open(dir.path())?;
    store.init("alice", "laptop")?;
    let (bytes, secret) = store.export_recovery()?;
    for index in [0, 8, 9, 10, 21, 22, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(RecoveryArchive::decrypt(&bad, &secret).is_err());
    }
    for len in [
        0,
        1,
        HEADER.len(),
        HEADER.len() + NONCE_LEN,
        bytes.len() - 1,
    ] {
        assert!(RecoveryArchive::decrypt(&bytes[..len], &secret).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RecoveryArchive::decrypt(&trailing, &secret).is_err());
    assert!(RecoveryArchive::decrypt(&vec![0; MAX_PACKAGE + 1], &secret).is_err());
    for invalid in [
        "",
        "EG1-password",
        "EG2-0000",
        "EG1-💥",
        "EG1-000000000000000000000000000000000000000000000000000000000000000G",
    ] {
        assert!(RecoverySecret::parse(invalid).is_err());
    }
    assert_eq!(
        RecoverySecret::parse(&secret.encode())?.encode().as_str(),
        secret.encode().as_str()
    );
    Ok(())
}

#[test]
fn restore_and_migration_are_atomic_and_preserve_existing_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let original = alice.init("alice", "laptop")?;
    let group = alice.create_group("engineering")?;
    let (bytes, secret) = alice.export_recovery()?;
    let archive = RecoveryArchive::decrypt(&bytes, &secret)?;
    assert!(archive.restore(&alice).is_err());
    assert_eq!(alice.registration()?, original);
    assert_eq!(alice.group("engineering")?, group);
    let path = root.path().join("restored");
    let restored = IdentityStore::open(&path)?;
    restored.connection.execute_batch("CREATE TRIGGER fail_restore BEFORE INSERT ON recovery_metadata BEGIN SELECT RAISE(ABORT, 'injected'); END;")?;
    assert!(archive.restore(&restored).is_err());
    assert!(restored.registration().is_err());
    assert!(restored.recovery_status()?.is_none());
    restored
        .connection
        .execute_batch("DROP TRIGGER fail_restore;")?;
    archive.restore(&restored)?;
    // Simulate schema 3. The migration must preserve cryptographic identity/group state.
    alice.connection.execute_batch(
        "DROP TABLE recovery_metadata; DELETE FROM epochgrid_migrations WHERE version=4; CREATE TRIGGER fail_recovery_migration BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=4 BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;",
    )?;
    drop(alice);
    assert!(IdentityStore::open(&root.path().join("alice")).is_err());
    let connection = rusqlite::Connection::open(root.path().join("alice/identity.sqlite"))?;
    let tables: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='recovery_metadata'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(tables, 0, "failed migration must roll back table creation");
    connection.execute_batch("DROP TRIGGER fail_recovery_migration;")?;
    drop(connection);
    let alice = IdentityStore::open(&root.path().join("alice"))?;
    assert_eq!(alice.registration()?, original);
    assert_eq!(alice.group("engineering")?, group);
    assert!(alice.recovery_status()?.is_none());
    alice.ensure_messaging_identity()?;
    Ok(())
}

#[test]
fn sticky_key_changes_revocations_and_expired_identity_survive_recovery() -> Result<()> {
    use crate::revocation::{Revocation, RevocationLog, RevokeRequest};
    use openmls::prelude::{KeyPackage, Lifetime, tls_codec::Serialize as _};
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let mut registration = alice.init("alice", "laptop")?;
    let mut desktop = IdentityStore::open(&root.path().join("desktop"))?;
    let sibling = desktop.init("alice", "desktop")?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let original_bob = bob.init("bob", "laptop")?;
    let key = nkeys::KeyPair::new_user();
    let snapshot = Snapshot::signed(
        vec![registration.clone(), sibling.clone(), original_bob.clone()],
        &key,
    )?;
    alice.accept_checkpoint(&snapshot)?;
    alice.verify_device("bob", "laptop", &trust::fingerprint(&original_bob)?)?;
    let mut impostor = IdentityStore::open(&root.path().join("impostor"))?;
    assert!(
        alice
            .observe_device(&impostor.init("bob", "laptop")?)
            .is_err()
    );
    let revoked = RevocationLog::signed(
        vec![Revocation {
            request: RevokeRequest::signed(
                "alice",
                "desktop",
                &sibling.payload.nats_public_key,
                &alice.nkey()?,
            )?,
            chat_cutoff: 42,
        }],
        &key,
    )?;
    alice.accept_revocations(&revoked, &snapshot)?;
    // An expired public package must not expire the independent control credential.
    let (signer, credential) = alice.signer()?;
    let package = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(1, 2))
        .build(SUITE, &alice.provider, &signer, credential)
        .map_err(|e| anyhow!("expired package fixture: {e:?}"))?;
    registration.payload.mls_key_package = package.key_package().tls_serialize_detached()?;
    registration.signature = alice.nkey()?.sign(&registration.payload.signing_bytes()?)?;
    alice.connection.execute(
        "UPDATE local_identity SET registration=?1",
        [postcard::to_allocvec(&registration)?],
    )?;
    assert!(identity::verify(&registration).is_err());
    let (bytes, secret) = alice.export_recovery()?;
    let archive = RecoveryArchive::decrypt(&bytes, &secret)?;
    let restored = IdentityStore::open(&root.path().join("restored"))?;
    archive.restore(&restored)?;
    assert_eq!(
        restored.device_trust("bob", "laptop")?,
        alice.device_trust("bob", "laptop")?
    );
    assert!(
        restored
            .trust_warning()?
            .context("warning missing")?
            .contains("CHANGED")
    );
    assert!(restored.is_revoked(&sibling.payload.nats_public_key)?);
    assert_eq!(restored.revocation_checkpoint()?, Some(revoked.checkpoint));
    let empty = RevocationLog::signed(vec![], &key)?;
    assert!(restored.accept_revocations(&empty, &snapshot).is_err());
    Ok(())
}
