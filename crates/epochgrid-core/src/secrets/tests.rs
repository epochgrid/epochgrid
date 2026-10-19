use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct Memory {
    items: Mutex<BTreeMap<String, Zeroizing<String>>>,
    fail_after_create: AtomicBool,
    locked: AtomicBool,
}
impl Backend for Memory {
    fn read(&self, id: &str) -> Result<Option<Zeroizing<String>>> {
        ensure!(!self.locked.load(Ordering::SeqCst), Error::Locked);
        Ok(self.items.lock().unwrap().get(id).cloned())
    }
    fn create(&self, id: &str, secret: &str) -> Result<()> {
        let mut items = self.items.lock().unwrap();
        ensure!(!items.contains_key(id), Error::Duplicate);
        items.insert(id.into(), Zeroizing::new(secret.into()));
        // Simulate a lost response after the service durably accepted the write.
        ensure!(
            !self.fail_after_create.swap(false, Ordering::SeqCst),
            Error::Timeout
        );
        Ok(())
    }
}
fn fixture() -> Result<(tempfile::TempDir, Arc<Memory>, Vault)> {
    let root = tempfile::tempdir()?;
    let backend = Arc::new(Memory::default());
    let vault = Vault {
        root: root.path().into(),
        backend: backend.clone(),
    };
    Ok((root, backend, vault))
}
#[test]
fn pending_creation_survives_lost_response_without_replacing_key() -> Result<()> {
    let (root, backend, vault) = fixture()?;
    backend.fail_after_create.store(true, Ordering::SeqCst);
    assert!(vault.provision("device", Kind::User).is_err());
    let original = backend
        .items
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    let restarted = Vault {
        root: root.path().into(),
        backend: backend.clone(),
    };
    let reference = restarted.provision("device", Kind::User)?;
    assert_eq!(*reference.read_with(backend.as_ref())?, *original);
    assert_eq!(backend.items.lock().unwrap().len(), 1);
    let bytes = std::fs::read(root.path().join("credentials.json"))?;
    assert!(
        !bytes
            .windows(original.len())
            .any(|w| w == original.as_bytes())
    );
    Ok(())
}
#[test]
fn missing_committed_key_and_wrong_binding_never_regenerate() -> Result<()> {
    let (_root, backend, vault) = fixture()?;
    let reference = vault.provision("device", Kind::User)?;
    backend.items.lock().unwrap().remove(&reference.id);
    assert!(vault.provision("device", Kind::User).is_err());
    assert!(backend.items.lock().unwrap().is_empty());
    backend
        .items
        .lock()
        .unwrap()
        .insert(reference.id.clone(), Kind::User.generate()?);
    assert!(vault.provision("device", Kind::User).is_err());
    assert!(reference.read_with(backend.as_ref()).is_err());
    Ok(())
}
#[test]
fn locked_backend_leaves_pending_state_without_plaintext_fallback() -> Result<()> {
    let (root, backend, vault) = fixture()?;
    backend.locked.store(true, Ordering::SeqCst);
    assert!(vault.provision("device", Kind::User).is_err());
    assert!(backend.items.lock().unwrap().is_empty());
    let before: Metadata =
        serde_json::from_slice(&std::fs::read(root.path().join("credentials.json"))?)?;
    backend.locked.store(false, Ordering::SeqCst);
    let reference = vault.provision("device", Kind::User)?;
    assert_eq!(reference.id, before.slots["device"].id);
    Ok(())
}
#[test]
fn restore_retries_same_key_but_rejects_other_identity_or_kind() -> Result<()> {
    let (_root, backend, vault) = fixture()?;
    let original = Kind::User.generate()?;
    let reference = vault.import("device", Kind::User, &original)?;
    assert_eq!(vault.import("device", Kind::User, &original)?, reference);
    assert!(
        vault
            .import("device", Kind::User, &Kind::User.generate()?)
            .is_err()
    );
    assert!(vault.provision("device", Kind::Account).is_err());
    assert_eq!(backend.items.lock().unwrap().len(), 1);
    Ok(())
}
#[test]
fn metadata_commit_failure_is_resumable_and_never_deletes_an_item() -> Result<()> {
    let (root, backend, vault) = fixture()?;
    // First persist intent, then leave a key with no committed public binding.
    backend.fail_after_create.store(true, Ordering::SeqCst);
    assert!(vault.provision("device", Kind::User).is_err());
    let pending = root.path().join("credentials.pending");
    std::fs::create_dir(&pending)?;
    assert!(vault.provision("device", Kind::User).is_err());
    assert_eq!(backend.items.lock().unwrap().len(), 1);
    std::fs::remove_dir(pending)?;
    vault.provision("device", Kind::User)?;
    assert_eq!(backend.items.lock().unwrap().len(), 1);
    Ok(())
}
#[test]
fn old_plaintext_database_is_rejected_without_modification() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("identity.sqlite");
    let db = rusqlite::Connection::open(&path)?;
    db.execute_batch(
        "CREATE TABLE local_identity(id INTEGER PRIMARY KEY, seed TEXT, registration BLOB);",
    )?;
    drop(db);
    let before = std::fs::read(&path)?;
    assert!(crate::identity::IdentityStore::open(root.path()).is_err());
    assert_eq!(std::fs::read(path)?, before);
    assert!(!root.path().join("credentials.json").exists());
    Ok(())
}

/// This test deliberately locks its collection. Only run in its own disposable bus.
#[test]
#[ignore = "requires dedicated disposable Secret Service; verify.sh secrets"]
fn live_keyring_restart_binding_duplicate_and_lock() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut identity = crate::identity::IdentityStore::open(root.path())?;
    let registration = identity.init("alice", "laptop")?;
    let secret = Zeroizing::new(identity.nkey()?.seed()?);
    drop(identity);
    let identity = crate::identity::IdentityStore::open(root.path())?;
    assert_eq!(
        identity.nkey()?.public_key(),
        registration.payload.nats_public_key
    );
    drop(identity);
    for entry in std::fs::read_dir(root.path())? {
        let bytes = std::fs::read(entry?.path())?;
        assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
    }
    let vault = Vault::new(root.path());
    let reference = vault.provision("device", Kind::User)?;
    let database = vault.provision("database-identity", Kind::Database)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::connect(EncryptionType::Dh).await?;
        let attributes = HashMap::from([
            ("application", "org.epochgrid.credentials.v1"),
            ("id", reference.id.as_str()),
        ]);
        let collection = service.get_default_collection().await?;
        let duplicate = collection
            .create_item(
                "duplicate",
                attributes,
                secret.as_bytes(),
                false,
                "text/plain",
            )
            .await?;
        assert!(matches!(
            reference.read().unwrap_err().downcast_ref::<Error>(),
            Some(Error::Duplicate)
        ));
        duplicate.delete().await?;
        let duplicate_database = collection
            .create_item(
                "duplicate database key",
                HashMap::from([
                    ("application", "org.epochgrid.credentials.v1"),
                    ("id", database.id.as_str()),
                ]),
                database.read()?.as_bytes(),
                false,
                "text/plain",
            )
            .await?;
        assert!(matches!(
            crate::identity::IdentityStore::open(root.path())
                .err()
                .unwrap()
                .downcast_ref::<Error>(),
            Some(Error::Duplicate)
        ));
        duplicate_database.delete().await?;
        let mut wrong = reference.clone();
        wrong.public_key = nkeys::KeyPair::new_user().public_key();
        assert!(wrong.read().is_err());
        collection.lock().await?;
        assert!(matches!(
            crate::identity::IdentityStore::open(root.path())
                .err()
                .unwrap()
                .downcast_ref::<Error>(),
            Some(Error::Locked)
        ));
        assert!(matches!(
            reference.read().unwrap_err().downcast_ref::<Error>(),
            Some(Error::Locked)
        ));
        Result::<()>::Ok(())
    })?;
    Ok(())
}

#[test]
#[ignore = "verify.sh secrets supplies an unreachable bus address"]
fn live_unavailable_bus_is_bounded() -> Result<()> {
    let started = std::time::Instant::now();
    let reference = SecretRef {
        id: nkeys::KeyPair::new_user().public_key(),
        kind: Kind::User,
        public_key: nkeys::KeyPair::new_user().public_key(),
    };
    assert!(reference.read().is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(7));
    Ok(())
}

#[test]
fn identity_transaction_failure_reuses_the_protected_key_on_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut identity = crate::identity::IdentityStore::open(root.path())?;
    identity.connection.execute_batch("CREATE TRIGGER fail_identity BEFORE INSERT ON local_identity BEGIN SELECT RAISE(ABORT, 'injected commit failure'); END;")?;
    assert!(identity.init("alice", "laptop").is_err());
    assert!(identity.registration().is_err());
    let reference = identity.vault.provision("device", Kind::User)?;
    let original = reference.read()?;
    drop(identity);
    let mut identity = crate::identity::IdentityStore::open(root.path())?;
    identity
        .connection
        .execute_batch("DROP TRIGGER fail_identity;")?;
    let registration = identity.init("alice", "laptop")?;
    assert_eq!(registration.payload.nats_public_key, reference.public_key);
    assert_eq!(identity.nkey()?.seed()?, *original);
    drop(identity);
    for entry in std::fs::read_dir(root.path())? {
        let bytes = std::fs::read(entry?.path())?;
        assert!(
            !bytes
                .windows(original.len())
                .any(|w| w == original.as_bytes())
        );
    }
    Ok(())
}

#[test]
fn database_key_provisioning_retries_and_rejects_replacement() -> Result<()> {
    let (root, backend, vault) = fixture()?;
    backend.fail_after_create.store(true, Ordering::SeqCst);
    assert!(
        vault
            .provision("database-identity", Kind::Database)
            .is_err()
    );
    let reference = vault.provision("database-identity", Kind::Database)?;
    let key = reference.read_with(backend.as_ref())?;
    assert_eq!(key.len(), 64);
    assert_eq!(backend.items.lock().unwrap().len(), 1);
    let metadata = std::fs::read(root.path().join("credentials.json"))?;
    assert!(!metadata.windows(key.len()).any(|w| w == key.as_bytes()));
    backend.items.lock().unwrap().remove(&reference.id);
    assert!(
        vault
            .provision("database-identity", Kind::Database)
            .is_err()
    );
    assert!(backend.items.lock().unwrap().is_empty());
    backend
        .items
        .lock()
        .unwrap()
        .insert(reference.id.clone(), Kind::Database.generate()?);
    assert!(reference.read_with(backend.as_ref()).is_err());
    assert!(
        vault
            .provision("database-identity", Kind::Database)
            .is_err()
    );
    backend
        .items
        .lock()
        .unwrap()
        .insert(reference.id.clone(), Zeroizing::new("invalid".into()));
    assert!(reference.read_with(backend.as_ref()).is_err());
    Ok(())
}
