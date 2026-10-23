use super::*;

fn state(root: &Path, role: &str) -> Result<State> {
    Ok(serde_json::from_slice(&std::fs::read(
        root.join(format!("{role}.database.json")),
    )?)?)
}

fn scan(root: &Path, markers: &[&[u8]]) -> Result<()> {
    // Inspect in a different process: ordinary fd closes here would release
    // POSIX locks belonging to live SQLite connections.
    use std::io::Write;
    let mut child = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import json, pathlib, sys
root, markers = json.load(sys.stdin)
for path in pathlib.Path(root).iterdir():
    if path.is_file():
        content = path.read_bytes()
        assert all(bytes.fromhex(marker) not in content for marker in markers), str(path)
"#,
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    let payload = Zeroizing::new(serde_json::to_vec(&(
        root,
        markers
            .iter()
            .map(|m| data_encoding::HEXLOWER.encode(m))
            .collect::<Vec<_>>(),
    ))?);
    child.stdin.take().unwrap().write_all(&payload)?;
    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn encrypted_pages_wal_journal_restart_and_independent_keys() -> Result<()> {
    let root = tempfile::tempdir()?;
    let marker = b"private transcript MLS attachment-key marker 25";
    let db = open(root.path(), "identity")?;
    let identity = state(root.path(), "identity")?;
    let key = identity.key.read()?;
    let raw_key = Zeroizing::new(data_encoding::HEXLOWER.decode(key.as_bytes())?);
    db.execute_batch(
        "CREATE TABLE sample(value BLOB); PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;",
    )?;
    db.execute("INSERT INTO sample VALUES(?1)", [marker.as_slice()])?;
    assert!(root.path().join("identity.sqlite-wal").metadata()?.len() > 32);
    scan(root.path(), &[marker, key.as_bytes(), &raw_key])?;
    let reader = open(root.path(), "identity")?;
    assert_eq!(
        reader.query_row("SELECT value FROM sample", [], |r| r.get::<_, Vec<u8>>(0))?,
        marker
    );
    drop(reader);
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE; UPDATE sample SET value=zeroblob(100000);")?;
    assert!(root.path().join("identity.sqlite-journal").exists());
    scan(root.path(), &[marker, key.as_bytes(), &raw_key])?;
    db.execute_batch("ROLLBACK")?;
    drop(db);
    let db = open(root.path(), "identity")?;
    assert_eq!(
        db.query_row("SELECT value FROM sample", [], |r| r.get::<_, Vec<u8>>(0))?,
        marker
    );
    assert_eq!(state(root.path(), "identity")?.key, identity.key);
    let auth = open(root.path(), "auth")?;
    assert_ne!(*state(root.path(), "auth")?.key.read()?, *key);
    drop(auth);
    let plain = Connection::open(root.path().join("identity.sqlite"))?;
    assert!(
        plain
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r
                .get::<_, u64>(0))
            .is_err()
    );
    assert!(keyed(&root.path().join("identity.sqlite"), &"00".repeat(32)).is_err());
    assert!(
        keyed(
            &root.path().join("identity.sqlite"),
            &state(root.path(), "auth")?.key.read()?
        )
        .is_err()
    );
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    assert_eq!(integrity, "ok");
    let mut check = db.prepare("PRAGMA cipher_integrity_check")?;
    assert!(check.query([])?.next()?.is_none());
    Ok(())
}

#[test]
fn interrupted_creation_reuses_key_and_never_resets_established_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    // Key and metadata durable, database not yet created.
    let key = Vault::new(root.path()).provision("database-identity", Kind::Database)?;
    let mut pending = State {
        version: 1,
        role: "identity".into(),
        key: key.clone(),
        ready: false,
    };
    let meta = root.path().join("identity.database.json");
    save(&meta, &pending)?;
    // An empty file is also a valid interrupted creation, but only while pending.
    private_file(&root.path().join("identity.sqlite"), false)?;
    // Fail the final metadata write after the binding transaction has committed.
    std::fs::create_dir(root.path().join("identity.database.pending"))?;
    assert!(open(root.path(), "identity").is_err());
    std::fs::remove_dir(root.path().join("identity.database.pending"))?;
    drop(open(root.path(), "identity")?);
    assert_eq!(state(root.path(), "identity")?.key, key);
    // Binding committed but final metadata rename lost.
    save(&meta, &pending)?;
    drop(open(root.path(), "identity")?);
    assert!(state(root.path(), "identity")?.ready);
    pending.ready = true;
    let path = root.path().join("identity.sqlite");
    let original = std::fs::read(&path)?;
    std::fs::remove_file(&meta)?;
    assert!(open(root.path(), "identity").is_err());
    assert_eq!(std::fs::read(&path)?, original);
    save(&meta, &pending)?;
    std::fs::remove_file(&path)?;
    assert!(open(root.path(), "identity").is_err());
    assert!(!path.exists());
    private_file(&path, false)?;
    assert!(open(root.path(), "identity").is_err());
    Ok(())
}

#[test]
fn wrong_binding_corruption_and_plaintext_are_rejected_without_data_changes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let db = open(root.path(), "identity")?;
    db.execute("UPDATE database_binding SET role='auth'", [])?;
    drop(db);
    let path = root.path().join("identity.sqlite");
    let original = std::fs::read(&path)?;
    assert!(open(root.path(), "identity").is_err());
    assert_eq!(std::fs::read(&path)?, original);
    let mut damaged = original.clone();
    damaged[100] ^= 1;
    std::fs::write(&path, &damaged)?;
    assert!(open(root.path(), "identity").is_err());
    assert_eq!(std::fs::read(&path)?, damaged);
    let legacy = tempfile::tempdir()?;
    let db = Connection::open(legacy.path().join("auth.sqlite"))?;
    db.execute_batch("CREATE TABLE old(value TEXT)")?;
    drop(db);
    let original = std::fs::read(legacy.path().join("auth.sqlite"))?;
    assert!(open(legacy.path(), "auth").is_err());
    assert_eq!(std::fs::read(legacy.path().join("auth.sqlite"))?, original);
    assert!(!legacy.path().join("credentials.json").exists());
    Ok(())
}

#[test]
fn provisioning_lock_prevents_competing_creation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = private_file(&root.path().join("auth.database.lock"), false)?;
    lock.try_lock()?;
    assert!(open(root.path(), "auth").is_err());
    assert!(!root.path().join("credentials.json").exists());
    lock.unlock()?;
    drop(lock);
    drop(open(root.path(), "auth")?);
    Ok(())
}

#[test]
fn real_identity_private_signer_transcript_and_registry_are_not_plaintext() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("client");
    let mut identity = crate::identity::IdentityStore::open(&home)?;
    identity.init("alice", "laptop")?;
    let signer = Zeroizing::new(identity.connection.query_row(
        "SELECT signature_key FROM openmls_signature_keys LIMIT 1",
        [],
        |r| r.get::<_, Vec<u8>>(0),
    )?);
    assert!(signer.len() > 32);
    let marker = b"private-m25-transcript-regression-marker";
    identity.connection.execute(
        "INSERT INTO transcript(gid,payload,plaintext,outgoing) VALUES('test',?1,?2,1)",
        params![b"test-envelope".as_slice(), marker.as_slice()],
    )?;
    scan(&home, &[&signer, marker])?;
    drop(identity);
    scan(&home, &[&signer, marker])?;
    let registry_home = root.path().join("registry");
    let mut registry = crate::identity_model::AuthRegistry::open(&registry_home)?;
    let token = registry.invite("private-registry-marker-25", 60)?;
    scan(
        &registry_home,
        &[b"private-registry-marker-25", token.as_bytes()],
    )?;
    drop(registry);
    scan(
        &registry_home,
        &[b"private-registry-marker-25", token.as_bytes()],
    )?;
    Ok(())
}

#[test]
fn registry_connections_see_other_process_invites_and_commits() -> Result<()> {
    let root = tempfile::tempdir()?;
    let reader = crate::identity_model::AuthRegistry::open(root.path())?;
    let writer = crate::identity_model::AuthRegistry::open(root.path())?;
    // Prime the reader's page cache before the other connection changes the WAL.
    assert_eq!(
        reader
            .db
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?,
        0
    );
    for name in ["alice", "bob"] {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "database::tests::registry_external_writer"])
            .env("EPOCHGRID_TEST_REGISTRY_HOME", root.path())
            .env("EPOCHGRID_TEST_REGISTRY_HANDLE", name)
            .status()?;
        assert!(status.success());
        let binding = crate::identity_model::IdentityBinding {
            provider: "local".into(),
            subject: name.into(),
        };
        assert_eq!(reader.resolve(&binding)?, writer.resolve(&binding)?);
    }
    Ok(())
}

#[test]
fn registry_external_writer() -> Result<()> {
    if let Some(root) = std::env::var_os("EPOCHGRID_TEST_REGISTRY_HOME") {
        let mut registry = crate::identity_model::AuthRegistry::open(Path::new(&root))?;
        registry.invite(&std::env::var("EPOCHGRID_TEST_REGISTRY_HANDLE")?, 60)?;
    }
    Ok(())
}

#[test]
fn crash_writer() -> Result<()> {
    let Some(root) = std::env::var_os("EPOCHGRID_TEST_CRASH_HOME") else {
        return Ok(());
    };
    let db = open(Path::new(&root), "auth")?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE crash_test(value TEXT); INSERT INTO crash_test VALUES('committed-before-crash'); BEGIN IMMEDIATE; INSERT INTO crash_test VALUES('uncommitted-before-crash');")?;
    // Deliberately bypass SQLite's destructors and checkpoint-on-close.
    std::process::exit(0);
}

#[test]
fn process_crash_recovers_encrypted_wal() -> Result<()> {
    let root = tempfile::tempdir()?;
    let status = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "database::tests::crash_writer"])
        .env("EPOCHGRID_TEST_CRASH_HOME", root.path())
        .status()?;
    assert!(status.success());
    assert!(root.path().join("auth.sqlite-wal").metadata()?.len() > 32);
    scan(
        root.path(),
        &[b"committed-before-crash", b"uncommitted-before-crash"],
    )?;
    let db = open(root.path(), "auth")?;
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM crash_test", [], |r| r
            .get::<_, u64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn inspection_missing_partial_plaintext_and_wrong_metadata_never_initialize() -> Result<()> {
    use inspection::InspectionError;
    let root = tempfile::tempdir()?;
    assert!(matches!(
        inspection::inspect(root.path(), "auth")
            .err()
            .unwrap()
            .downcast_ref(),
        Some(InspectionError::Missing)
    ));
    assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    let registry = crate::identity_model::AuthRegistry::open(root.path())?;
    let path = root.path().join("auth.database.json");
    let original = std::fs::read(&path)?;
    let mut metadata = state(root.path(), "auth")?;
    metadata.ready = false;
    save(&path, &metadata)?;
    assert!(matches!(
        inspection::inspect(root.path(), "auth")
            .err()
            .unwrap()
            .downcast_ref(),
        Some(InspectionError::Incomplete)
    ));
    assert!(!state(root.path(), "auth")?.ready);
    metadata.ready = true;
    metadata.role = "identity".into();
    save(&path, &metadata)?;
    assert!(matches!(
        inspection::inspect(root.path(), "auth")
            .err()
            .unwrap()
            .downcast_ref(),
        Some(InspectionError::MetadataInvalid)
    ));
    std::fs::remove_file(&path)?;
    assert!(matches!(
        inspection::inspect(root.path(), "auth")
            .err()
            .unwrap()
            .downcast_ref(),
        Some(InspectionError::MetadataMissing)
    ));
    assert!(!path.exists());
    std::fs::write(&path, original)?;
    inspection::auth(root.path())?;
    drop(registry);
    let legacy = tempfile::tempdir()?;
    let plain = Connection::open(legacy.path().join("auth.sqlite"))?;
    plain.execute_batch("CREATE TABLE private_old_state(value TEXT)")?;
    assert!(matches!(
        inspection::inspect(legacy.path(), "auth")
            .err()
            .unwrap()
            .downcast_ref(),
        Some(InspectionError::Plaintext)
    ));
    assert!(!legacy.path().join("credentials.json").exists());
    assert_eq!(std::fs::read_dir(legacy.path())?.count(), 1);
    Ok(())
}

#[test]
fn inspection_observes_live_wal_snapshot_without_writes_or_lock_loss() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut registry = crate::identity_model::AuthRegistry::open(root.path())?;
    registry.invite("before", 120)?;
    let reader = inspection::inspect(root.path(), "auth")?;
    assert_eq!(
        reader.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, u64>(0))?,
        1
    );
    registry.invite("after", 120)?;
    assert_eq!(
        reader.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, u64>(0))?,
        1
    );
    assert!(reader.execute("DELETE FROM users", []).is_err());
    drop(reader);
    let reader = inspection::inspect(root.path(), "auth")?;
    assert_eq!(
        reader.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, u64>(0))?,
        2
    );
    drop(reader);
    registry.db.execute_batch("BEGIN IMMEDIATE")?;
    // Inspection opens/closes a format probe and keyed reader in this process.
    // Those closes must not release the writer's POSIX locks.
    inspection::auth(root.path())?;
    let run = || {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "database::tests::registry_external_writer"])
            .env("EPOCHGRID_TEST_REGISTRY_HOME", root.path())
            .env("EPOCHGRID_TEST_REGISTRY_HANDLE", "contender")
            .output()
    };
    assert!(!run()?.status.success());
    registry.db.execute_batch("ROLLBACK")?;
    assert!(run()?.status.success());
    Ok(())
}

#[test]
fn inspection_rejects_bindings_schema_and_control_identity_without_repair() -> Result<()> {
    use inspection::InspectionError;
    let root = tempfile::tempdir()?;
    let registry = crate::identity_model::AuthRegistry::open(root.path())?;
    registry
        .db
        .execute("UPDATE database_binding SET role='identity'", [])?;
    assert!(matches!(
        inspection::auth(root.path()).unwrap_err().downcast_ref(),
        Some(InspectionError::Binding)
    ));
    registry
        .db
        .execute("UPDATE database_binding SET role='auth'", [])?;
    registry
        .db
        .execute("INSERT INTO auth_migrations VALUES(99)", [])?;
    assert!(matches!(
        inspection::auth(root.path()).unwrap_err().downcast_ref(),
        Some(InspectionError::Schema)
    ));
    registry
        .db
        .execute("DELETE FROM auth_migrations WHERE version=99", [])?;
    registry
        .db
        .execute("DELETE FROM auth_migrations WHERE version=1", [])?;
    assert!(matches!(
        inspection::auth(root.path()).unwrap_err().downcast_ref(),
        Some(InspectionError::Schema)
    ));
    assert_eq!(
        registry
            .db
            .query_row("SELECT COUNT(*) FROM auth_migrations", [], |row| row
                .get::<_, u64>(0))?,
        1
    );
    let control_home = root.path().join("control");
    let mut identity = crate::identity::IdentityStore::open(&control_home)?;
    let key = identity.init("service", "laptop")?.payload.nats_public_key;
    inspection::control(&control_home, &key)?;
    assert!(matches!(
        inspection::control(&control_home, &nkeys::KeyPair::new_user().public_key())
            .unwrap_err()
            .downcast_ref(),
        Some(InspectionError::ControlBinding)
    ));
    identity
        .connection
        .execute_batch("DROP TABLE participant_events")?;
    assert!(matches!(
        inspection::control(&control_home, &key)
            .unwrap_err()
            .downcast_ref(),
        Some(InspectionError::Schema)
    ));
    assert_eq!(
        identity.connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='participant_events'",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        0
    );
    Ok(())
}

#[test]
fn inspection_rejects_swapped_database_keys_and_corruption() -> Result<()> {
    use inspection::InspectionError;
    let root = tempfile::tempdir()?;
    drop(crate::identity_model::AuthRegistry::open(root.path())?);
    drop(open(root.path(), "identity")?);
    let path = root.path().join("auth.database.json");
    let original = std::fs::read(&path)?;
    let mut metadata = state(root.path(), "auth")?;
    metadata.key = state(root.path(), "identity")?.key;
    save(&path, &metadata)?;
    assert!(matches!(
        inspection::auth(root.path()).unwrap_err().downcast_ref(),
        Some(InspectionError::CredentialBinding)
    ));
    std::fs::write(path, original)?;
    // All connections are closed before deliberately damaging the database.
    let db_path = root.path().join("auth.sqlite");
    let mut bytes = std::fs::read(&db_path)?;
    bytes[100] ^= 1;
    std::fs::write(&db_path, &bytes)?;
    assert!(inspection::auth(root.path()).is_err());
    assert_eq!(std::fs::read(db_path)?, bytes);
    Ok(())
}
