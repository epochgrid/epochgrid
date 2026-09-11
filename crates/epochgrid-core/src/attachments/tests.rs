use super::*;
#[test]
fn encryption_binding_tamper_expiry_limits_and_safe_rendering() -> Result<()> {
    let plaintext = b"EPOCHGRID_ATTACHMENT_SECRET_91F3";
    let limits = Limits::default();
    let (mut manifest, ciphertext) =
        encrypt("group", "private.txt", "text/plain", plaintext, limits)?;
    assert!(!ciphertext.windows(plaintext.len()).any(|w| w == plaintext));
    assert_eq!(&*manifest.decrypt("group", &ciphertext, limits)?, plaintext);
    assert!(manifest.decrypt("other", &ciphertext, limits).is_err());
    let mut corrupt = ciphertext.clone();
    corrupt[0] ^= 1;
    assert!(manifest.decrypt("group", &corrupt, limits).is_err());
    assert!(
        manifest
            .decrypt("group", &ciphertext[..ciphertext.len() - 1], limits)
            .is_err()
    );
    let encoded = manifest.encode()?;
    let decoded = Manifest::decode(&encoded)?.context("missing attachment")?;
    assert_eq!(&*decoded.decrypt("group", &ciphertext, limits)?, plaintext);
    assert!(display(&encoded).contains("private.txt"));
    assert!(!display(&encoded).contains("key"));
    assert_eq!(display(b"ordinary chat"), "ordinary chat");
    assert_eq!(
        display(b"\xffEGATT\x02"),
        "[unsupported or invalid attachment]"
    );
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(Manifest::decode(&trailing).is_err());
    assert!(encrypt("group", "../escape", "text/plain", plaintext, limits).is_err());
    assert!(encrypt("group", "file", "bad\r\nmime", plaintext, limits).is_err());
    assert!(
        encrypt(
            "group",
            "file",
            "text/plain",
            plaintext,
            Limits {
                max_bytes: 1,
                ..limits
            }
        )
        .is_err()
    );
    manifest.expires_at = 1;
    assert!(manifest.decrypt("group", &ciphertext, limits).is_err());
    let (empty, ciphertext) = encrypt("group", "empty", "application/octet-stream", b"", limits)?;
    assert!(empty.decrypt("group", &ciphertext, limits)?.is_empty());
    Ok(())
}

#[test]
fn manifest_index_is_atomic_authenticated_and_survives_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let own = alice.init("alice", "laptop")?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let peer = bob.init("bob", "laptop")?;
    let group = alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &peer)?;
    let welcome: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
        [],
        |r| r.get(0),
    )?;
    bob.accept_welcome(&welcome, &own)?;
    let (manifest, _) = encrypt(
        &group.gid,
        "file",
        "text/plain",
        b"secret",
        Limits::default(),
    )?;
    let payload = manifest.encode()?;
    let bytes = alice.encrypt_message("engineering", &payload)?;
    bob.connection.execute_batch("CREATE TRIGGER fail_attachment BEFORE INSERT ON attachments BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(bob.decrypt_message("engineering", &bytes).is_err());
    assert!(bob.attachments("engineering")?.is_empty());
    bob.connection
        .execute_batch("DROP TRIGGER fail_attachment;")?;
    bob.decrypt_message("engineering", &bytes)?;
    assert_eq!(
        bob.attachment("engineering", &manifest.id)?.summary(),
        manifest.summary()
    );
    assert!(bob.decrypt_message("engineering", &bytes)?.is_none());
    assert!(
        alice
            .encrypt_message("engineering", b"\xffEGATT\x02")
            .is_err()
    );
    drop(bob);
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    assert_eq!(bob.attachments("engineering")?.len(), 1);
    assert_eq!(
        bob.attachment("engineering", &manifest.id)?.summary(),
        manifest.summary()
    );
    // Recovery excludes the attachment DEKs and index.
    let (archive, secret) = alice.export_recovery()?;
    let restored = IdentityStore::open(&root.path().join("restored"))?;
    crate::recovery::RecoveryArchive::decrypt(&archive, &secret)?.restore(&restored)?;
    let count: u64 =
        restored
            .connection
            .query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0))?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn migration_preserves_history_and_rolls_back_on_failure() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut store = IdentityStore::open(root.path())?;
    let identity = store.init("alice", "laptop")?;
    let group = store.create_group("engineering")?;
    store.connection.execute_batch("DROP TABLE attachments; DELETE FROM epochgrid_migrations WHERE version=5;
        CREATE TRIGGER fail_attachment_migration BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=5 BEGIN SELECT RAISE(ABORT,'injected migration'); END;")?;
    drop(store);
    assert!(IdentityStore::open(root.path()).is_err());
    let connection = rusqlite::Connection::open(root.path().join("identity.sqlite"))?;
    let count: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='attachments'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    connection.execute_batch("DROP TRIGGER fail_attachment_migration")?;
    drop(connection);
    let store = IdentityStore::open(root.path())?;
    assert_eq!(store.registration()?, identity);
    assert_eq!(store.group("engineering")?, group);
    assert!(store.attachments("engineering")?.is_empty());
    Ok(())
}
