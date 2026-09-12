use super::*;

fn welcome(
    sender: &IdentityStore,
    recipient: &IdentityStore,
    user: &str,
    device: &str,
) -> Result<()> {
    let bytes: Vec<u8> = sender.connection.query_row(
        "SELECT payload FROM outbox WHERE subject=?1 ORDER BY id DESC LIMIT 1",
        [format!("epochgrid.v1.user.{user}.{device}.inbox")],
        |r| r.get(0),
    )?;
    recipient.accept_welcome(&bytes, &sender.registration()?)?;
    Ok(())
}
#[test]
fn participant_response_atomic_restart_replay_and_no_loops() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let mut status = IdentityStore::open(&root.path().join("status"))?;
    alice.init("alice", "laptop")?;
    let registration = status.init("status", "service")?;
    alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &registration)?;
    welcome(&alice, &status, "status", "service")?;
    assert_eq!(
        alice.users("engineering")?,
        vec!["@status [service]", "alice"]
    );
    assert!(alice.respond_status("engineering").is_err());
    let event = ApplicationEvent::new(&alice, "engineering", b"/status", None)?;
    let request = alice.encrypt_event("engineering", &event)?;
    status.decrypt_message("engineering", &request)?;
    status.connection.execute_batch("CREATE TRIGGER fail_response BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'test failure'); END;")?;
    assert!(status.respond_status("engineering").is_err());
    let processed: u64 =
        status
            .connection
            .query_row("SELECT COUNT(*) FROM participant_events", [], |r| r.get(0))?;
    assert_eq!(processed, 0);
    status
        .connection
        .execute_batch("DROP TRIGGER fail_response;")?;
    assert_eq!(status.respond_status("engineering")?, 1);
    let response: Vec<u8> = status.connection.query_row(
        "SELECT payload FROM outbox ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    assert!(
        !response
            .windows(STATUS_RESPONSE.len())
            .any(|w| w == STATUS_RESPONSE.as_bytes())
    );
    assert_eq!(
        alice
            .decrypt_message("engineering", &response)?
            .context("response")?
            .plaintext,
        STATUS_RESPONSE.as_bytes()
    );
    drop(status);
    let status = IdentityStore::open(&root.path().join("status"))?;
    assert_eq!(status.respond_status("engineering")?, 0);
    // Same application event in new MLS ciphertext must not trigger a second response.
    let replay = alice.encrypt_event("engineering", &event)?;
    status.decrypt_message("engineering", &replay)?;
    assert_eq!(status.respond_status("engineering")?, 0);
    let id = alice.resolve_message(
        "engineering",
        &alice
            .application_id(alice.history("engineering", 100, None)?[0].id)?
            .context("ID")?,
    )?;
    for relation in [Relation::ReplyTo(id), Relation::Replace(id)] {
        let bytes = alice.encrypt_related("engineering", relation, b"/status")?;
        status.decrypt_message("engineering", &bytes)?;
    }
    assert_eq!(status.respond_status("engineering")?, 0);
    let own = status.encrypt_message("engineering", b"/status")?;
    assert!(status.decrypt_message("engineering", &own)?.is_none());
    assert_eq!(status.respond_status("engineering")?, 0);
    Ok(())
}
#[test]
fn removal_advances_epoch_and_excludes_service_from_future_plaintext() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let mut status = IdentityStore::open(&root.path().join("status"))?;
    alice.init("alice", "laptop")?;
    let b = bob.init("bob", "laptop")?;
    let s = status.init("status", "service")?;
    alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &s)?;
    welcome(&alice, &status, "status", "service")?;
    alice.prepare_invitation("engineering", &b)?;
    welcome(&alice, &bob, "bob", "laptop")?;
    let handshake = || -> Result<Vec<u8>> {
        Ok(alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%handshake' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?)
    };
    status.process_handshake("engineering", &handshake()?, 2)?;
    assert!(
        bob.remove_member("engineering", "status", "service")
            .is_err()
    );
    assert!(
        alice
            .remove_member("engineering", "alice", "laptop")
            .is_err()
    );
    let before = alice.group_epoch("engineering")?;
    let old = alice.encrypt_message("engineering", b"previously visible")?;
    status.decrypt_message("engineering", &old)?;
    let queued = status.encrypt_message("engineering", b"old epoch pending")?;
    alice.remove_member("engineering", "status", "service")?;
    assert_eq!(alice.group_epoch("engineering")?, before + 1);
    let future = alice.encrypt_message("engineering", b"EPOCHGRID_SERVICE_REMOVED_SECRET_91F3")?;
    // Withholding the Remove Commit still does not give the service new epoch keys.
    assert!(status.group_active("engineering")?);
    assert!(status.decrypt_message("engineering", &future).is_err());
    bob.process_handshake("engineering", &handshake()?, 3)?;
    status.process_handshake("engineering", &handshake()?, 3)?;
    assert!(!status.group_active("engineering")?);
    status.block_revoked_outbox()?;
    let blocked: bool = status.connection.query_row("SELECT EXISTS(SELECT 1 FROM blocked_outbox b JOIN outbox o ON o.id=b.id WHERE o.payload=?1)",[queued],|r|r.get(0))?;
    assert!(blocked);
    assert!(status.decrypt_message("engineering", &future).is_err());
    assert!(status.respond_status("engineering").is_err());
    assert!(status.encrypt_message("engineering", b"forbidden").is_err());
    assert_eq!(
        bob.decrypt_message("engineering", &future)?
            .context("Bob future message")?
            .plaintext,
        b"EPOCHGRID_SERVICE_REMOVED_SECRET_91F3"
    );
    assert_eq!(
        status.history("engineering", 100, None)?[0]
            .plaintext
            .as_deref(),
        Some(b"previously visible".as_slice())
    );
    Ok(())
}
