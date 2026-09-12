use super::*;
fn pair(root: &std::path::Path) -> Result<(IdentityStore, IdentityStore)> {
    let mut alice = IdentityStore::open(&root.join("alice"))?;
    let mut bob = IdentityStore::open(&root.join("bob"))?;
    let ar = alice.init("alice", "laptop")?;
    let br = bob.init("bob", "laptop")?;
    alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &br)?;
    let welcome: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
        [],
        |r| r.get(0),
    )?;
    bob.accept_welcome(&welcome, &ar)?;
    Ok((alice, bob))
}
fn stage(store: &IdentityStore, seq: u64, bytes: &[u8]) -> Result<()> {
    store.stage_chat(seq, &store.group("engineering")?.subject("message"), bytes)?;
    assert_eq!(store.process_history("engineering")?.rejected, 0);
    Ok(())
}
fn latest_id(store: &IdentityStore) -> Result<MessageId> {
    let id: i64 = store
        .connection
        .query_row("SELECT MAX(id) FROM transcript", [], |r| r.get(0))?;
    parse_id(
        &store
            .application_id(id)?
            .context("missing application ID")?,
    )
}
fn projected(store: &IdentityStore, id: &MessageId) -> Result<String> {
    let entry = store
        .conversation("engineering", 100, None)?
        .into_iter()
        .find(|e| e.message_id.as_deref() == Some(id_text(id).as_str()))
        .context("projection missing")?;
    Ok(String::from_utf8(
        entry.entry.plaintext.context("plaintext missing")?,
    )?)
}
#[test]
fn codec_ids_and_validation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (alice, _bob) = pair(root.path())?;
    let event = ApplicationEvent::new(
        &alice,
        "engineering",
        b"hello",
        Some(Relation::ReplyTo([7; 32])),
    )?;
    let wire = event.wire()?;
    assert_eq!(
        ApplicationEvent::decode(&wire)?.context("event")?.wire()?,
        wire
    );
    assert_eq!(parse_id(&id_text(&[7; 32]))?, [7; 32]);
    for text in ["", "abc", &"G".repeat(64), &"0".repeat(65)] {
        assert!(parse_id(text).is_err());
    }
    for text in ["%", "abcd_123", "00000000"] {
        assert!(alice.resolve_message("engineering", text).is_err());
    }
    let mut bad = wire.clone();
    bad[PREFIX.len()] = 2;
    assert!(ApplicationEvent::decode(&bad).is_err());
    let mut bad = wire.clone();
    bad.push(0);
    assert!(ApplicationEvent::decode(&bad).is_err());
    assert!(ApplicationEvent::decode(PREFIX).is_err());
    assert!(
        ApplicationEvent::new(&alice, "engineering", &vec![0; MAX_PLAINTEXT + 1], None).is_err()
    );
    for value in ["", "two words", "\n"] {
        assert!(
            ApplicationEvent::new(
                &alice,
                "engineering",
                b"",
                Some(Relation::Reaction {
                    target: [0; 32],
                    value: value.into(),
                    add: true
                })
            )
            .is_err()
        );
    }
    assert_eq!(postcard::to_allocvec(&Relation::ReplyTo([0; 32]))?[0], 0);
    assert_eq!(postcard::to_allocvec(&Relation::Replace([0; 32]))?[0], 1);
    assert_eq!(
        postcard::to_allocvec(&Relation::Reaction {
            target: [0; 32],
            value: "👍".into(),
            add: true
        })?[0],
        2
    );
    Ok(())
}
#[test]
fn late_targets_counter_order_reactions_ownership_and_replay() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (alice, bob) = pair(root.path())?;
    let original = alice.encrypt_message("engineering", b"deploy tonight")?;
    let id = latest_id(&alice)?;
    let edit1 = alice.encrypt_related("engineering", Relation::Replace(id), b"deploy tomorrow")?;
    let edit2 = alice.encrypt_related("engineering", Relation::Replace(id), b"deploy next week")?;
    // Transport order deliberately opposes signed device-counter order; target arrives last.
    stage(&bob, 2, &edit2)?;
    assert!(
        String::from_utf8(
            bob.conversation("engineering", 10, None)?[0]
                .entry
                .plaintext
                .clone()
                .context("text")?
        )?
        .contains("unresolved")
    );
    stage(&bob, 3, &edit1)?;
    stage(&bob, 1, &original)?;
    for (seq, bytes) in [(1, &original), (2, &edit2), (3, &edit1)] {
        stage(&alice, seq, bytes)?;
    }
    assert_eq!(projected(&bob, &id)?, "deploy next week [edited]");
    assert_eq!(projected(&alice, &id)?, projected(&bob, &id)?);
    assert_eq!(
        bob.history("engineering", 10, None)?[0]
            .plaintext
            .as_deref(),
        Some(b"deploy tonight".as_slice())
    );
    assert!(
        bob.encrypt_related("engineering", Relation::Replace(id), b"forged edit")
            .is_err()
    );
    let malicious = ApplicationEvent::new(
        &bob,
        "engineering",
        b"forged edit",
        Some(Relation::Replace(id)),
    )?;
    let forged = bob.encrypt_event("engineering", &malicious)?;
    stage(&alice, 4, &forged)?;
    stage(&bob, 4, &forged)?;
    assert_eq!(projected(&alice, &id)?, "deploy next week [edited]");
    let reply = bob.encrypt_related("engineering", Relation::ReplyTo(id), b"confirmed")?;
    let reply_id = latest_id(&bob)?;
    stage(&alice, 5, &reply)?;
    stage(&bob, 5, &reply)?;
    assert!(projected(&alice, &reply_id)?.contains("reply to alice/laptop"));
    for (seq, add) in [(6, true), (7, false), (8, true)] {
        let bytes = bob.encrypt_related(
            "engineering",
            Relation::Reaction {
                target: id,
                value: "👍".into(),
                add,
            },
            b"",
        )?;
        stage(&alice, seq, &bytes)?;
        stage(&bob, seq, &bytes)?;
        assert_eq!(projected(&alice, &id)?.contains("reaction 👍: bob"), add);
    }
    let snapshot = projected(&bob, &id)?;
    let rows = {
        let mut stmt=bob.connection.prepare("SELECT transcript_id,gid,message_id,target,kind,counter,event FROM message_events ORDER BY transcript_id DESC")?;
        stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, u64>(5)?,
                r.get::<_, Vec<u8>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    bob.transaction(|| {
        bob.connection.execute("DELETE FROM message_events", [])?;
        for (row, gid, id, target, kind, counter, event) in &rows {
            bob.connection.execute(
                "INSERT INTO message_events VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![row, gid, id, target, kind, counter, event],
            )?;
        }
        Ok(())
    })?;
    assert_eq!(projected(&bob, &id)?, snapshot);
    drop(bob);
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    assert_eq!(projected(&bob, &id)?, snapshot);
    // A counter fork is resolved by event ID, not delivery order.
    let fork_a = ApplicationEvent::new(
        &alice,
        "engineering",
        b"fork A",
        Some(Relation::Replace(id)),
    )?;
    let mut fork_b = fork_a.clone();
    fork_b.content = b"fork B".to_vec();
    let bytes_a = alice.encrypt_event("engineering", &fork_a)?;
    let id_a = latest_id(&alice)?;
    let bytes_b = alice.encrypt_event("engineering", &fork_b)?;
    let id_b = latest_id(&alice)?;
    stage(&bob, 10, &bytes_b)?;
    stage(&bob, 9, &bytes_a)?;
    assert!(projected(&bob, &id)?.starts_with(if id_a > id_b {
        "fork A [edited]"
    } else {
        "fork B [edited]"
    }));
    Ok(())
}
#[test]
fn duplicate_application_ids_bind_sender_and_share_presentation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (alice, bob) = pair(root.path())?;
    let event = ApplicationEvent::new(&alice, "engineering", b"one logical message", None)?;
    let first = alice.encrypt_event("engineering", &event)?;
    let id = latest_id(&alice)?;
    let second = alice.encrypt_event("engineering", &event)?;
    assert_ne!(first, second);
    assert_eq!(id, latest_id(&alice)?);
    stage(&bob, 1, &first)?;
    stage(&bob, 2, &second)?;
    assert_eq!(bob.history("engineering", 10, None)?.len(), 2);
    assert_eq!(bob.conversation("engineering", 10, None)?.len(), 1);
    bob.mark_displayed(bob.history("engineering", 10, None)?[0].id)?;
    assert_eq!(bob.unread_count("engineering")?, 0);
    let third = alice.encrypt_event("engineering", &event)?;
    stage(&bob, 3, &third)?;
    assert_eq!(bob.unread_count("engineering")?, 0);
    bob.encrypt_event("engineering", &event)?;
    assert_ne!(id, latest_id(&bob)?);
    Ok(())
}
#[test]
fn legacy_migration_and_index_failure_preserve_crypto_and_transcript() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (alice, bob) = pair(root.path())?;
    let legacy = alice.transaction(|| {
        let mut group = alice.load_group(&alice.group("engineering")?)?;
        Ok(group
            .create_message(&alice.provider, &alice.signer()?.0, b"legacy text")
            .map_err(|e| anyhow!("{e:?}"))?
            .to_bytes()?)
    })?;
    bob.decrypt_message("engineering", &legacy)?;
    let old_id = latest_id(&bob)?;
    bob.connection.execute_batch("DROP TABLE message_events; DELETE FROM epochgrid_migrations WHERE version=7; CREATE TRIGGER fail_migration BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=7 BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(bob.migrate_relationships().is_err());
    assert!(!bob.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='message_events')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    bob.connection
        .execute_batch("DROP TRIGGER fail_migration")?;
    drop(bob);
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    assert_eq!(latest_id(&bob)?, old_id);
    let bytes = alice.encrypt_message("engineering", b"atomic receive")?;
    bob.connection.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON message_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(bob.decrypt_message("engineering", &bytes).is_err());
    assert_eq!(bob.history("engineering", 10, None)?.len(), 1);
    bob.connection.execute_batch("DROP TRIGGER fail_event")?;
    assert!(bob.decrypt_message("engineering", &bytes)?.is_some());
    alice.connection.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON message_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
    assert!(
        alice
            .encrypt_message("engineering", b"rollback send")
            .is_err()
    );
    alice.connection.execute_batch("DROP TRIGGER fail_event")?;
    let retry = alice.encrypt_message("engineering", b"successful retry")?;
    assert!(bob.decrypt_message("engineering", &retry)?.is_some());
    Ok(())
}

#[test]
fn multi_device_reactions_remove_only_that_devices_contribution() -> Result<()> {
    let root = tempfile::tempdir()?;
    let (alice, bob) = pair(root.path())?;
    let mut desktop = IdentityStore::open(&root.path().join("desktop"))?;
    let registration = desktop.init("alice", "desktop")?;
    alice.prepare_invitation("engineering", &registration)?;
    let welcome: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%inbox' ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    desktop.accept_welcome(&welcome, &alice.registration()?)?;
    let commit: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%handshake' ORDER BY id DESC LIMIT 1",
        [],
        |r| r.get(0),
    )?;
    bob.stage_chat(1, &bob.group("engineering")?.subject("handshake"), &commit)?;
    assert_eq!(bob.process_history("engineering")?.rejected, 0);
    let bytes = bob.encrypt_message("engineering", b"two Alice devices")?;
    let id = latest_id(&bob)?;
    for store in [&alice, &bob, &desktop] {
        stage(store, 2, &bytes)?;
    }
    for (seq, store, add) in [
        (3, &alice, true),
        (4, &desktop, true),
        (5, &desktop, false),
        (6, &alice, false),
    ] {
        let bytes = store.encrypt_related(
            "engineering",
            Relation::Reaction {
                target: id,
                value: "+".into(),
                add,
            },
            b"",
        )?;
        stage(&bob, seq, &bytes)?;
        assert_eq!(
            projected(&bob, &id)?.matches("reaction +: alice").count(),
            usize::from(seq < 6)
        );
    }
    // The other Alice device still cannot edit a laptop-authored message.
    let laptop = alice.encrypt_message("engineering", b"laptop original")?;
    let laptop_id = latest_id(&alice)?;
    stage(&desktop, 7, &laptop)?;
    assert!(
        desktop
            .encrypt_related("engineering", Relation::Replace(laptop_id), b"desktop edit")
            .is_err()
    );
    Ok(())
}
