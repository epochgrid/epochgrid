use crate::{
    identity::IdentityStore,
    revocation::{Revocation, RevocationLog, RevokeRequest},
    transparency::Snapshot,
};
use anyhow::{Context, Result};
fn queued(store: &IdentityStore, suffix: &str) -> Result<Vec<u8>> {
    Ok(store.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE ?1 ORDER BY id DESC LIMIT 1",
        [format!("%{suffix}")],
        |r| r.get(0),
    )?)
}
fn three(
    root: &std::path::Path,
) -> Result<(
    IdentityStore,
    IdentityStore,
    IdentityStore,
    Snapshot,
    nkeys::KeyPair,
)> {
    let mut alice = IdentityStore::open(&root.join("alice"))?;
    let mut bob = IdentityStore::open(&root.join("bob"))?;
    let mut desktop = IdentityStore::open(&root.join("desktop"))?;
    let ar = alice.init("alice", "laptop")?;
    let br = bob.init("bob", "laptop")?;
    let dr = desktop.init("alice", "desktop")?;
    let group = alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &br)?;
    bob.accept_welcome(&queued(&alice, "inbox")?, &ar)?;
    alice.prepare_invitation("engineering", &dr)?;
    desktop.accept_welcome(&queued(&alice, "inbox")?, &ar)?;
    bob.stage_chat(
        2,
        &group.subject("handshake"),
        &queued(&alice, "handshake")?,
    )?;
    bob.process_history("engineering")?;
    let key = nkeys::KeyPair::new_user();
    let registrations = Snapshot::signed(vec![ar, br, dr], &key)?;
    Ok((alice, bob, desktop, registrations, key))
}
#[test]
fn revoke_leaf_atomic_remove_restart_and_future_secrecy() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (alice, bob, desktop, registrations, key) = three(dir.path())?;
    let group = alice.group("engineering")?;
    let old_event = desktop.seal_ephemeral(
        "engineering",
        crate::ephemeral::EphemeralEvent::TypingStarted,
    )?;
    assert!(bob.open_ephemeral("engineering", &old_event).is_ok());
    let target = desktop.nkey()?.public_key();
    let forbidden = RevokeRequest::signed("alice", "desktop", &target, &bob.nkey()?)?;
    assert!(forbidden.validate(&registrations, &[]).is_err());
    let request = RevokeRequest::signed("alice", "desktop", &target, &alice.nkey()?)?;
    let log = RevocationLog::signed(
        vec![Revocation {
            request,
            chat_cutoff: 2,
        }],
        &key,
    )?;
    alice.encrypt_message("engineering", b"queued under the old epoch")?;
    for local in [&alice, &bob, &desktop] {
        local.accept_revocations(&log, &registrations)?;
    }
    assert!(bob.open_ephemeral("engineering", &old_event).is_err());
    assert!(
        desktop
            .seal_ephemeral(
                "engineering",
                crate::ephemeral::EphemeralEvent::TypingStarted
            )
            .is_err()
    );
    alice.block_revoked_outbox()?;
    let blocked: u64 =
        alice
            .connection
            .query_row("SELECT COUNT(*) FROM blocked_outbox", [], |r| r.get(0))?;
    assert_eq!(blocked, 1);
    alice.transparency_failure("REVOCATION FAILURE: injected audit failure")?;
    assert!(
        alice
            .trust_warning()?
            .context("warning missing")?
            .contains("injected audit failure")
    );
    alice.clear_transparency_warning()?;
    assert!(
        alice
            .encrypt_message("engineering", b"must wait for rekey")
            .is_err()
    );
    assert!(!bob.reconcile_revocations("engineering")?);
    alice.connection.execute_batch("CREATE TRIGGER fail_remove BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END;")?;
    assert!(alice.reconcile_revocations("engineering").is_err());
    assert_eq!(alice.group_epoch("engineering")?, 2);
    alice.connection.execute_batch("DROP TRIGGER fail_remove")?;
    assert!(alice.reconcile_revocations("engineering")?);
    assert!(!alice.reconcile_revocations("engineering")?);
    let commit = queued(&alice, "handshake")?;
    for local in [&bob, &desktop] {
        local.stage_chat(3, &group.subject("handshake"), &commit)?;
        assert_eq!(local.process_history("engineering")?.rejected, 0);
    }
    assert!(!desktop.load_group(&group)?.is_active());
    let fresh_event = alice.seal_ephemeral(
        "engineering",
        crate::ephemeral::EphemeralEvent::TypingStarted,
    )?;
    assert!(bob.open_ephemeral("engineering", &fresh_event).is_ok());
    assert!(desktop.open_ephemeral("engineering", &fresh_event).is_err());
    assert!(bob.open_ephemeral("engineering", &old_event).is_err());
    let secret = b"EPOCHGRID_AFTER_REVOCATION_91F3";
    let ciphertext = alice.encrypt_message("engineering", secret)?;
    assert!(!ciphertext.windows(secret.len()).any(|w| w == secret));
    assert_eq!(
        bob.decrypt_message("engineering", &ciphertext)?
            .context("message missing")?
            .plaintext,
        secret
    );
    assert!(desktop.decrypt_message("engineering", &ciphertext).is_err());
    assert!(
        desktop
            .encrypt_message("engineering", b"removed sender")
            .is_err()
    );
    drop(alice);
    drop(bob);
    drop(desktop);
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let desktop = IdentityStore::open(&dir.path().join("desktop"))?;
    assert!(desktop.is_revoked(&target)?);
    assert_eq!(bob.group_epoch("engineering")?, 3);
    assert_eq!(
        alice.members("engineering")?,
        vec!["alice/laptop", "bob/laptop"]
    );
    let reply = bob.encrypt_message("engineering", b"after restart")?;
    assert!(alice.decrypt_message("engineering", &reply)?.is_some());
    assert!(desktop.decrypt_message("engineering", &reply).is_err());
    assert!(
        alice
            .accept_revocations(&RevocationLog::signed(Vec::new(), &key)?, &registrations)
            .is_err()
    );
    Ok(())
}
#[test]
fn creator_revocation_successor_and_reused_leaf_slot() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (alice, bob, desktop, registrations, key) = three(dir.path())?;
    let group = alice.group("engineering")?;
    let mut newcomer = IdentityStore::open(&dir.path().join("newcomer"))?;
    let nr = newcomer.init("charlie", "laptop")?;
    // This valid creator Commit arrives after the signed cutoff and must not advance peers.
    alice.prepare_invitation("engineering", &nr)?;
    let late = queued(&alice, "handshake")?;
    let request = RevokeRequest::signed(
        "alice",
        "laptop",
        &alice.nkey()?.public_key(),
        &desktop.nkey()?,
    )?;
    let log = RevocationLog::signed(
        vec![Revocation {
            request,
            chat_cutoff: 2,
        }],
        &key,
    )?;
    for local in [&bob, &desktop] {
        local.accept_revocations(&log, &registrations)?;
        local.stage_chat(3, &group.subject("handshake"), &late)?;
        assert_eq!(local.process_history("engineering")?.rejected, 1);
        assert_eq!(local.group_epoch("engineering")?, 2);
    }
    assert!(!desktop.reconcile_revocations("engineering")?);
    assert!(bob.reconcile_revocations("engineering")?);
    desktop.stage_chat(4, &group.subject("handshake"), &queued(&bob, "handshake")?)?;
    assert_eq!(desktop.process_history("engineering")?.rejected, 0);
    assert_eq!(
        desktop.members("engineering")?,
        vec!["bob/laptop", "alice/desktop"]
    );
    // The new member reuses slot 0; Bob remains the authenticated coordinator.
    bob.prepare_invitation("engineering", &nr)?;
    newcomer.accept_welcome(&queued(&bob, "inbox")?, &bob.registration()?)?;
    desktop.stage_chat(5, &group.subject("handshake"), &queued(&bob, "handshake")?)?;
    assert_eq!(desktop.process_history("engineering")?.rejected, 0);
    for local in [&bob, &desktop, &newcomer] {
        assert_eq!(
            local.coordinator(&local.load_group(&group)?)?,
            Some(openmls::prelude::LeafNodeIndex::new(1))
        );
    }
    let message = bob.encrypt_message("engineering", b"successor group remains usable")?;
    assert!(desktop.decrypt_message("engineering", &message)?.is_some());
    assert!(newcomer.decrypt_message("engineering", &message)?.is_some());
    assert!(alice.decrypt_message("engineering", &message).is_err());
    Ok(())
}

#[test]
fn revocation_signatures_prefixes_wire_and_migration() -> Result<()> {
    use crate::wire::{self, Body};
    let dir = tempfile::tempdir()?;
    let (alice, bob, desktop, registrations, key) = three(dir.path())?;
    let request = RevokeRequest::signed(
        "alice",
        "desktop",
        &desktop.nkey()?.public_key(),
        &alice.nkey()?,
    )?;
    let log = RevocationLog::signed(
        vec![Revocation {
            request: request.clone(),
            chat_cutoff: 2,
        }],
        &key,
    )?;
    log.validate(&registrations)?;
    let bytes = wire::encode(Body::RevocationLog(log.clone()))?;
    assert_eq!(&bytes[..2], &[1, 14]);
    assert!(matches!(wire::decode(&bytes)?, Body::RevocationLog(decoded) if decoded == log));
    assert_eq!(wire::encode(Body::RegistrationAudit)?, vec![1, 12]);
    assert_eq!(wire::encode(Body::RevocationAudit)?, vec![1, 13]);
    assert_eq!(&wire::encode(Body::Revoke(request.clone()))?[..2], &[1, 15]);
    assert_eq!(wire::encode(Body::Revoked)?, vec![1, 16]);
    let mut tampered = log.clone();
    tampered.entries[0].chat_cutoff += 1;
    assert!(tampered.validate(&registrations).is_err());
    let mut forged = request;
    forged.device = "laptop".into();
    assert!(forged.validate(&registrations, &[]).is_err());
    assert!(
        RevocationLog::signed(log.entries.clone(), &nkeys::KeyPair::new_user())?
            .validate(&registrations)
            .is_err()
    );
    alice.accept_revocations(&log, &registrations)?;
    let mut rewritten = log.entries.clone();
    rewritten[0].chat_cutoff += 1;
    assert!(
        alice
            .accept_revocations(&RevocationLog::signed(rewritten, &key)?, &registrations)
            .is_err()
    );
    let second = RevokeRequest::signed(
        "alice",
        "laptop",
        &alice.nkey()?.public_key(),
        &desktop.nkey()?,
    )?;
    assert!(second.validate(&registrations, &log.entries).is_err());
    let path = dir.path().join("bob");
    let registration = bob.registration()?;
    bob.connection.execute_batch("DROP TABLE revoked_devices; DROP TABLE revocation_checkpoint; DROP TABLE blocked_outbox; DROP TABLE group_coordinators; DELETE FROM epochgrid_migrations WHERE version=3; CREATE TRIGGER fail_revocation_migration BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=3 BEGIN SELECT RAISE(ABORT,'injected failure'); END;")?;
    drop(bob);
    assert!(IdentityStore::open(&path).is_err());
    let db = rusqlite::Connection::open(path.join("identity.sqlite"))?;
    let partial: u64 = db.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('revoked_devices','revocation_checkpoint','blocked_outbox','group_coordinators')", [], |r|r.get(0))?;
    assert_eq!(partial, 0);
    db.execute_batch("DROP TRIGGER fail_revocation_migration")?;
    drop(db);
    let bob = IdentityStore::open(&path)?;
    assert_eq!(bob.registration()?, registration);
    assert_eq!(bob.group_epoch("engineering")?, 2);
    assert_eq!(
        bob.coordinator(&bob.load_group(&bob.group("engineering")?)?)?,
        Some(openmls::prelude::LeafNodeIndex::new(0))
    );
    Ok(())
}

#[test]
fn historical_creator_commits_and_stale_peer_outbox() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (alice, bob, desktop, mut registrations, key) = three(dir.path())?;
    let group = alice.group("engineering")?;
    let mut added = IdentityStore::open(&dir.path().join("added"))?;
    let record = added.init("charlie", "laptop")?;
    registrations.entries.push(record.clone());
    registrations = Snapshot::signed(registrations.entries, &key)?;
    alice.prepare_invitation("engineering", &record)?;
    let historic = queued(&alice, "handshake")?;
    let log = RevocationLog::signed(
        vec![Revocation {
            request: RevokeRequest::signed(
                "alice",
                "laptop",
                &alice.nkey()?.public_key(),
                &desktop.nkey()?,
            )?,
            chat_cutoff: 3,
        }],
        &key,
    )?;
    desktop.encrypt_message("engineering", b"offline old epoch")?;
    for peer in [&bob, &desktop] {
        peer.accept_revocations(&log, &registrations)?;
        peer.stage_chat(3, &group.subject("handshake"), &historic)?;
        assert_eq!(peer.process_history("engineering")?.rejected, 0);
    }
    assert!(bob.reconcile_revocations("engineering")?);
    desktop.stage_chat(4, &group.subject("handshake"), &queued(&bob, "handshake")?)?;
    assert_eq!(desktop.process_history("engineering")?.rejected, 0);
    assert!(!desktop.rekey_pending("engineering")?);
    let blocked: u64 =
        desktop
            .connection
            .query_row("SELECT COUNT(*) FROM blocked_outbox", [], |r| r.get(0))?;
    assert_eq!(
        blocked, 1,
        "merging removal must block already queued old-epoch ciphertext"
    );
    Ok(())
}

#[test]
fn unsupported_mls_identity_rotation_cannot_escape_revocation_binding() -> Result<()> {
    use openmls::prelude::*;
    let dir = tempfile::tempdir()?;
    let (alice, bob, _, _, _) = three(dir.path())?;
    let descriptor = alice.group("engineering")?;
    let mut group = alice.load_group(&descriptor)?;
    let (old_signer, mut credential) = alice.signer()?;
    let new_signer = openmls_basic_credential::SignatureKeyPair::new(
        crate::identity::SUITE.signature_algorithm(),
    )
    .map_err(|e| anyhow::anyhow!("create test signer: {e:?}"))?;
    credential.signature_key = new_signer.to_public_vec().into();
    let bundle = group
        .self_update_with_new_signer(
            &alice.provider,
            &old_signer,
            NewSignerBundle {
                signer: &new_signer,
                credential_with_key: credential,
            },
            LeafNodeParameters::default(),
        )
        .map_err(|e| anyhow::anyhow!("create valid MLS signing-key update: {e:?}"))?;
    let bytes = bundle.into_commit().to_bytes()?;
    bob.stage_chat(3, &descriptor.subject("handshake"), &bytes)?;
    assert_eq!(bob.process_history("engineering")?.rejected, 1);
    assert_eq!(bob.group_epoch("engineering")?, 2);
    Ok(())
}
