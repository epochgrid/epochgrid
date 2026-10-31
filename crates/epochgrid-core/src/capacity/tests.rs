use super::*;
use crate::{
    identity::IdentityStore,
    identity_model::{AuthRegistry, token_user},
    wire::{self, Body},
};

#[test]
fn registry_limit_rollback_idempotence_revocation_and_restart() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("registry");
    let mut registry = AuthRegistry::open(&home)?;
    let policy = Capacity {
        retained_users: 2,
        retained_devices: 1,
        devices_per_user: 1,
        retained_tokens: 2,
        ..Capacity::default()
    };
    crate::secrets::save(&home.join(FILE), &policy)?;
    registry.capacity = policy;
    let token = registry.invite("alice", 60)?;
    let mut alice = IdentityStore::open(&root.path().join("alice"))?;
    let registration = alice.init(token_user(&token)?.as_str(), "laptop")?;
    registry.enroll(&token, &registration)?;
    registry.enroll(&token, &registration)?;
    let bob_token = registry.invite("bob", 60)?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let bob_registration = bob.init(token_user(&bob_token)?.as_str(), "laptop")?;
    assert!(registry.enroll(&bob_token, &bob_registration).is_err());
    assert!(
        registry
            .enrollment_admission(&bob_token, &bob_registration.payload.nats_public_key)
            .is_ok()
    );
    assert!(registry.invite("carol", 60).is_err());
    assert_eq!(
        registry
            .db
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?,
        2
    );
    let usage = registry.diagnostic_usage()?;
    assert_eq!(usage.users.used, 2);
    assert_eq!(usage.devices.used, 1);
    assert_eq!(usage.devices.limit, 1);
    assert!(usage.database_bytes.used > 0);
    assert!(usage.database_bytes.used <= usage.database_bytes.limit);
    assert_eq!(usage.groups.used, 0);
    registry.revoke(&registration.payload.nats_public_key)?;
    drop(registry);
    let mut registry = AuthRegistry::open(&home)?;
    assert_eq!(registry.diagnostic_usage()?.devices.used, 1);
    // Revoking does not free retained identity capacity or consume Bob's token.
    assert!(registry.enroll(&bob_token, &bob_registration).is_err());
    assert!(
        registry
            .enrollment_admission(&bob_token, &bob_registration.payload.nats_public_key)
            .is_ok()
    );
    Ok(())
}

#[test]
fn concurrent_invites_cannot_oversubscribe() -> Result<()> {
    let root = tempfile::tempdir()?;
    AuthRegistry::open(root.path())?;
    let policy = Capacity {
        retained_users: 1,
        ..Capacity::default()
    };
    crate::secrets::save(&root.path().join(FILE), &policy)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let registries = [
        AuthRegistry::open(root.path())?,
        AuthRegistry::open(root.path())?,
    ];
    let threads: Vec<_> = ["alice", "bob"]
        .into_iter()
        .zip(registries)
        .map(|(name, mut registry)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || -> Result<bool> {
                barrier.wait();
                Ok(registry.invite(name, 60).is_ok())
            })
        })
        .collect();
    let mut successes = 0;
    for thread in threads {
        successes += usize::from(thread.join().unwrap()?);
    }
    assert_eq!(successes, 1);
    assert_eq!(
        AuthRegistry::open(root.path())?
            .db
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn outbox_capacity_rolls_back_mls_and_retains_history() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("alice");
    let mut alice = IdentityStore::open(&home)?;
    let alice_registration = alice.init("alice", "laptop")?;
    let mut bob = IdentityStore::open(&root.path().join("bob"))?;
    let bob_registration = bob.init("bob", "laptop")?;
    alice.create_group("engineering")?;
    alice.prepare_invitation("engineering", &bob_registration)?;
    let welcome: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
        [],
        |r| r.get(0),
    )?;
    bob.accept_welcome(&welcome, &alice_registration)?;
    alice.connection.execute("UPDATE outbox SET sent=1", [])?;
    let policy = Capacity {
        pending_messages: 1,
        ..Capacity::default()
    };
    crate::secrets::save(&home.join(FILE), &policy)?;
    alice.capacity = policy;
    let first = alice.encrypt_message("engineering", b"one")?;
    assert!(alice.encrypt_message("engineering", b"rejected").is_err());
    assert_eq!(alice.history("engineering", 10, None)?.len(), 1);
    assert_eq!(
        bob.decrypt_message("engineering", &first)?
            .unwrap()
            .plaintext,
        b"one"
    );
    drop(alice);
    let alice = IdentityStore::open(&home)?;
    assert!(alice.encrypt_message("engineering", b"still full").is_err());
    alice.connection.execute("UPDATE outbox SET sent=1", [])?;
    let next = alice.encrypt_message("engineering", b"two")?;
    assert_eq!(
        bob.decrypt_message("engineering", &next)?
            .unwrap()
            .plaintext,
        b"two"
    );
    // Existing ciphertext and transcript rows survive quota recovery.
    assert_eq!(alice.history("engineering", 10, None)?.len(), 2);
    Ok(())
}

#[test]
fn maximum_retained_snapshots_fit_with_revocation_headroom() -> Result<()> {
    let root = tempfile::tempdir()?;
    let signer = nkeys::KeyPair::new_user();
    let mut entries = Vec::new();
    let mut revocations = Vec::new();
    let mut largest = 0;
    for i in 0..32 {
        let mut device = IdentityStore::open(&root.path().join(format!("device-{i}")))?;
        let registration = device.init(&format!("{i:032}"), &"d".repeat(32))?;
        let bytes = wire::encode(Body::Register(registration.clone()))?.len();
        largest = largest.max(bytes);
        assert!(bytes <= REGISTRATION_BYTES as usize);
        revocations.push(crate::revocation::Revocation {
            request: crate::revocation::RevokeRequest::signed(
                &registration.payload.user_id,
                &registration.payload.device_id,
                &registration.payload.nats_public_key,
                &signer,
            )?,
            chat_cutoff: i64::MAX as u64,
        });
        entries.push(registration);
    }
    let snapshot = crate::transparency::Snapshot::signed(entries, &signer)?;
    let log = crate::revocation::RevocationLog::signed(revocations, &signer)?;
    log.validate(&snapshot)?;
    let audit_bytes = wire::encode(Body::AuditLog(snapshot))?.len();
    let revocation_bytes = wire::encode(Body::RevocationLog(log))?.len();
    println!(
        "capacity fixture: registration_max={largest}, audit_32={audit_bytes}, revocation_32={revocation_bytes}"
    );
    assert!(audit_bytes < 49152);
    assert!(revocation_bytes < 16384);
    // The enforced registration ceiling plus framing also fits independent of fixture size.
    assert!(32 * REGISTRATION_BYTES + 1024 < wire::MAX_WIRE as u64);
    Ok(())
}

#[test]
fn client_policy_refuses_active_home_and_lower_retained_usage() -> Result<()> {
    let root = tempfile::tempdir()?;
    let home = root.path().join("device");
    let mut store = IdentityStore::open(&home)?;
    let registration = store.init("alice", "laptop")?;
    store.transaction(|| store.queue("test", b"retained"))?;
    let path = root.path().join("policy.json");
    std::fs::write(&path, serde_json::to_vec(&Capacity::default())?)?;
    assert!(Capacity::install_client(&home, &path).is_err());
    drop(store);
    let lower = Capacity {
        pending_bytes: 1,
        ..Capacity::default()
    };
    std::fs::write(&path, serde_json::to_vec(&lower)?)?;
    assert!(Capacity::install_client(&home, &path).is_err());
    assert!(!home.join(FILE).exists());
    std::fs::write(&path, serde_json::to_vec(&Capacity::default())?)?;
    Capacity::install_client(&home, &path)?;
    let store = IdentityStore::open(&home)?;
    assert_eq!(store.registration()?, registration);
    assert_eq!(
        store
            .connection
            .query_row("SELECT payload FROM outbox", [], |r| r.get::<_, Vec<u8>>(0))?,
        b"retained"
    );
    Ok(())
}

#[test]
fn pending_byte_boundary_recovery_reserve_and_sqlite_full_preserve_state() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut store = IdentityStore::open(root.path())?;
    let registration = store.init("alice", "laptop")?;
    store.capacity.pending_bytes = 3;
    store.transaction(|| store.queue("test", b"ab"))?;
    store.transaction(|| store.queue("test", b"c"))?;
    assert!(store.transaction(|| store.queue("test", b"d")).is_err());
    store.recovery_transaction(|| store.queue("repair", b"reserved"))?;
    assert!(store.transaction(|| store.queue("test", b"e")).is_err());
    let count: u64 = store
        .connection
        .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
    assert_eq!(count, 3);
    store
        .connection
        .execute_batch("CREATE TABLE capacity_failure_probe(bytes BLOB)")?;
    let pages: u64 = store
        .connection
        .query_row("PRAGMA page_count", [], |r| r.get(0))?;
    store
        .connection
        .pragma_update(None, "max_page_count", pages + 1)?;
    let failed = store.transaction(|| {
        store.connection.execute(
            "INSERT INTO capacity_failure_probe VALUES(zeroblob(1048576))",
            [],
        )?;
        Ok(())
    });
    assert!(failed.is_err());
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM capacity_failure_probe", [], |r| r
                .get::<_, u64>(0))?,
        0
    );
    assert_eq!(
        store
            .connection
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get::<_, u64>(0))?,
        count
    );
    assert_eq!(store.registration()?, registration);
    Ok(())
}

#[test]
fn policy_limits_roll_back_membership_generations_and_new_groups() -> Result<()> {
    use crate::authorization::{Member, PolicyUpdate};
    let root = tempfile::tempdir()?;
    let mut registry = AuthRegistry::open(&root.path().join("registry"))?;
    let mut keys = Vec::new();
    for name in ["alice", "bob"] {
        let token = registry.invite(name, 60)?;
        let mut store = IdentityStore::open(&root.path().join(name))?;
        let registration = store.init(token_user(&token)?.as_str(), "laptop")?;
        registry.enroll(&token, &registration)?;
        let key = store.nkey()?;
        registry.activate(&key.public_key())?;
        keys.push(key);
    }
    registry.capacity.membership_edges = 1;
    registry.capacity.groups_per_device = 1;
    let initial = PolicyUpdate {
        version: 1,
        gid: "a".repeat(32),
        expected_generation: 0,
        epoch: 0,
        signer: keys[0].public_key(),
        members: vec![Member {
            nkey: keys[0].public_key(),
            leaf: 0,
        }],
    };
    let signed = initial.clone().sign(&keys[0])?;
    assert_eq!(registry.apply_policy(&signed)?, 1);
    let before = registry.authorize(&keys[0].public_key())?.generation;
    assert_eq!(registry.apply_policy(&signed)?, 1);
    let mut expansion = initial.clone();
    expansion.expected_generation = 1;
    expansion.epoch = 1;
    expansion.members.push(Member {
        nkey: keys[1].public_key(),
        leaf: 1,
    });
    assert!(registry.apply_policy(&expansion.sign(&keys[0])?).is_err());
    assert_eq!(
        registry.authorize(&keys[0].public_key())?.generation,
        before
    );
    assert!(
        registry
            .authorized_groups(&keys[1].public_key())?
            .is_empty()
    );
    registry.capacity.membership_edges = 2;
    let mut second = initial;
    second.gid = "b".repeat(32);
    assert!(registry.apply_policy(&second.sign(&keys[0])?).is_err());
    assert_eq!(
        registry
            .db
            .query_row("SELECT COUNT(*) FROM authorization_groups", [], |r| r
                .get::<_, u64>(0))?,
        1
    );
    registry.revoke(&keys[0].public_key())?;
    Ok(())
}

#[test]
fn authenticated_audit_observation_can_use_recovery_space() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut store = IdentityStore::open(root.path())?;
    let registration = store.init("alice", "laptop")?;
    let pages: u64 = store
        .connection
        .query_row("PRAGMA page_count", [], |r| r.get(0))?;
    let size: String = store
        .connection
        .query_row("PRAGMA cipher_page_size", [], |r| r.get(0))?;
    let used = pages * size.parse::<u64>()?;
    store.capacity.database_bytes = used * 2;
    store.capacity.recovery_bytes = used + 4096;
    assert!(
        store
            .capacity
            .check_database(&store.connection, false)
            .is_err()
    );
    store.observe_device(&registration)?;
    assert!(
        store
            .transaction(|| store.queue("normal", b"blocked"))
            .is_err()
    );
    assert_eq!(store.registration()?, registration);
    Ok(())
}
