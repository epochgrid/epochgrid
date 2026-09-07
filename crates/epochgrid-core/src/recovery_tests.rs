//! Child processes are killed with stores and transactions still open. These
//! tests exercise OS lock release and SQLite recovery, not Rust destructor paths.
use crate::identity::IdentityStore;
use anyhow::{Context, Result, ensure};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn pause(root: &Path, mode: &str) -> Result<()> {
    std::fs::write(root.join(format!("ready-{mode}")), b"ready")?;
    loop {
        std::thread::park();
    }
}
fn crash(root: &Path, mode: &str, user: &str) -> Result<()> {
    let mut child = Process(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "recovery_tests::crash_worker", "--nocapture"])
            .env("EPOCHGRID_TEST_CRASH_ROOT", root)
            .env("EPOCHGRID_TEST_CRASH_MODE", mode)
            .stdout(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join(format!("ready-{mode}")).exists() {
        ensure!(
            child.0.try_wait()?.is_none(),
            "crash worker exited early: {mode}"
        );
        ensure!(Instant::now() < deadline, "crash worker timed out: {mode}");
        std::thread::sleep(Duration::from_millis(10));
    }
    ensure!(
        IdentityStore::open(&root.join(user)).is_err(),
        "worker must hold device lock"
    );
    child.0.kill()?;
    ensure!(!child.0.wait()?.success());
    Ok(())
}
fn welcome(alice: &IdentityStore) -> Result<Vec<u8>> {
    Ok(alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
        [],
        |r| r.get(0),
    )?)
}

#[test]
fn crash_worker() -> Result<()> {
    let Some(root) = std::env::var_os("EPOCHGRID_TEST_CRASH_ROOT") else {
        return Ok(()); // Only the parent recovery test runs a worker scenario.
    };
    let root = Path::new(&root);
    let mode = std::env::var("EPOCHGRID_TEST_CRASH_MODE")?;
    let user = if matches!(mode.as_str(), "invite" | "send") {
        "alice"
    } else {
        "bob"
    };
    let store = IdentityStore::open(&root.join(user))?;
    match mode.as_str() {
        "invite" => {
            let bob = IdentityStore::open(&root.join("bob"))?;
            store.prepare_invitation("engineering", &bob.registration()?)?;
        }
        "join" => {
            let alice = IdentityStore::open(&root.join("alice"))?;
            store.accept_welcome(&welcome(&alice)?, &alice.registration()?)?;
        }
        "send" => {
            store.encrypt_message("engineering", b"committed before crash")?;
        }
        "stage" => {
            store.stage_chat(
                2,
                &store.group("engineering")?.subject("message"),
                &std::fs::read(root.join("ciphertext"))?,
            )?;
        }
        "receive-uncommitted" => {
            return store.transaction(|| {
                ensure!(
                    store
                        .decrypt_inner("engineering", &std::fs::read(root.join("ciphertext"))?)?
                        .is_some()
                );
                store.connection.execute(
                    "UPDATE chat_deliveries SET state='processed' WHERE sequence=2",
                    [],
                )?;
                // Kill while ratchet, transcript, dedup and progress writes are uncommitted.
                pause(root, &mode)
            });
        }
        "receive-committed" => {
            ensure!(store.process_history("engineering")?.decrypted == 1);
        }
        "reply" => {
            store.encrypt_message("engineering", b"reply after crashes")?;
        }
        _ => anyhow::bail!("unknown crash scenario"),
    }
    pause(root, &mode)
}

#[test]
fn abrupt_exit_recovers_invitation_ratchets_transcript_and_device_lock() -> Result<()> {
    let root = tempfile::tempdir()?;
    let a = root.path().join("alice");
    let b = root.path().join("bob");
    let mut alice = IdentityStore::open(&a)?;
    let mut bob = IdentityStore::open(&b)?;
    let alice_identity = alice.init("alice", "laptop")?;
    let bob_identity = bob.init("bob", "laptop")?;
    let group = alice.create_group("engineering")?;
    drop(alice);
    drop(bob);

    crash(root.path(), "invite", "alice")?;
    let alice = IdentityStore::open(&a)?;
    assert_eq!(alice.group("engineering")?, group);
    assert_eq!(alice.load_group(&group)?.epoch().as_u64(), 1);
    assert_eq!(
        alice
            .connection
            .query_row("SELECT COUNT(*) FROM outbox WHERE sent=0", [], |r| r
                .get::<_, i64>(0))?,
        2
    );
    let invitation = welcome(&alice)?;
    drop(alice);
    crash(root.path(), "join", "bob")?;
    let bob = IdentityStore::open(&b)?;
    // The private KeyPackage has already been consumed: this must use the join marker.
    assert_eq!(bob.accept_welcome(&invitation, &alice_identity)?, group);
    assert_eq!(bob.groups()?.len(), 1);
    drop(bob);

    crash(root.path(), "send", "alice")?;
    let alice = IdentityStore::open(&a)?;
    let ciphertext: Vec<u8> = alice.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%message'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(alice.history("engineering", 10, None)?.len(), 1);
    assert!(
        alice.history("engineering", 10, None)?[0]
            .sequence
            .is_none()
    );
    std::fs::write(root.path().join("ciphertext"), &ciphertext)?;
    drop(alice);
    crash(root.path(), "stage", "bob")?;
    crash(root.path(), "receive-uncommitted", "bob")?;
    let bob = IdentityStore::open(&b)?;
    assert!(bob.history("engineering", 10, None)?.is_empty());
    assert_eq!(
        bob.connection.query_row(
            "SELECT state FROM chat_deliveries WHERE sequence=2",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "pending"
    );
    assert_eq!(
        bob.connection
            .query_row("SELECT COUNT(*) FROM received", [], |r| r.get::<_, i64>(0))?,
        0
    );
    drop(bob);
    crash(root.path(), "receive-committed", "bob")?;
    let bob = IdentityStore::open(&b)?;
    assert_eq!(bob.process_history("engineering")?.decrypted, 0);
    assert!(bob.decrypt_message("engineering", &ciphertext)?.is_none());
    let unread = bob
        .unread("engineering")?
        .context("committed unread message lost")?;
    assert_eq!(
        unread.plaintext.as_deref(),
        Some(b"committed before crash".as_slice())
    );
    bob.mark_displayed(unread.id)?;
    drop(bob);
    crash(root.path(), "reply", "bob")?;

    let alice = IdentityStore::open(&a)?;
    let bob = IdentityStore::open(&b)?;
    assert_eq!(alice.registration()?, alice_identity);
    assert_eq!(bob.registration()?, bob_identity);
    assert_eq!(alice.group("engineering")?, bob.group("engineering")?);
    assert_eq!(alice.members("engineering")?, bob.members("engineering")?);
    assert!(bob.unread("engineering")?.is_none());
    let reply: Vec<u8> = bob.connection.query_row(
        "SELECT payload FROM outbox WHERE subject LIKE '%message'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(
        alice
            .decrypt_message("engineering", &reply)?
            .context("reply lost")?
            .plaintext,
        b"reply after crashes"
    );
    let next = alice.encrypt_message("engineering", b"ratchets still agree")?;
    assert_eq!(
        bob.decrypt_message("engineering", &next)?
            .context("next message lost")?
            .plaintext,
        b"ratchets still agree"
    );
    for store in [&alice, &bob] {
        assert_eq!(
            store
                .connection
                .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
            "ok"
        );
    }
    Ok(())
}
