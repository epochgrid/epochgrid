use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    identity::IdentityStore,
    transparency::{self, Snapshot},
    transport, trust,
    wire::{self, Body},
};
use std::net::TcpListener;

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn verified_directory_migration_rollback_substitution_and_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root, port)?;
    let _nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let key = admin.nkey()?;
    let admin_client = connect(&url, &admin).await?;
    drop(admin);
    let directory = transport::provision(admin_client.clone()).await?;
    let enrollment = serde_json::from_slice(&std::fs::read(root.join("enrollment.json"))?)?;
    let alice_record = IdentityStore::open(&root.join("alice"))?.registration()?;
    let bob_record = IdentityStore::open(&root.join("bob"))?.registration()?;
    // M12 directory registrations existed before any transparency log.
    for record in [alice_record.clone(), bob_record.clone()] {
        transport::accept(&directory, &enrollment, record).await?;
    }
    cli(
        root,
        &url,
        "alice",
        &["transparency", "pin", &key.public_key()],
        None,
    )
    .await?;
    let service = daemon(root, &url)?;
    ready(root, &url, false).await?;
    let bob_fingerprint = trust::fingerprint(&bob_record)?;
    ensure!(
        cli(root, &url, "bob", &["device", "fingerprint"], None)
            .await?
            .contains(&trust::display_fingerprint(&bob_fingerprint))
    );
    ensure!(
        cli(
            root,
            &url,
            "alice",
            &[
                "identity",
                "verify",
                "bob",
                "--fingerprint",
                &"0".repeat(64)
            ],
            None
        )
        .await
        .is_err()
    );
    cli(
        root,
        &url,
        "alice",
        &[
            "device",
            "verify",
            "bob",
            "laptop",
            "--fingerprint",
            &bob_fingerprint,
        ],
        None,
    )
    .await?;
    ensure!(
        cli(root, &url, "alice", &["device", "list", "bob"], None)
            .await?
            .contains("[verified]")
    );
    let js = async_nats::jetstream::new(admin_client.clone());
    let log = js.get_key_value("TRANSPARENCY").await?;
    let original = transparency::read(&log).await?;
    ensure!(original.entries == vec![alice_record.clone(), bob_record.clone()]);
    let checkpoint = IdentityStore::open(&root.join("alice"))?
        .checkpoint()?
        .context("checkpoint missing")?;
    // A missing projection is repaired from the committed log after restart.
    drop(service);
    directory.delete(bob_record.payload.key()).await?;
    let _service = daemon(root, &url)?;
    ready(root, &url, false).await?;
    ensure!(directory.get(bob_record.payload.key()).await?.is_some());
    ensure!(
        IdentityStore::open(&root.join("alice"))?
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state
            == "verified"
    );
    let alice = IdentityStore::open(&root.join("alice"))?;
    let alice_client = connect(&url, &alice).await?;
    drop(alice);
    ensure!(
        alice_client
            .request("$JS.API.STREAM.INFO.KV_TRANSPARENCY", "".into())
            .await
            .is_err()
    );
    drop(alice_client);
    // Even correctly signed snapshots cannot roll back or rewrite this client's prefix.
    let mut reordered = original.entries.clone();
    reordered.swap(0, 1);
    for forged in [
        Snapshot::signed(vec![alice_record.clone()], &key)?,
        Snapshot::signed(reordered, &key)?,
        Snapshot::signed(original.entries.clone(), &nkeys::KeyPair::new_user())?,
    ] {
        log.put("snapshot", wire::encode(Body::AuditLog(forged))?.into())
            .await?;
        ensure!(
            cli(root, &url, "alice", &["transparency", "audit"], None)
                .await
                .is_err()
        );
        ensure!(
            cli(root, &url, "alice", &["transparency", "status"], None)
                .await?
                .contains("FAILURE")
        );
        ensure!(
            IdentityStore::open(&root.join("alice"))?.checkpoint()? == Some(checkpoint.clone())
        );
        log.put(
            "snapshot",
            wire::encode(Body::AuditLog(original.clone()))?.into(),
        )
        .await?;
        cli(root, &url, "alice", &["transparency", "audit"], None).await?;
    }
    // Replacing the projection alone cannot replace the identity clients discover.
    let fake = IdentityStore::open(&root.join("replacement"))?.init("bob", "laptop")?;
    directory
        .put(
            bob_record.payload.key(),
            wire::encode(Body::Register(fake.clone()))?.into(),
        )
        .await?;
    let found = cli(root, &url, "alice", &["identity", "lookup", "bob"], None).await?;
    ensure!(found.contains(&bob_record.payload.nats_public_key));
    ensure!(!found.contains(&fake.payload.nats_public_key));
    // Model a compromised log signer as well: observed device replacement is sticky.
    let substituted = Snapshot::signed(vec![alice_record, fake], &key)?;
    log.put(
        "snapshot",
        wire::encode(Body::AuditLog(substituted))?.into(),
    )
    .await?;
    ensure!(
        cli(root, &url, "alice", &["identity", "lookup", "bob"], None)
            .await
            .is_err()
    );
    let local = IdentityStore::open(&root.join("alice"))?;
    ensure!(
        local
            .device_trust("bob", "laptop")?
            .context("trust missing")?
            .state
            == "changed"
    );
    ensure!(local.checkpoint()? == Some(checkpoint));
    drop(local);
    ensure!(
        cli(root, &url, "alice", &["transparency", "status"], None)
            .await?
            .contains("CHANGED")
    );
    ensure!(
        cli(
            root,
            &url,
            "alice",
            &[
                "device",
                "verify",
                "bob",
                "laptop",
                "--fingerprint",
                &bob_fingerprint
            ],
            None
        )
        .await
        .is_err()
    );
    let evidence = cli(
        root,
        &url,
        "alice",
        &["device", "fingerprint", "bob", "laptop", "--offline"],
        None,
    )
    .await?;
    ensure!(
        evidence.contains("[changed]")
            && evidence.contains("Pinned fingerprint:")
            && evidence.contains("Latest fingerprint:")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires nats-server; run explicitly in CI"]
async fn transparency_atomic_competing_appends_and_idempotence() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root, port)?;
    let _nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let key = admin.nkey()?;
    let client = connect(&url, &admin).await?;
    drop(admin);
    let directory = transport::provision(client.clone()).await?;
    let enrollment = serde_json::from_slice(&std::fs::read(root.join("enrollment.json"))?)?;
    let log = transparency::provision(client, &directory, &enrollment, &key).await?;
    let a = IdentityStore::open(&root.join("alice"))?.registration()?;
    let b = IdentityStore::open(&root.join("bob"))?.registration()?;
    let (first, second) = tokio::join!(
        transparency::register(&log, &directory, &enrollment, &key, a.clone()),
        transparency::register(&log, &directory, &enrollment, &key, b.clone()),
    );
    first?;
    second?;
    let snapshot = transparency::read(&log).await?;
    ensure!(
        snapshot.entries.len() == 2
            && snapshot.entries.contains(&a)
            && snapshot.entries.contains(&b)
    );
    transparency::register(&log, &directory, &enrollment, &key, a.clone()).await?;
    ensure!(transparency::read(&log).await? == snapshot);
    let mut conflicting = a.clone();
    conflicting.payload.created_at += 1;
    conflicting.signature = IdentityStore::open(&root.join("alice"))?
        .nkey()?
        .sign(&conflicting.payload.signing_bytes()?)?;
    ensure!(
        transparency::register(&log, &directory, &enrollment, &key, conflicting)
            .await
            .is_err()
    );
    ensure!(transparency::read(&log).await? == snapshot);
    ensure!(Snapshot::signed(vec![a; 256], &key).is_err());
    Ok(())
}
