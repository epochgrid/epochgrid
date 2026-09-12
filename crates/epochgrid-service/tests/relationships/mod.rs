use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, transport};
use std::{net::TcpListener, time::Duration};
#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn append_only_relationships_offline_replay_and_restart() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), workflow())
        .await
        .context("relationship workflow exceeded 90s")?
}
async fn workflow() -> Result<()> {
    let root = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root.path(), port)?;
    let _nats = server(root.path())?;
    let admin = IdentityStore::open(&root.path().join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let _service = daemon(root.path(), &url)?;
    ready(root.path(), &url, true).await?;
    cli(root.path(), &url, "bob", &["identity", "register"], None).await?;
    cli(
        root.path(),
        &url,
        "alice",
        &["channel", "create", "engineering"],
        None,
    )
    .await?;
    cli(
        root.path(),
        &url,
        "alice",
        &["channel", "invite", "engineering", "bob"],
        None,
    )
    .await?;
    cli(
        root.path(),
        &url,
        "bob",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    let original = "EPOCHGRID_RELATION_ORIGINAL_91F3";
    let first = "EPOCHGRID_RELATION_EDIT_ONE_72A1";
    let second = "EPOCHGRID_RELATION_EDIT_TWO_A4B2";
    let reply = "EPOCHGRID_RELATION_REPLY_B838";
    cli(
        root.path(),
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(original.as_bytes()),
    )
    .await?;
    let events = cli(
        root.path(),
        &url,
        "alice",
        &["message", "events", "engineering", "--offline"],
        None,
    )
    .await?;
    let id = events
        .lines()
        .next()
        .context("ID line")?
        .strip_prefix("id: ")
        .context("ID")?
        .to_owned();
    ensure!(id.len() == 64);
    let js = async_nats::jetstream::new(observer);
    let mut stream = js.get_stream("CHAT").await?;
    let original_sequence = stream.info().await?.state.last_sequence;
    let saved = stream.get_raw_message(original_sequence).await?;
    cli(
        root.path(),
        &url,
        "bob",
        &["message", "reply", "engineering", &id, reply],
        None,
    )
    .await?;
    cli(
        root.path(),
        &url,
        "bob",
        &["message", "react", "engineering", &id, "approve"],
        None,
    )
    .await?;
    // Bob is offline for both edits. Each invocation opens a fresh Alice process.
    cli(
        root.path(),
        &url,
        "alice",
        &["message", "edit", "engineering", &id, first],
        None,
    )
    .await?;
    cli(
        root.path(),
        &url,
        "alice",
        &["message", "edit", "engineering", &id, second],
        None,
    )
    .await?;
    ensure!(
        cli(
            root.path(),
            &url,
            "bob",
            &["message", "edit", "engineering", &id, "forged"],
            None
        )
        .await
        .is_err()
    );
    let history = cli(
        root.path(),
        &url,
        "bob",
        &["message", "history", "engineering"],
        None,
    )
    .await?;
    ensure!(
        history.contains(second)
            && history.contains("[edited]")
            && history.contains("reaction approve: bob")
            && history.contains("reply to alice/laptop")
    );
    cli(
        root.path(),
        &url,
        "bob",
        &[
            "message",
            "react",
            "engineering",
            &id,
            "approve",
            "--remove",
        ],
        None,
    )
    .await?;
    let current = cli(
        root.path(),
        &url,
        "alice",
        &["message", "history", "engineering"],
        None,
    )
    .await?;
    ensure!(!current.contains("reaction approve: bob"));
    ensure!(stream.info().await?.state.last_sequence == original_sequence + 5);
    ensure!(stream.get_raw_message(original_sequence).await?.payload == saved.payload);
    let alice = IdentityStore::open(&root.path().join("alice"))?;
    let client = transport::connect(&url, &alice).await?;
    // Broker redelivery/republication must not create another logical event.
    async_nats::jetstream::new(client)
        .publish(saved.subject.clone(), saved.payload.clone())
        .await?
        .await?;
    drop(alice);
    let mut snapshots = Vec::new();
    for home in ["alice", "bob"] {
        cli(
            root.path(),
            &url,
            home,
            &["channel", "sync", "engineering"],
            None,
        )
        .await?;
        let store = IdentityStore::open(&root.path().join(home))?;
        let raw = store.history("engineering", 100, None)?;
        ensure!(raw.len() == 6 && raw[0].plaintext.as_deref() == Some(original.as_bytes()));
        let view = store.conversation("engineering", 100, None)?;
        snapshots.push(
            view.into_iter()
                .map(|e| (e.message_id, e.entry.sequence, e.entry.plaintext))
                .collect::<Vec<_>>(),
        );
        ensure!(store.rejected_history("engineering")? == 0);
    }
    ensure!(snapshots[0] == snapshots[1]);
    for sequence in 1..=stream.info().await?.state.last_sequence {
        let stored = stream.get_raw_message(sequence).await?;
        for secret in [original, first, second, reply] {
            ensure!(
                !stored
                    .payload
                    .windows(secret.len())
                    .any(|w| w == secret.as_bytes())
            );
        }
    }
    let audit = cli(
        root.path(),
        &url,
        "bob",
        &["message", "events", "engineering", "--offline"],
        None,
    )
    .await?;
    ensure!(audit.contains(original) && audit.contains(&id));
    Ok(())
}
