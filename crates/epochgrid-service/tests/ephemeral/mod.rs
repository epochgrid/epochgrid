use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{ephemeral::EphemeralEvent, identity::IdentityStore, transport};
use futures_util::StreamExt;
use std::{net::TcpListener, time::Duration};
#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn encrypted_core_events_are_not_durable() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), workflow())
        .await
        .context("ephemeral workflow exceeded 60s")?
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
    let alice = IdentityStore::open(&root.path().join("alice"))?;
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    let ac = transport::connect(&url, &alice).await?;
    let bc = transport::connect(&url, &bob).await?;
    let subject = alice.group("engineering")?.subject("ephemeral");
    let mut sub = bc.subscribe(subject.clone()).await?;
    bc.flush().await?;
    let js = async_nats::jetstream::new(observer);
    let mut chat = js.get_stream("CHAT").await?;
    let mut mailbox = js.get_stream("MAILBOX").await?;
    let before = (
        chat.info().await?.state.last_sequence,
        mailbox.info().await?.state.last_sequence,
    );
    for event in [EphemeralEvent::TypingStarted, EphemeralEvent::TypingStopped] {
        let bytes = alice.seal_ephemeral("engineering", event)?;
        ac.publish(subject.clone(), bytes.clone().into()).await?;
        ac.flush().await?;
        let message = tokio::time::timeout(Duration::from_secs(2), sub.next())
            .await?
            .context("missing live event")?;
        ensure!(message.payload.as_ref() == bytes);
        ensure!(!bytes.windows(6).any(|w| w == b"Typing"));
        ensure!(bob.open_ephemeral("engineering", &message.payload)?.sender == "alice/laptop");
    }
    ensure!(
        (
            chat.info().await?.state.last_sequence,
            mailbox.info().await?.state.last_sequence
        ) == before
    );
    ensure!(
        chat.cached_info()
            .config
            .subjects
            .iter()
            .all(|s| !s.contains("ephemeral"))
    );
    sub.unsubscribe().await?;
    bc.flush().await?;
    drop(sub);
    ac.publish(
        subject.clone(),
        alice
            .seal_ephemeral("engineering", EphemeralEvent::TypingStarted)?
            .into(),
    )
    .await?;
    ac.flush().await?;
    let mut late = bc.subscribe(subject).await?;
    bc.flush().await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(250), late.next())
            .await
            .is_err()
    );
    ensure!(bob.history("engineering", 100, None)?.is_empty());
    Ok(())
}
