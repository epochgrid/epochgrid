use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    identity::IdentityStore,
    receipts::{self, ReceiptState, Submission},
    transport,
};
use std::{net::TcpListener, time::Duration};
#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn three_device_receipts_offline_restart_and_ciphertext_only() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), workflow())
        .await
        .context("receipt workflow exceeded 90s")?
}
async fn workflow() -> Result<()> {
    let root = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root.path(), port)?;
    let mut desktop = IdentityStore::open(&root.path().join("alice-desktop"))?;
    let registration = desktop.init("alice", "desktop")?;
    drop(desktop);
    transport::dev_config_with_enrollment(
        root.path(),
        port,
        &[format!(
            "alice/desktop={}",
            registration.payload.nats_public_key
        )],
    )?;
    let _nats = server(root.path())?;
    let admin = IdentityStore::open(&root.path().join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let _service = daemon(root.path(), &url)?;
    ready(root.path(), &url, true).await?;
    for device in ["bob", "alice-desktop"] {
        cli(root.path(), &url, device, &["identity", "register"], None).await?;
    }
    cli(
        root.path(),
        &url,
        "alice",
        &["channel", "create", "engineering"],
        None,
    )
    .await?;
    for (home, user, device) in [
        ("bob", "bob", "laptop"),
        ("alice-desktop", "alice", "desktop"),
    ] {
        cli(
            root.path(),
            &url,
            "alice",
            &["channel", "invite", "engineering", user, "--device", device],
            None,
        )
        .await?;
        cli(
            root.path(),
            &url,
            home,
            &["channel", "join", "--from", "alice"],
            None,
        )
        .await?;
    }
    let secret = b"EPOCHGRID_RECEIPTS_TEST_SECRET_91F3";
    cli(
        root.path(),
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(secret),
    )
    .await?;
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    let id = bob.history("engineering", 1, None)?[0].id;
    ensure!(bob.message_status(id)?.submission == Submission::ServerAccepted);
    ensure!(bob.message_status(id)?.devices.is_empty());
    let alice = IdentityStore::open(&root.path().join("alice"))?;
    let desktop = IdentityStore::open(&root.path().join("alice-desktop"))?;
    let ac = transport::connect(&url, &alice).await?;
    let dc = transport::connect(&url, &desktop).await?;
    let bc = transport::connect(&url, &bob).await?;
    let js = async_nats::jetstream::new(observer);
    let mut chat = js.get_stream("CHAT").await?;
    let before = chat.info().await?.state.last_sequence;
    let mut mailbox = js.get_stream("MAILBOX").await?;
    let mailbox_before = mailbox.info().await?.state.last_sequence;
    let reference =
        epochgrid_core::transparency::hash(&chat.get_raw_message(before).await?.payload)?;
    let mut observed = bc
        .subscribe(bob.group("engineering")?.subject("ephemeral"))
        .await?;
    bc.flush().await?;
    tokio::try_join!(
        receipts::exchange(&alice, &ac, "engineering", Duration::from_secs(5)),
        receipts::exchange(&desktop, &dc, "engineering", Duration::from_secs(5)),
        receipts::exchange(&bob, &bc, "engineering", Duration::from_secs(5))
    )?;
    ensure!(
        bob.message_status(id)?.devices
            == vec![
                ("alice/desktop".into(), ReceiptState::Delivered),
                ("alice/laptop".into(), ReceiptState::Delivered)
            ]
    );
    desktop.mark_displayed(desktop.history("engineering", 1, None)?[0].id)?;
    drop(desktop);
    drop(bob);
    let desktop = IdentityStore::open(&root.path().join("alice-desktop"))?;
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    tokio::try_join!(
        receipts::exchange(&alice, &ac, "engineering", Duration::from_secs(5)),
        receipts::exchange(&desktop, &dc, "engineering", Duration::from_secs(5)),
        receipts::exchange(&bob, &bc, "engineering", Duration::from_secs(5))
    )?;
    ensure!(
        bob.message_status(id)?.devices
            == vec![
                ("alice/desktop".into(), ReceiptState::Read),
                ("alice/laptop".into(), ReceiptState::Delivered)
            ]
    );
    ensure!(chat.info().await?.state.last_sequence == before);
    ensure!(mailbox.info().await?.state.last_sequence == mailbox_before);
    use futures_util::{FutureExt, StreamExt};
    let mut count = 0;
    for _ in 0..100 {
        let Some(Some(message)) = observed.next().now_or_never() else {
            break;
        };
        ensure!(
            !message
                .payload
                .windows(reference.len())
                .any(|w| w == reference)
        );
        ensure!(!message.payload.windows(secret.len()).any(|w| w == secret));
        count += 1;
    }
    ensure!(count > 0, "no receipt traffic observed");
    for sequence in 1..=before {
        let message = chat.get_raw_message(sequence).await?;
        ensure!(!message.payload.windows(secret.len()).any(|w| w == secret));
    }
    ensure!(bob.history("engineering", 100, None)?.len() == 1);
    drop(bob);
    let output = cli(
        root.path(),
        &url,
        "bob",
        &["message", "receipts", "engineering", "--offline"],
        None,
    )
    .await?;
    ensure!(output.contains("alice/desktop: read") && output.contains("alice/laptop: delivered"));
    Ok(())
}
