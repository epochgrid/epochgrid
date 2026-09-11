use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    attachments::{self, Limits},
    identity::IdentityStore,
    transport,
};
use std::{net::TcpListener, time::Duration};

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn encrypted_object_roundtrip_restart_tamper_and_expiration() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), workflow())
        .await
        .context("attachment workflow exceeded 120s")?
}
async fn workflow() -> Result<()> {
    let root = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root.path(), port)?;
    let nats = server(root.path())?;
    let admin = IdentityStore::open(&root.path().join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root.path(), &url)?;
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
    let secret = b"EPOCHGRID_ATTACHMENT_TEST_SECRET_91F3";
    let content = secret.repeat(8192);
    let filename = "EPOCHGRID_PRIVATE_FILENAME_91F3.bin";
    let path = root.path().join(filename);
    std::fs::write(&path, &content)?;
    let result = cli(
        root.path(),
        &url,
        "alice",
        &[
            "attachment",
            "send",
            "engineering",
            path.to_str().context("path")?,
        ],
        None,
    )
    .await?;
    let id = result
        .trim()
        .strip_prefix("EpochGrid encrypted attachment sent: ")
        .context("missing ID")?
        .to_owned();
    // Bob was offline during upload and manifest publication; sync persists both for restart.
    cli(
        root.path(),
        &url,
        "bob",
        &["channel", "sync", "engineering"],
        None,
    )
    .await?;
    let list = cli(
        root.path(),
        &url,
        "bob",
        &["attachment", "list", "engineering"],
        None,
    )
    .await?;
    ensure!(list.contains(&id) && list.contains(filename));
    let history = cli(
        root.path(),
        &url,
        "bob",
        &["message", "history", "engineering", "--offline"],
        None,
    )
    .await?;
    ensure!(history.contains("[attachment") && history.contains(filename));
    let destination = root.path().join("saved.bin");
    let args = [
        "attachment",
        "save",
        "engineering",
        &id,
        destination.to_str().context("path")?,
    ];
    cli(root.path(), &url, "bob", &args, None).await?;
    ensure!(std::fs::read(&destination)? == content);
    ensure!(cli(root.path(), &url, "bob", &args, None).await.is_err());
    ensure!(std::fs::read(&destination)? == content);
    let js = async_nats::jetstream::new(observer.clone());
    for name in ["CHAT", "MAILBOX", attachments::STREAM] {
        let mut stream = js.get_stream(name).await?;
        let last = stream.info().await?.state.last_sequence;
        for sequence in 1..=last {
            let message = stream.get_raw_message(sequence).await?;
            for marker in [secret.as_slice(), filename.as_bytes()] {
                ensure!(
                    !message.payload.windows(marker.len()).any(|w| w == marker),
                    "plaintext attachment data or filename in NATS"
                );
            }
        }
    }
    // Operator retention changes update the existing bucket without deleting objects.
    attachments::provision(observer.clone(), 3600, 16 * 1024 * 1024).await?;
    let mut stream = js.get_stream(attachments::STREAM).await?;
    ensure!(stream.info().await?.config.max_age == Duration::from_secs(3600));
    drop(service);
    drop(nats);
    drop(observer);
    let nats = server(root.path())?;
    let admin = IdentityStore::open(&root.path().join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root.path(), &url)?;
    ready(root.path(), &url, false).await?;
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    let bob_client = transport::connect(&url, &bob).await?;
    ensure!(
        &*attachments::download(&bob, &bob_client, "engineering", &id, Limits::default()).await?
            == &content
    );
    ensure!(
        attachments::download(
            &bob,
            &bob_client,
            "engineering",
            &id,
            Limits {
                max_bytes: 1,
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    let alice = IdentityStore::open(&root.path().join("alice"))?;
    let alice_client = transport::connect(&url, &alice).await?;
    // Corrupt one stored ciphertext chunk; no destination may appear on authentication failure.
    let js = async_nats::jetstream::new(observer.clone());
    let bucket = js.get_object_store(attachments::BUCKET).await?;
    let info = bucket.info(&id).await?;
    ensure!(info.chunks > 1);
    let stream = js.get_stream(attachments::STREAM).await?;
    let subject = format!("$O.ATTACHMENTS.C.{}", info.nuid);
    let chunk = stream.get_first_raw_message_by_subject(&subject, 1).await?;
    stream.delete_message(chunk.sequence).await?;
    let mut corrupt = chunk.payload.to_vec();
    corrupt[0] ^= 1;
    async_nats::jetstream::new(alice_client.clone())
        .publish(subject, corrupt.into())
        .await?
        .await?;
    let rejected = root.path().join("must-not-exist");
    ensure!(
        attachments::save_file(
            &bob,
            &bob_client,
            "engineering",
            &id,
            &rejected,
            Limits::default()
        )
        .await
        .is_err()
    );
    ensure!(!rejected.exists());
    let expiring = attachments::send_file(
        &alice,
        &alice_client,
        "engineering",
        &path,
        "application/octet-stream",
        Limits {
            ttl_seconds: 1,
            ..Default::default()
        },
    )
    .await?;
    epochgrid_core::history::resume(&bob, &bob_client, "engineering").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    ensure!(
        attachments::download(
            &bob,
            &bob_client,
            "engineering",
            &expiring,
            Limits::default()
        )
        .await
        .is_err()
    );
    // A malformed metadata link is rejected rather than followed recursively.
    let mut linked = bucket.info(&id).await?;
    linked.options = Some(async_nats::jetstream::object_store::ObjectOptions {
        link: Some(async_nats::jetstream::object_store::ObjectLink {
            name: Some(id.clone()),
            bucket: attachments::BUCKET.into(),
        }),
        max_chunk_size: None,
    });
    let metadata = stream
        .get_first_raw_message_by_subject("$O.ATTACHMENTS.M.*", 1)
        .await?;
    let metadata_info: async_nats::jetstream::object_store::ObjectInfo =
        serde_json::from_slice(&metadata.payload)?;
    ensure!(metadata_info.name == id);
    async_nats::jetstream::new(alice_client.clone())
        .publish(metadata.subject, serde_json::to_vec(&linked)?.into())
        .await?
        .await?;
    let error = attachments::download(&bob, &bob_client, "engineering", &id, Limits::default())
        .await
        .err()
        .context("object link was accepted")?;
    ensure!(error.to_string().contains("unsupported link"));
    drop(alice);
    drop(bob);
    cli(
        root.path(),
        &url,
        "service",
        &["device", "revoke", "bob", "laptop"],
        None,
    )
    .await?;
    let bob = IdentityStore::open(&root.path().join("bob"))?;
    ensure!(transport::connect(&url, &bob).await.is_err());
    drop(service);
    drop(nats);
    Ok(())
}
