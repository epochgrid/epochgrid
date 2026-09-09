use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, transport};
use openmls::prelude::{tls_codec::Deserialize as _, *};
use std::{net::TcpListener, time::Duration};

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn enrollment_three_device_epochs_offline_and_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root, port)?;
    let nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, true).await?;
    cli(root, &url, "bob", &["identity", "register"], None).await?;
    cli(
        root,
        &url,
        "alice",
        &["channel", "create", "engineering"],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "alice",
        &["channel", "invite", "engineering", "bob"],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "bob",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    let markers: [&[u8]; 5] = [
        b"MULTI_OLD_HISTORY_91F3",
        b"MULTI_OFFLINE_OLD_47BC",
        b"MULTI_NEW_EPOCH_A1DE",
        b"MULTI_BOB_BOTH_ALICES_F329",
        b"MULTI_DESKTOP_REPLY_581A",
    ];
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(markers[0]),
    )
    .await?;
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    // Emulate an M11 consumer with acknowledged progress; service upgrade must preserve it.
    let bob_key = IdentityStore::open(&root.join("bob"))?.nkey()?.public_key();
    let js = async_nats::jetstream::new(observer.clone());
    let chat = js.get_stream("CHAT").await?;
    let consumer: async_nats::jetstream::consumer::PullConsumer = chat
        .get_consumer(&format!("device_{bob_key}"))
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let acknowledged = consumer.cached_info().ack_floor.stream_sequence;
    ensure!(acknowledged > 0);
    let _legacy = chat
        .create_consumer(async_nats::jetstream::consumer::pull::Config {
            durable_name: Some(format!("device_{bob_key}")),
            filter_subject: "epochgrid.v1.group.*.message".into(),
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_secs(2),
            max_ack_pending: 1,
            max_batch: 1,
            ..Default::default()
        })
        .await?;
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(markers[1]),
    )
    .await?;
    // A new installation creates its own keys; initialization alone grants no network rights.
    let enrollment = cli(
        root,
        &url,
        "alice-desktop",
        &["device", "add", "alice", "--device", "desktop"],
        None,
    )
    .await?;
    let desktop_identity = IdentityStore::open(&root.join("alice-desktop"))?.registration()?;
    let public_binding = format!("alice/desktop={}", desktop_identity.payload.nats_public_key);
    ensure!(enrollment.contains(&public_binding));
    ensure!(
        cli(root, &url, "alice-desktop", &["identity", "register"], None)
            .await
            .is_err()
    );
    drop(service);
    drop(nats);
    drop(observer);
    drop(js);
    drop(chat);
    drop(consumer);
    cli(
        root,
        &url,
        "alice",
        &[
            "dev-config",
            "--root",
            root.to_str().context("test path")?,
            "--port",
            &port.to_string(),
            "--enroll",
            &public_binding,
        ],
        None,
    )
    .await?;
    // Subsequent bootstraps preserve the explicitly authorized public binding.
    transport::dev_config(root, port)?;
    let nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, false).await?;
    let js = async_nats::jetstream::new(observer.clone());
    let chat = js.get_stream("CHAT").await?;
    let upgraded: async_nats::jetstream::consumer::PullConsumer = chat
        .get_consumer(&format!("device_{bob_key}"))
        .await
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    ensure!(upgraded.cached_info().config.filter_subject == "epochgrid.v1.group.*.*");
    ensure!(upgraded.cached_info().ack_floor.stream_sequence == acknowledged);
    let before = cli(root, &url, "bob", &["device", "list", "alice"], None).await?;
    ensure!(before.lines().count() == 1);
    cli(root, &url, "alice-desktop", &["identity", "register"], None).await?;
    let listed = cli(root, &url, "bob", &["device", "list", "alice"], None).await?;
    ensure!(
        listed.lines().count() == 2
            && listed.contains("alice/laptop")
            && listed.contains("alice/desktop")
    );
    ensure!(cli(root, &url, "alice-desktop", &["device", "list"], None).await? == listed);
    cli(
        root,
        &url,
        "alice",
        &[
            "channel",
            "invite",
            "engineering",
            "alice",
            "--device",
            "desktop",
        ],
        None,
    )
    .await?;
    cli(
        root,
        &url,
        "alice",
        &["message", "send", "engineering"],
        Some(markers[2]),
    )
    .await?;
    cli(
        root,
        &url,
        "alice-desktop",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    // Bob catches up the old application, Commit and new application in stream order before sending.
    cli(
        root,
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(markers[3]),
    )
    .await?;
    cli(
        root,
        &url,
        "alice-desktop",
        &["message", "send", "engineering"],
        Some(markers[4]),
    )
    .await?;
    let mut public_keys = std::collections::BTreeSet::new();
    let mut secrets = Vec::new();
    for user in ["alice", "alice-desktop", "bob"] {
        cli(root, &url, user, &["channel", "sync", "engineering"], None).await?;
        ensure!(
            cli(
                root,
                &url,
                user,
                &["channel", "members", "engineering", "--users"],
                None
            )
            .await?
                == "alice\nbob\n"
        );
        let devices = cli(
            root,
            &url,
            user,
            &["channel", "members", "engineering"],
            None,
        )
        .await?;
        ensure!(devices.lines().count() == 3 && devices.contains("alice/desktop"));
        let store = IdentityStore::open(&root.join(user))?;
        ensure!(store.group_epoch("engineering")? == 2);
        ensure!(public_keys.insert(store.nkey()?.public_key()));
        secrets.push(store.nkey()?.seed()?);
        let entries = store.history("engineering", 10, None)?;
        let expected = if user == "alice-desktop" {
            &markers[2..]
        } else {
            &markers[..]
        };
        ensure!(entries.len() == expected.len());
        for (entry, marker) in entries.iter().zip(expected) {
            ensure!(entry.plaintext.as_deref() == Some(*marker));
        }
        ensure!(entries.last().and_then(|e| e.sender.as_deref()) == Some("alice/desktop"));
        ensure!(store.rejected_history("engineering")? == 0);
    }
    // The new device gets only its own durable APIs, not Bob's mailbox.
    let desktop = IdentityStore::open(&root.join("alice-desktop"))?;
    let client = connect(&url, &desktop).await?;
    ensure!(
        async_nats::jetstream::new(client)
            .get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
                format!("device_{bob_key}"),
                "MAILBOX"
            )
            .await
            .is_err()
    );
    ensure!(desktop.registration()? == desktop_identity);
    drop(desktop);
    let mut chat = js.get_stream("CHAT").await?;
    let mut commits = 0;
    for sequence in 1..=chat.info().await?.state.last_sequence {
        let message = chat.get_raw_message(sequence).await?;
        for secret in markers
            .into_iter()
            .chain(secrets.iter().map(|s| s.as_bytes()))
        {
            ensure!(!message.payload.windows(secret.len()).any(|w| w == secret));
        }
        let message = MlsMessageIn::tls_deserialize_exact(&message.payload)?;
        ensure!(message.wire_format() == WireFormat::PrivateMessage);
        if message
            .try_into_protocol_message()
            .map_err(|_| anyhow::anyhow!("invalid MLS framing"))?
            .content_type()
            == ContentType::Commit
        {
            commits += 1;
        }
    }
    ensure!(commits == 2);
    drop(service);
    drop(nats);
    // New offline CLI processes keep exactly their own transcript, even after all infrastructure stops.
    for user in ["alice", "alice-desktop", "bob"] {
        let text = cli(
            root,
            "nats://127.0.0.1:1",
            user,
            &["message", "history", "engineering", "--offline"],
            None,
        )
        .await?;
        ensure!(text.contains(std::str::from_utf8(markers[4])?));
        if user == "alice-desktop" {
            ensure!(!text.contains(std::str::from_utf8(markers[0])?));
        }
    }
    Ok(())
}
