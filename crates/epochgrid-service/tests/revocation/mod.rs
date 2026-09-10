use super::{
    connect,
    mvp::{cli, daemon, ready},
    server,
};
use anyhow::{Result, ensure};
use epochgrid_core::{
    identity::IdentityStore,
    transport,
    wire::{self, Body},
};
use std::{net::TcpListener, time::Duration};

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn revoke_live_device_rekey_and_enforce_after_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    let mut desktop = IdentityStore::open(&root.join("desktop"))?;
    desktop.init("alice", "desktop")?;
    let desktop_key = desktop.nkey()?.public_key();
    drop(desktop);
    transport::dev_config_with_enrollment(root, port, &[format!("alice/desktop={desktop_key}")])?;
    let nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let service = daemon(root, &url)?;
    ready(root, &url, true).await?;
    for who in ["bob", "desktop"] {
        cli(root, &url, who, &["identity", "register"], None).await?;
    }
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
        "desktop",
        &["channel", "join", "--from", "alice"],
        None,
    )
    .await?;
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    ensure!(
        cli(
            root,
            &url,
            "bob",
            &["device", "revoke", "alice", "laptop"],
            None
        )
        .await
        .is_err()
    );
    let alice = IdentityStore::open(&root.join("alice"))?;
    let alice_key = alice.nkey()?.public_key();
    let revoked_connection = connect(&url, &alice).await?;
    drop(alice);
    // Revoke the creator while connected: Bob succeeds it and Alice's other device survives.
    cli(
        root,
        &url,
        "desktop",
        &["device", "revoke", "alice", "laptop"],
        None,
    )
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "{error:#}; service: {}",
            std::fs::read_to_string(root.join("service.log")).unwrap_or_default()
        )
    })?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while revoked_connection.connection_state() == async_nats::connection::State::Connected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    let alice = IdentityStore::open(&root.join("alice"))?;
    ensure!(transport::connect(&url, &alice).await.is_err());
    drop(alice);
    let js = async_nats::jetstream::new(observer.clone());
    for name in ["CHAT", "MAILBOX"] {
        let stream = js.get_stream(name).await?;
        ensure!(
            stream
                .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&format!(
                    "device_{alice_key}"
                ))
                .await
                .is_err()
        );
    }
    let legacy = observer
        .request(wire::AUDIT, wire::encode(Body::Audit)?.into())
        .await?;
    ensure!(matches!(wire::decode(&legacy.payload)?, Body::Rejected));
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    cli(
        root,
        &url,
        "desktop",
        &["channel", "sync", "engineering"],
        None,
    )
    .await?;
    let secret = b"EPOCHGRID_REVOKED_CREATOR_CANNOT_READ_91F3";
    cli(
        root,
        &url,
        "bob",
        &["message", "send", "engineering"],
        Some(secret),
    )
    .await?;
    cli(
        root,
        &url,
        "desktop",
        &["channel", "sync", "engineering"],
        None,
    )
    .await?;
    let desktop = IdentityStore::open(&root.join("desktop"))?;
    ensure!(desktop.group_epoch("engineering")? == 3);
    ensure!(
        desktop
            .history("engineering", 100, None)?
            .iter()
            .any(|m| m.plaintext.as_deref() == Some(secret))
    );
    drop(desktop);
    let mut stream = js.get_stream("CHAT").await?;
    let last = stream.info().await?.state.last_sequence;
    let mut alice = Some(IdentityStore::open(&root.join("alice"))?);
    for seq in 1..=last {
        let message = stream.get_raw_message(seq).await?;
        ensure!(!message.payload.windows(secret.len()).any(|w| w == secret));
        if seq == last {
            ensure!(
                alice
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing store"))?
                    .decrypt_message("engineering", &message.payload)
                    .is_err()
            );
        }
    }
    drop(alice.take());
    // A retry by an active same-user device is idempotent.
    cli(
        root,
        &url,
        "desktop",
        &["device", "revoke", "alice", "laptop"],
        None,
    )
    .await?;
    drop(service);
    drop(nats);
    drop(revoked_connection);
    drop(observer);
    transport::dev_config(root, port)?;
    let _nats = server(root)?;
    let desktop = IdentityStore::open(&root.join("desktop"))?;
    let _connected = connect(&url, &desktop).await?;
    drop(desktop);
    let _service = daemon(root, &url)?;
    for _ in 0..30 {
        if cli(root, &url, "desktop", &["transparency", "audit"], None)
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(
        cli(root, &url, "alice", &["identity", "register"], None)
            .await
            .is_err()
    );
    cli(
        root,
        &url,
        "desktop",
        &["message", "send", "engineering"],
        Some(b"survivor restart reply"),
    )
    .await?;
    cli(root, &url, "bob", &["channel", "sync", "engineering"], None).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn durable_intent_retries_failed_enforcement_and_service_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    transport::dev_config(root, port)?;
    let _nats = server(root)?;
    let admin = IdentityStore::open(&root.join("service"))?;
    let observer = connect(&url, &admin).await?;
    drop(admin);
    let mut service = Some(daemon(root, &url)?);
    ready(root, &url, true).await?;
    cli(root, &url, "bob", &["identity", "register"], None).await?;
    let public_path = root.join("public-enrollment.json");
    let original = std::fs::read(&public_path)?;
    for (position, user) in ["bob", "alice"].iter().enumerate() {
        let target = IdentityStore::open(&root.join(user))?;
        let live = connect(&url, &target).await?;
        drop(target);
        // Simulate an unavailable actuator after intent has reached durable KV.
        std::fs::write(&public_path, b"invalid configuration")?;
        ensure!(
            cli(
                root,
                &url,
                "service",
                &["device", "revoke", user, "laptop"],
                None
            )
            .await
            .is_err()
        );
        let reply = observer
            .request(
                wire::REVOCATIONS,
                wire::encode(Body::RevocationAudit)?.into(),
            )
            .await?;
        let Body::RevocationLog(log) = wire::decode(&reply.payload)? else {
            anyhow::bail!("missing durable intent")
        };
        ensure!(log.entries.len() == position + 1);
        let target = IdentityStore::open(&root.join(user))?;
        ensure!(transport::connect(&url, &target).await.is_ok());
        if position == 1 {
            drop(service.take());
        }
        std::fs::write(&public_path, &original)?;
        if position == 1 {
            service = Some(daemon(root, &url)?);
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while live.connection_state() == async_nats::connection::State::Connected {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await?;
        ensure!(transport::connect(&url, &target).await.is_err());
    }
    drop(service);
    Ok(())
}
