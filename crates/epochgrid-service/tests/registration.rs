use anyhow::{Result, ensure};
use epochgrid_core::{
    identity::IdentityStore,
    transport,
    wire::{self, Body},
};
use futures_util::StreamExt;
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Process(Child);
impl Process {
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "child did not exit within 5s",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.wait();
    }
}
fn server(root: &std::path::Path) -> Result<Process> {
    Ok(Process(
        Command::new(std::env::var("NATS_SERVER").unwrap_or_else(|_| "nats-server".into()))
            .arg("-c")
            .arg(root.join("nats.conf"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    ))
}
async fn service(root: &std::path::Path, url: &str) -> Result<Process> {
    let child = Process(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .arg("--home")
            .arg(root.join("service"))
            .arg("--enrollment")
            .arg(root.join("enrollment.json"))
            .arg("--server")
            .arg(url)
            .stdout(Stdio::null())
            .spawn()?,
    );
    Ok(child)
}
async fn connect(url: &str, identity: &IdentityStore) -> Result<async_nats::Client> {
    for _ in 0..50 {
        if let Ok(client) = transport::connect(url, identity).await {
            return Ok(client);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("NATS did not start")
}
async fn register_ready(client: &async_nats::Client, identity: &IdentityStore) -> Result<()> {
    for _ in 0..50 {
        if transport::register(client, identity.registration()?)
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("service did not become ready")
}
#[tokio::test]
#[ignore = "requires nats-server; run explicitly in CI and development"]
async fn nats_registration_and_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    transport::dev_config(dir.path(), port)?;
    let url = format!("nats://127.0.0.1:{port}");
    let nats = server(dir.path())?;
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let client = connect(&url, &alice).await?;
    let daemon = service(dir.path(), &url).await?;
    register_ready(&client, &alice).await?;
    let bob_client = connect(&url, &bob).await?;
    transport::register(&bob_client, bob.registration()?).await?;
    ensure!(transport::lookup(&client, "bob", "laptop").await? == bob.registration()?);
    ensure!(
        transport::lookup(&client, "unknown", "laptop")
            .await
            .is_err()
    );
    ensure!(transport::lookup(&client, "bob.*", "laptop").await.is_err());
    // A crafted reply must not turn the service into a KV-writing deputy.
    client
        .publish_with_reply(
            wire::REGISTER,
            format!("$KV.IDENTITIES.{}", alice.registration()?.payload.key()),
            wire::encode(Body::Register(alice.registration()?))?.into(),
        )
        .await?;
    // Exact retries preserve the original registration.
    transport::register(&client, alice.registration()?).await?;
    let mut bad = alice.registration()?;
    bad.payload.user_id = "mallory".into();
    bad.signature = alice.nkey()?.sign(&bad.payload.signing_bytes()?)?;
    ensure!(transport::register(&client, bad).await.is_err());
    let mut bad = alice.registration()?;
    bad.signature[0] ^= 1;
    ensure!(transport::register(&client, bad).await.is_err());
    let mut conflict = alice.registration()?;
    conflict.payload.created_at += 1;
    conflict.signature = alice.nkey()?.sign(&conflict.payload.signing_bytes()?)?;
    ensure!(transport::register(&client, conflict).await.is_err());
    let response = client
        .request(wire::REGISTER, vec![255, 255].into())
        .await?;
    ensure!(matches!(wire::decode(&response.payload)?, Body::Rejected));
    // A fully valid MLS/NKey binding still requires operator enrollment.
    let outsider_dir = tempfile::tempdir()?;
    let mut outsider = IdentityStore::open(outsider_dir.path())?;
    let outsider_registration = outsider.init("alice", "laptop")?;
    epochgrid_core::identity::verify(&outsider_registration)?;
    ensure!(
        transport::register(&client, outsider_registration)
            .await
            .is_err()
    );
    // NATS reports unauthorized subscription attempts asynchronously.
    let (events, mut received) = tokio::sync::mpsc::channel(16);
    let restricted = async_nats::ConnectOptions::with_nkey(alice.nkey()?.seed()?)
        .event_callback(move |event| {
            let events = events.clone();
            async move {
                if matches!(event, async_nats::Event::ServerError(_)) {
                    let _ = events.send(event).await;
                }
            }
        })
        .connect(&url)
        .await?;
    let _subscription = restricted
        .subscribe("epochgrid.v1.user.bob.laptop.inbox")
        .await?;
    restricted.flush().await?;
    let event = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("permission error missing"))?;
    ensure!(matches!(event, async_nats::Event::ServerError(_)));
    let unknown = nkeys::KeyPair::new_user();
    ensure!(
        async_nats::ConnectOptions::with_nkey(unknown.seed()?)
            .connect(&url)
            .await
            .is_err()
    );
    ensure!(async_nats::connect(&url).await.is_err());
    // A client cannot directly read the directory through the JetStream API.
    ensure!(
        client
            .request("$JS.API.STREAM.INFO.KV_IDENTITIES", "".into())
            .await
            .is_err()
    );
    let admin = IdentityStore::open(&dir.path().join("service"))?;
    let admin_client = connect(&url, &admin).await?;
    let js = async_nats::jetstream::new(admin_client.clone());
    let kv = js.get_key_value("IDENTITIES").await?;
    let before = kv
        .entry(alice.registration()?.payload.key())
        .await?
        .ok_or_else(|| anyhow::anyhow!("registration missing"))?;
    ensure!(before.revision == 1);
    ensure!(
        matches!(wire::decode(&before.value)?, Body::Register(r) if r == alice.registration()?)
    );
    let seed = alice.nkey()?.seed()?;
    ensure!(
        !before
            .value
            .windows(seed.len())
            .any(|w| w == seed.as_bytes())
    );
    for name in ["CHAT", "MAILBOX", "KV_CHANNELS"] {
        js.get_stream(name).await?;
    }
    drop(daemon);
    drop(nats);
    drop(client);
    drop(bob_client);
    drop(admin_client);
    // Restart server, service and clients against their existing disk state.
    let _nats = server(dir.path())?;
    drop(alice);
    let alice_reopened = IdentityStore::open(&dir.path().join("alice"))?;
    let client = connect(&url, &alice_reopened).await?;
    drop(admin);
    let _daemon = service(dir.path(), &url).await?;
    register_ready(&client, &alice_reopened).await?;
    let admin = IdentityStore::open(&dir.path().join("service"))?;
    let admin_client = connect(&url, &admin).await?;
    let js = async_nats::jetstream::new(admin_client);
    let kv = js.get_key_value("IDENTITIES").await?;
    let after = kv
        .entry(alice_reopened.registration()?.payload.key())
        .await?
        .ok_or_else(|| anyhow::anyhow!("registration lost"))?;
    ensure!(before.value == after.value && before.revision == after.revision);
    ensure!(kv.get(bob.registration()?.payload.key()).await?.is_some());
    alice_reopened.create_group("engineering")?;
    epochgrid_core::delivery::invite(&alice_reopened, &client, "engineering", "bob", "laptop")
        .await?;
    // Bob was not consuming his mailbox when Alice published the Welcome.
    let bob_client = connect(&url, &bob).await?;
    let joined = epochgrid_core::delivery::join_next(&bob, &bob_client, "alice", "laptop").await?;
    ensure!(joined == alice_reopened.group("engineering")?);
    ensure!(bob.members("engineering")? == alice_reopened.members("engineering")?);
    // Invitation retries flush original ciphertext; a new group cannot reuse Bob's package.
    epochgrid_core::delivery::invite(&alice_reopened, &client, "engineering", "bob", "laptop")
        .await?;
    ensure!(
        transport::claim_keypackage(&client, "bob", "laptop", "anothergroup")
            .await
            .is_err()
    );

    let secret = b"EPOCHGRID_TEST_SECRET_91F3";
    let mut bob_messages =
        epochgrid_core::messaging::subscribe(&bob, &bob_client, "engineering").await?;
    epochgrid_core::messaging::send(&alice_reopened, &client, "engineering", secret).await?;
    let received = tokio::time::timeout(Duration::from_secs(3), bob_messages.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Bob did not receive ciphertext"))?;
    ensure!(received.payload.as_ref() != secret);
    let decrypted = bob
        .decrypt_message("engineering", &received.payload)?
        .ok_or_else(|| anyhow::anyhow!("message unexpectedly deduplicated"))?;
    ensure!(decrypted.sender == "alice/laptop" && decrypted.plaintext == secret);
    let mut alice_messages =
        epochgrid_core::messaging::subscribe(&alice_reopened, &client, "engineering").await?;
    epochgrid_core::messaging::send(&bob, &bob_client, "engineering", b"confirmed").await?;
    let reply = tokio::time::timeout(Duration::from_secs(3), alice_messages.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Alice did not receive reply"))?;
    let reply = alice_reopened
        .decrypt_message("engineering", &reply.payload)?
        .ok_or_else(|| anyhow::anyhow!("reply missing"))?;
    ensure!(reply.sender == "bob/laptop" && reply.plaintext == b"confirmed");
    let mut chat = js.get_stream("CHAT").await?;
    let last_sequence = chat.info().await?.state.last_sequence;
    ensure!(last_sequence >= 3);
    for sequence in 1..=last_sequence {
        let stored = chat.get_raw_message(sequence).await?;
        ensure!(
            !stored.payload.windows(secret.len()).any(|w| w == secret),
            "plaintext found in JetStream"
        );
        ensure!(
            !stored
                .payload
                .windows(b"confirmed".len())
                .any(|w| w == b"confirmed")
        );
    }
    // Reload both MLS providers, then continue over the live NATS connection.
    drop(bob_messages);
    drop(alice_messages);
    drop(bob);
    drop(alice_reopened);
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let mut messages =
        epochgrid_core::messaging::subscribe(&bob, &bob_client, "engineering").await?;
    epochgrid_core::messaging::send(&alice, &client, "engineering", b"after restart").await?;
    let message = tokio::time::timeout(Duration::from_secs(3), messages.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("restart message missing"))?;
    ensure!(
        bob.decrypt_message("engineering", &message.payload)?
            .map(|m| m.plaintext)
            == Some(b"after restart".to_vec())
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires nats-server; run explicitly in CI and development"]
async fn durable_history_offline_ack_recovery_and_server_restart() -> Result<()> {
    use epochgrid_core::{delivery, history, messaging};
    let dir = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    transport::dev_config(dir.path(), port)?;
    let url = format!("nats://127.0.0.1:{port}");
    let nats = server(dir.path())?;
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let alice_client = connect(&url, &alice).await?;
    let _daemon = service(dir.path(), &url).await?;
    register_ready(&alice_client, &alice).await?;
    let bob_client = connect(&url, &bob).await?;
    transport::register(&bob_client, bob.registration()?).await?;
    alice.create_group("engineering")?;
    delivery::invite(&alice, &alice_client, "engineering", "bob", "laptop").await?;
    let secret = b"EPOCHGRID_OFFLINE_SECRET_91F3";
    messaging::send(&alice, &alice_client, "engineering", secret).await?;
    // Pull before joining; another channel's sync must not discard unknown-group data.
    bob.create_group("local")?;
    ensure!(history::catch_up(&bob, &bob_client, "local").await?.staged == 2);
    delivery::join_next(&bob, &bob_client, "alice", "laptop").await?;
    ensure!(bob.process_history("engineering")?.decrypted == 1);
    drop(bob_client);
    drop(bob);
    // Bob has no process/connection while Alice writes the backlog.
    for index in 0..40 {
        messaging::send(
            &alice,
            &alice_client,
            "engineering",
            format!("offline-{index:03}").as_bytes(),
        )
        .await?;
    }
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let bob_client = connect(&url, &bob).await?;
    // Receive and stage, then lose the ACK and exit. The durable must redeliver.
    let consumer = history::consumer(&bob, &bob_client).await?;
    let mut batch = consumer
        .fetch()
        .max_messages(1)
        .expires(Duration::from_secs(2))
        .messages()
        .await?;
    let delivery = batch
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("delivery missing"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    bob.stage_chat(
        delivery
            .info()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .stream_sequence,
        delivery.subject.as_str(),
        &delivery.payload,
    )?;
    drop(delivery);
    drop(batch);
    drop(consumer);
    drop(bob_client);
    drop(bob);
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let bob_client = connect(&url, &bob).await?;
    let report = history::catch_up(&bob, &bob_client, "engineering").await?;
    ensure!(report.decrypted == 40 && report.rejected == 0);
    let entries = bob.history("engineering", 100, None)?;
    ensure!(entries.len() == 41 && entries[0].plaintext.as_deref() == Some(secret.as_slice()));
    for (index, entry) in entries.iter().skip(1).enumerate() {
        ensure!(entry.plaintext.as_deref() == Some(format!("offline-{index:03}").as_bytes()));
    }
    ensure!(entries.windows(2).all(|w| w[0].sequence < w[1].sequence));
    ensure!(
        history::catch_up(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 0
    );
    let mut consumer = history::consumer(&bob, &bob_client).await?;
    ensure!(consumer.info().await?.num_ack_pending == 0);
    // Repeated ciphertext publications must never create duplicate transcript entries.
    let js = async_nats::jetstream::new(alice_client.clone());
    let ciphertext = alice.encrypt_message("engineering", b"duplicate-check")?;
    delivery::flush_outbox(&alice, &alice_client).await?;
    js.publish(
        alice.group("engineering")?.subject("message"),
        ciphertext.into(),
    )
    .await?
    .await?;
    // A malformed packet is quarantined while the following valid packet is processed.
    js.publish(
        alice.group("engineering")?.subject("message"),
        vec![255, 0].into(),
    )
    .await?
    .await?;
    messaging::send(
        &alice,
        &alice_client,
        "engineering",
        b"after corrupt packet",
    )
    .await?;
    let report = history::catch_up(&bob, &bob_client, "engineering").await?;
    ensure!(report.decrypted == 2 && report.rejected == 1);
    ensure!(bob.history("engineering", 100, None)?.len() == 43);
    // New traffic after the initial snapshot is picked up by the same durable path.
    messaging::send(&alice, &alice_client, "engineering", b"after catch-up").await?;
    ensure!(
        history::catch_up(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    messaging::send(&bob, &bob_client, "engineering", b"offline reply").await?;
    ensure!(
        history::catch_up(&alice, &alice_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    ensure!(alice.history("engineering", 100, None)?.len() == 45);
    let alice_js = async_nats::jetstream::new(alice_client.clone());
    ensure!(
        alice_js
            .get_consumer_from_stream::<async_nats::jetstream::consumer::pull::Config, _, _>(
                format!("device_{}", bob.nkey()?.public_key()),
                "CHAT"
            )
            .await
            .is_err()
    );
    // Restart NATS with persisted consumers, then verify offline sends still catch up.
    drop(nats);
    let _nats = server(dir.path())?;
    let alice_client = connect(&url, &alice).await?;
    let bob_client = connect(&url, &bob).await?;
    messaging::send(&alice, &alice_client, "engineering", b"server restarted").await?;
    ensure!(
        history::catch_up(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    drop(bob);
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    ensure!(bob.history("engineering", 100, None)?.len() == 46);
    ensure!(bob.unread("engineering")?.is_some());
    let admin = IdentityStore::open(&dir.path().join("service"))?;
    let admin_client = connect(&url, &admin).await?;
    let js = async_nats::jetstream::new(admin_client);
    let mut chat = js.get_stream("CHAT").await?;
    let last = chat.info().await?.state.last_sequence;
    for sequence in 1..=last {
        let stored = chat.get_raw_message(sequence).await?;
        ensure!(!stored.payload.windows(secret.len()).any(|w| w == secret));
        ensure!(
            !stored
                .payload
                .windows(b"offline-".len())
                .any(|w| w == b"offline-")
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires nats-server; run explicitly in CI and development"]
async fn resume_pending_invitation_and_ambiguous_publish() -> Result<()> {
    use epochgrid_core::{delivery, history, messaging};
    let dir = tempfile::tempdir()?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    transport::dev_config(dir.path(), port)?;
    let url = format!("nats://127.0.0.1:{port}");
    let _nats = server(dir.path())?;
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let alice_client = connect(&url, &alice).await?;
    let _daemon = service(dir.path(), &url).await?;
    register_ready(&alice_client, &alice).await?;
    let bob_client = connect(&url, &bob).await?;
    transport::register(&bob_client, bob.registration()?).await?;
    let group = alice.create_group("engineering")?;
    let recipient = transport::claim_keypackage(&alice_client, "bob", "laptop", &group.gid).await?;
    alice.prepare_invitation("engineering", &recipient)?;
    drop(alice);
    drop(alice_client);
    // Restart after the local epoch/Commit/Welcome transaction, before any publish.
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let alice_client = connect(&url, &alice).await?;
    history::resume(&alice, &alice_client, "engineering").await?;
    let js = async_nats::jetstream::new(bob_client.clone());
    let consumer: async_nats::jetstream::consumer::PullConsumer = js
        .get_consumer_from_stream(format!("device_{}", bob.nkey()?.public_key()), "MAILBOX")
        .await?;
    let mut batch = consumer
        .fetch()
        .max_messages(1)
        .expires(Duration::from_secs(2))
        .messages()
        .await?;
    let message = batch
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Welcome missing"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    ensure!(bob.accept_welcome(&message.payload, &alice.registration()?)? == group);
    // Model a lost Welcome ACK after the join commit. Retry must not consume keys again.
    drop(message);
    drop(batch);
    drop(consumer);
    drop(js);
    drop(bob_client);
    drop(bob);
    let bob = IdentityStore::open(&dir.path().join("bob"))?;
    let bob_client = connect(&url, &bob).await?;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if let Ok(joined) = delivery::join_next(&bob, &bob_client, "alice", "laptop").await {
                ensure!(joined == group);
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    let mut mailbox: async_nats::jetstream::consumer::PullConsumer =
        async_nats::jetstream::new(bob_client.clone())
            .get_consumer_from_stream(format!("device_{}", bob.nkey()?.public_key()), "MAILBOX")
            .await?;
    ensure!(mailbox.info().await?.num_ack_pending == 0);
    ensure!(bob.groups()?.len() == 1 && bob.group("engineering")? == group);

    let admin = IdentityStore::open(&dir.path().join("service"))?;
    let admin_client = connect(&url, &admin).await?;
    let admin_js = async_nats::jetstream::new(admin_client);
    let mut chat = admin_js.get_stream("CHAT").await?;
    let mut config = chat.info().await?.config.clone();
    // Shorten only this isolated test's dedup window to exercise an overdue retry.
    config.duplicate_window = Duration::from_secs(1);
    admin_js.update_stream(config).await?;
    let secret = b"EPOCHGRID_RESUME_SECRET_91F3";
    let ciphertext = alice.encrypt_message("engineering", secret)?;
    let mut headers = async_nats::HeaderMap::new();
    // Two invitation outbox rows precede this first application message.
    headers.insert("Nats-Msg-Id", format!("{}:3", alice.nkey()?.public_key()));
    let ack = async_nats::jetstream::new(alice_client.clone())
        .publish_with_headers(group.subject("message"), headers, ciphertext.clone().into())
        .await?
        .await?;
    let original_sequence = ack.sequence;
    // Server stored it, but the publishing process never committed its local sent marker.
    drop(alice_client);
    drop(alice);
    ensure!(
        history::resume(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let alice = IdentityStore::open(&dir.path().join("alice"))?;
    let alice_client = connect(&url, &alice).await?;
    history::resume(&alice, &alice_client, "engineering").await?;
    let last = chat.info().await?.state.last_sequence;
    ensure!(
        last > original_sequence,
        "test must exercise publication after dedup expiry"
    );
    ensure!(chat.get_raw_message(last).await?.payload.as_ref() == ciphertext);
    ensure!(
        history::resume(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 0
    );
    for store in [&alice, &bob] {
        let entries = store.history("engineering", 10, None)?;
        ensure!(entries.len() == 1 && entries[0].sequence == Some(original_sequence));
        ensure!(entries[0].plaintext.as_deref() == Some(secret.as_slice()));
    }
    // A second resume has no pending publish, and both ratchets can continue.
    history::resume(&alice, &alice_client, "engineering").await?;
    ensure!(chat.info().await?.state.last_sequence == last);
    messaging::send(
        &bob,
        &bob_client,
        "engineering",
        b"reply after ambiguous send",
    )
    .await?;
    ensure!(
        history::resume(&alice, &alice_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    messaging::send(&alice, &alice_client, "engineering", b"next generation").await?;
    ensure!(
        history::resume(&bob, &bob_client, "engineering")
            .await?
            .decrypted
            == 1
    );
    for sequence in 1..=chat.info().await?.state.last_sequence {
        let stored = chat.get_raw_message(sequence).await?;
        ensure!(!stored.payload.windows(secret.len()).any(|w| w == secret));
    }
    Ok(())
}

mod mvp;

mod multi_device;

mod verification;

mod revocation;

mod encrypted_recovery;

mod attachments;
