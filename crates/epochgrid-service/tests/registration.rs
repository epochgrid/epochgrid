use anyhow::{Result, ensure};
use epochgrid_core::{
    identity::IdentityStore,
    transport,
    wire::{self, Body},
};
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
    let alice_reopened = IdentityStore::open(&dir.path().join("alice"))?;
    let client = connect(&url, &alice_reopened).await?;
    let _daemon = service(dir.path(), &url).await?;
    register_ready(&client, &alice_reopened).await?;
    let admin_client = connect(&url, &admin).await?;
    let kv = async_nats::jetstream::new(admin_client)
        .get_key_value("IDENTITIES")
        .await?;
    let after = kv
        .entry(alice_reopened.registration()?.payload.key())
        .await?
        .ok_or_else(|| anyhow::anyhow!("registration lost"))?;
    ensure!(before.value == after.value && before.revision == after.revision);
    ensure!(kv.get(bob.registration()?.payload.key()).await?.is_some());
    Ok(())
}
