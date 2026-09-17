use super::{Process, mvp::cli};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, identity_model::AuthRegistry, transport};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

async fn init(root: &Path) -> Result<()> {
    let mut output = tempfile::tempfile()?;
    let mut child = Process(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .arg("--home")
            .arg(root.join("backend"))
            .arg("auth-init")
            .stdout(Stdio::null())
            .stderr(output.try_clone()?)
            .spawn()?,
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                output.seek(SeekFrom::Start(0))?;
                let mut text = String::new();
                output.take(8192).read_to_string(&mut text)?;
                ensure!(status.success(), "auth-init failed: {text}");
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("auth-init timed out")?
}
fn daemon(root: &Path, url: &str) -> Result<Process> {
    let log = File::options()
        .create(true)
        .append(true)
        .open(root.join("backend.log"))?;
    Ok(Process(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .arg("--home")
            .arg(root.join("backend"))
            .arg("--server")
            .arg(url)
            .args(["serve", "--auth-config"])
            .arg(root.join("backend/auth.json"))
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    ))
}
async fn errors_at_least(errors: &AtomicUsize, count: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while errors.load(Ordering::SeqCst) < count {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("expected NATS authorization denial")?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires built workspace binaries and nats-server; run explicitly in CI"]
async fn dynamic_enrollment_inbox_isolation_revocation_without_reload() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(90), workflow())
        .await
        .context("dynamic auth test exceeded 90s")?
}
async fn workflow() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    init(root).await?;
    let path = root.join("backend/auth.json");
    let mut config: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    config["development_plaintext"] = true.into();
    config["authorization_ttl_seconds"] = 3.into();
    std::fs::write(&path, serde_json::to_vec(&config)?)?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("nats://127.0.0.1:{port}");
    let config = format!(
        "listen: 127.0.0.1:{port}\nmax_payload: 65536\njetstream {{store_dir: \"{}\"}}\n{}",
        root.join("js").display(),
        std::fs::read_to_string(root.join("backend/nats-reference.conf"))?
    );
    std::fs::write(root.join("nats.conf"), &config)?;
    let log = File::create(root.join("nats.log"))?;
    let mut nats = Process(
        Command::new(std::env::var("NATS_SERVER")?)
            .arg("-c")
            .arg(root.join("nats.conf"))
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    // Authenticate the fixed callout service credential to establish actual readiness.
    let auth_config = epochgrid_core::auth_callout::Config::load(&path)?;
    let mut ready = false;
    for _ in 0..30 {
        if auth_config.connect(&url).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ensure!(ready, "NATS failed startup");
    let mut backend = daemon(root, &url)?;
    let mut registry = AuthRegistry::open(&root.join("backend"))?;
    for user in ["alice", "bob"] {
        let token = registry.invite(user, 60)?;
        // Initial startup may deny until the signed revocation log has been reconciled.
        let mut enrolled = false;
        for _ in 0..3 {
            if cli(
                root,
                &url,
                user,
                &["identity", "enroll"],
                Some(token.as_bytes()),
            )
            .await
            .is_ok()
            {
                enrolled = true;
                break;
            }
            ensure!(
                backend.0.try_wait()?.is_none(),
                "backend exited: {}",
                std::fs::read_to_string(root.join("backend.log"))?
            );
        }
        ensure!(enrolled, "dynamic enrollment failed");
    }
    let alice = IdentityStore::open(&root.join("alice"))?;
    let bob = IdentityStore::open(&root.join("bob"))?;
    let a = alice.registration()?.payload;
    let b = bob.registration()?.payload;
    ensure!(
        !config.contains(&a.nats_public_key) && !config.contains(&b.nats_public_key),
        "device appears in static NATS configuration"
    );
    let client = transport::connect(&url, &alice).await?;
    let found =
        epochgrid_core::transparency::lookup(&client, &alice, &b.user_id, &b.device_id).await?;
    ensure!(found.payload.nats_public_key == b.nats_public_key);
    let mut unknown = IdentityStore::open(&root.join("unknown"))?;
    unknown.init(&a.user_id, "unknown")?;
    ensure!(
        transport::connect(&url, &unknown).await.is_err(),
        "unregistered device admitted"
    );
    // Exercise the signed policy endpoint: devices never obtain policy-write authority
    // merely by being admitted to the NATS account.
    use epochgrid_core::{
        authorization::{Member, PolicyUpdate, SUBJECT},
        wire::{self, Body},
    };
    use futures_util::StreamExt;
    let gid = "a".repeat(32);
    let policy = PolicyUpdate {
        version: 1,
        gid: gid.clone(),
        expected_generation: 0,
        epoch: 0,
        signer: a.nats_public_key.clone(),
        members: vec![Member {
            nkey: a.nats_public_key.clone(),
            leaf: 0,
        }],
    }
    .sign(&alice.nkey()?)?;
    let reply = client
        .request(
            SUBJECT,
            wire::encode(Body::GroupPolicy(policy.clone()))?.into(),
        )
        .await?;
    ensure!(matches!(
        wire::decode(&reply.payload)?,
        Body::PolicyApplied { generation: 1 }
    ));
    let bob_client = transport::connect(&url, &bob).await?;
    let mut takeover = policy.update.clone();
    takeover.signer = b.nats_public_key.clone();
    takeover.expected_generation = 1;
    takeover.epoch = 1;
    takeover.members.push(Member {
        nkey: b.nats_public_key.clone(),
        leaf: 1,
    });
    let reply = bob_client
        .request(
            SUBJECT,
            wire::encode(Body::GroupPolicy(takeover.sign(&bob.nkey()?)?))?.into(),
        )
        .await?;
    ensure!(matches!(wire::decode(&reply.payload)?, Body::Rejected));
    let group_client = transport::connect(&url, &alice).await?;
    let allowed = format!("epochgrid.v1.group.{gid}.ephemeral");
    let mut events = group_client.subscribe(allowed.clone()).await?;
    group_client.flush().await?;
    group_client.publish(allowed, vec![0_u8; 32].into()).await?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(2), events.next())
            .await?
            .is_some(),
        "authorized group traffic missing"
    );
    // Issue Bob a group grant, then remove it without revoking his whole device.
    let mut shared = policy.update.clone();
    shared.expected_generation = 1;
    shared.epoch = 1;
    shared.members.push(Member {
        nkey: b.nats_public_key.clone(),
        leaf: 1,
    });
    let response = client
        .request(
            SUBJECT,
            wire::encode(Body::GroupPolicy(shared.clone().sign(&alice.nkey()?)?))?.into(),
        )
        .await?;
    ensure!(matches!(
        wire::decode(&response.payload)?,
        Body::PolicyApplied { generation: 2 }
    ));
    let removed_errors = Arc::new(AtomicUsize::new(0));
    let observed_removal = removed_errors.clone();
    let member_client = async_nats::ConnectOptions::with_nkey(bob.nkey()?.seed()?)
        .custom_inbox_prefix(format!("_INBOX.{}", b.nats_public_key))
        .event_callback(move |event| {
            let errors = observed_removal.clone();
            async move {
                if matches!(event, async_nats::Event::ServerError(async_nats::ServerError::Other(ref message)) if message.to_ascii_lowercase().contains("permissions violation")) {
                    errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .connect(&url)
        .await?;
    let subject = format!("epochgrid.v1.group.{gid}.ephemeral");
    let mut membership = member_client.subscribe(subject.clone()).await?;
    member_client.flush().await?;
    member_client
        .publish(subject.clone(), vec![0_u8; 32].into())
        .await?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(2), membership.next())
            .await?
            .is_some()
    );
    shared.expected_generation = 2;
    shared.epoch = 2;
    shared.members.pop();
    let response = client
        .request(
            SUBJECT,
            wire::encode(Body::GroupPolicy(shared.sign(&alice.nkey()?)?))?.into(),
        )
        .await?;
    ensure!(matches!(
        wire::decode(&response.payload)?,
        Body::PolicyApplied { generation: 3 }
    ));
    // Lease expiry causes a fresh callout and the existing subscription is denied.
    tokio::time::timeout(Duration::from_secs(6), async {
        while removed_errors.load(Ordering::SeqCst) < 1 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("removed group subscription survived lease renewal")?;
    member_client
        .publish(subject, vec![0_u8; 32].into())
        .await?;
    member_client.flush().await?;
    errors_at_least(&removed_errors, 2).await?;
    let removed = transport::connect(&url, &bob).await?;
    ensure!(registry.authorized_groups(&b.nats_public_key)?.is_empty());
    drop(removed);
    let errors = Arc::new(AtomicUsize::new(0));
    let observed = errors.clone();
    let scoped = async_nats::ConnectOptions::with_nkey(alice.nkey()?.seed()?)
        .custom_inbox_prefix(format!("_INBOX.{}", a.nats_public_key))
        .event_callback(move |event| {
            let errors = observed.clone();
            async move {
                if matches!(event, async_nats::Event::ServerError(_)) {
                    errors.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .connect(&url)
        .await?;
    let bob_inbox = format!("epochgrid.v1.user.{}.{}.inbox", b.user_id, b.device_id);
    let _forbidden = scoped.subscribe(bob_inbox.clone()).await?;
    scoped.flush().await?;
    errors_at_least(&errors, 1).await?;
    scoped
        .publish(bob_inbox.clone(), "forbidden".into())
        .await?;
    scoped.flush().await?;
    errors_at_least(&errors, 2).await?;
    let unrelated = format!("epochgrid.v1.group.{}.message", "b".repeat(32));
    let _other = scoped.subscribe(unrelated.clone()).await?;
    scoped.flush().await?;
    errors_at_least(&errors, 3).await?;
    scoped.publish(unrelated, vec![0_u8; 32].into()).await?;
    scoped.flush().await?;
    errors_at_least(&errors, 4).await?;

    let disconnected = Arc::new(AtomicUsize::new(0));
    let watch = disconnected.clone();
    let bob_live = async_nats::ConnectOptions::with_nkey(bob.nkey()?.seed()?)
        .custom_inbox_prefix(format!("_INBOX.{}", b.nats_public_key))
        .event_callback(move |event| {
            let watch = watch.clone();
            async move {
                if matches!(event, async_nats::Event::Disconnected) {
                    watch.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .connect(&url)
        .await?;
    let _own = bob_live.subscribe(bob_inbox).await?;
    bob_live.flush().await?;
    let control = IdentityStore::open(&root.join("backend/control"))?;
    let admin = transport::connect(&url, &control).await?;
    epochgrid_core::revocation::revoke(&admin, &control, &b.user_id, &b.device_id).await?;
    ensure!(
        transport::connect(&url, &bob).await.is_err(),
        "revoked device reconnected"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while disconnected.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("existing revoked connection did not expire")?;
    ensure!(std::fs::read_to_string(root.join("nats.conf"))? == config);
    ensure!(
        !root.join("backend/auth/users.conf").exists()
            && !root.join("backend/revoked-nkeys.json").exists()
    );
    ensure!(nats.0.try_wait()?.is_none());
    ensure!(
        !std::fs::read_to_string(root.join("nats.log"))?
            .to_ascii_lowercase()
            .contains("reload")
    );
    drop(control);
    drop(admin);
    drop(backend);
    backend = daemon(root, &url)?;
    // A revoked identity remains denied while the service replays durable state.
    ensure!(transport::connect(&url, &bob).await.is_err());
    ensure!(
        backend.0.try_wait()?.is_none(),
        "backend restart failed: {}",
        std::fs::read_to_string(root.join("backend.log"))?
    );
    ensure!(transport::connect(&url, &alice).await.is_ok());
    ensure!(std::fs::read_to_string(root.join("nats.conf"))? == config);
    Ok(())
}
