//! Operator-owned fixtures: production TLS, both auth modes, R1 and R3.
use super::{Process, tls};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    auth_callout::Config, identity::IdentityStore, identity_model::AuthRegistry, tls::TlsConfig,
    transport, wire,
};
use nats_jwt_rs::{account::Account, operator::Operator, user::User};
use nkeys::KeyPair;
use std::{net::TcpListener, path::Path, process::Command, time::Duration};

const STREAMS: [&str; 5] = [
    "CHAT",
    "MAILBOX",
    "KV_IDENTITIES",
    "KV_CHANNELS",
    "KV_TRANSPARENCY",
];

fn account(key: &KeyPair) -> nats_jwt_rs::Claims<Account> {
    let mut claim = Account::new_claims("fixture".into(), key.public_key());
    claim.nats.generic_fields.version = 2;
    claim
}
fn user(key: &KeyPair) -> nats_jwt_rs::Claims<User> {
    let mut claim = User::new_claims("fixture".into(), key.public_key());
    claim.nats.generic_fields.version = 2;
    claim
}
async fn connect(
    root: &Path,
    url: &str,
    key: &KeyPair,
    jwt: Option<&str>,
) -> Result<async_nats::Client> {
    let mut options = async_nats::ConnectOptions::with_nkey(key.seed()?)
        .custom_inbox_prefix(format!("_INBOX.{}", key.public_key()))
        .connection_timeout(Duration::from_secs(3))
        .request_timeout(Some(Duration::from_secs(5)));
    if let Some(jwt) = jwt {
        let signer = std::sync::Arc::new(KeyPair::from_seed(&key.seed()?)?);
        options = options.jwt(jwt.into(), move |nonce| {
            let signer = signer.clone();
            async move { signer.sign(&nonce).map_err(async_nats::AuthError::new) }
        });
    }
    let client = TlsConfig {
        ca_path: Some(root.join("ca.pem")),
        ..Default::default()
    }
    .apply(url, options)?
    .connect(url)
    .await?;
    tokio::time::timeout(Duration::from_secs(5), client.flush())
        .await
        .context("connection buffer flush timed out")??;
    Ok(client)
}
fn broker(root: &Path, index: usize) -> Result<Process> {
    let mut command = Command::new(std::env::var("NATS_SERVER")?);
    command
        .arg("-c")
        .arg(root.join(format!("nats-{index}.conf")));
    tls::daemon(command, &root.join(format!("nats-{index}.log")))
}
async fn ready(
    root: &Path,
    url: &str,
    key: &KeyPair,
    jwt: Option<&str>,
) -> Result<async_nats::Client> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(client) = connect(root, url, key, jwt).await {
                return Ok(client);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("NATS connection readiness timed out")?
}
async fn denied_admission(root: &Path, url: &str, key: Option<&KeyPair>) -> Result<()> {
    let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let options = match key {
        Some(key) => async_nats::ConnectOptions::with_nkey(key.seed()?),
        None => async_nats::ConnectOptions::new(),
    };
    let options = options
        .connection_timeout(Duration::from_secs(5))
        .event_callback(move |event| {
            let events = events.clone();
            async move {
                if let async_nats::Event::ServerError(error) = event {
                    let _ = events.send(error.to_string());
                }
            }
        });
    let result = TlsConfig {
        ca_path: Some(root.join("ca.pem")),
        ..Default::default()
    }
    .apply(url, options)?
    .connect(url)
    .await;
    match result {
        Err(error) => ensure!(
            error.kind() == async_nats::ConnectErrorKind::AuthorizationViolation,
            "expected authorization denial, got {error}"
        ),
        Ok(_client) => {
            // async-nats may return after an INFO update, before authentication settles.
            let error = tokio::time::timeout(Duration::from_secs(8), observed.recv())
                .await
                .context("admission was not explicitly denied")?
                .context("admission observer closed")?;
            ensure!(
                error
                    .to_ascii_lowercase()
                    .contains("authorization violation"),
                "expected authorization denial, got {error}"
            );
        }
    }
    Ok(())
}
async fn backend_ready(root: &Path, service: &mut Process) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            ensure!(
                service.0.try_wait()?.is_none(),
                "backend exited before admission readiness"
            );
            if std::fs::read_to_string(root.join("service.log"))?
                .contains("Auth Callout service ready")
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("backend admission readiness timed out")?
}
async fn command(root: &Path, url: &str, who: &str, args: &[&str], input: &[u8]) -> Result<()> {
    tls::success(
        tls::run(
            tls::cli(root, url, who, Some(&root.join("ca.pem")), false).args(args),
            input,
        )
        .await?,
    )
    .with_context(|| format!("{who}: {}", args.join(" ")))
}
async fn sync(root: &Path, url: &str, who: &str) -> Result<()> {
    command(root, url, who, &["channel", "sync", "engineering"], &[]).await
}
fn contains(root: &Path, who: &str, text: &[u8]) -> Result<()> {
    ensure!(
        IdentityStore::open(&root.join(who))?
            .history("engineering", 100, None)?
            .iter()
            .any(|m| m.plaintext.as_deref() == Some(text)),
        "{who}: expected message missing"
    );
    Ok(())
}
async fn send(root: &Path, url: &str, who: &str, text: &[u8]) -> Result<()> {
    // Persist once, then exercise the production CLI's durable flush path.
    sync(root, url, who).await?;
    IdentityStore::open(&root.join(who))?.encrypt_message("engineering", text)?;
    command(root, url, who, &["channel", "flush"], &[]).await
}

async fn workflow(root: &Path, operator_mode: bool, nodes: usize) -> Result<()> {
    let version = tls::run(
        Command::new(std::env::var("NATS_SERVER")?).arg("--version"),
        &[],
    )
    .await?;
    ensure!(
        version.status.success() && version.stdout == b"nats-server: v2.14.5\n",
        "qualification requires the pinned NATS Server 2.14.5 binary"
    );
    tls::certificates(root).await?;
    std::fs::write(
        root.join("route.extensions"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n",
    )?;
    tls::success(
        tls::run(
            Command::new("openssl").current_dir(root).args([
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                "route.extensions",
                "-out",
                "route.pem",
            ]),
            &[],
        )
        .await?,
    )?;
    tls::success(
        tls::run(
            Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
                .arg("--home")
                .arg(root.join("backend"))
                .arg("auth-init"),
            &[],
        )
        .await?,
    )?;
    let path = root.join("backend/auth.json");
    let mut config = Config::load(&path)?;
    let admin_key = KeyPair::new_user();
    let other_key = KeyPair::new_user();
    let mut admin_jwt = None;
    let mut other_jwt = None;
    let operator_config;
    if operator_mode {
        let operator = KeyPair::new_operator();
        let auth = KeyPair::new_account();
        let app = KeyPair::new_account();
        let sys = KeyPair::new_account();
        let other = KeyPair::new_account();
        let mut op = Operator::new_claims("qualification".into(), operator.public_key());
        op.nats.generic_fields.version = 2;
        op.nats.system_account = Some(sys.public_key());
        let mut auth_claim = account(&auth);
        auth_claim.nats.authorization = Some(nats_jwt_rs::account::ExternalAuthorization {
            auth_users: Some([config.connection.public_key.clone()].into()),
            allowed_accounts: Some([app.public_key()].into()),
            xkey: Some(config.encryption.public_key.clone()),
        });
        let mut app_claim = account(&app);
        app_claim.nats.signing_keys = Some(
            [nats_jwt_rs::types::SigningKey {
                key: config.issuer.public_key.clone(),
                scope: None,
            }]
            .into_iter()
            .collect(),
        );
        app_claim.nats.limits.as_mut().unwrap().jetstream =
            Some(nats_jwt_rs::account::JetStreamLimits {
                memory_storage: Some(64 * 1024 * 1024),
                disk_storage: Some(512 * 1024 * 1024),
                streams: Some(16),
                consumer: Some(128),
                ..Default::default()
            });
        let mut auth_user = User::new_claims(
            "EpochGrid auth service".into(),
            config.connection.public_key.clone(),
        );
        auth_user.nats.generic_fields.version = 2;
        auth_user.nats.permissions.permissions.subscribe.allow =
            vec!["$SYS.REQ.USER.AUTH".into(), "_INBOX.>".into()];
        auth_user.nats.permissions.permissions.publish.allow = vec!["$SYS._INBOX.>".into()];
        config.operator_jwt = Some(epochgrid_core::auth_callout::OperatorJwt {
            auth_account: auth.public_key(),
            connection_jwt: auth_user.encode(&auth)?,
        });
        config.target_account = app.public_key();
        std::fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
        let mut sentinel = user(&KeyPair::new_user());
        sentinel.nats.permissions.bearer_token = Some(true);
        sentinel.nats.permissions.permissions.publish.deny = vec![">".into()];
        sentinel.nats.permissions.permissions.subscribe.deny = vec![">".into()];
        operator_config = format!(
            "operator: {}\nsystem_account: {}\nresolver: MEM\nresolver_preload: {{\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n}}\ndefault_sentinel: {}\n",
            op.encode(&operator)?,
            sys.public_key(),
            auth.public_key(),
            auth_claim.encode(&operator)?,
            app.public_key(),
            app_claim.encode(&operator)?,
            sys.public_key(),
            account(&sys).encode(&operator)?,
            other.public_key(),
            account(&other).encode(&operator)?,
            sentinel.encode(&auth)?
        );
        admin_jwt = Some(user(&admin_key).encode(&app)?);
        other_jwt = Some(user(&other_key).encode(&other)?);
    } else {
        operator_config = format!(
            "accounts {{\nAUTH {{users: [{{nkey: \"{}\", permissions: {{subscribe: [\"$SYS.REQ.USER.AUTH\", \"_INBOX.>\"], publish: [\"$SYS._INBOX.>\"]}}}}]}}\nEPOCHGRID {{jetstream: enabled, users: [{{nkey: \"{}\"}}]}}\nOTHER {{users: [{{nkey: \"{}\"}}]}}\n}}\nauthorization {{timeout: 2, auth_callout {{issuer: \"{}\", xkey: \"{}\", account: AUTH, auth_users: [\"{}\", \"{}\", \"{}\"], allowed_accounts: [EPOCHGRID]}}}}\n",
            config.connection.public_key,
            admin_key.public_key(),
            other_key.public_key(),
            config.issuer.public_key,
            config.encryption.public_key,
            config.connection.public_key,
            admin_key.public_key(),
            other_key.public_key()
        );
    }
    // Reserve all ports until the complete configuration is ready.
    let reservations = (0..nodes * 2)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    let ports = reservations
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let urls: Vec<_> = ports[..nodes]
        .iter()
        .map(|p| format!("tls://localhost:{p}"))
        .collect();
    let routes = ports[nodes..]
        .iter()
        .map(|p| format!("\"nats://127.0.0.1:{p}\""))
        .collect::<Vec<_>>()
        .join(",");
    let mut originals = Vec::new();
    for i in 0..nodes {
        let cluster = if nodes > 1 {
            format!(
                "cluster {{name: qualification, listen: 127.0.0.1:{}, routes: [{routes}], tls {{cert_file: \"{}\", key_file: \"{}\", ca_file: \"{}\", verify: true, min_version: \"1.3\"}}}}\n",
                ports[nodes + i],
                root.join("route.pem").display(),
                root.join("server.key").display(),
                root.join("ca.pem").display()
            )
        } else {
            String::new()
        };
        let text = format!(
            "server_name: node{i}\nlisten: 127.0.0.1:{}\nclient_advertise: localhost:{}\nmax_payload: 65536\njetstream {{store_dir: \"{}\"}}\ntls {{cert_file: \"{}\", key_file: \"{}\", min_version: \"1.3\"}}\n{cluster}{operator_config}",
            ports[i],
            ports[i],
            root.join(format!("js{i}")).display(),
            root.join("server.pem").display(),
            root.join("server.key").display()
        );
        std::fs::write(root.join(format!("nats-{i}.conf")), &text)?;
        originals.push(text);
    }
    drop(reservations);
    let mut brokers = (0..nodes)
        .map(|i| broker(root, i).map(Some))
        .collect::<Result<Vec<_>>>()?;
    let admin = ready(root, &urls[0], &admin_key, admin_jwt.as_deref()).await?;
    // Operator pre-provisions all resources; EpochGrid must reuse their replication settings.
    let js = async_nats::jetstream::new(admin.clone());
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if transport::provision(admin.clone()).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("JetStream provisioning readiness")?;
    js.create_key_value(async_nats::jetstream::kv::Config {
        bucket: "TRANSPARENCY".into(),
        history: 1,
        max_value_size: wire::MAX_WIRE as i32,
        ..Default::default()
    })
    .await?;
    let mut resource_configs = Vec::new();
    for name in STREAMS {
        let mut stream = js.get_stream(name).await?;
        let mut resource = stream.info().await?.config.clone();
        resource.num_replicas = nodes;
        js.update_stream(resource).await?;
        resource_configs.push((
            name,
            js.get_stream(name).await?.info().await?.config.clone(),
        ));
    }
    let mut service = tls::daemon(
        tls::backend(root, &urls[0], Some(&root.join("ca.pem")), false),
        &root.join("service.log"),
    )?;
    backend_ready(root, &mut service).await?;
    denied_admission(root, &urls[0], Some(&KeyPair::new_user()))
        .await
        .context("unregistered device")?;
    denied_admission(root, &urls[0], None)
        .await
        .context("missing possession proof")?;
    for who in ["alice", "bob"] {
        let token = AuthRegistry::open(&root.join("backend"))?.invite(who, 120)?;
        command(
            root,
            &urls[0],
            who,
            &["identity", "enroll"],
            token.as_bytes(),
        )
        .await?;
    }
    let alice = IdentityStore::open(&root.join("alice"))?
        .registration()?
        .payload;
    let bob = IdentityStore::open(&root.join("bob"))?
        .registration()?
        .payload;
    command(
        root,
        &urls[0],
        "alice",
        &["channel", "create", "engineering"],
        &[],
    )
    .await?;
    command(
        root,
        &urls[0],
        "alice",
        &["channel", "invite", "engineering", &bob.user_id],
        &[],
    )
    .await?;
    command(
        root,
        &urls[0],
        "bob",
        &["channel", "join", "--from", &alice.user_id],
        &[],
    )
    .await?;
    send(root, &urls[0], "alice", b"before broker loss").await?;
    sync(root, &urls[0], "bob").await?;
    contains(root, "bob", b"before broker loss")?;
    send(root, &urls[0], "bob", b"bidirectional reply").await?;
    sync(root, &urls[0], "alice").await?;
    contains(root, "alice", b"bidirectional reply")?;
    // Every node must support admission, not just the seed server.
    for url in &urls {
        command(root, url, "alice", &["identity", "register"], &[]).await?;
    }
    // Wrong trust must fail at transport, before any successful registration.
    let bad = tls::run(
        tls::cli(
            root,
            &urls[0],
            "alice",
            Some(&root.join("wrong.pem")),
            false,
        )
        .args(["identity", "register"]),
        &[],
    )
    .await?;
    ensure!(!bad.status.success(), "wrong trust admitted");
    // Another account cannot see application messages even with wildcard permission.
    use futures_util::StreamExt;
    let other = connect(root, &urls[0], &other_key, other_jwt.as_deref()).await?;
    let mut isolated = other.subscribe("epochgrid.v1.>").await?;
    other.flush().await?;
    other
        .publish("epochgrid.v1.probe", "other-account control".into())
        .await?;
    let control = tokio::time::timeout(Duration::from_secs(3), isolated.next())
        .await?
        .context("other-account subscription closed")?;
    ensure!(
        control.payload.as_ref() == b"other-account control",
        "other-account subscription was not ready"
    );
    send(root, &urls[0], "alice", b"account isolation marker").await?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(300), isolated.next())
            .await
            .is_err(),
        "cross-account leak"
    );
    // Require explicit server permission errors, not generic request timeouts.
    let alice_key = IdentityStore::open(&root.join("alice"))?.nkey()?;
    let (errors, mut observed) = tokio::sync::mpsc::unbounded_channel();
    let options = async_nats::ConnectOptions::with_nkey(alice_key.seed()?)
        .connection_timeout(Duration::from_secs(3))
        .event_callback(move |event| {
            let errors = errors.clone();
            async move {
                if let async_nats::Event::ServerError(error) = event {
                    let _ = errors.send(error.to_string());
                }
            }
        });
    let scoped = TlsConfig {
        ca_path: Some(root.join("ca.pem")),
        ..Default::default()
    }
    .apply(&urls[0], options)?
    .connect(&urls[0])
    .await?;
    let inbox = format!("epochgrid.v1.user.{}.{}.inbox", bob.user_id, bob.device_id);
    for (subscribe, subject) in [
        (true, inbox.clone()),
        (false, inbox),
        (true, "$SYS.REQ.USER.AUTH".into()),
        (false, "$SYS.REQ.USER.AUTH".into()),
        (false, "$JS.API.STREAM.MSG.GET.CHAT".into()),
        (false, "$JS.API.CONSUMER.CREATE.CHAT.forbidden".into()),
        (
            false,
            format!(
                "$JS.API.CONSUMER.MSG.NEXT.MAILBOX.device_{}",
                bob.nats_public_key
            ),
        ),
    ] {
        let _subscription = if subscribe {
            Some(scoped.subscribe(subject.clone()).await?)
        } else {
            scoped.publish(subject.clone(), "{}".into()).await?;
            None
        };
        scoped.flush().await?;
        let error = tokio::time::timeout(Duration::from_secs(3), observed.recv())
            .await
            .context("missing explicit permission denial")?
            .context("error observer closed")?;
        ensure!(
            error.to_ascii_lowercase().contains("permissions violation")
                && error.contains(&subject),
            "unexpected authorization result: {error}"
        );
    }
    // Kill the CHAT leader in R3, and the only node in R1. Keep data directories.
    let leader = js
        .get_stream("CHAT")
        .await?
        .info()
        .await?
        .cluster
        .as_ref()
        .and_then(|c| c.leader.clone())
        .unwrap_or_else(|| "node0".into());
    let killed = leader
        .strip_prefix("node")
        .context("unexpected leader")?
        .parse::<usize>()?;
    brokers[killed].take();
    let survivor = if nodes > 1 { (killed + 1) % nodes } else { 0 };
    if nodes == 1 {
        brokers[0] = Some(broker(root, 0)?);
    }
    // Each stream and durable has an independent leader election. CHAT readiness
    // alone does not establish that directory/authorization operations can resume.
    tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let mut ready = true;
            for name in STREAMS {
                match js.get_stream(name).await {
                    Ok(mut stream) => {
                        ready &= stream.info().await.is_ok();
                        if name == "CHAT" || name == "MAILBOX" {
                            for key in [&alice.nats_public_key, &bob.nats_public_key] {
                                ready &=
                                    stream.consumer_info(&format!("device_{key}")).await.is_ok();
                            }
                        }
                    }
                    Err(_) => ready = false,
                }
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("stream/consumer failover readiness")?;
    command(
        root,
        &urls[survivor],
        "alice",
        &["identity", "register"],
        &[],
    )
    .await?;
    send(root, &urls[survivor], "alice", b"after broker loss").await?;
    sync(root, &urls[survivor], "bob").await?;
    contains(root, "bob", b"after broker loss")?;
    contains(root, "bob", b"before broker loss")?;
    // Bob never fetched this acknowledged message before broker loss.
    contains(root, "bob", b"account isolation marker")?;
    if nodes > 1 {
        brokers[killed] = Some(broker(root, killed)?);
    }
    drop(service);
    // An available broker with no Auth Callout service must reject fresh admission.
    denied_admission(root, &urls[survivor], Some(&alice_key))
        .await
        .context("Auth Callout outage")?;
    std::fs::write(root.join("service.log"), "")?;
    service = tls::daemon(
        tls::backend(root, &urls[survivor], Some(&root.join("ca.pem")), false),
        &root.join("service.log"),
    )?;
    backend_ready(root, &mut service).await?;
    sync(root, &urls[survivor], "bob").await?;
    contains(root, "bob", b"after broker loss")?;
    command(
        root,
        &urls[survivor],
        "backend/control",
        &["device", "revoke", &bob.user_id, &bob.device_id],
        &[],
    )
    .await?;
    let bob_key = IdentityStore::open(&root.join("bob"))?.nkey()?;
    denied_admission(root, &urls[survivor], Some(&bob_key))
        .await
        .context("revoked device")?;
    for (name, expected) in resource_configs {
        let mut stream = js.get_stream(name).await?;
        ensure!(
            stream.info().await?.config == expected,
            "operator resource configuration changed: {name}"
        );
        if nodes > 1 {
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if stream.info().await?.cluster.as_ref().is_some_and(|c| {
                        c.leader.is_some()
                            && c.replicas.len() == nodes - 1
                            && c.replicas.iter().all(|r| r.current && !r.offline)
                    }) {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .with_context(|| format!("{name}: restored replicas did not catch up"))??;
        }
    }
    for (i, text) in originals.iter().enumerate() {
        ensure!(
            std::fs::read_to_string(root.join(format!("nats-{i}.conf")))? == *text,
            "operator config changed"
        );
        ensure!(
            !text.contains(&alice.nats_public_key) && !text.contains(&bob.nats_public_key),
            "static device allow-list"
        );
    }
    Ok(())
}
async fn qualify(operator: bool, nodes: usize) -> Result<()> {
    let root = tempfile::tempdir()?;
    let result = tokio::time::timeout(
        Duration::from_secs(240),
        workflow(root.path(), operator, nodes),
    )
    .await
    .context("BYO qualification exceeded 240s")
    .and_then(|r| r);
    if result.is_err() {
        // No protocol payload/debug logging: only bounded process diagnostics.
        for name in
            std::iter::once("service.log".into()).chain((0..nodes).map(|i| format!("nats-{i}.log")))
        {
            let text = std::fs::read_to_string(root.path().join(&name)).unwrap_or_default();
            let lines = text.lines().rev().take(30).collect::<Vec<_>>();
            eprintln!(
                "{name}:\n{}",
                lines.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
    }
    result
}
#[tokio::test]
#[ignore = "run verify.sh byo-nats"]
async fn configuration_standalone() -> Result<()> {
    qualify(false, 1).await
}
#[tokio::test]
#[ignore = "run verify.sh byo-nats"]
async fn configuration_cluster() -> Result<()> {
    qualify(false, 3).await
}
#[tokio::test]
#[ignore = "run verify.sh byo-nats"]
async fn operator_jwt_standalone() -> Result<()> {
    qualify(true, 1).await
}
#[tokio::test]
#[ignore = "run verify.sh byo-nats"]
async fn operator_jwt_cluster() -> Result<()> {
    qualify(true, 3).await
}
