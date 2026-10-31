//! Operator-owned fixtures: production TLS, both auth modes, R1 and R3.
use super::{Process, tls};
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    auth_callout::Config, identity::IdentityStore, identity_model::AuthRegistry, tls::TlsConfig,
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
    connect_monitored(
        root,
        url,
        key,
        jwt,
        &epochgrid_core::validation::PermissionMonitor::default(),
    )
    .await
}
async fn connect_monitored(
    root: &Path,
    url: &str,
    key: &KeyPair,
    jwt: Option<&str>,
    monitor: &epochgrid_core::validation::PermissionMonitor,
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
    .apply(url, monitor.configure(options))?
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

async fn validate_offline(root: &Path, endpoint: &str, expected_success: bool) -> Result<()> {
    let result = tls::run(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .env("EPOCHGRID_TLS_CA_PATH", root.join("ca.pem"))
            .arg("--home")
            .arg(root.join("backend"))
            .arg("--server")
            .arg(endpoint)
            .arg("validate")
            .arg("--auth-config")
            .arg(root.join("backend/auth.json"))
            .args(["--offline", "--format", "json"]),
        &[],
    )
    .await?;
    let report = epochgrid_core::validation::Report::parse(&result.stdout)?;
    ensure!(
        report.success == expected_success && result.status.success() == expected_success,
        "offline validation result mismatch: {}",
        report.human()
    );
    ensure!(
        report
            .checks
            .iter()
            .any(|check| check.id == "coverage.network"
                && check.status == epochgrid_core::validation::Status::NotChecked),
        "offline report overstates network coverage"
    );
    Ok(())
}

async fn validate_online(
    root: &Path,
    endpoints: &[String],
    expected_success: bool,
    code: Option<&str>,
) -> Result<()> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_epochgrid-service"));
    command
        .env("EPOCHGRID_TLS_CA_PATH", root.join("ca.pem"))
        .arg("--home")
        .arg(root.join("backend"))
        .arg("validate")
        .arg("--auth-config")
        .arg(root.join("backend/auth.json"))
        .args(["--online", "--format", "json"]);
    for endpoint in endpoints {
        command.arg("--endpoint").arg(endpoint);
    }
    let result = tls::run(&mut command, &[]).await?;
    let report = epochgrid_core::validation::Report::parse(&result.stdout)?;
    ensure!(
        report.mode == "online"
            && report.success == expected_success
            && result.status.success() == expected_success,
        "online result mismatch: {}",
        report.human()
    );
    if let Some(code) = code {
        ensure!(
            report.checks.iter().any(|c| c.observed["code"] == code),
            "missing {code}: {}",
            report.human()
        );
    }
    Ok(())
}

async fn rejected_startup(root: &Path, url: &str, code: &str) -> Result<()> {
    let result = tls::run(
        &mut tls::backend(root, url, Some(&root.join("ca.pem")), false),
        &[],
    )
    .await?;
    ensure!(
        !result.status.success() && String::from_utf8_lossy(&result.stderr).contains(code),
        "startup should reject {code}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    denied_admission(root, url, Some(&KeyPair::new_user())).await?;
    Ok(())
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
    let auth = KeyPair::new_account();
    let app = KeyPair::new_account();
    let mut init = Command::new(env!("CARGO_BIN_EXE_epochgrid-service"));
    init.arg("--home")
        .arg(root.join("backend"))
        .arg("auth-init")
        .arg("--auth-mode")
        .arg(if operator_mode {
            "operator-jwt"
        } else {
            "configuration"
        })
        .arg("--target-account")
        .arg(if operator_mode {
            app.public_key()
        } else {
            "EPOCHGRID".into()
        })
        .arg("--replicas")
        .arg(nodes.to_string());
    if operator_mode {
        init.arg("--auth-account").arg(auth.public_key());
    }
    tls::success(tls::run(&mut init, &[]).await?)?;
    let path = root.join("backend/auth.json");
    let artifacts = root.join("backend/deployment-artifacts");
    let mut config = Config::load_for_export(&path)?;
    let manifest = epochgrid_core::deployment::DeploymentManifest::load(&root.join("backend"))?;
    ensure!(
        manifest.replicas() == nodes,
        "explicit initialization replicas lost"
    );
    if operator_mode {
        ensure!(
            Config::load(&path).is_err(),
            "pending JWT must reject runtime loading"
        );
        ensure!(
            !artifacts.join("nats-reference.conf").exists(),
            "operator initialization must not fall back"
        );
    }
    let admin_key = KeyPair::new_user();
    let other_key = KeyPair::new_user();
    let mut admin_jwt = None;
    let mut other_jwt = None;
    let operator_config;
    if operator_mode {
        let operator = KeyPair::new_operator();
        let sys = KeyPair::new_account();
        let other = KeyPair::new_account();
        let mut op = Operator::new_claims("qualification".into(), operator.public_key());
        op.nats.generic_fields.version = 2;
        op.nats.system_account = Some(sys.public_key());
        let mut auth_claim = account(&auth);
        let delegation: serde_json::Value =
            serde_json::from_slice(&std::fs::read(artifacts.join("operator-delegation.json"))?)?;
        ensure!(
            delegation["authentication_account"] == auth.public_key()
                && delegation["application_account"] == app.public_key(),
            "delegation account mismatch"
        );
        auth_claim.nats.authorization = Some(serde_json::from_value(
            delegation["external_authorization"].clone(),
        )?);
        let mut app_claim = account(&app);
        app_claim.nats.signing_keys = Some(
            serde_json::from_value::<Vec<String>>(delegation["application_signing_keys"].clone())?
                .into_iter()
                .map(|key| nats_jwt_rs::types::SigningKey { key, scope: None })
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
        ensure!(
            delegation["service_user"]["subject"] == config.connection.public_key
                && delegation["service_user"]["bearer_token"] == false,
            "invalid service signing request"
        );
        auth_user.nats.permissions.permissions.subscribe.allow =
            serde_json::from_value(delegation["service_user"]["subscribe"].clone())?;
        auth_user.nats.permissions.permissions.publish.allow =
            serde_json::from_value(delegation["service_user"]["publish"].clone())?;
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
        // Integrate the generated snippet; only the fixture's administrator and
        // unrelated account are operator additions.
        let snippet = std::fs::read_to_string(artifacts.join("nats-reference.conf"))?;
        operator_config = snippet
            .replace(
                "\"EPOCHGRID\" { jetstream: enabled }",
                &format!(
                    "\"EPOCHGRID\" {{ jetstream: enabled, users: [{{nkey: \"{}\"}}] }}",
                    admin_key.public_key()
                ),
            )
            .replace(
                "accounts {",
                &format!(
                    "accounts {{ OTHER {{ users: [{{nkey: \"{}\"}}] }}",
                    other_key.public_key()
                ),
            )
            .replace(
                &format!("auth_users: [\"{}\"]", config.connection.public_key),
                &format!(
                    "auth_users: [\"{}\", \"{}\", \"{}\"]",
                    config.connection.public_key,
                    admin_key.public_key(),
                    other_key.public_key()
                ),
            );
    }
    Config::load(&path)?;
    let auth_before_export = std::fs::read(&path)?;
    tls::success(
        tls::run(
            Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
                .arg("--home")
                .arg(root.join("backend"))
                .arg("deployment-export")
                .arg("--auth-config")
                .arg(&path),
            &[],
        )
        .await?,
    )?;
    ensure!(
        std::fs::read(&path)? == auth_before_export,
        "export changed auth configuration"
    );
    validate_offline(root, "tls://localhost:1", true).await?;
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
    // Operator pre-provisions the generated native stream specifications.
    let js = async_nats::jetstream::new(admin.clone());
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if js.query_account().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("JetStream account readiness")?;
    // The auth-account credential can connect but cannot inspect application resources.
    // This must report permission denial, rather than turn a successful INFO into a pass.
    let monitor = epochgrid_core::validation::PermissionMonitor::default();
    let limited = connect_monitored(
        root,
        &urls[0],
        &KeyPair::from_seed(&config.connection.read()?)?,
        config
            .operator_jwt
            .as_ref()
            .map(|o| o.connection_jwt.as_str()),
        &monitor,
    )
    .await?;
    let denied = epochgrid_core::validation::inspect_resources(&limited, &manifest, &monitor).await;
    ensure!(
        !denied.success
            && denied
                .checks
                .iter()
                .any(|c| c.observed["code"] == "permission_denied"),
        "inspection permission denial was not classified: {}",
        denied.human()
    );
    drop(limited);
    let mut resource_configs = Vec::new();
    for name in STREAMS {
        let resource: async_nats::jetstream::stream::Config =
            serde_json::from_slice(&std::fs::read(artifacts.join(format!("{name}.json")))?)?;
        ensure!(
            resource.num_replicas == nodes,
            "generated replication mismatch"
        );
        js.create_stream(resource).await?;
        let observed = js.get_stream(name).await?.info().await?.config.clone();
        ensure!(
            manifest.compare(name, &observed)?.is_empty(),
            "generated resource differs from contract: {name}"
        );
        if let Some(bucket) = name.strip_prefix("KV_") {
            let store = js.get_key_value(bucket).await?;
            ensure!(
                store.status().await?.history() == 1,
                "generated KV history mismatch"
            );
        }
        resource_configs.push((name, observed));
    }
    let mut worker = crate::role_fixture::Worker::setup(root, &urls[0]).await?;
    validate_online(root, &urls[..1], false, None).await?;
    // Startup cannot create missing resources or alter incompatible operator settings.
    js.delete_stream("MAILBOX").await?;
    rejected_startup(root, &urls[0], "resource_missing").await?;
    ensure!(
        js.get_stream("MAILBOX").await.is_err(),
        "startup created missing stream"
    );
    js.create_stream(
        resource_configs
            .iter()
            .find(|(name, _)| *name == "MAILBOX")
            .unwrap()
            .1
            .clone(),
    )
    .await?;
    let mut altered = resource_configs[0].1.clone();
    altered.subjects = vec!["operator.unrelated.>".into()];
    js.update_stream(altered.clone()).await?;
    rejected_startup(root, &urls[0], "resource_incompatible").await?;
    ensure!(
        js.get_stream("CHAT").await?.info().await?.config == altered,
        "startup changed operator configuration"
    );
    js.update_stream(resource_configs[0].1.clone()).await?;
    let mut service = tls::daemon(
        tls::backend(root, &urls[0], Some(&root.join("ca.pem")), false),
        &root.join("service.log"),
    )?;
    backend_ready(root, &mut service).await?;
    diagnostic_status(root, 1).await?;
    worker.start().await?;
    let original_status = diagnostic_status(root, 0).await?;
    let observed_capacity = original_status
        .observations
        .as_ref()
        .and_then(|o| o.capacity.as_ref())
        .context("authority capacity observation missing")?;
    ensure!(
        observed_capacity.availability == epochgrid_core::diagnostics::Availability::Current
            && observed_capacity
                .usage
                .as_ref()
                .is_some_and(|u| u.database_bytes.used > 0),
        "capacity usage was not collected"
    );
    eprintln!(
        "diagnostic capacity collection_ms={:?}",
        observed_capacity.collection_ms
    );
    let original_instance = original_status.instance;
    crate::role_fixture::Worker::check_authority_permissions(root, &urls[0]).await?;
    validate_offline(root, &urls[0], true).await?;
    validate_online(root, &urls, true, None).await?;
    validate_online(
        root,
        &[urls[0].replace("localhost", "127.0.0.1")],
        false,
        None,
    )
    .await?;
    validate_online(
        root,
        &["tls://localhost:1".into()],
        false,
        Some("endpoint_unavailable"),
    )
    .await?;
    for (name, field) in [
        ("CHAT", "subjects"),
        ("MAILBOX", "retention"),
        ("KV_CHANNELS", "history"),
    ] {
        let original = resource_configs
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1
            .clone();
        let mut altered = original.clone();
        match field {
            "subjects" => altered.subjects = vec!["operator.altered.>".into()],
            "retention" => {
                altered.retention = async_nats::jetstream::stream::RetentionPolicy::Interest
            }
            _ => altered.max_messages_per_subject = 2,
        }
        js.update_stream(altered.clone()).await?;
        validate_online(root, &urls[..1], false, Some("resource_incompatible")).await?;
        ensure!(
            service.0.try_wait()?.is_none(),
            "online failure stopped backend"
        );
        ensure!(
            js.get_stream(name).await?.info().await?.config == altered,
            "validation changed resource"
        );
        js.update_stream(original).await?;
    }
    // Declared replica expectations must not silently degrade to the observed topology.
    let manifest_bytes = std::fs::read(root.join("backend/deployment.json"))?;
    std::fs::write(
        root.join("backend/deployment.json"),
        serde_json::to_vec(&epochgrid_core::deployment::DeploymentManifest::new(
            if nodes == 1 { 3 } else { 1 },
        )?)?,
    )?;
    validate_online(root, &urls[..1], false, Some("resource_incompatible")).await?;
    std::fs::write(root.join("backend/deployment.json"), manifest_bytes)?;
    let manifest_path = root.join("backend/deployment.json");
    let saved_manifest = root.join("backend/deployment.saved");
    std::fs::rename(&manifest_path, &saved_manifest)?;
    validate_offline(root, &urls[0], false).await?;
    ensure!(
        service.0.try_wait()?.is_none(),
        "validation failure stopped the backend"
    );
    std::fs::rename(saved_manifest, manifest_path)?;
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
    // Saturate the real separate-UID forwarding worker. Lost/rejected requests
    // are not accepted mutations, and heartbeat/reconciliation remain bounded.
    let rss_before = std::fs::read_to_string(format!("/proc/{}/status", service.0.id()))?
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap_or("VmRSS unavailable")
        .to_owned();
    let overload_inbox = admin.new_inbox();
    let mut overload_replies = admin.subscribe(overload_inbox.clone()).await?;
    let audit = epochgrid_core::wire::encode(epochgrid_core::wire::Body::RegistrationAudit)?;
    for _ in 0..512 {
        admin
            .publish_with_reply(
                epochgrid_core::wire::AUDIT,
                overload_inbox.clone(),
                audit.clone().into(),
            )
            .await?;
    }
    admin.flush().await?;
    let mut replies = 0;
    let mut rejected = 0;
    let drain = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(drain);
    loop {
        use futures_util::StreamExt;
        tokio::select! {
            _ = &mut drain => break,
            message = overload_replies.next() => {
                let Some(message) = message else { break };
                replies += 1;
                if matches!(epochgrid_core::wire::decode(&message.payload)?, epochgrid_core::wire::Body::Rejected) { rejected += 1; }
            }
        }
    }
    ensure!(
        replies < 512 || rejected > 0,
        "saturation did not exercise a bounded rejection/loss boundary"
    );
    let rss_after = std::fs::read_to_string(format!("/proc/{}/status", service.0.id()))?
        .lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap_or("VmRSS unavailable")
        .to_owned();
    eprintln!(
        "capacity flood: responses={replies}, rejected={rejected}; authority {rss_before} -> {rss_after}"
    );
    validate_online(root, &urls[..1], true, None).await?;

    // Operator-owned quota exhaustion must preserve accepted history and pending MLS intent.
    let chat_config = js.get_stream("CHAT").await?.info().await?.config.clone();
    let before = js.get_stream("CHAT").await?.info().await?.state.clone();
    let mut full = chat_config.clone();
    full.max_bytes = before.bytes as i64 + 1;
    js.update_stream(full).await?;
    IdentityStore::open(&root.join("alice"))?
        .encrypt_message("engineering", b"retained across broker quota")?;
    let rejected = tls::run(
        tls::cli(root, &urls[0], "alice", Some(&root.join("ca.pem")), false)
            .args(["channel", "flush"]),
        &[],
    )
    .await?;
    ensure!(
        !rejected.status.success(),
        "full broker accepted new publish"
    );
    let after = js.get_stream("CHAT").await?.info().await?.state.clone();
    ensure!(
        after.messages == before.messages && after.first_sequence == before.first_sequence,
        "quota exhaustion evicted accepted history"
    );
    diagnostic_status(root, 0).await?;
    contains(root, "alice", b"retained across broker quota")?;
    validate_online(root, &urls[..1], false, Some("resource_incompatible")).await?;
    // Only the fixture's operator credential restores the declared capacity.
    js.update_stream(chat_config).await?;
    command(root, &urls[0], "alice", &["channel", "flush"], &[]).await?;
    sync(root, &urls[0], "bob").await?;
    diagnostic_status(root, 0).await?;
    contains(root, "bob", b"retained across broker quota")?;
    contains(root, "bob", b"before broker loss")?;
    validate_online(root, &urls[..1], true, None).await?;

    // Native R3 KV replacement needs incoming-record headroom before releasing the old value.
    let kv = js.get_key_value("TRANSPARENCY").await?;
    let current = kv.entry("snapshot").await?.context("snapshot missing")?;
    let mut kv_stream = js.get_stream("KV_TRANSPARENCY").await?;
    let kv_info = kv_stream.info().await?.clone();
    let mut bounded_kv = kv_info.config.clone();
    bounded_kv.max_bytes = kv_info.state.bytes as i64 + 256;
    js.update_stream(bounded_kv).await?;
    let replacement = kv
        .update("snapshot", current.value.clone(), current.revision)
        .await;
    if nodes == 1 {
        replacement.context("standalone history-one replacement")?;
    } else {
        let error = replacement
            .expect_err("R3 replacement unexpectedly fit without incoming-record headroom");
        ensure!(
            error.to_string().contains("maximum bytes exceeded"),
            "unexpected R3 KV failure: {error}"
        );
        ensure!(
            kv.entry("snapshot")
                .await?
                .context("retained snapshot missing")?
                .revision
                == current.revision,
            "rejected R3 replacement changed the committed revision"
        );
    }
    ensure!(
        kv.put("capacity-probe", vec![0u8; 65536].into())
            .await
            .is_err(),
        "KV quota ignored"
    );
    ensure!(
        kv.get("snapshot").await?.as_ref() == Some(&current.value),
        "KV replacement lost snapshot"
    );
    js.update_stream(kv_info.config).await?;
    let retained = kv
        .entry("snapshot")
        .await?
        .context("retained snapshot missing")?;
    kv.update("snapshot", retained.value.clone(), retained.revision)
        .await
        .context("KV replacement after operator capacity increase")?;
    ensure!(
        kv.status().await?.history() == 1,
        "capacity change altered native KV history"
    );

    // A new retained registration cannot fit the constrained transparency
    // snapshot. Preserve the committed registry intent while admission is closed,
    // then recover the same home after an explicit operator capacity increase.
    let mut pending_stream = js.get_stream("KV_TRANSPARENCY").await?;
    let pending_info = pending_stream.info().await?.clone();
    let mut constrained = pending_info.config.clone();
    constrained.max_bytes = pending_info.state.bytes as i64 + 128;
    js.update_stream(constrained).await?;
    let token = AuthRegistry::open(&root.join("backend"))?.invite("diagnostic-device", 120)?;
    let rejected = tls::run(
        tls::cli(
            root,
            &urls[0],
            "diagnostic-device",
            Some(&root.join("ca.pem")),
            false,
        )
        .args(["identity", "enroll"]),
        token.as_bytes(),
    )
    .await?;
    ensure!(
        !rejected.status.success(),
        "quota-blocked enrollment unexpectedly succeeded"
    );
    let pending = diagnostic_status(root, 1).await?;
    ensure!(
        pending
            .reasons
            .contains(&epochgrid_core::diagnostics::Reason::ReconciliationPending),
        "missing pending-reconciliation reason"
    );
    ensure!(
        pending
            .observations
            .as_ref()
            .is_some_and(|o| o.reconciliation_failure > 0),
        "repair failure was not observed"
    );
    js.update_stream(pending_info.config).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let output = tls::run(
                Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
                    .arg("--home")
                    .arg(root.join("backend"))
                    .args(["status", "--role", "authority", "--format", "json"]),
                &[],
            )
            .await?;
            if output.status.success() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("quota recovery did not reopen admission")??;
    let restored = diagnostic_status(root, 0).await?;
    ensure!(
        restored.instance == original_instance,
        "quota recovery replaced authority state"
    );
    let retained = IdentityStore::open(&root.join("diagnostic-device"))?.registration()?;
    AuthRegistry::open(&root.join("backend"))?.authorize(&retained.payload.nats_public_key)?;

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
    worker.stop().await?;
    let stopped = diagnostic_status(root, 1).await?;
    ensure!(
        stopped
            .observations
            .as_ref()
            .is_some_and(|o| !o.worker_live),
        "worker loss diagnostics"
    );
    validate_online(root, &urls[..1], false, Some("role_not_ready")).await?;
    denied_admission(root, &urls[0], Some(&alice_key)).await?;
    ensure!(
        service.0.try_wait()?.is_none(),
        "worker loss stopped authority"
    );
    worker.start().await?;
    diagnostic_status(root, 0).await?;
    validate_online(root, &urls[..1], true, None).await?;
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
    worker.set_running(false)?;
    diagnostic_status(root, 2).await?;
    // An available broker with no Auth Callout service must reject fresh admission.
    denied_admission(root, &urls[survivor], Some(&alice_key))
        .await
        .context("Auth Callout outage")?;
    let manifest_path = root.join("backend/deployment.json");
    let saved_manifest = std::fs::read(&manifest_path)?;
    std::fs::remove_file(&manifest_path)?;
    rejected_startup(root, &urls[survivor], "state_missing").await?;
    denied_admission(root, &urls[survivor], Some(&alice_key)).await?;
    std::fs::write(&manifest_path, saved_manifest)?;
    std::fs::write(root.join("service.log"), "")?;
    service = tls::daemon(
        tls::backend(root, &urls[survivor], Some(&root.join("ca.pem")), false),
        &root.join("service.log"),
    )?;
    backend_ready(root, &mut service).await?;
    diagnostic_status(root, 1).await?;
    worker.start().await?;
    let restarted = diagnostic_status(root, 0).await?;
    ensure!(
        restarted.instance != original_instance,
        "diagnostic instance survived restart"
    );
    validate_offline(root, &urls[0], true).await?;
    validate_online(root, &urls, true, None).await?;
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

/// No endpoint, keyring, or database needed for the local operational snapshot.
async fn diagnostic_status(
    root: &Path,
    expected: i32,
) -> Result<epochgrid_core::diagnostics::Report> {
    use epochgrid_core::diagnostics::{Report, Role};
    let result = tls::run(
        Command::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/PRIVATE_MARKER",
            )
            .env("EPOCHGRID_NATS_URL", "PRIVATE_MARKER")
            .arg("--home")
            .arg(root.join("backend"))
            .args(["status", "--role", "authority", "--format", "json"]),
        &[],
    )
    .await?;
    ensure!(
        result.status.code() == Some(expected),
        "unexpected diagnostic exit: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    ensure!(result.stderr.is_empty(), "diagnostic stderr must be empty");
    let report = Report::parse(&result.stdout, Role::Authority)?;
    ensure!(
        !String::from_utf8_lossy(&result.stdout).contains("PRIVATE_MARKER"),
        "diagnostic disclosure"
    );
    Ok(report)
}
