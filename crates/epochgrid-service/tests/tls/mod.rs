//! Real production-profile binaries, isolated CA material and operator-owned NATS.
use super::Process;
use anyhow::{Context, Result, ensure};
use epochgrid_core::{identity::IdentityStore, identity_model::AuthRegistry, tls::TlsConfig};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    time::Duration,
};

fn production(command: &mut Command, ca: Option<&Path>, first: bool) {
    command
        .env("EPOCHGRID_PROFILE", "production")
        .env("EPOCHGRID_TLS_MIN_VERSION", "1.3")
        .env("EPOCHGRID_TLS_FIRST", if first { "true" } else { "false" })
        .env_remove("EPOCHGRID_TLS_CA_PATH")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR");
    if let Some(path) = ca {
        command.env("EPOCHGRID_TLS_CA_PATH", path);
    }
}
async fn run(command: &mut Command, input: &[u8]) -> Result<Output> {
    let mut stdin = tempfile::tempfile()?;
    stdin.write_all(input)?;
    stdin.seek(SeekFrom::Start(0))?;
    let mut out = tempfile::tempfile()?;
    let mut err = tempfile::tempfile()?;
    let mut child = Process(
        command
            .stdin(stdin)
            .stdout(out.try_clone()?)
            .stderr(err.try_clone()?)
            .spawn()?,
    );
    let status = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(status) = child.0.try_wait()? {
                return Ok::<_, anyhow::Error>(status);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("TLS test subprocess timed out")??;
    out.seek(SeekFrom::Start(0))?;
    err.seek(SeekFrom::Start(0))?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    out.take(16384).read_to_end(&mut stdout)?;
    err.take(16384).read_to_end(&mut stderr)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}
async fn openssl(root: &Path, args: &[&str]) -> Result<()> {
    let output = run(Command::new("openssl").current_dir(root).args(args), &[]).await?;
    ensure!(
        output.status.success(),
        "certificate fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
async fn certificates(root: &Path) -> Result<()> {
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "2",
            "-subj",
            "/CN=EpochGrid Test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )
    .await?;
    openssl(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "wrong.key",
            "-out",
            "wrong.pem",
            "-days",
            "2",
            "-subj",
            "/CN=Unrelated CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )
    .await?;
    std::fs::write(
        root.join("extensions"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
    )?;
    for leaf in ["server", "rotated"] {
        openssl(
            root,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                &format!("{leaf}.key"),
                "-out",
                &format!("{leaf}.csr"),
                "-subj",
                "/CN=localhost",
            ],
        )
        .await?;
        openssl(
            root,
            &[
                "x509",
                "-req",
                "-in",
                &format!("{leaf}.csr"),
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                "extensions",
                "-out",
                &format!("{leaf}.pem"),
            ],
        )
        .await?;
    }
    Ok(())
}
fn cli(root: &Path, url: &str, name: &str, ca: Option<&Path>, first: bool) -> Command {
    let binary = Path::new(env!("CARGO_BIN_EXE_epochgrid-service")).with_file_name("epochgrid");
    let mut command = Command::new(binary);
    command
        .arg("--home")
        .arg(root.join(name))
        .args(["--server", url]);
    production(&mut command, ca, first);
    command
}
fn backend(root: &Path, url: &str, ca: Option<&Path>, first: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_epochgrid-service"));
    command
        .arg("--home")
        .arg(root.join("backend"))
        .args(["--server", url, "serve", "--auth-config"])
        .arg(root.join("backend/auth.json"));
    production(&mut command, ca, first);
    command
}
fn daemon(mut command: Command, log: &Path) -> Result<Process> {
    let log = File::options().create(true).append(true).open(log)?;
    Ok(Process(
        command.stdout(log.try_clone()?).stderr(log).spawn()?,
    ))
}
fn broker(root: &Path, port: u16, first: bool, leaf: &str) -> Result<Process> {
    let config = format!(
        "listen: 127.0.0.1:{port}\njetstream {{store_dir: \"{}\"}}\ntls {{cert_file: \"{}\",key_file: \"{}\",min_version: \"1.2\",handshake_first: {first}}}\n{}",
        root.join("js").display(),
        root.join(format!("{leaf}.pem")).display(),
        root.join(format!("{leaf}.key")).display(),
        std::fs::read_to_string(root.join("backend/nats-reference.conf"))?
    );
    std::fs::write(root.join("nats.conf"), config)?;
    let mut command = Command::new(std::env::var("NATS_SERVER")?);
    command.arg("-c").arg(root.join("nats.conf"));
    daemon(command, &root.join("nats.log"))
}
async fn ready(port: u16, process: &mut Process) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            ensure!(process.0.try_wait()?.is_none(), "TLS NATS process exited");
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("TLS listener did not start")?
}
fn success(output: Output) -> Result<()> {
    ensure!(
        output.status.success(),
        "production TLS command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
// A tiny TLS-1.2-only NATS greeting fixture checks negotiation, not just parsing
// the minimum-version option. Every socket and synchronization wait is bounded.
async fn minimum_version_probe(
    root: &Path,
    minimum: epochgrid_core::tls::MinimumVersion,
) -> Result<()> {
    use async_nats::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    };
    use std::io::{BufRead, BufReader};
    let certs = CertificateDer::pem_file_iter(root.join("server.pem"))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(root.join("server.key"))?;
    let server = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("tls://localhost:{}", listener.local_addr()?.port());
    let options = TlsConfig {
        ca_path: Some(root.join("ca.pem")),
        minimum,
        first: true,
        ..Default::default()
    }
    .apply(
        &url,
        async_nats::ConnectOptions::new().connection_timeout(Duration::from_secs(3)),
    )?;
    let (finish, done) = std::sync::mpsc::channel();
    let serving = tokio::task::spawn_blocking(move || -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(
                        std::time::Instant::now() < deadline,
                        "TLS version fixture accept deadline"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut connection = rustls::ServerConnection::new(std::sync::Arc::new(server))?;
        connection.complete_io(&mut socket)?;
        ensure!(
            connection.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_2),
            "unexpected negotiated TLS version"
        );
        let mut stream = rustls::StreamOwned::new(connection, socket);
        stream.write_all(b"INFO {\"server_id\":\"test\",\"server_name\":\"tls12-test\",\"version\":\"2.14.5\",\"host\":\"localhost\",\"port\":4222,\"max_payload\":65536,\"proto\":1,\"headers\":true}\r\n")?;
        stream.flush()?;
        let mut stream = BufReader::new(stream);
        for _ in 0..3 {
            let mut line = String::new();
            ensure!(stream.read_line(&mut line)? > 0, "TLS fixture EOF");
            if line == "PING\r\n" {
                stream.get_mut().write_all(b"PONG\r\n")?;
                stream.get_mut().flush()?;
                done.recv_timeout(Duration::from_secs(5))?;
                return Ok(());
            }
        }
        anyhow::bail!("TLS fixture did not receive PING")
    });
    let connected = options.connect(&url).await;
    let _ = finish.send(());
    let server_result = serving.await?;
    match minimum {
        epochgrid_core::tls::MinimumVersion::Tls12 => {
            connected?;
            server_result?;
        }
        epochgrid_core::tls::MinimumVersion::Tls13 => {
            ensure!(
                connected.is_err() && server_result.is_err(),
                "TLS 1.3 minimum accepted a TLS 1.2-only peer"
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires built binaries, openssl and nats-server; run via verify.sh nats"]
async fn production_tls_enrollment_negative_trust_and_certificate_rotation() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(120), workflow())
        .await
        .context("TLS workflow exceeded 120s")?
}
async fn workflow() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    certificates(root).await?;
    minimum_version_probe(root, epochgrid_core::tls::MinimumVersion::Tls13).await?;
    minimum_version_probe(root, epochgrid_core::tls::MinimumVersion::Tls12).await?;
    let ca = root.join("ca.pem");
    let wrong = root.join("wrong.pem");
    let mut init = Command::new(env!("CARGO_BIN_EXE_epochgrid-service"));
    production(&mut init, None, false);
    success(
        run(
            init.arg("--home")
                .arg(root.join("backend"))
                .arg("auth-init"),
            &[],
        )
        .await?,
    )?;
    let port = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let url = format!("tls://localhost:{port}");
    let mut nats = broker(root, port, false, "server")?;
    ready(port, &mut nats).await?;
    // Auth listener has exactly the same fail-closed profile as clients.
    for (endpoint, trust) in [
        (url.clone(), Some(wrong.as_path())),
        (format!("tls://127.0.0.1:{port}"), Some(ca.as_path())),
        (format!("nats://localhost:{port}"), None),
    ] {
        ensure!(
            !run(&mut backend(root, &endpoint, trust, false), &[])
                .await?
                .status
                .success(),
            "backend accepted invalid TLS configuration"
        );
    }
    let config_path = root.join("backend/auth.json");
    let original = std::fs::read(&config_path)?;
    let mut insecure: serde_json::Value = serde_json::from_slice(&original)?;
    insecure["development_plaintext"] = true.into();
    std::fs::write(&config_path, serde_json::to_vec(&insecure)?)?;
    let rejected = run(&mut backend(root, &url, Some(&ca), false), &[]).await?;
    ensure!(
        !rejected.status.success()
            && String::from_utf8_lossy(&rejected.stderr).contains("development_plaintext requires"),
        "production accepted the development plaintext setting"
    );
    std::fs::write(&config_path, original)?;
    let mut service = daemon(
        backend(root, &url, Some(&ca), false),
        &root.join("service.log"),
    )?;
    let mut registry = AuthRegistry::open(&root.join("backend"))?;
    let token = registry.invite("alice", 60)?;
    let mut enrolled = false;
    for _ in 0..3 {
        let output = run(
            cli(root, &url, "alice", Some(&ca), false).args(["identity", "enroll"]),
            token.as_bytes(),
        )
        .await?;
        if output.status.success() {
            enrolled = true;
            break;
        }
        ensure!(
            service.0.try_wait()?.is_none(),
            "TLS backend exited: {}",
            std::fs::read_to_string(root.join("service.log"))?
        );
    }
    ensure!(enrolled, "production TLS enrollment did not complete");
    success(
        run(
            cli(root, &url, "alice", Some(&ca), false).args(["identity", "register"]),
            &[],
        )
        .await?,
    )?;
    for (endpoint, trust) in [
        (url.clone(), None),
        (url.clone(), Some(wrong.as_path())),
        (format!("tls://127.0.0.1:{port}"), Some(ca.as_path())),
        (format!("nats://localhost:{port}"), None),
    ] {
        ensure!(
            !run(
                cli(root, &endpoint, "alice", trust, false).args(["identity", "register"]),
                &[]
            )
            .await?
            .status
            .success(),
            "client accepted invalid TLS configuration"
        );
    }
    let mut development_tls = cli(root, &url, "alice", Some(&wrong), false);
    development_tls
        .env("EPOCHGRID_PROFILE", "development")
        .args(["identity", "register"]);
    ensure!(
        !run(&mut development_tls, &[]).await?.status.success(),
        "development mode bypassed TLS trust checks"
    );
    // Verify native-root loading without changing host trust or global test env.
    let mut native = cli(root, &url, "alice", None, false);
    native
        .env("SSL_CERT_FILE", &ca)
        .env("SSL_CERT_DIR", root.join("empty-roots"))
        .args(["identity", "register"]);
    std::fs::create_dir(root.join("empty-roots"))?;
    success(run(&mut native, &[]).await?)?;
    // Explicit TLS 1.2 minimum still negotiates with a modern server.
    let mut compatible = cli(root, &url, "alice", Some(&ca), false);
    compatible
        .env("EPOCHGRID_TLS_MIN_VERSION", "1.2")
        .args(["identity", "register"]);
    success(run(&mut compatible, &[]).await?)?;
    // A retained connection must reconnect through TLS after leaf rotation.
    let identity = IdentityStore::open(&root.join("alice"))?;
    let key = identity.nkey()?;
    let options = TlsConfig {
        ca_path: Some(ca.clone()),
        ..Default::default()
    }
    .apply(
        &url,
        async_nats::ConnectOptions::with_nkey(key.seed()?)
            .custom_inbox_prefix(format!("_INBOX.{}", key.public_key()))
            .connection_timeout(Duration::from_secs(3))
            .request_timeout(Some(Duration::from_secs(3))),
    )?;
    let connected = options.connect(&url).await?;
    connected.flush().await?;
    drop(nats);
    nats = broker(root, port, false, "rotated")?;
    ready(port, &mut nats).await?;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if connected.flush().await.is_ok()
                && epochgrid_core::transport::register(&connected, identity.registration()?)
                    .await
                    .is_ok()
            {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("certificate rotation did not reconnect")??;
    drop(connected);
    drop(identity);
    success(
        run(
            cli(root, &url, "alice", Some(&ca), false).args(["identity", "register"]),
            &[],
        )
        .await?,
    )?;
    drop(service);
    drop(nats);
    // TLS-first protects INFO as well as credentials; both binaries use this mode.
    nats = broker(root, port, true, "rotated")?;
    ready(port, &mut nats).await?;
    service = daemon(
        backend(root, &url, Some(&ca), true),
        &root.join("service.log"),
    )?;
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let output = run(
                cli(root, &url, "alice", Some(&ca), true).args(["identity", "register"]),
                &[],
            )
            .await?;
            if output.status.success() {
                return Ok::<_, anyhow::Error>(());
            }
            ensure!(
                service.0.try_wait()?.is_none(),
                "TLS-first backend exited: {}",
                std::fs::read_to_string(root.join("service.log"))?
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .with_context(|| {
        format!(
            "TLS-first readiness failed: {}",
            std::fs::read_to_string(root.join("service.log")).unwrap_or_default()
        )
    })??;
    ensure!(service.0.try_wait()?.is_none());
    ensure!(
        !std::fs::read_to_string(root.join("nats.conf"))?.contains(
            &IdentityStore::open(&root.join("alice"))?
                .nkey()?
                .public_key()
        )
    );
    Ok(())
}
