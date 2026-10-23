//! Real separate-account worker fixture, enabled by the isolated BYO phase.
use super::{Process, tls};
use anyhow::{Context, Result, ensure};
use epochgrid_core::auth_callout::Config;
use std::{fs, os::unix::fs::PermissionsExt};
use std::{path::Path, process::Command, time::Duration};

pub(crate) struct Worker {
    public: tempfile::TempDir,
    process: Process,
    pid: String,
    generation: u64,
    pub tls_first: bool,
}

impl Worker {
    pub async fn setup(root: &Path, url: &str) -> Result<Self> {
        let public = tempfile::Builder::new()
            .prefix("epochgrid-roles-")
            .tempdir()?;
        fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755))?;
        fs::copy(root.join("ca.pem"), public.path().join("ca.pem"))?;
        fs::set_permissions(
            public.path().join("ca.pem"),
            fs::Permissions::from_mode(0o644),
        )?;
        let config = Config::load(&root.join("backend/auth.json"))?;
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("backend/credentials.json"))?)?;
        let mut references = vec![config.issuer.id, config.encryption.id, config.connection.id];
        for slot in metadata["slots"]
            .as_object()
            .context("credential slots")?
            .values()
        {
            references.push(slot["id"].as_str().context("credential ID")?.to_owned());
        }
        fs::write(
            public.path().join("probe.json"),
            serde_json::to_vec(&serde_json::json!({
                "authority_home":root.join("backend"),
                "authority_bus":std::env::var("DBUS_SESSION_BUS_ADDRESS")?,
                "references":references,
            }))?,
        )?;
        fs::set_permissions(
            public.path().join("probe.json"),
            fs::Permissions::from_mode(0o644),
        )?;
        // The checkout (and any ancestor) may be private to the test runner.
        // Stage only public executable code; never relax checkout/home permissions
        // or copy authority state into this cross-UID exchange.
        let runtime = public.path().join("runtime");
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o755))?;
        let examples = runtime.join("examples");
        fs::create_dir(&examples)?;
        fs::set_permissions(&examples, fs::Permissions::from_mode(0o755))?;
        let binary = Path::new(env!("CARGO_BIN_EXE_epochgrid-service"));
        let scripts = std::env::current_dir()?.join("scripts/dev");
        for (source, destination) in [
            (binary.to_path_buf(), runtime.join("epochgrid-service")),
            (
                binary
                    .parent()
                    .context("service binary directory")?
                    .join("examples/backend-role-probe"),
                examples.join("backend-role-probe"),
            ),
            (
                scripts.join("role-worker-fixture.py"),
                runtime.join("role-worker-fixture.py"),
            ),
            (
                scripts.join("with-test-keyring.sh"),
                runtime.join("with-test-keyring.sh"),
            ),
        ] {
            fs::copy(&source, &destination)
                .with_context(|| format!("stage role fixture executable {}", source.display()))?;
            fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
        }
        let helper = runtime.join("role-worker-fixture.py");
        let log = public.path().join("worker.log");
        let mut command = Command::new("sudo");
        command
            .current_dir(&runtime)
            .args(["-n", "-u", "nobody", "--", "python3"])
            .arg(helper)
            .arg("launch")
            .arg("--exchange")
            .arg(public.path())
            .arg("--binary")
            .arg(runtime.join("epochgrid-service"))
            .arg("--url")
            .arg(url);
        let mut process = tls::daemon(command, &log)?;
        let (pid, key) = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                ensure!(
                    process.0.try_wait()?.is_none(),
                    "separate worker setup failed: {}",
                    fs::read_to_string(&log)?
                );
                let output = fs::read_to_string(&log)?;
                let value = |prefix: &str| {
                    output
                        .lines()
                        .find_map(|line| line.strip_prefix(prefix))
                        .map(str::to_owned)
                };
                if let (Some(pid), Some(key)) = (value("WORKER_PID="), value("WORKER_NKEY=")) {
                    return Ok::<_, anyhow::Error>((pid, key));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("separate worker setup deadline")??;
        let mut worker = Self {
            public,
            process,
            pid,
            generation: 0,
            tls_first: false,
        };
        let original = ["auth.json", "credentials.json", "control/credentials.json"]
            .map(|name| fs::read(root.join("backend").join(name)))
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()?;
        let binding_command = || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_epochgrid-service"));
            command
                .arg("--home")
                .arg(root.join("backend"))
                .arg("role-bind")
                .args(["--worker-uid", "65534", "--worker-nkey", &key, "--socket"])
                .arg(worker.public.path().join("control.sock"));
            command
        };
        let result = tls::run(&mut binding_command(), &[]).await?;
        ensure!(
            result.status.success(),
            "role binding failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        // Resume after the permission artifact was committed but binding was lost.
        fs::remove_file(root.join("backend/backend-roles.json"))?;
        let retry = tls::run(&mut binding_command(), &[]).await?;
        ensure!(
            retry.status.success() && retry.stdout == result.stdout,
            "role setup retry changed identity"
        );
        let permissions = root.join("backend/runtime-permissions.json");
        let saved = fs::read(&permissions)?;
        fs::write(&permissions, b"edited by operator")?;
        let rejected = tls::run(&mut binding_command(), &[]).await?;
        ensure!(
            !rejected.status.success() && fs::read(&permissions)? == b"edited by operator",
            "role export overwrote edits"
        );
        fs::write(&permissions, saved)?;
        for (name, before) in ["auth.json", "credentials.json", "control/credentials.json"]
            .into_iter()
            .zip(original)
        {
            ensure!(
                fs::read(root.join("backend").join(name))? == before,
                "role transition changed established identity/configuration"
            );
        }
        let bindings: serde_json::Value = serde_json::from_slice(&result.stdout)?;
        fs::write(
            worker.public.path().join("bindings.json"),
            serde_json::to_vec(&bindings)?,
        )?;
        fs::set_permissions(
            worker.public.path().join("bindings.json"),
            fs::Permissions::from_mode(0o644),
        )?;
        worker.set_running(false)?;
        Ok(worker)
    }

    pub fn set_running(&mut self, running: bool) -> Result<()> {
        self.generation += 1;
        let staged = self.public.path().join("command.next");
        fs::write(
            &staged,
            serde_json::to_vec(
                &serde_json::json!({"generation":self.generation,"running":running,"tls_first":self.tls_first}),
            )?,
        )?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o644))?;
        fs::rename(staged, self.public.path().join("command.json"))?;
        Ok(())
    }

    pub async fn start(&mut self) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // The authority must finish recovery before the fixture starts its worker.
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let ready = tokio::time::timeout(Duration::from_secs(1), async {
                    let mut stream = tokio::net::UnixStream::connect(
                        self.public.path().join("control.sock.status"),
                    )
                    .await?;
                    let request =
                        br#"{"version":1,"sequence":0,"operation":{"operation":"inspect"}}"#;
                    stream.write_u32(request.len() as u32).await?;
                    stream.write_all(request).await?;
                    let size = stream.read_u32().await? as usize;
                    ensure!(size <= 4096, "oversized status");
                    let mut bytes = vec![0; size];
                    stream.read_exact(&mut bytes).await?;
                    let status: serde_json::Value = serde_json::from_slice(&bytes)?;
                    Ok::<_, anyhow::Error>(status["operation"]["reconciled"] == true)
                })
                .await;
                if matches!(ready, Ok(Ok(true))) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("authority reconciliation deadline")?;
        // Even the authority account cannot impersonate the configured worker UID.
        let mut impostor =
            tokio::net::UnixStream::connect(self.public.path().join("control.sock")).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), impostor.read_u8())
                .await?
                .is_err(),
            "wrong-UID worker accepted"
        );
        let log = self.public.path().join("worker.log");
        let previous = fs::read_to_string(&log)?
            .matches("WORKER_VALIDATED=passed")
            .count();
        self.set_running(true)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                ensure!(
                    self.process.0.try_wait()?.is_none(),
                    "worker supervisor exited: {}",
                    fs::read_to_string(&log)?
                );
                let output = fs::read_to_string(&log)?;
                if output.matches("WORKER_VALIDATED=passed").count() > previous {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .with_context(|| {
            format!(
                "worker readiness deadline: {}",
                fs::read_to_string(log).unwrap_or_default()
            )
        })?
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.set_running(false)?;
        tokio::time::timeout(Duration::from_secs(6), async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            loop {
                let mut stream =
                    tokio::net::UnixStream::connect(self.public.path().join("control.sock.status"))
                        .await?;
                let request = br#"{"version":1,"sequence":0,"operation":{"operation":"inspect"}}"#;
                stream.write_u32(request.len() as u32).await?;
                stream.write_all(request).await?;
                let size = stream.read_u32().await? as usize;
                ensure!(size <= 4096, "oversized role status");
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await?;
                let status: serde_json::Value = serde_json::from_slice(&bytes)?;
                if status["operation"]["worker_live"] == false {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("worker loss did not close readiness within lease")?
    }

    pub async fn check_authority_permissions(root: &Path, url: &str) -> Result<()> {
        let probe = Path::new(env!("CARGO_BIN_EXE_epochgrid-service"))
            .parent()
            .unwrap()
            .join("examples/backend-role-probe");
        tls::success(
            tls::run(
                Command::new(probe)
                    .env("EPOCHGRID_PROFILE", "production")
                    .env("EPOCHGRID_TLS_CA_PATH", root.join("ca.pem"))
                    .args(["--disposable-fixture", "authority"])
                    .arg(root.join("backend"))
                    .arg(url),
                &[],
            )
            .await?,
        )
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Terminate only the dedicated process group announced by the helper.
        if self.pid.parse::<u32>().is_ok_and(|pid| pid > 1) {
            let _ = Command::new("sudo")
                .args([
                    "-n",
                    "-u",
                    "nobody",
                    "--",
                    "kill",
                    "-TERM",
                    "--",
                    &format!("-{}", self.pid),
                ])
                .status();
        }
    }
}
