//! Linux role bindings and bounded, peer-authenticated local control transport.
use anyhow::{Context, Result, ensure};
use epochgrid_core::{
    secrets::{Kind, SecretRef, Vault},
    transport, wire,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
};

const VERSION: u16 = 1;
const LIMIT: usize = 512 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);
pub const BINDINGS: &str = "backend-roles.json";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
    pub version: u16,
    pub authority_uid: u32,
    pub worker_uid: u32,
    pub worker_nkey: String,
    pub socket: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerConfig {
    version: u16,
    connection: SecretRef,
    bindings: Bindings,
}

fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

fn owned(path: &Path, owner: u32, private: bool) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() || meta.is_dir(),
        "role path must be a regular file or directory"
    );
    ensure!(
        !meta.file_type().is_symlink() && meta.uid() == owner,
        "role path ownership mismatch"
    );
    ensure!(
        meta.mode() & if private { 0o077 } else { 0o022 } == 0,
        "unsafe role path permissions"
    );
    Ok(())
}

pub fn runtime_lock(home: &Path) -> Result<File> {
    owned(home, uid(), true)?;
    let path = home.join("runtime.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&path)?;
    owned(&path, uid(), true)?;
    ensure!(
        file.metadata()?.is_file(),
        "runtime lock must be a regular file"
    );
    file.try_lock()
        .context("backend runtime is active; stop it before changing role bindings")?;
    Ok(file)
}

impl Bindings {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && self.authority_uid != self.worker_uid,
            "distinct authority and worker accounts required"
        );
        ensure!(
            self.authority_uid != 0 && self.worker_uid != 0,
            "runtime roles must not run as root"
        );
        ensure!(
            self.socket.is_absolute() && self.socket.as_os_str().len() < 100,
            "absolute short Unix socket path required"
        );
        ensure!(
            nkeys::KeyPair::from_public_key(&self.worker_nkey)?.key_pair_type()
                == nkeys::KeyPairType::User,
            "invalid worker public key"
        );
        Ok(())
    }
    pub fn load(home: &Path) -> Result<Self> {
        let path = home.join(BINDINGS);
        owned(home, uid(), true)?;
        owned(&path, uid(), true)?;
        let value: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        value.validate()?;
        ensure!(value.authority_uid == uid(), "authority account required");
        Ok(value)
    }
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output parent required")?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|_| anyhow::anyhow!("output exists; refusing replacement"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Run under the worker's own unlocked keyring session. Only a public NKey is printed.
pub fn worker_init(home: &Path) -> Result<()> {
    ensure!(uid() != 0, "worker must not run as root");
    let reference = Vault::new(home).provision("worker", Kind::User)?;
    println!("{}", reference.public_key);
    Ok(())
}

/// Explicit stopped-service transition; never opens/replaces databases or signing keys.
pub fn bind(
    home: &Path,
    auth_config: &Path,
    worker_uid: u32,
    worker_nkey: String,
    socket: PathBuf,
) -> Result<()> {
    owned(home, uid(), true)?;
    let bindings = Bindings {
        version: VERSION,
        authority_uid: uid(),
        worker_uid,
        worker_nkey,
        socket,
    };
    bindings.validate()?;
    let _runtime = runtime_lock(home)?;
    owned(auth_config, uid(), true)?;
    ensure!(
        auth_config
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .canonicalize()?
            == home.canonicalize()?,
        "auth configuration must reside in authority home"
    );
    let config = epochgrid_core::auth_callout::Config::load(auth_config)?;
    ensure!(
        bindings.worker_nkey != config.control_nkey
            && bindings.worker_nkey != config.connection.public_key,
        "worker must have an independent connection identity"
    );
    let bytes = serde_json::to_vec_pretty(&bindings)?;
    let path = home.join(BINDINGS);
    let bound = path.exists();
    if bound {
        owned(&path, uid(), true)?;
        ensure!(
            std::fs::read(&path)? == bytes,
            "role binding already exists with different choices"
        );
    }
    // Public capability artifact is written before the binding completion marker.
    // Identical retries repair an interrupted export without replacing either file.
    let capabilities = serde_json::to_vec_pretty(&serde_json::json!({
        "version":1,
        "authority":{"nkey":config.control_nkey, "publish":epochgrid_core::backend_roles::authority_publish(),
            "subscribe":[format!("_INBOX.{}.>",config.control_nkey)]},
        "worker":{"nkey":bindings.worker_nkey, "publish":epochgrid_core::backend_roles::worker_publish(),
            "subscribe":std::iter::once(format!("_INBOX.{}.>",bindings.worker_nkey)).chain(epochgrid_core::backend_roles::worker_subscribe()).collect::<Vec<_>>()},
    }))?;
    let capabilities_path = home.join("runtime-permissions.json");
    if capabilities_path.exists() {
        owned(&capabilities_path, uid(), true)?;
        ensure!(
            std::fs::read(capabilities_path)? == capabilities,
            "runtime permission artifact differs; refusing replacement"
        );
    } else {
        publish(&capabilities_path, &capabilities)?;
    }
    if !bound {
        publish(&path, &bytes)?;
    }
    // Public handoff only: caller copies this into the worker account's setup input.
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}

pub fn worker_configure(home: &Path, bindings_path: &Path) -> Result<()> {
    let bindings: Bindings = serde_json::from_slice(&std::fs::read(bindings_path)?)?;
    bindings.validate()?;
    ensure!(bindings.worker_uid == uid(), "worker account required");
    let connection = Vault::new(home).existing("worker", Kind::User)?;
    ensure!(
        connection.public_key == bindings.worker_nkey,
        "worker binding mismatch"
    );
    let bytes = serde_json::to_vec_pretty(&WorkerConfig {
        version: VERSION,
        connection,
        bindings,
    })?;
    let path = home.join("worker.json");
    if path.exists() {
        owned(&path, uid(), true)?;
        ensure!(
            std::fs::read(path)? == bytes,
            "worker configuration already differs"
        );
    } else {
        publish(&path, &bytes)?;
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u16,
    sequence: u64,
    operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Ready,
    Heartbeat,
    Request {
        subject: String,
        payload: Vec<u8>,
    },
    Response {
        payload: Vec<u8>,
    },
    Inspect,
    Status {
        reconciled: bool,
        worker_live: bool,
    },
    Diagnose {
        version: u16,
    },
    Diagnostic {
        report: Box<epochgrid_core::diagnostics::Report>,
    },
}

async fn read(stream: &mut UnixStream) -> Result<Frame> {
    read_limit(stream, LIMIT).await
}
async fn read_limit(stream: &mut UnixStream, limit: usize) -> Result<Frame> {
    tokio::time::timeout(DEADLINE, async {
        let size = stream.read_u32().await? as usize;
        ensure!(size > 0 && size <= limit, "invalid IPC frame length");
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        let frame: Frame = serde_json::from_slice(&bytes)?;
        ensure!(frame.version == VERSION, "unsupported IPC version");
        Ok(frame)
    })
    .await
    .context("IPC read deadline")?
}

async fn write(stream: &mut UnixStream, sequence: u64, operation: Operation) -> Result<()> {
    let bytes = serde_json::to_vec(&Frame {
        version: VERSION,
        sequence,
        operation,
    })?;
    ensure!(bytes.len() <= LIMIT, "IPC output too large");
    tokio::time::timeout(DEADLINE, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        Ok(())
    })
    .await
    .context("IPC write deadline")?
}

pub struct Request {
    pub subject: String,
    pub payload: Vec<u8>,
    pub active: Arc<AtomicBool>,
    pub response: oneshot::Sender<Vec<u8>>,
}

/// Discard requests whose worker session expired while queued. A closed listener
/// is a terminal runtime error, not another stale request to poll indefinitely.
pub async fn next_request(receiver: &mut mpsc::Receiver<Request>) -> Result<Request> {
    loop {
        let request = receiver
            .recv()
            .await
            .context("local control listener ended")?;
        if request.active.load(Ordering::Acquire) {
            return Ok(request);
        }
    }
}

struct Session(Arc<AtomicBool>);
impl Drop for Session {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct Server {
    pub requests: mpsc::Receiver<Request>,
    pub live: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    status_task: tokio::task::JoinHandle<()>,
    _lock: File,
    socket: PathBuf,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
        self.task.abort();
        self.status_task.abort();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(status_path(&self.socket));
    }
}

impl Server {
    pub fn bind(bindings: &Bindings, runtime: Arc<crate::diagnostics::Runtime>) -> Result<Self> {
        bindings.validate()?;
        ensure!(
            uid() == bindings.authority_uid,
            "authority account required"
        );
        let parent = bindings
            .socket
            .parent()
            .context("socket directory required")?;
        owned(parent, uid(), false)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(parent.join("authority.lock"))?;
        lock.try_lock().context("authority already running")?;
        if bindings.socket.exists() {
            let meta = std::fs::symlink_metadata(&bindings.socket)?;
            ensure!(
                meta.file_type().is_socket() && meta.uid() == uid(),
                "unsafe stale socket"
            );
            std::fs::remove_file(&bindings.socket)?;
        }
        let listener = UnixListener::bind(&bindings.socket)?;
        std::fs::set_permissions(&bindings.socket, std::fs::Permissions::from_mode(0o666))?;
        let (sender, requests) = mpsc::channel(1);
        let live = runtime.live.clone();
        let task_live = live.clone();
        let last_seen = runtime.last_seen.clone();
        let seen = last_seen.clone();
        let worker_uid = bindings.worker_uid;
        let authority_uid = bindings.authority_uid;
        let status_socket = status_path(&bindings.socket);
        if status_socket.exists() {
            let meta = std::fs::symlink_metadata(&status_socket)?;
            ensure!(
                meta.file_type().is_socket() && meta.uid() == uid(),
                "unsafe stale status socket"
            );
            std::fs::remove_file(&status_socket)?;
        }
        let status_listener = UnixListener::bind(&status_socket)?;
        std::fs::set_permissions(&status_socket, std::fs::Permissions::from_mode(0o666))?;
        let status_runtime = runtime.clone();
        let status_sender = sender.clone();
        let status_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = match status_listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => {
                        tracing::error!("diagnostic listener unavailable");
                        break;
                    }
                };
                let Ok(peer) = stream.peer_cred() else {
                    continue;
                };
                let role = if peer.uid() == authority_uid {
                    epochgrid_core::diagnostics::Role::Authority
                } else if peer.uid() == worker_uid {
                    epochgrid_core::diagnostics::Role::Control
                } else {
                    continue;
                };
                // One connection at a time, one total deadline, and a small request
                // frame. Never touch the worker lease or the control session here.
                let _ = tokio::time::timeout(DEADLINE, async {
                    let request = read_limit(&mut stream, 256).await?;
                    ensure!(request.sequence == 0, "status sequence required");
                    let report = status_runtime.snapshot(
                        role,
                        status_sender.max_capacity() - status_sender.capacity(),
                    );
                    let response = match request.operation {
                        Operation::Inspect => {
                            let obs = report
                                .observations
                                .as_ref()
                                .context("runtime unavailable")?;
                            Operation::Status {
                                reconciled: obs.reconciled,
                                worker_live: obs.worker_live,
                            }
                        }
                        Operation::Diagnose { version }
                            if version == epochgrid_core::diagnostics::VERSION =>
                        {
                            Operation::Diagnostic {
                                report: Box::new(report),
                            }
                        }
                        _ => anyhow::bail!("unsupported status operation"),
                    };
                    let encoded = serde_json::to_vec(&Frame {
                        version: VERSION,
                        sequence: 0,
                        operation: response,
                    })?;
                    ensure!(
                        encoded.len() <= epochgrid_core::diagnostics::MAX_REPORT,
                        "diagnostic output limit"
                    );
                    stream.write_u32(encoded.len() as u32).await?;
                    stream.write_all(&encoded).await?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
            }
        });
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                if !stream
                    .peer_cred()
                    .is_ok_and(|peer| peer.uid() == worker_uid)
                {
                    continue;
                }
                let mut event = epochgrid_core::audit::Event::committed(
                    epochgrid_core::audit::Kind::WorkerSessionStarted,
                );
                event.actor = epochgrid_core::audit::Actor::BoundWorker;
                event.stage = epochgrid_core::audit::Stage::Observation;
                runtime.queue_audit(event);
                let active = Arc::new(AtomicBool::new(true));
                let _session = Session(active.clone());
                let _readiness = Session(task_live.clone());
                if session(&mut stream, &sender, &task_live, &seen, active)
                    .await
                    .is_err()
                {
                    runtime.disconnects.increment();
                    tracing::warn!("control worker disconnected or invalid; admission closed");
                }
                let mut event = epochgrid_core::audit::Event::committed(
                    epochgrid_core::audit::Kind::WorkerSessionEnded,
                );
                event.actor = epochgrid_core::audit::Actor::BoundWorker;
                event.stage = epochgrid_core::audit::Stage::Observation;
                runtime.queue_audit(event);
            }
            task_live.store(false, Ordering::Release);
        });
        Ok(Self {
            requests,
            live,
            task,
            status_task,
            _lock: lock,
            socket: bindings.socket.clone(),
        })
    }
}

fn status_path(socket: &Path) -> PathBuf {
    let mut path = socket.as_os_str().to_os_string();
    path.push(".status");
    path.into()
}

async fn inspect(bindings: &Bindings) -> Result<bool> {
    tokio::time::timeout(DEADLINE, async {
        let mut stream = UnixStream::connect(status_path(&bindings.socket)).await?;
        ensure!(
            stream.peer_cred()?.uid() == bindings.authority_uid,
            "unexpected authority peer"
        );
        write(&mut stream, 0, Operation::Inspect).await?;
        let response = read(&mut stream).await?;
        ensure!(response.sequence == 0, "invalid status sequence");
        let Operation::Status {
            reconciled,
            worker_live,
        } = response.operation
        else {
            anyhow::bail!("status response required")
        };
        Ok(reconciled && worker_live)
    })
    .await
    .context("role inspection deadline")?
}

/// Existing public bindings only: deliberately no Vault lookup or runtime lock.
fn diagnostic_bindings(home: &Path, role: epochgrid_core::diagnostics::Role) -> Result<Bindings> {
    use epochgrid_core::diagnostics::Role;
    use std::io::Read;
    owned(home, uid(), true)?;
    let path = home.join(if role == Role::Authority {
        BINDINGS
    } else {
        "worker.json"
    });
    owned(&path, uid(), true)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == uid() && meta.mode() & 0o077 == 0,
        "invalid role file"
    );
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "role configuration too large");
    let bindings = match role {
        Role::Authority => serde_json::from_slice::<Bindings>(&bytes)?,
        Role::Control => {
            let config: WorkerConfig = serde_json::from_slice(&bytes)?;
            ensure!(
                config.version == VERSION,
                "unsupported worker configuration"
            );
            config.bindings
        }
    };
    bindings.validate()?;
    ensure!(
        uid()
            == match role {
                Role::Authority => bindings.authority_uid,
                Role::Control => bindings.worker_uid,
            },
        "wrong role account"
    );
    Ok(bindings)
}

pub async fn diagnostic_status(
    home: &Path,
    role: epochgrid_core::diagnostics::Role,
) -> epochgrid_core::diagnostics::Report {
    use epochgrid_core::diagnostics::{MAX_REPORT, Reason, Report, VERSION};
    let bindings = match diagnostic_bindings(home, role) {
        Ok(bindings) => bindings,
        Err(_) => return Report::unknown(role, Reason::ConfigurationInvalid),
    };
    let result = tokio::time::timeout(DEADLINE, async {
        let mut stream = UnixStream::connect(status_path(&bindings.socket))
            .await
            .map_err(|_| Reason::AuthorityUnavailable)?;
        if !stream
            .peer_cred()
            .is_ok_and(|p| p.uid() == bindings.authority_uid)
        {
            return Err(Reason::AuthorityUnavailable);
        }
        write(&mut stream, 0, Operation::Diagnose { version: VERSION })
            .await
            .map_err(|_| Reason::AuthorityUnavailable)?;
        let frame = read_limit(&mut stream, MAX_REPORT)
            .await
            .map_err(|_| Reason::UnsupportedResponse)?;
        if frame.sequence != 0 {
            return Err(Reason::UnsupportedResponse);
        }
        let Operation::Diagnostic { report } = frame.operation else {
            return Err(Reason::UnsupportedResponse);
        };
        let bytes = serde_json::to_vec(&report).map_err(|_| Reason::UnsupportedResponse)?;
        Report::parse(&bytes, role).map_err(|_| Reason::UnsupportedResponse)
    })
    .await;
    match result {
        Ok(Ok(report)) => report,
        Ok(Err(reason)) => Report::unknown(role, reason),
        Err(_) => Report::unknown(role, Reason::ObservationTimeout),
    }
}

fn worker_config(home: &Path) -> Result<WorkerConfig> {
    owned(home, uid(), true)?;
    owned(&home.join("worker.json"), uid(), true)?;
    let config: WorkerConfig = serde_json::from_slice(&std::fs::read(home.join("worker.json"))?)?;
    config.bindings.validate()?;
    ensure!(
        config.version == VERSION
            && config.bindings.worker_uid == uid()
            && config.connection.kind == Kind::User
            && config.connection.public_key == config.bindings.worker_nkey,
        "worker binding mismatch"
    );
    ensure!(
        Vault::new(home).existing("worker", Kind::User)? == config.connection,
        "worker credential mismatch"
    );
    Ok(config)
}

pub async fn validate(
    home: &Path,
    worker: bool,
    online: bool,
    endpoint: Option<&str>,
) -> epochgrid_core::validation::Report {
    use epochgrid_core::validation::{Check, Report, Status};
    use serde_json::json;
    let mut report = Report {
        version: 1,
        mode: if online { "online" } else { "offline" }.into(),
        success: false,
        checks: Vec::new(),
    };
    let config = if worker {
        worker_config(home).map(|c| c.bindings)
    } else {
        Bindings::load(home)
    };
    report.checks.push(Check {
        id: "local.backend_role".into(), status: if config.is_ok() { Status::Passed } else { Status::Failed }, required: true,
        expected: json!("separate accounts, private role state and matching credential binding"),
        observed: json!({"code":if config.is_ok() { "role_valid" } else { "role_invalid" }}),
        remediation: config.as_ref().err().map(|_| "Run role setup under the correct account and unlocked keyring; no state was initialized.".into()),
    });
    let trust_valid = epochgrid_core::tls::TlsConfig::from_env()
        .and_then(|tls| tls.validate_local())
        .is_ok();
    report.checks.push(Check {
        id: "local.role_trust".into(),
        status: if trust_valid {
            Status::Passed
        } else {
            Status::Failed
        },
        required: true,
        expected: json!("usable local TLS policy and trust roots"),
        observed: json!({"valid":trust_valid}),
        remediation: None,
    });
    if let Some(endpoint) = endpoint {
        let valid = epochgrid_core::tls::TlsConfig::from_env()
            .and_then(|tls| tls.validate_endpoint(endpoint))
            .is_ok();
        report.checks.push(Check {
            id: "local.role_transport".into(),
            status: if valid {
                Status::Passed
            } else {
                Status::Failed
            },
            required: true,
            expected: json!("valid transport input"),
            observed: json!({"valid":valid}),
            remediation: None,
        });
    }
    let ready = if online {
        match &config {
            Ok(bindings) => inspect(bindings).await.ok(),
            Err(_) => None,
        }
    } else {
        None
    };
    report.checks.push(Check {
        id: "runtime.backend_role".into(), status: if !online {Status::NotChecked} else if ready == Some(true) {Status::Passed} else {Status::Failed}, required: online,
        expected: json!("authority reconciled with current worker lease"),
        observed: json!({"code":if !online {"offline"} else if ready == Some(true) {"role_ready"} else {"role_not_ready"}}),
        remediation: (online && ready != Some(true)).then(|| "Start the authority and worker with matching bindings, then inspect startup failures.".into()),
    });
    report.checks.push(Check {id:"coverage.role_network".into(), status:Status::NotChecked, required:false,
        expected:json!("application resources and endpoint inspection"), observed:json!("Use authority validate --online for resource/TLS checks; worker validation does not hold authority credentials."), remediation:None});
    report.success = report
        .checks
        .iter()
        .filter(|c| c.required)
        .all(|c| c.status == Status::Passed);
    report
}

async fn session(
    stream: &mut UnixStream,
    sender: &mpsc::Sender<Request>,
    live: &AtomicBool,
    seen: &Mutex<Instant>,
    active: Arc<AtomicBool>,
) -> Result<()> {
    let first = read(stream).await?;
    ensure!(
        first.sequence == 0 && matches!(first.operation, Operation::Ready),
        "worker handshake required"
    );
    write(stream, 0, Operation::Heartbeat).await?;
    *seen
        .lock()
        .map_err(|_| anyhow::anyhow!("readiness unavailable"))? = Instant::now();
    live.store(true, Ordering::Release);
    let mut sequence = 1u64;
    loop {
        let frame = read(stream).await?;
        ensure!(frame.sequence == sequence, "stale IPC sequence");
        *seen
            .lock()
            .map_err(|_| anyhow::anyhow!("readiness unavailable"))? = Instant::now();
        let operation = match frame.operation {
            Operation::Heartbeat => Operation::Heartbeat,
            Operation::Request { subject, payload } => {
                ensure!(
                    payload.len() <= wire::MAX_WIRE && allowed(&subject),
                    "invalid control request"
                );
                let (response, receive) = oneshot::channel();
                let bytes = tokio::time::timeout(DEADLINE, async {
                    sender
                        .send(Request {
                            subject,
                            payload,
                            active: active.clone(),
                            response,
                        })
                        .await?;
                    Ok::<_, anyhow::Error>(receive.await?)
                })
                .await
                .context("authority operation deadline")??;
                Operation::Response { payload: bytes }
            }
            _ => anyhow::bail!("unexpected IPC operation"),
        };
        write(stream, sequence, operation).await?;
        sequence = sequence.checked_add(1).context("IPC sequence exhausted")?;
    }
}

fn allowed(subject: &str) -> bool {
    matches!(
        subject,
        wire::REGISTER
            | wire::LOOKUP
            | wire::DEVICES
            | wire::KEYPACKAGE
            | wire::AUDIT
            | wire::REVOKE
            | wire::REVOCATIONS
            | epochgrid_core::auth_callout::ENROLL
            | epochgrid_core::authorization::SUBJECT
            | epochgrid_core::authorization::RELAY
    )
}

pub async fn worker(home: &Path, url: &str) -> Result<()> {
    let config = worker_config(home)?;
    let _runtime = runtime_lock(home)?;
    let key = nkeys::KeyPair::from_seed(&config.connection.read()?)?;
    let client = tokio::time::timeout(
        DEADLINE,
        transport::connection_options(url, &key)?.connect(url),
    )
    .await??;
    if epochgrid_core::tls::TlsConfig::from_env()?.profile
        == epochgrid_core::tls::Profile::Production
    {
        ensure!(
            client.server_info().max_payload == wire::MAX_WIRE,
            "capacity contract requires server max_payload 65536"
        );
    }
    let mut controls = futures_util::stream::select(
        client.subscribe("epochgrid.v1.identity.*").await?,
        client.subscribe("epochgrid.v1.channel.*").await?,
    );
    // INFO/flush alone need not prove authenticated operations succeeded. Complete
    // a private inbox round trip before opening the independently bounded IPC phase.
    let inbox = client.new_inbox();
    let mut probe = client.subscribe(inbox.clone()).await?;
    tokio::time::timeout(DEADLINE, async {
        client.flush().await?;
        client.publish(inbox, "ready".into()).await?;
        let response = probe
            .next()
            .await
            .context("worker readiness subscription ended")?;
        ensure!(
            response.payload == "ready",
            "worker authenticated readiness failed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("worker NATS readiness deadline")??;
    drop(probe);
    let mut stream =
        tokio::time::timeout(DEADLINE, UnixStream::connect(&config.bindings.socket)).await??;
    ensure!(
        stream.peer_cred()?.uid() == config.bindings.authority_uid,
        "unexpected authority peer"
    );
    write(&mut stream, 0, Operation::Ready).await?;
    let first = read(&mut stream).await?;
    ensure!(
        first.sequence == 0 && matches!(first.operation, Operation::Heartbeat),
        "invalid authority handshake"
    );
    let mut sequence = 1u64;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(1));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::info!("EpochGrid control worker ready");
    loop {
        let (operation, reply) = tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            _ = heartbeat.tick() => (Operation::Heartbeat, None),
            message = controls.next() => {
                let message = message.context("control subscription ended")?;
                let Some(reply) = message.reply else { continue };
                if !reply.as_str().starts_with("_INBOX.") || !allowed(&message.subject)
                    || message.payload.len() > wire::MAX_WIRE { continue; }
                (Operation::Request { subject: message.subject.to_string(), payload: message.payload.to_vec() }, Some(reply))
            }
        };
        write(&mut stream, sequence, operation).await?;
        let response = read(&mut stream).await?;
        ensure!(response.sequence == sequence, "stale authority response");
        match (reply, response.operation) {
            (Some(reply), Operation::Response { payload }) => {
                ensure!(
                    payload.len() <= wire::MAX_WIRE,
                    "oversized authority response"
                );
                client.publish(reply, payload.into()).await?;
            }
            (None, Operation::Heartbeat) => (),
            _ => anyhow::bail!("unexpected authority response"),
        }
        sequence = sequence.checked_add(1).context("IPC sequence exhausted")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn diagnostics_are_bounded_private_and_do_not_renew_the_lease() -> Result<()> {
        use epochgrid_core::diagnostics::{Reason, Report, Role};
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        std::fs::create_dir(&home)?;
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700))?;
        let bindings = Bindings {
            version: VERSION,
            authority_uid: uid(),
            worker_uid: if uid() == 65534 { 65533 } else { 65534 },
            worker_nkey: nkeys::KeyPair::new_user().public_key(),
            socket: root.path().join("control.sock"),
        };
        publish(&home.join(BINDINGS), &serde_json::to_vec(&bindings)?)?;
        let runtime = Arc::new(crate::diagnostics::Runtime::new(Arc::new(
            AtomicBool::new(true),
        ))?);
        runtime.live.store(true, Ordering::Release);
        *runtime.last_seen.lock().unwrap() = Instant::now() - Duration::from_secs(6);
        let lease = *runtime.last_seen.lock().unwrap();
        let _server = Server::bind(&bindings, runtime.clone())?;
        let report = diagnostic_status(&home, Role::Authority).await;
        assert_eq!(report.exit_code(), 1);
        assert!(report.reasons.contains(&Reason::WorkerLeaseExpired));
        assert_eq!(*runtime.last_seen.lock().unwrap(), lease);
        assert!(!inspect(&bindings).await?);
        Report::parse(&serde_json::to_vec(&report)?, Role::Authority)?;
        assert!(!home.join("credentials.json").exists());
        for operation in [Operation::Diagnose { version: 999 }, Operation::Ready] {
            let mut stream = UnixStream::connect(status_path(&bindings.socket)).await?;
            write(&mut stream, 0, operation).await?;
            assert!(
                read_limit(&mut stream, epochgrid_core::diagnostics::MAX_REPORT)
                    .await
                    .is_err()
            );
        }
        let mut oversized = UnixStream::connect(status_path(&bindings.socket)).await?;
        oversized.write_u32(257).await?;
        assert!(oversized.read_u8().await.is_err());
        let mut malformed = UnixStream::connect(status_path(&bindings.socket)).await?;
        let marker = br#"{"secret":"PRIVATE_MARKER"}"#;
        malformed.write_u32(marker.len() as u32).await?;
        malformed.write_all(marker).await?;
        assert!(malformed.read_u8().await.is_err());
        // A slow inspection occupies only its own bounded listener task.
        let _slow = UnixStream::connect(status_path(&bindings.socket)).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!runtime.ready());
        assert_eq!(*runtime.last_seen.lock().unwrap(), lease);
        let wrong = diagnostic_status(&home, Role::Control).await;
        assert_eq!(wrong.exit_code(), 2);
        assert!(!wrong.human().contains("PRIVATE_MARKER"));
        Ok(())
    }
    #[tokio::test]
    async fn missing_diagnostics_never_initialize_or_expose_paths() -> Result<()> {
        use epochgrid_core::diagnostics::{Reason, Role};
        let root = tempfile::tempdir()?;
        let home = root.path().join("PRIVATE_MARKER");
        for role in [Role::Authority, Role::Control] {
            let report = diagnostic_status(&home, role).await;
            assert_eq!(report.reasons, vec![Reason::ConfigurationInvalid]);
            assert!(!report.human().contains("PRIVATE_MARKER"));
            assert!(!home.exists());
        }
        Ok(())
    }
    #[tokio::test]
    async fn stale_requests_are_discarded_and_closed_listener_is_terminal() -> Result<()> {
        let (send, mut receive) = mpsc::channel(2);
        let (stale_reply, stale_result) = oneshot::channel();
        send.send(Request {
            subject: wire::AUDIT.into(),
            payload: vec![],
            active: Arc::new(AtomicBool::new(false)),
            response: stale_reply,
        })
        .await?;
        let (live_reply, _live_result) = oneshot::channel();
        send.send(Request {
            subject: wire::LOOKUP.into(),
            payload: vec![],
            active: Arc::new(AtomicBool::new(true)),
            response: live_reply,
        })
        .await?;
        assert_eq!(next_request(&mut receive).await?.subject, wire::LOOKUP);
        assert!(stale_result.await.is_err());
        drop(send);
        assert!(next_request(&mut receive).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn missing_worker_validation_never_initializes_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("missing");
        let report = validate(&home, true, false, None).await;
        assert!(!report.success);
        assert!(!home.exists());
        epochgrid_core::validation::Report::parse(&serde_json::to_vec(&report)?)?;
        Ok(())
    }

    #[test]
    fn rejects_same_user_root_and_invalid_role_bindings() {
        let mut bindings = Bindings {
            version: VERSION,
            authority_uid: 1000,
            worker_uid: 1000,
            worker_nkey: nkeys::KeyPair::new_user().public_key(),
            socket: PathBuf::from("/tmp/roles/control.sock"),
        };
        assert!(bindings.validate().is_err());
        bindings.worker_uid = 0;
        assert!(bindings.validate().is_err());
        bindings.worker_uid = 65534;
        assert!(bindings.validate().is_ok());
        bindings.socket = PathBuf::from("relative/socket");
        assert!(bindings.validate().is_err());
    }
    #[tokio::test]
    async fn rejects_oversized_frame_before_allocating_payload() -> Result<()> {
        let (mut sender, mut receiver) = UnixStream::pair()?;
        sender.write_u32((LIMIT + 1) as u32).await?;
        assert!(read(&mut receiver).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn rejects_replayed_sequence_and_closes_readiness() -> Result<()> {
        let (mut worker, mut authority) = UnixStream::pair()?;
        let (sender, _receiver) = mpsc::channel(1);
        let live = Arc::new(AtomicBool::new(false));
        let observed = live.clone();
        let task = tokio::spawn(async move {
            let _guard = Session(live.clone());
            session(
                &mut authority,
                &sender,
                &live,
                &Mutex::new(Instant::now()),
                Arc::new(AtomicBool::new(true)),
            )
            .await
        });
        write(&mut worker, 0, Operation::Ready).await?;
        read(&mut worker).await?;
        write(&mut worker, 0, Operation::Heartbeat).await?;
        assert!(task.await?.is_err());
        assert!(!observed.load(Ordering::Acquire));
        Ok(())
    }

    #[tokio::test]
    async fn abandoned_request_expires_session_without_accepting_late_reply() -> Result<()> {
        let (mut worker, mut authority) = UnixStream::pair()?;
        let (sender, mut receiver) = mpsc::channel(1);
        let live = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicBool::new(true));
        let task_live = live.clone();
        let task_active = active.clone();
        let task = tokio::spawn(async move {
            let _readiness = Session(task_live.clone());
            let _session = Session(task_active.clone());
            session(
                &mut authority,
                &sender,
                &task_live,
                &Mutex::new(Instant::now()),
                task_active,
            )
            .await
        });
        write(&mut worker, 0, Operation::Ready).await?;
        read(&mut worker).await?;
        write(
            &mut worker,
            1,
            Operation::Request {
                subject: wire::AUDIT.into(),
                payload: wire::encode(wire::Body::Audit)?,
            },
        )
        .await?;
        let request = receiver.recv().await.context("forwarded request missing")?;
        drop(worker);
        assert!(
            tokio::time::timeout(DEADLINE + Duration::from_secs(1), task)
                .await??
                .is_err()
        );
        assert!(!active.load(Ordering::Acquire));
        assert!(!live.load(Ordering::Acquire));
        assert!(request.response.send(vec![]).is_err());
        Ok(())
    }
    #[test]
    fn no_arbitrary_subject_or_signing_proxy() {
        for subject in [
            "sign",
            "$JS.API.STREAM.DELETE.CHAT",
            "epochgrid.v1.identity.unknown",
            "epochgrid.v1.group.secret.message",
        ] {
            assert!(!allowed(subject));
        }
    }
}
