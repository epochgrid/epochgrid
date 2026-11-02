mod audit;
mod deployment_setup;
mod diagnostics;
mod dynamic;
mod roles;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use epochgrid_core::{
    broker_control::BrokerControl,
    identity::IdentityStore,
    revocation, transparency,
    transport::{self, Enrollment},
    wire::{self, Body},
};
use futures_util::StreamExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "EpochGrid NATS identity service")]
struct Args {
    /// Explicitly run the legacy owned-broker fixture (never production).
    #[arg(long)]
    dev_static: bool,
    #[command(subcommand)]
    command: Option<ServiceCommand>,
    /// Retention for ciphertext objects, in seconds (60 seconds to one year).
    #[arg(long, default_value_t = 604800)]
    attachment_retention_seconds: u64,
    /// Total ciphertext bucket capacity in bytes.
    #[arg(long, default_value_t = 536870912)]
    attachment_store_max_bytes: i64,
    #[arg(long, default_value = ".dev/service")]
    home: PathBuf,
    #[arg(long, default_value = ".dev/enrollment.json")]
    enrollment: PathBuf,
    #[arg(long, env = "EPOCHGRID_NATS_URL", global = true)]
    server: Option<String>,
}
#[derive(Subcommand)]
enum ServiceCommand {
    /// Inspect or maintain security evidence while the authority is stopped.
    Audit {
        #[command(subcommand)]
        command: audit::Command,
    },
    /// Inspect the running authority without database, keyring or broker access.
    Status {
        #[arg(long, value_enum)]
        role: StatusRole,
        #[arg(long, value_enum, default_value = "human")]
        format: ReportFormat,
    },
    /// Provision the control worker connection in this account's keyring.
    WorkerInit,
    /// Bind an existing backend to a separate worker account (service stopped).
    RoleBind {
        /// Defaults to auth.json within --home.
        #[arg(long)]
        auth_config: Option<PathBuf>,
        #[arg(long)]
        worker_uid: u32,
        #[arg(long)]
        worker_nkey: String,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Configure the worker from public authority bindings, without private keys.
    WorkerConfigure {
        #[arg(long)]
        bindings: PathBuf,
    },
    /// Run the isolated registry, signing and reconciliation authority.
    ServeAuthority {
        #[arg(long)]
        auth_config: PathBuf,
    },
    /// Forward control requests using this worker's own keyring and local IPC.
    ServeControl,
    /// Inspect worker state without authority credentials or state initialization.
    ValidateControl {
        #[arg(long, required_unless_present = "online", conflicts_with = "online")]
        offline: bool,
        #[arg(long)]
        online: bool,
        #[arg(long, value_enum, default_value = "human")]
        format: ReportFormat,
    },
    /// Inspect established state offline or against a running backend.
    Validate {
        #[arg(long)]
        auth_config: PathBuf,
        #[arg(long, required_unless_present = "online", conflicts_with = "online")]
        offline: bool,
        #[arg(long)]
        online: bool,
        /// Additional endpoints to inspect individually (online only, maximum 8 total).
        #[arg(long, requires = "online")]
        endpoint: Vec<String>,
        #[arg(long, value_enum, default_value = "human")]
        format: ReportFormat,
    },
    /// Initialize integration keys and public deployment artifacts; never modify NATS.
    AuthInit(deployment_setup::InitOptions),
    /// Export public deployment artifacts from established credentials; never provision keys.
    DeploymentExport {
        #[arg(long)]
        auth_config: PathBuf,
        /// Required for existing installations without a deployment manifest.
        #[arg(long)]
        replicas: Option<usize>,
        /// New artifact directory; an identical existing bundle is accepted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Prepare finite capacity for an established stopped backend without resetting state.
    CapacityExport {
        #[arg(long)]
        auth_config: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Explicitly replace an installed policy after validating retained usage.
        #[arg(long)]
        replace: bool,
    },
    /// Issue a local provider enrollment token to stdout; protect its delivery.
    UserInvite {
        #[arg(long)]
        handle: String,
        #[arg(long, default_value_t = 600)]
        ttl: u64,
    },
    /// Legacy combined dynamic fixture, restricted to explicit development homes.
    Serve {
        #[arg(long)]
        auth_config: PathBuf,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum StatusRole {
    Authority,
    Control,
}
#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Human,
    Json,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if let Some(ServiceCommand::Audit { command }) = &args.command {
        return audit::run(&args.home, command);
    }
    if let Some(ServiceCommand::Status { role, format }) = &args.command {
        let role = match role {
            StatusRole::Authority => epochgrid_core::diagnostics::Role::Authority,
            StatusRole::Control => epochgrid_core::diagnostics::Role::Control,
        };
        let report = roles::diagnostic_status(&args.home, role).await;
        match format {
            ReportFormat::Human => print!("{}", report.human()),
            ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        }
        std::process::exit(report.exit_code());
    }
    if let Some(ServiceCommand::ValidateControl { online, format, .. }) = &args.command {
        let report = roles::validate(&args.home, true, *online, args.server.as_deref()).await;
        match format {
            ReportFormat::Human => print!("{}", report.human()),
            ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        }
        anyhow::ensure!(
            report.success,
            "worker validation failed; see the validation report"
        );
        return Ok(());
    }
    // Validation owns stdout and handles malformed local inputs in its report.
    // No service initialization, Auth Callout listener or signal tasks.
    // Online validation alone performs its bounded inspection connections.
    if let Some(ServiceCommand::Validate {
        auth_config,
        format,
        online,
        endpoint,
        ..
    }) = &args.command
    {
        let mut report = if *online {
            let endpoints: Vec<_> = args.server.iter().chain(endpoint.iter()).cloned().collect();
            epochgrid_core::validation::online(&args.home, auth_config, &endpoints).await
        } else {
            epochgrid_core::validation::offline(&args.home, auth_config, args.server.as_deref())
        };
        if *online || args.home.join(roles::BINDINGS).exists() {
            let role = roles::validate(&args.home, false, *online, None).await;
            report.success &= role.success;
            report.checks.extend(role.checks);
        }
        match format {
            ReportFormat::Human => print!("{}", report.human()),
            ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        }
        anyhow::ensure!(
            report.success,
            "validation failed; see the validation report"
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // Install before readiness: a background shell may initially ignore SIGINT.
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    // Poll once to register Tokio's handler before any request can report ready.
    if let std::task::Poll::Ready(result) = futures_util::poll!(&mut interrupt) {
        return result.map_err(Into::into);
    }
    let server = args.server.as_deref().unwrap_or("nats://127.0.0.1:4222");
    let tls = epochgrid_core::tls::TlsConfig::from_env()?;
    tls.warn_development();
    anyhow::ensure!(
        !args.dev_static || tls.profile == epochgrid_core::tls::Profile::Development,
        "--dev-static requires EPOCHGRID_PROFILE=development"
    );
    if let Some(command) = args.command {
        return match command {
            ServiceCommand::Audit { .. } => {
                unreachable!("audit handled before runtime initialization")
            }
            ServiceCommand::Status { .. } => {
                unreachable!("status handled before runtime initialization")
            }
            ServiceCommand::WorkerInit => roles::worker_init(&args.home),
            ServiceCommand::RoleBind {
                auth_config,
                worker_uid,
                worker_nkey,
                socket,
            } => roles::bind(
                &args.home,
                &auth_config.unwrap_or_else(|| args.home.join("auth.json")),
                worker_uid,
                worker_nkey,
                socket,
            ),
            ServiceCommand::WorkerConfigure { bindings } => {
                roles::worker_configure(&args.home, &bindings)
            }
            ServiceCommand::ServeAuthority { auth_config } => {
                dynamic::authority(&args.home, server, &auth_config).await
            }
            ServiceCommand::ServeControl => roles::worker(&args.home, server).await,
            ServiceCommand::Validate { .. } | ServiceCommand::ValidateControl { .. } => {
                unreachable!("validation handled before runtime setup")
            }
            ServiceCommand::AuthInit(options) => dynamic::init(&args.home, &options),
            ServiceCommand::DeploymentExport {
                auth_config,
                replicas,
                output,
            } => deployment_setup::export(&args.home, &auth_config, replicas, output.as_deref()),
            ServiceCommand::CapacityExport {
                auth_config,
                policy,
                output,
                replace,
            } => deployment_setup::capacity_export(
                &args.home,
                &auth_config,
                &policy,
                &output,
                replace,
            ),
            ServiceCommand::UserInvite { handle, ttl } => {
                epochgrid_core::audit::inspect(&args.home)?;
                let token = epochgrid_core::identity_model::AuthRegistry::open(&args.home)?
                    .invite(&handle, ttl)?;
                println!("{}", token.as_str());
                Ok(())
            }
            ServiceCommand::Serve { auth_config } => {
                dynamic::serve(&args.home, server, &auth_config).await
            }
        };
    }
    anyhow::ensure!(
        args.dev_static,
        "choose serve-authority --auth-config FILE or serve-control; legacy static fixtures require explicit --dev-static"
    );
    tracing::warn!("DEVELOPMENT ONLY: static users and broker reload actuator enabled");
    let enrollment: Enrollment = serde_json::from_slice(&std::fs::read(&args.enrollment)?)?;
    let identity = IdentityStore::open(&args.home)?;
    let client = transport::connect(server, &identity).await?;
    let signing_key = identity.nkey()?;
    drop(identity);
    let store = transport::provision(client.clone()).await?;
    epochgrid_core::attachments::provision(
        client.clone(),
        args.attachment_retention_seconds,
        args.attachment_store_max_bytes,
    )
    .await?;
    transport::provision_mailboxes(client.clone(), &enrollment).await?;
    transport::provision_chat_consumers(client.clone(), &enrollment).await?;
    let log =
        epochgrid_core::transparency::provision(client.clone(), &store, &enrollment, &signing_key)
            .await?;
    let registrations = transparency::read(&log).await?;
    revocation::initialize(&log, &registrations, &signing_key).await?;
    let root = args
        .enrollment
        .parent()
        .context("enrollment directory missing")?;
    let mut control = BrokerControl::connect(root, server).await?;
    control
        .enforce(
            &revocation::read(&log, &registrations).await?,
            &client,
            true,
        )
        .await?;
    let mut retry = tokio::time::interval(std::time::Duration::from_secs(2));
    let mut requests = client.subscribe("epochgrid.v1.identity.*").await?;
    client.flush().await?;
    tracing::info!("EpochGrid identity service ready");
    loop {
        tokio::select! {
            _ = &mut interrupt => break,
            _ = retry.tick() => {
                let result = async {
                    let registrations = transparency::read(&log).await?;
                    control.enforce(&revocation::read(&log, &registrations).await?, &client, false).await
                }.await;
                if let Err(error) = result { tracing::error!(%error, "revocation enforcement pending; retrying"); }
            }
            message = requests.next() => {
                let Some(message) = message else { break };
                let Some(reply) = message.reply else { continue };
                // A requester controls reply subjects. Never exercise the service's
                // publish authority against KV, stream or administrative subjects.
                if !reply.as_str().starts_with("_INBOX.") { continue; }
                let state = async {
                    let registrations = transparency::read(&log).await?;
                    let revocations = revocation::read(&log, &registrations).await?;
                    Ok::<_, anyhow::Error>((registrations, revocations))
                }.await;
                let (registrations, revocations) = match state {
                    Ok(state) => state,
                    Err(error) => {
                        tracing::error!(%error, "directory integrity failure; request rejected");
                        client.publish(reply, wire::encode(Body::Rejected)?.into()).await?;
                        continue;
                    }
                };
                let revoked_keys = revocations.keys();
                let active: Enrollment = enrollment.iter().filter(|(_,key)| !revoked_keys.contains(*key)).map(|(endpoint,key)| (endpoint.clone(),key.clone())).collect();
                let response = match (message.subject.as_str(), wire::decode(&message.payload)) {
                    (wire::REGISTER, Ok(Body::Register(registration))) => {
                        if epochgrid_core::transparency::register(&log, &store, &active, &signing_key, registration).await.is_ok() { Body::Registered } else { Body::Rejected }
                    }
                    (wire::AUDIT, Ok(Body::RegistrationAudit)) => Body::AuditLog(registrations.clone()),
                    (wire::AUDIT, Ok(Body::Audit)) if revocations.entries.is_empty() => Body::AuditLog(registrations.clone()),
                    (wire::REVOCATIONS, Ok(Body::RevocationAudit)) => Body::RevocationLog(revocations),
                    (wire::REVOKE, Ok(Body::Revoke(request))) => {
                        let result = async {
                            let cutoff = epochgrid_core::revocation::chat_cutoff(&client).await?;
                            let log = revocation::append(&log, &registrations, &signing_key, request, cutoff).await?;
                            control.enforce(&log, &client, false).await
                        }.await;
                        match result { Ok(()) => Body::Revoked, Err(error) => { tracing::error!(%error, "revocation not completed; inspect status and retry"); Body::Rejected } }
                    },
                    (wire::DEVICES, Ok(Body::ListDevices { user })) => epochgrid_core::devices::find_devices(&store, &active, &user).await.unwrap_or(Body::Rejected),
                    (wire::LOOKUP, Ok(Body::Lookup { user, device })) => transport::find(&store, &active, &user, &device).await.unwrap_or(Body::Rejected),
                    (wire::KEYPACKAGE, Ok(Body::ClaimKeyPackage { user, device, group })) => transport::claim(&store, &active, &user, &device, &group).await.unwrap_or(Body::Rejected),
                    _ => Body::Rejected,
                };
                if matches!(response, Body::Rejected) { tracing::warn!("identity request rejected"); }
                // A bounded listing can still exceed the envelope byte limit. Reject
                // that response without terminating the service.
                let bytes = match wire::encode(response) {
                    Ok(bytes) => bytes,
                    Err(_) => wire::encode(Body::Rejected)?,
                };
                client.publish(reply, bytes.into()).await?;
            }
        }
    }
    client.flush().await?;
    Ok(())
}
