mod dynamic;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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
    #[arg(
        long,
        env = "EPOCHGRID_NATS_URL",
        default_value = "nats://127.0.0.1:4222"
    )]
    server: String,
}
#[derive(Subcommand)]
enum ServiceCommand {
    /// Generate EpochGrid integration keys and a reference snippet, never modify NATS.
    AuthInit,
    /// Issue a local provider enrollment token to stdout; protect its delivery.
    UserInvite {
        #[arg(long)]
        handle: String,
        #[arg(long, default_value_t = 600)]
        ttl: u64,
    },
    /// Dynamic admission/control path. Does not read or modify NATS server config.
    Serve {
        #[arg(long)]
        auth_config: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
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
    let args = Args::parse();
    let tls = epochgrid_core::tls::TlsConfig::from_env()?;
    tls.warn_development();
    anyhow::ensure!(
        !args.dev_static || tls.profile == epochgrid_core::tls::Profile::Development,
        "--dev-static requires EPOCHGRID_PROFILE=development"
    );
    if let Some(command) = args.command {
        return match command {
            ServiceCommand::AuthInit => dynamic::init(&args.home),
            ServiceCommand::UserInvite { handle, ttl } => {
                let token = epochgrid_core::identity_model::AuthRegistry::open(&args.home)?
                    .invite(&handle, ttl)?;
                println!("{}", token.as_str());
                Ok(())
            }
            ServiceCommand::Serve { auth_config } => {
                dynamic::serve(&args.home, &args.server, &auth_config).await
            }
        };
    }
    anyhow::ensure!(
        args.dev_static,
        "choose serve --auth-config FILE; legacy fixtures require explicit --dev-static"
    );
    tracing::warn!("DEVELOPMENT ONLY: static users and broker reload actuator enabled");
    let enrollment: Enrollment = serde_json::from_slice(&std::fs::read(&args.enrollment)?)?;
    let identity = IdentityStore::open(&args.home)?;
    let client = transport::connect(&args.server, &identity).await?;
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
    let mut control = BrokerControl::connect(root, &args.server).await?;
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
