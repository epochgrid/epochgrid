use anyhow::Result;
use clap::Parser;
use epochgrid_core::{
    identity::IdentityStore,
    transport::{self, Enrollment},
    wire::{self, Body},
};
use futures_util::StreamExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "EpochGrid NATS identity service")]
struct Args {
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
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let enrollment: Enrollment = serde_json::from_slice(&std::fs::read(args.enrollment)?)?;
    let identity = IdentityStore::open(&args.home)?;
    let client = transport::connect(&args.server, &identity).await?;
    let store = transport::provision(client.clone()).await?;
    let mut requests = client.subscribe(wire::REGISTER).await?;
    client.flush().await?;
    tracing::info!("EpochGrid identity service ready");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            message = requests.next() => {
                let Some(message) = message else { break };
                let Some(reply) = message.reply else { continue };
                // A requester controls reply subjects. Never exercise the service's
                // publish authority against KV, stream or administrative subjects.
                if !reply.as_str().starts_with("_INBOX.") { continue; }
                let accepted = match wire::decode(&message.payload) {
                    Ok(Body::Register(registration)) => transport::accept(&store, &enrollment, registration).await.is_ok(),
                    _ => false,
                };
                if !accepted { tracing::warn!("registration rejected"); }
                client.publish(reply, wire::encode(if accepted { Body::Registered } else { Body::Rejected })?.into()).await?;
            }
        }
    }
    client.flush().await?;
    Ok(())
}
