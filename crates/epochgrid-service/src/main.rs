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
    drop(identity);
    let store = transport::provision(client.clone()).await?;
    let mut requests = client.subscribe("epochgrid.v1.identity.*").await?;
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
                let response = match (message.subject.as_str(), wire::decode(&message.payload)) {
                    (wire::REGISTER, Ok(Body::Register(registration))) => {
                        if transport::accept(&store, &enrollment, registration).await.is_ok() { Body::Registered } else { Body::Rejected }
                    }
                    (wire::LOOKUP, Ok(Body::Lookup { user, device })) => transport::find(&store, &enrollment, &user, &device).await.unwrap_or(Body::Rejected),
                    _ => Body::Rejected,
                };
                if matches!(response, Body::Rejected) { tracing::warn!("identity request rejected"); }
                client.publish(reply, wire::encode(response)?.into()).await?;
            }
        }
    }
    client.flush().await?;
    Ok(())
}
