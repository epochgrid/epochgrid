//! One explicit service installation, reusing the regular client transport/state.
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use epochgrid_core::{delivery, history, identity::IdentityStore, transport};
use std::{path::Path, time::Duration};

#[derive(Subcommand)]
pub enum Command {
    /// Respond to original /status messages in one explicitly joined channel.
    Run {
        name: String,
        /// Perform one bounded catch-up/response pass and exit (at most 100 events).
        #[arg(long)]
        once: bool,
    },
}
pub async fn run(home: &Path, server: &str, command: Command) -> Result<()> {
    let Command::Run { name, once } = command;
    let store = IdentityStore::open(home)?;
    ensure!(
        store.registration()?.payload.device_id == "service",
        "initialize a dedicated identity with --device service"
    );
    ensure!(
        store.group_active(&name)?,
        "participant is removed from this channel"
    );
    let client = transport::connect(server, &store).await?;
    eprintln!("EpochGrid service participant running; Ctrl-C stops");
    loop {
        let pass = async {
            tokio::time::timeout(Duration::from_secs(15), async {
                history::resume(&store, &client, &name).await?;
                ensure!(
                    store.group_active(&name)?,
                    "participant removed from channel"
                );
                store.respond_status(&name)?;
                delivery::flush_outbox(&store, &client).await
            })
            .await
            .context("participant pass timed out")?
        };
        let result = tokio::select! {
            result = pass => result,
            signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
        };
        if once {
            return result;
        }
        // Fail closed after removal/revocation. Retry transient network failures,
        // but never respond until a complete authenticated catch-up succeeds.
        ensure!(
            store.group_active(&name)? && !store.is_revoked(&store.nkey()?.public_key())?,
            "participant removed or revoked"
        );
        if let Err(error) = result {
            tracing::warn!(error = %error, "participant pass failed; retaining state and retrying");
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            signal = tokio::signal::ctrl_c() => { signal?; return Ok(()); }
        }
    }
}
