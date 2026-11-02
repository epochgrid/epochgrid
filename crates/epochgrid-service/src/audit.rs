use anyhow::Result;
use clap::Subcommand;
use epochgrid_core::{audit, identity_model::AuthRegistry};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum Command {
    /// Add audit schema to an existing encrypted registry under the runtime lock.
    Upgrade,
    /// Verify restored storage capacity and reopen ordinary audit recording.
    Recover,
    Info,
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        store: String,
        #[arg(long)]
        after: u64,
        #[arg(long)]
        upper: u64,
        #[arg(long, default_value_t = 1000)]
        max_records: u64,
    },
    Retention {
        #[arg(long)]
        through: u64,
    },
    Prune {
        #[arg(long)]
        through: u64,
        #[arg(long)]
        apply: bool,
    },
}
pub fn run(home: &Path, command: &Command) -> Result<()> {
    let _lock = crate::roles::runtime_lock(home)?;
    // Missing/unsupported state is refused before opening any writable handle.
    if matches!(command, Command::Upgrade) {
        audit::upgrade(home)?;
        return Ok(());
    }
    audit::inspect(home)?;
    match command {
        Command::Upgrade => unreachable!(),
        Command::Recover => audit::recover(home)?,
        Command::Info => println!("{}", serde_json::to_string_pretty(&audit::inspect(home)?)?),
        Command::Export {
            output,
            store,
            after,
            upper,
            max_records,
        } => {
            let registry = AuthRegistry::open(home).ok();
            // Evidence must remain exportable even if every audit record slot is full.
            let operation = registry
                .as_ref()
                .and_then(|registry| registry.audit_export_start().ok());
            if operation.is_none() {
                eprintln!(
                    "audit lifecycle recording unavailable; exported coverage remains incomplete"
                );
            }
            if operation.is_none()
                && let Some(registry) = &registry
            {
                let mut lost = audit::Event::committed(audit::Kind::Export);
                lost.stage = audit::Stage::Intent;
                lost.outcome = audit::Outcome::Unknown;
                lost.reason = audit::Reason::CoverageUncertain;
                lost.actor = audit::Actor::LocalOperator;
                registry.audit_repair(lost);
            }
            let result = audit::export(home, output, store, *after, *upper, *max_records);
            if let Some(registry) = &registry {
                registry.audit_effect_result(audit::Kind::Export, operation, result.is_ok());
                if !registry.audit_info().is_ok_and(|state| !state.degraded) {
                    eprintln!("audit storage degraded; inspect coverage before recovery");
                }
            }
            result?;
        }
        Command::Retention { through } => audit::set_retention(home, *through)?,
        Command::Prune { through, apply } => println!(
            "{}",
            serde_json::to_string(&audit::prune(home, *through, *apply)?)?
        ),
    }
    Ok(())
}
