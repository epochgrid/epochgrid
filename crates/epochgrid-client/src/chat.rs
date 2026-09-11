use anyhow::{Context, Result};
use epochgrid_core::{
    history::{self, HistoryEntry, SyncReport},
    identity::IdentityStore,
    messaging, transport,
};
use std::{io::BufRead, path::Path, time::Duration};

fn text(bytes: &[u8]) -> String {
    epochgrid_core::attachments::display(bytes)
        .chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn display(message: &HistoryEntry, numbered: bool) {
    let prefix = if numbered {
        format!(
            "[{}] ",
            message
                .sequence
                .map_or_else(|| "pending".into(), |s| s.to_string())
        )
    } else {
        String::new()
    };
    if let Some(plaintext) = &message.plaintext {
        println!(
            "{prefix}{}> {}",
            message.sender.as_deref().unwrap_or("unknown"),
            text(plaintext).trim_end_matches('\n')
        );
    } else {
        println!("{prefix}[plaintext unavailable: processed before local history was enabled]");
    }
}
fn report(report: &SyncReport) {
    if report.rejected > 0 || report.unavailable > 0 {
        eprintln!(
            "EpochGrid history: {} rejected, {} unavailable; use message history to inspect retained history",
            report.rejected, report.unavailable
        );
    }
}
pub async fn history(
    home: &Path,
    server: &str,
    name: &str,
    limit: u32,
    before: Option<u64>,
    offline: bool,
) -> Result<()> {
    anyhow::ensure!((1..=1000).contains(&limit), "history limit must be 1–1000");
    let store = IdentityStore::open(home)?;
    if offline {
        report(&store.process_history(name)?);
    } else {
        let client = transport::connect(server, &store).await?;
        report(&history::resume(&store, &client, name).await?);
    }
    for entry in store.history(name, limit, before)? {
        display(&entry, true);
    }
    let rejected = store.rejected_history(name)?;
    if rejected > 0 {
        eprintln!(
            "EpochGrid: {rejected} invalid or undecryptable deliveries retained in local quarantine"
        );
    }
    Ok(())
}
pub async fn receive(home: &Path, server: &str, name: &str, timeout: u64) -> Result<()> {
    let store = IdentityStore::open(home)?;
    store.group(name)?;
    // Locally committed messages remain available even when NATS is unreachable.
    store.process_history(name)?;
    if let Some(message) = store.unread(name)? {
        display(&message, false);
        store.mark_displayed(message.id)?;
        return Ok(());
    }
    let client = transport::connect(server, &store).await?;
    epochgrid_core::delivery::flush_outbox(&store, &client).await?;
    eprintln!("EpochGrid listening: {name}");
    tokio::time::timeout(Duration::from_secs(timeout), async {
        loop {
            report(&history::resume(&store, &client, name).await?);
            if let Some(message) = store.unread(name)? {
                display(&message, false);
                store.mark_displayed(message.id)?;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .context("timed out waiting for an authenticated message")?
}
pub async fn interactive(home: &Path, server: &str, name: &str) -> Result<()> {
    let store = IdentityStore::open(home)?;
    let client = transport::connect(server, &store).await?;
    report(&history::resume(&store, &client, name).await?);
    // Drain every undisplayed incoming message; history pagination is independent.
    while let Some(message) = store.unread(name)? {
        display(&message, false);
        store.mark_displayed(message.id)?;
    }
    println!("[{name}] — encrypted chat with catch-up; /quit exits");
    // Detached stdin thread owns no device or MLS state and cannot hold shutdown open.
    let (input, mut lines) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let stop = line.is_err();
            if input.blocking_send(line).is_err() || stop {
                break;
            }
        }
    });
    let mut poll = tokio::time::interval(Duration::from_millis(200));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            line = lines.recv() => {
                let Some(line) = line else { break; };
                let line = line?;
                if line == "/quit" { break; }
                if line.is_empty() { continue; }
                if messaging::send(&store, &client, name, line.as_bytes()).await.is_err() {
                    eprintln!("EpochGrid send failed; pending ciphertext can be retried with channel flush");
                }
            }
            _ = poll.tick() => {
                // An error stops this client without acknowledging unstaged data.
                // Reopening resumes the durable consumer and any local pending work.
                report(&history::resume(&store, &client, name).await?);
                while let Some(message) = store.unread(name)? { display(&message, false); store.mark_displayed(message.id)?; }
            }
        }
    }
    Ok(())
}
