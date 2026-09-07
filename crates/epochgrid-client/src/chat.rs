use anyhow::{Context, Result};
use epochgrid_core::{
    identity::IdentityStore,
    messaging::{self, DecryptedMessage},
    transport,
};
use futures_util::StreamExt;
use std::{io::BufRead, path::Path, time::Duration};

fn display(message: DecryptedMessage) {
    // Do not interpret terminal control sequences received from another endpoint.
    let text: String = String::from_utf8_lossy(&message.plaintext)
        .chars()
        .flat_map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect();
    println!("{}> {}", message.sender, text.trim_end_matches('\n'));
}
pub async fn receive(home: &Path, server: &str, name: &str, timeout: u64) -> Result<()> {
    let store = IdentityStore::open(home)?;
    let client = transport::connect(server, &store).await?;
    let mut subscription = messaging::subscribe(&store, &client, name).await?;
    eprintln!("EpochGrid listening: {name}");
    tokio::time::timeout(Duration::from_secs(timeout), async {
        while let Some(message) = subscription.next().await {
            match store.decrypt_message(name, &message.payload) {
                Ok(Some(message)) => {
                    display(message);
                    return Ok(());
                }
                Ok(None) => {}
                Err(_) => eprintln!("EpochGrid rejected an invalid MLS message"),
            }
        }
        anyhow::bail!("NATS subscription closed")
    })
    .await
    .context("timed out waiting for a live message")?
}
pub async fn interactive(home: &Path, server: &str, name: &str) -> Result<()> {
    let store = IdentityStore::open(home)?;
    let client = transport::connect(server, &store).await?;
    let mut subscription = messaging::subscribe(&store, &client, name).await?;
    epochgrid_core::delivery::flush_outbox(&store, &client).await?;
    println!("[{name}] — live encrypted chat; /quit exits");
    // A detached OS input thread avoids Tokio's uncancellable stdin read keeping
    // the runtime alive after Ctrl-C. It owns no device or MLS state.
    let (input, mut lines) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let stop = line.is_err();
            if input.blocking_send(line).is_err() || stop {
                break;
            }
        }
    });
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
            message = subscription.next() => {
                let Some(message) = message else { anyhow::bail!("NATS subscription closed"); };
                match store.decrypt_message(name, &message.payload) {
                    Ok(Some(message)) => display(message),
                    Ok(None) => {},
                    Err(_) => eprintln!("EpochGrid rejected an invalid MLS message"),
                }
            }
        }
    }
    Ok(())
}
