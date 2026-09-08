use super::{Action, ChannelView, MessageView, Snapshot};
use anyhow::{Context, Result};
use epochgrid_core::{delivery, history, identity::IdentityStore, transport};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, watch};

pub struct Worker {
    pub commands: mpsc::Sender<Action>,
    pub updates: watch::Receiver<Snapshot>,
    stop: watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    pub fn start(home: PathBuf, server: String) -> Self {
        let (commands, receiver) = mpsc::channel(32);
        let (updates, state) = watch::channel(Snapshot::default());
        let (stop, mut stopping) = watch::channel(false);
        let thread = std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let store = IdentityStore::open(&home)?;
                    let mut session = Session::new(store, server)?;
                    tokio::select! {
                        result = session.run(receiver, &updates) => result,
                        _ = stopping.changed() => Ok(()),
                    }
                })
            })();
            if let Err(error) = result {
                updates.send_modify(|s| s.fatal = Some(format!("{error:#}")));
            }
        });
        Self {
            commands,
            updates: state,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
struct Session {
    store: IdentityStore,
    server: String,
    selected: Option<String>,
    before: Option<u64>,
    client: Option<async_nats::Client>,
    retry: Instant,
    delay: u64,
    status: String,
    notice: String,
    send_count: u64,
    send_error: Option<String>,
}
impl Session {
    fn new(store: IdentityStore, server: String) -> Result<Self> {
        store.registration()?;
        let selected = store.groups()?.first().map(|g| g.name.clone());
        Ok(Self {
            store,
            server,
            selected,
            before: None,
            client: None,
            retry: Instant::now(),
            delay: 1,
            status: "Offline — connecting".into(),
            notice: "Type /help for commands".into(),
            send_count: 0,
            send_error: None,
        })
    }
    fn snapshot(&self) -> Result<Snapshot> {
        let identity = self.store.registration()?.payload;
        let channels = self
            .store
            .groups()?
            .into_iter()
            .map(|g| {
                Ok(ChannelView {
                    unread: self.store.unread_count(&g.name)?,
                    name: g.name,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut messages = Vec::new();
        let mut members = Vec::new();
        if let Some(name) = &self.selected {
            members = self.store.members(name)?;
            messages = self
                .store
                .history(name, 100, self.before)?
                .into_iter()
                .map(|entry| MessageView {
                    id: entry.id,
                    sequence: entry.sequence,
                    text: entry
                        .plaintext
                        .map(|s| super::safe_text(&String::from_utf8_lossy(&s)))
                        .unwrap_or_else(|| "[plaintext unavailable]".into()),
                    sender: entry.sender.unwrap_or_else(|| "unknown".into()),
                })
                .collect();
        }
        Ok(Snapshot {
            identity: format!("{}/{}", identity.user_id, identity.device_id),
            channels,
            selected: self.selected.clone(),
            messages,
            members,
            status: self.status.clone(),
            notice: if let Some(name) = &self.selected {
                let rejected = self.store.rejected_history(name)?;
                if rejected > 0 {
                    format!(
                        "{rejected} invalid/undecryptable messages quarantined. {}",
                        self.notice
                    )
                } else {
                    self.notice.clone()
                }
            } else {
                self.notice.clone()
            },
            older: self.before.is_some(),
            fatal: None,
            send_count: self.send_count,
            send_error: self.send_error.clone(),
        })
    }
    async fn run(
        &mut self,
        mut commands: mpsc::Receiver<Action>,
        updates: &watch::Sender<Snapshot>,
    ) -> Result<()> {
        updates.send_replace(self.snapshot()?);
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    if let Err(error) = self.command(command).await { self.notice = format!("Action failed: {error:#}"); }
                }
                _ = tick.tick() => {
                    self.network().await;
                    // Staged data remains usable even when a network ACK/connection fails.
                    for group in self.store.groups()? { self.store.process_history(&group.name)?; }
                }
            }
            updates.send_replace(self.snapshot()?);
        }
    }
    async fn network(&mut self) {
        if self.client.is_none() && Instant::now() < self.retry {
            return;
        }
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            if self.client.is_none() {
                self.client = Some(transport::connect(&self.server, &self.store).await?);
            }
            let client = self.client.as_ref().context("connection missing")?;
            delivery::flush_outbox(&self.store, client).await?;
            if let Some(group) = self.store.groups()?.first() {
                history::catch_up(&self.store, client, &group.name).await?;
            } else {
                client.flush().await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                self.status = "Online".into();
                self.delay = 1;
            }
            error => {
                self.notice = match error {
                    Ok(Err(error)) => format!("Sync failed: {error:#}"),
                    _ => "Network timeout; durable work will be retried".into(),
                };
                self.client = None;
                self.status = format!(
                    "Offline — retry in {}s; encrypted sends stay queued",
                    self.delay
                );
                self.retry = Instant::now() + Duration::from_secs(self.delay);
                self.delay = (self.delay * 2).min(8);
            }
        }
    }
    async fn command(&mut self, action: Action) -> Result<()> {
        match action {
            Action::Select(name) => {
                self.store.group(&name)?;
                self.selected = Some(name);
                self.before = None;
            }
            Action::Older => {
                if let Some(name) = &self.selected {
                    let entries = self.store.history(name, 100, self.before)?;
                    if let Some(first) = entries.iter().filter_map(|e| e.sequence).min()
                        && !self.store.history(name, 1, Some(first))?.is_empty()
                    {
                        self.before = Some(first);
                    }
                }
            }
            Action::Latest => {
                self.before = None;
            }
            Action::Viewed(ids) => {
                for id in ids {
                    self.store.mark_displayed(id)?;
                }
            }
            Action::Create(name) => {
                self.store.create_group(&name)?;
                self.selected = Some(name);
                self.before = None;
                self.notice = "Channel created; invite a peer before sending".into();
            }
            Action::Send { name, text } => {
                let result = self.store.encrypt_message(&name, text.as_bytes());
                self.send_count += 1;
                self.send_error = result.as_ref().err().map(|error| format!("{error:#}"));
                result?;
                self.before = None;
                self.notice =
                    "Encrypted message saved locally; pending server acknowledgment".into();
            }
            Action::Invite { name, user, device } => {
                let client = self
                    .client
                    .as_ref()
                    .context("offline; retry invite when connected")?;
                tokio::time::timeout(
                    Duration::from_secs(8),
                    delivery::invite(&self.store, client, &name, &user, &device),
                )
                .await
                .context("invite timed out; retry the same invite to resume")??;
                self.notice = "Invitation delivered".into();
            }
            Action::Join { user, device } => {
                let client = self
                    .client
                    .as_ref()
                    .context("offline; retry join when connected")?;
                let group = tokio::time::timeout(
                    Duration::from_secs(8),
                    delivery::join_next(&self.store, client, &user, &device),
                )
                .await
                .context("join timed out; retry to acknowledge any redelivery")??;
                self.selected = Some(group.name);
                self.before = None;
                self.notice = "Channel joined".into();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_worker_exposes_identity_creation_and_errors() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut store = IdentityStore::open(dir.path())?;
        store.init("alice", "laptop")?;
        let mut session = Session::new(store, "nats://127.0.0.1:1".into())?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            session
                .command(Action::Create("engineering".into()))
                .await?;
            assert!(
                session
                    .command(Action::Send {
                        name: "engineering".into(),
                        text: "no peer".into()
                    })
                    .await
                    .is_err()
            );
            session.network().await;
            Ok::<_, anyhow::Error>(())
        })?;
        let snapshot = session.snapshot()?;
        assert_eq!(snapshot.identity, "alice/laptop");
        assert_eq!(snapshot.selected.as_deref(), Some("engineering"));
        assert!(snapshot.status.starts_with("Offline"));
        assert!(snapshot.messages.is_empty());
        Ok(())
    }
}
