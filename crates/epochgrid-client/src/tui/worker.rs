use super::{Action, ChannelView, MessageView, Snapshot};
use anyhow::{Context, Result};
use epochgrid_core::ephemeral::{EphemeralEvent, TypingState};
use epochgrid_core::{delivery, history, identity::IdentityStore, transport};
use futures_util::{FutureExt, StreamExt};
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
    ephemeral: Option<async_nats::Subscriber>,
    typing: TypingState,
    receipt_poll: Instant,
    receipt_cursor: usize,
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
            ephemeral: None,
            typing: TypingState::default(),
            receipt_poll: Instant::now(),
            receipt_cursor: 0,
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
                .map(|entry| {
                    Ok(MessageView {
                        status: if entry.outgoing {
                            Some(self.store.message_status(entry.id)?.summary())
                        } else {
                            None
                        },
                        id: entry.id,
                        sequence: entry.sequence,
                        text: entry
                            .plaintext
                            .map(|s| super::safe_text(&epochgrid_core::attachments::display(&s)))
                            .unwrap_or_else(|| "[plaintext unavailable]".into()),
                        sender: entry.sender.unwrap_or_else(|| "unknown".into()),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        }
        Ok(Snapshot {
            identity: format!("{}/{}", identity.user_id, identity.device_id),
            channels,
            selected: self.selected.clone(),
            messages,
            typing: if let Some(name) = &self.selected {
                self.typing
                    .active(&self.store.group(name)?.gid, self.store.group_epoch(name)?)
            } else {
                Vec::new()
            },
            members,
            status: self.status.clone(),
            security_warning: self.store.trust_warning()?,
            notice: if let Some(warning) = self.store.trust_warning()? {
                warning
            } else if let Some(name) = &self.selected {
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
            if self.ephemeral.is_none() {
                self.ephemeral = Some(client.subscribe("epochgrid.v1.group.*.ephemeral").await?);
                client.flush().await?;
            }
            epochgrid_core::transparency::audit(client, &self.store).await?;
            delivery::flush_outbox(&self.store, client).await?;
            if let Some(group) = self.store.groups()?.first() {
                history::catch_up(&self.store, client, &group.name).await?;
                for group in self.store.groups()? {
                    self.store.process_history(&group.name)?;
                    self.store.reconcile_revocations(&group.name)?;
                }
                delivery::flush_outbox(&self.store, client).await?;
            } else {
                client.flush().await?;
            }
            if let Some(subscriber) = &mut self.ephemeral {
                let groups = self.store.groups()?;
                let own = self.store.registration()?.payload;
                let own = format!("{}/{}", own.user_id, own.device_id);
                for _ in 0..32 {
                    let Some(Some(message)) = subscriber.next().now_or_never() else {
                        break;
                    };
                    if let Some(group) = groups
                        .iter()
                        .find(|g| g.subject("ephemeral") == message.subject.as_str())
                        && let Ok(event) = self.store.open_ephemeral(&group.name, &message.payload)
                        && event.sender() != own
                    {
                        if let Some(response) = self.store.process_receipt(&group.name, &event)? {
                            let payload = self.store.seal_ephemeral(&group.name, response)?;
                            client
                                .publish(group.subject("ephemeral"), payload.into())
                                .await?;
                        }
                        self.typing.accept(&group.gid, event);
                    }
                }
            }
            if Instant::now() >= self.receipt_poll {
                self.receipt_poll = Instant::now() + Duration::from_secs(5);
                if let Some(name) = &self.selected {
                    let requests = self.store.receipt_requests(name, 100)?;
                    let group = self.store.group(name)?;
                    if self.store.members(name)?.len() > 1 {
                        for offset in 0..requests.len().min(8) {
                            let request = requests[(self.receipt_cursor + offset) % requests.len()];
                            let payload = self.store.seal_ephemeral(name, request)?;
                            client
                                .publish(group.subject("ephemeral"), payload.into())
                                .await?;
                        }
                    }
                    self.receipt_cursor = if requests.is_empty() {
                        0
                    } else {
                        (self.receipt_cursor + 8) % requests.len()
                    };
                }
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
                self.ephemeral = None;
                self.typing = TypingState::default();
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
            Action::Typing {
                name,
                active,
                observed,
            } => {
                if observed.elapsed() < Duration::from_secs(1)
                    && self.status == "Online"
                    && let Some(client) = self.client.as_ref().filter(|c| {
                        c.connection_state() == async_nats::connection::State::Connected
                    })
                    && let Ok(payload) = self.store.seal_ephemeral(
                        &name,
                        if active {
                            EphemeralEvent::TypingStarted
                        } else {
                            EphemeralEvent::TypingStopped
                        },
                    )
                {
                    let subject = self.store.group(&name)?.subject("ephemeral");
                    let _ = tokio::time::timeout(Duration::from_millis(500), async {
                        client.publish(subject, payload.into()).await?;
                        client.flush().await?;
                        Ok::<_, anyhow::Error>(())
                    })
                    .await;
                }
            }
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
                // Catch up membership before encrypting when connected; failures retain the draft.
                let synced = if let Some(client) = self.client.as_ref().filter(|client| {
                    client.connection_state() == async_nats::connection::State::Connected
                }) {
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        history::resume(&self.store, client, &name),
                    )
                    .await
                    .context("sync before send timed out; retry after reconnect")
                    .and_then(|result| result)
                    .map(|_| ())
                } else {
                    Ok(())
                };
                let result =
                    synced.and_then(|()| self.store.encrypt_message(&name, text.as_bytes()));
                self.send_count += 1;
                self.send_error = result.as_ref().err().map(|error| format!("{error:#}"));
                result?;
                self.before = None;
                self.notice =
                    "Encrypted message saved locally; pending server acknowledgment".into();
            }
            Action::Attach { name, path } => {
                let client = self
                    .client
                    .as_ref()
                    .context("offline; retry attachment when connected")?;
                let id = epochgrid_core::attachments::send_file(
                    &self.store,
                    client,
                    &name,
                    std::path::Path::new(&path),
                    "application/octet-stream",
                    epochgrid_core::attachments::Limits::from_env()?,
                )
                .await?;
                self.notice = format!("Encrypted attachment sent: {id}");
            }
            Action::SaveAttachment { name, id, path } => {
                let client = self
                    .client
                    .as_ref()
                    .context("offline; retry download when connected")?;
                epochgrid_core::attachments::save_file(
                    &self.store,
                    client,
                    &name,
                    &id,
                    std::path::Path::new(&path),
                    epochgrid_core::attachments::Limits::from_env()?,
                )
                .await?;
                self.notice = format!("Authenticated attachment saved: {path}");
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
    fn trust_warnings_override_routine_notices_after_restart() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut store = IdentityStore::open(dir.path())?;
        store.init("alice", "laptop")?;
        store.transparency_failure("TRANSPARENCY FAILURE: signed history rewritten")?;
        drop(store);
        let session = Session::new(
            IdentityStore::open(dir.path())?,
            "nats://127.0.0.1:1".into(),
        )?;
        assert_eq!(
            session.snapshot()?.notice,
            "TRANSPARENCY FAILURE: signed history rewritten"
        );
        Ok(())
    }
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
