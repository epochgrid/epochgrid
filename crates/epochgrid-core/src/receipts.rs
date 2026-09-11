//! Compact authenticated device claims; no durable receipt event stream.
use crate::{
    ephemeral::{AuthenticatedEvent, EphemeralEvent},
    identity::IdentityStore,
    transparency::hash,
};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptState {
    Delivered,
    Read,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Submission {
    Submitted,
    ServerAccepted,
}
#[derive(Debug)]
pub struct MessageStatus {
    pub submission: Submission,
    pub devices: Vec<(String, ReceiptState)>,
}
impl MessageStatus {
    pub fn summary(&self) -> String {
        let mut text = match self.submission {
            Submission::Submitted => "submitted",
            Submission::ServerAccepted => "server accepted",
        }
        .to_owned();
        for (device, state) in &self.devices {
            text.push_str(&format!(
                "; {device}: {}",
                match state {
                    ReceiptState::Delivered => "delivered",
                    ReceiptState::Read => "read",
                }
            ));
        }
        text
    }
}
impl IdentityStore {
    pub(crate) fn migrate_receipts(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=6)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
            self.connection.execute_batch("CREATE TABLE receipt_messages(transcript_id INTEGER PRIMARY KEY, gid TEXT NOT NULL, reference BLOB NOT NULL CHECK(length(reference)=32), UNIQUE(gid,reference)); CREATE TABLE device_receipts(transcript_id INTEGER NOT NULL, device TEXT NOT NULL, state INTEGER NOT NULL CHECK(state IN (0,1)), PRIMARY KEY(transcript_id,device));")?;
            let mut query = self.connection.prepare("SELECT id,gid,payload FROM transcript")?;
            let rows = query.query_map([], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?)))?;
            for row in rows { let (id,gid,payload) = row?; self.index_receipt(id, &gid, &payload)?; }
            self.connection.execute("INSERT INTO epochgrid_migrations VALUES(6)", [])?;
            Ok(())
        })?;
        }
        Ok(())
    }
    pub(crate) fn index_receipt(&self, id: i64, gid: &str, payload: &[u8]) -> Result<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO receipt_messages(transcript_id,gid,reference) VALUES(?1,?2,?3)",
            params![id, gid, hash(payload)?.as_slice()],
        )?;
        Ok(())
    }
    pub fn receipt_requests(&self, name: &str, limit: u32) -> Result<Vec<EphemeralEvent>> {
        ensure!(
            (1..=100).contains(&limit),
            "receipt request limit must be 1–100"
        );
        let mut statement = self.connection.prepare("SELECT r.reference FROM receipt_messages r JOIN transcript t ON t.id=r.transcript_id WHERE r.gid=?1 AND t.outgoing=1 AND t.stream_sequence IS NOT NULL ORDER BY t.id DESC LIMIT ?2")?;
        let rows = statement.query_map(params![self.group(name)?.gid, limit], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| {
            let reference = row?;
            Ok(EphemeralEvent::ReceiptRequest {
                message: reference
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid stored receipt reference"))?,
            })
        })
        .collect()
    }
    /// Only callers holding an authenticated current-epoch event can submit claims.
    pub fn process_receipt(
        &self,
        name: &str,
        event: &AuthenticatedEvent,
    ) -> Result<Option<EphemeralEvent>> {
        let group = self.group(name)?;
        self.ensure_can_send(&self.load_group(&group)?)?;
        ensure!(
            event.expires > std::time::Instant::now(),
            "expired receipt event"
        );
        ensure!(
            event.gid == group.gid && event.epoch == self.group_epoch(name)?,
            "receipt group or epoch changed"
        );
        match event.event {
            EphemeralEvent::ReceiptRequest { message } => {
                let displayed: Option<bool> = self.connection.query_row("SELECT t.displayed FROM receipt_messages r JOIN transcript t ON t.id=r.transcript_id WHERE r.gid=?1 AND r.reference=?2 AND t.outgoing=0 AND t.plaintext IS NOT NULL AND t.sender=?3", params![group.gid,message.as_slice(),event.sender], |r| r.get(0)).optional()?;
                Ok(displayed.map(|read| EphemeralEvent::Receipt {
                    message,
                    state: if read {
                        ReceiptState::Read
                    } else {
                        ReceiptState::Delivered
                    },
                }))
            }
            EphemeralEvent::Receipt { message, state } => {
                let id: Option<i64> = self.connection.query_row("SELECT t.id FROM receipt_messages r JOIN transcript t ON t.id=r.transcript_id WHERE r.gid=?1 AND r.reference=?2 AND t.outgoing=1", params![group.gid,message.as_slice()], |r| r.get(0)).optional()?;
                if let Some(id) = id {
                    self.connection.execute("INSERT INTO device_receipts(transcript_id,device,state) VALUES(?1,?2,?3) ON CONFLICT(transcript_id,device) DO UPDATE SET state=excluded.state WHERE excluded.state > device_receipts.state", params![id,event.sender,match state { ReceiptState::Delivered=>0, ReceiptState::Read=>1 }])?;
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
    pub fn message_status(&self, id: i64) -> Result<MessageStatus> {
        let accepted: bool = self.connection.query_row(
            "SELECT stream_sequence IS NOT NULL FROM transcript WHERE id=?1 AND outgoing=1",
            [id],
            |r| r.get(0),
        )?;
        let mut statement = self.connection.prepare(
            "SELECT device,state FROM device_receipts WHERE transcript_id=?1 ORDER BY device",
        )?;
        let devices = statement
            .query_map([id], |r| {
                Ok((
                    r.get(0)?,
                    if r.get::<_, u8>(1)? == 1 {
                        ReceiptState::Read
                    } else {
                        ReceiptState::Delivered
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(MessageStatus {
            submission: if accepted {
                Submission::ServerAccepted
            } else {
                Submission::Submitted
            },
            devices,
        })
    }
}

/// Bounded CLI rendezvous. Each peer must be online to recover missing claims.
pub async fn exchange(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    duration: std::time::Duration,
) -> Result<()> {
    use futures_util::StreamExt;
    use std::time::Duration;
    ensure!(
        (Duration::from_secs(1)..=Duration::from_secs(60)).contains(&duration),
        "receipt exchange must be 1–60 seconds"
    );
    let group = store.group(name)?;
    let mut subscription = tokio::time::timeout(Duration::from_secs(10), async {
        crate::transparency::audit(client, store).await?;
        crate::history::resume(store, client, name).await?;
        let subscription = client.subscribe(group.subject("ephemeral")).await?;
        client.flush().await?;
        Ok::<_, anyhow::Error>(subscription)
    })
    .await??;
    let deadline = tokio::time::Instant::now() + duration;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let own = store.registration()?.payload;
    let own = format!("{}/{}", own.user_id, own.device_id);
    let work = async {
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = tick.tick() => {
                    for request in store.receipt_requests(name, 100)? {
                        client.publish(group.subject("ephemeral"), store.seal_ephemeral(name, request)?.into()).await?;
                    }
                    client.flush().await?;
                }
                message = subscription.next() => {
                    let Some(message) = message else { anyhow::bail!("receipt subscription ended"); };
                    if let Ok(event) = store.open_ephemeral(name, &message.payload) && event.sender != own
                        && let Some(response) = store.process_receipt(name, &event)? {
                        client.publish(group.subject("ephemeral"), store.seal_ephemeral(name, response)?.into()).await?;
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    match tokio::time::timeout_at(deadline, work).await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ephemeral::EphemeralEvent;
    fn pair(root: &std::path::Path) -> Result<(IdentityStore, IdentityStore)> {
        let mut alice = IdentityStore::open(&root.join("alice"))?;
        let mut bob = IdentityStore::open(&root.join("bob"))?;
        let ar = alice.init("alice", "laptop")?;
        let br = bob.init("bob", "laptop")?;
        alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &br)?;
        let welcome: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
            [],
            |r| r.get(0),
        )?;
        bob.accept_welcome(&welcome, &ar)?;
        Ok((alice, bob))
    }
    fn receipt(alice: &IdentityStore, bob: &IdentityStore, message: [u8; 32]) -> Result<Vec<u8>> {
        let request =
            alice.seal_ephemeral("engineering", EphemeralEvent::ReceiptRequest { message })?;
        let event = bob.open_ephemeral("engineering", &request)?;
        let response = bob
            .process_receipt("engineering", &event)?
            .ok_or_else(|| anyhow::anyhow!("missing response"))?;
        bob.seal_ephemeral("engineering", response)
    }
    #[test]
    fn receipt_states_authentication_idempotence_and_restart() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (alice, bob) = pair(root.path())?;
        let payload = alice.encrypt_message("engineering", b"EPOCHGRID_RECEIPT_SECRET_91F3")?;
        let id = alice.history("engineering", 1, None)?[0].id;
        assert_eq!(alice.message_status(id)?.submission, Submission::Submitted);
        let group = alice.group("engineering")?;
        alice.stage_chat(2, &group.subject("message"), &payload)?;
        alice.process_history("engineering")?;
        assert_eq!(
            alice.message_status(id)?.submission,
            Submission::ServerAccepted
        );
        assert!(alice.message_status(id)?.devices.is_empty());
        assert!(receipt(&alice, &bob, hash(&payload)?).is_err());
        bob.stage_chat(2, &group.subject("message"), &payload)?;
        bob.process_history("engineering")?;
        let delivered = receipt(&alice, &bob, hash(&payload)?)?;
        alice.process_receipt(
            "engineering",
            &alice.open_ephemeral("engineering", &delivered)?,
        )?;
        assert_eq!(
            alice.message_status(id)?.devices,
            vec![("bob/laptop".into(), ReceiptState::Delivered)]
        );
        bob.mark_displayed(bob.history("engineering", 1, None)?[0].id)?;
        let read = receipt(&alice, &bob, hash(&payload)?)?;
        for bytes in [&read, &delivered, &read] {
            alice.process_receipt("engineering", &alice.open_ephemeral("engineering", bytes)?)?;
        }
        assert_eq!(
            alice.message_status(id)?.devices,
            vec![("bob/laptop".into(), ReceiptState::Read)]
        );
        let changes = alice.connection.total_changes();
        for bytes in [&read, &delivered] {
            alice.process_receipt("engineering", &alice.open_ephemeral("engineering", bytes)?)?;
        }
        assert_eq!(alice.connection.total_changes(), changes);
        let unknown = bob.seal_ephemeral(
            "engineering",
            EphemeralEvent::Receipt {
                message: [0; 32],
                state: ReceiptState::Read,
            },
        )?;
        alice.process_receipt(
            "engineering",
            &alice.open_ephemeral("engineering", &unknown)?,
        )?;
        assert_eq!(
            alice
                .connection
                .query_row("SELECT COUNT(*) FROM device_receipts", [], |r| r
                    .get::<_, u64>(0))?,
            1
        );
        let mut corrupt = read.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(alice.open_ephemeral("engineering", &corrupt).is_err());
        assert_eq!(alice.history("engineering", 100, None)?.len(), 1);
        drop(alice);
        drop(bob);
        let alice = IdentityStore::open(&root.path().join("alice"))?;
        let bob = IdentityStore::open(&root.path().join("bob"))?;
        assert_eq!(alice.message_status(id)?.devices[0].1, ReceiptState::Read);
        assert!(receipt(&alice, &bob, hash(&payload)?).is_ok());
        Ok(())
    }
    #[test]
    fn migration_backfills_without_reset_and_rolls_back_failure() -> Result<()> {
        let root = tempfile::tempdir()?;
        let (alice, _bob) = pair(root.path())?;
        let payload = alice.encrypt_message("engineering", b"preserved transcript")?;
        alice.connection.execute_batch("DROP TABLE receipt_messages; DROP TABLE device_receipts; DELETE FROM epochgrid_migrations WHERE version=6; CREATE TRIGGER fail_receipts BEFORE INSERT ON epochgrid_migrations WHEN NEW.version=6 BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
        assert!(alice.migrate_receipts().is_err());
        assert!(!alice.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='receipt_messages')",
            [],
            |r| r.get::<_, bool>(0)
        )?);
        alice
            .connection
            .execute_batch("DROP TRIGGER fail_receipts")?;
        drop(alice);
        let alice = IdentityStore::open(&root.path().join("alice"))?;
        let reference: Vec<u8> =
            alice
                .connection
                .query_row("SELECT reference FROM receipt_messages", [], |r| r.get(0))?;
        assert_eq!(reference, hash(&payload)?);
        assert_eq!(
            alice.history("engineering", 1, None)?[0]
                .plaintext
                .as_deref(),
            Some(b"preserved transcript".as_slice())
        );
        Ok(())
    }
}
