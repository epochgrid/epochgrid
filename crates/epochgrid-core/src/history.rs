//! Durable ciphertext staging and a device-local transcript. Plaintext stays local.
use crate::{identity::IdentityStore, messaging::InvalidMessage, wire};
use anyhow::{Context, Result, anyhow, ensure};
use futures_util::StreamExt;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

#[derive(Debug)]
pub struct HistoryEntry {
    pub id: i64,
    pub sequence: Option<u64>,
    pub sender: Option<String>,
    pub plaintext: Option<Vec<u8>>,
    pub outgoing: bool,
}
#[derive(Default, Debug)]
pub struct SyncReport {
    pub staged: u64,
    pub decrypted: usize,
    pub rejected: usize,
    pub unavailable: usize,
}
impl IdentityStore {
    /// Commit before acknowledging NATS. A redelivery must match the stored bytes.
    pub fn stage_chat(&self, sequence: u64, subject: &str, payload: &[u8]) -> Result<()> {
        ensure!(
            sequence > 0 && sequence <= i64::MAX as u64,
            "invalid CHAT sequence"
        );
        ensure!(
            payload.len() <= wire::MAX_WIRE && subject.len() <= 256,
            "invalid CHAT delivery size"
        );
        self.transaction(|| {
            let existing = self.connection.query_row("SELECT subject,payload FROM chat_deliveries WHERE sequence=?1", [sequence], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))).optional()?;
            if let Some((old_subject, old_payload)) = existing {
                ensure!(old_subject == subject && old_payload == payload, "CHAT sequence changed: possible stream reset; refusing to overwrite local history");
            } else {
                self.connection.execute("INSERT INTO chat_deliveries(sequence,subject,payload) VALUES(?1,?2,?3)", params![sequence, subject, payload])?;
            }
            Ok(())
        })
    }
    /// Process only this group, in stream order. Other groups remain staged.
    pub fn process_history(&self, name: &str) -> Result<SyncReport> {
        let group = self.group(name)?;
        let mut report = SyncReport::default();
        loop {
            let row = self.connection.query_row("SELECT sequence,payload FROM chat_deliveries WHERE subject=?1 AND state='pending' ORDER BY sequence LIMIT 1", [group.subject("message")], |r| Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?))).optional()?;
            let Some((sequence, payload)) = row else {
                break;
            };
            let result = self.transaction(|| {
                let decrypted = self.decrypt_inner(name, &payload)?.is_some();
                // Older clients erased plaintext after processing. Keep an explicit gap.
                let inserted = self.connection.execute("INSERT OR IGNORE INTO transcript(gid,payload,outgoing) VALUES(?1,?2,EXISTS(SELECT 1 FROM outbox WHERE payload=?2))", params![group.gid, payload])?;
                self.connection.execute("UPDATE transcript SET stream_sequence=CASE WHEN stream_sequence IS NULL OR stream_sequence>?1 THEN ?1 ELSE stream_sequence END WHERE gid=?2 AND payload=?3", params![sequence, group.gid, payload])?;
                self.connection.execute("UPDATE chat_deliveries SET state='processed' WHERE sequence=?1", [sequence])?;
                Ok((decrypted, inserted > 0))
            });
            match result {
                Ok((decrypted, unavailable)) => {
                    report.decrypted += usize::from(decrypted);
                    report.unavailable += usize::from(unavailable);
                }
                Err(error) if error.downcast_ref::<InvalidMessage>().is_some() => {
                    // Ratchet writes were rolled back. Quarantine the ciphertext locally
                    // so an invalid packet cannot block all subsequent history.
                    self.connection.execute(
                        "UPDATE chat_deliveries SET state='rejected' WHERE sequence=?1",
                        [sequence],
                    )?;
                    report.rejected += 1;
                }
                Err(error) => return Err(error), // Storage failures remain pending.
            }
        }
        Ok(report)
    }
    pub fn history(
        &self,
        name: &str,
        limit: u32,
        before: Option<u64>,
    ) -> Result<Vec<HistoryEntry>> {
        ensure!((1..=1000).contains(&limit), "history limit must be 1–1000");
        let group = self.group(name)?;
        let mut statement = self.connection.prepare("SELECT id,stream_sequence,sender,plaintext,outgoing FROM transcript WHERE gid=?1 AND (?2 IS NULL OR stream_sequence < ?2) ORDER BY stream_sequence IS NULL DESC,stream_sequence DESC,id DESC LIMIT ?3")?;
        let mut entries = statement
            .query_map(params![group.gid, before, limit], entry)?
            .collect::<Result<Vec<_>, _>>()?;
        entries.reverse();
        Ok(entries)
    }
    pub fn unread(&self, name: &str) -> Result<Option<HistoryEntry>> {
        let group = self.group(name)?;
        Ok(self.connection.query_row("SELECT id,stream_sequence,sender,plaintext,outgoing FROM transcript WHERE gid=?1 AND outgoing=0 AND plaintext IS NOT NULL AND displayed=0 ORDER BY stream_sequence IS NULL,stream_sequence,id LIMIT 1", [group.gid], entry).optional()?)
    }
    pub fn mark_displayed(&self, id: i64) -> Result<()> {
        self.connection
            .execute("UPDATE transcript SET displayed=1 WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn rejected_history(&self, name: &str) -> Result<u64> {
        Ok(self.connection.query_row(
            "SELECT COUNT(*) FROM chat_deliveries WHERE subject=?1 AND state='rejected'",
            [self.group(name)?.subject("message")],
            |r| r.get(0),
        )?)
    }
}
fn entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<HistoryEntry> {
    Ok(HistoryEntry {
        id: row.get(0)?,
        sequence: row.get(1)?,
        sender: row.get(2)?,
        plaintext: row.get(3)?,
        outgoing: row.get(4)?,
    })
}

pub async fn consumer(
    store: &IdentityStore,
    client: &async_nats::Client,
) -> Result<async_nats::jetstream::consumer::PullConsumer> {
    let consumer: async_nats::jetstream::consumer::PullConsumer =
        async_nats::jetstream::new(client.clone())
            .get_consumer_from_stream(format!("device_{}", store.nkey()?.public_key()), "CHAT")
            .await
            .context("CHAT consumer unavailable; re-run bootstrap and restart the service")?;
    let info = consumer.cached_info();
    ensure!(
        info.config.filter_subject == "epochgrid.v1.group.*.message"
            && info.config.max_ack_pending == 1,
        "unexpected CHAT consumer configuration"
    );
    Ok(consumer)
}
/// Drain the finite backlog visible when this call starts, without a live/replay race.
/// Chat calls this repeatedly; there is no second Core NATS receive path.
pub async fn catch_up(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
) -> Result<SyncReport> {
    store.group(name)?;
    let consumer = consumer(store, client).await?;
    let count = consumer.cached_info().num_pending + consumer.cached_info().num_ack_pending as u64;
    for _ in 0..count {
        let message = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let mut batch = consumer
                    .fetch()
                    .max_messages(1)
                    .expires(Duration::from_secs(2))
                    .messages()
                    .await?;
                if let Some(message) = batch.next().await {
                    return message.map_err(|e| anyhow!("CHAT delivery: {e}"));
                }
            }
        })
        .await
        .context("CHAT delivery timed out; local history is retained")??;
        let info = message
            .info()
            .map_err(|e| anyhow!("CHAT delivery metadata: {e}"))?;
        ensure!(info.stream == "CHAT", "unexpected stream");
        store.stage_chat(
            info.stream_sequence,
            message.subject.as_str(),
            &message.payload,
        )?;
        message.double_ack().await.map_err(|e| {
            anyhow!("CHAT acknowledgment failed; ciphertext is staged locally: {e}")
        })?;
    }
    let mut report = store.process_history(name)?;
    report.staged = count;
    Ok(report)
}

/// Resume committed outgoing work before fetching incoming history. Retrying uses
/// the original ciphertext, never advances a sending ratchet a second time.
pub async fn resume(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
) -> Result<SyncReport> {
    store.group(name)?;
    crate::delivery::flush_outbox(store, client).await?;
    catch_up(store, client, name).await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair() -> Result<(
        tempfile::TempDir,
        tempfile::TempDir,
        IdentityStore,
        IdentityStore,
    )> {
        let a = tempfile::tempdir()?;
        let b = tempfile::tempdir()?;
        let mut alice = IdentityStore::open(a.path())?;
        let mut bob = IdentityStore::open(b.path())?;
        let registration = alice.init("alice", "laptop")?;
        let bob_registration = bob.init("bob", "laptop")?;
        alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &bob_registration)?;
        let welcome: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
            [],
            |r| r.get(0),
        )?;
        bob.accept_welcome(&welcome, &registration)?;
        Ok((a, b, alice, bob))
    }
    #[test]
    fn ordered_history_replay_quarantine_and_restart() -> Result<()> {
        let (_a, b, alice, bob) = pair()?;
        let subject = alice.group("engineering")?.subject("message");
        let first = alice.encrypt_message("engineering", b"first")?;
        let second = alice.encrypt_message("engineering", b"second")?;
        // Stage out of order, including a corrupt packet before valid ciphertext.
        bob.stage_chat(4, &subject, &second)?;
        bob.stage_chat(1, &subject, &[255, 0])?;
        bob.stage_chat(2, &subject, &first)?;
        bob.stage_chat(3, &subject, &first)?;
        bob.stage_chat(2, &subject, &first)?;
        assert!(bob.stage_chat(2, &subject, &second).is_err());
        drop(bob); // Simulates durable stage/ack followed by exit before decryption.
        let bob = IdentityStore::open(b.path())?;
        let report = bob.process_history("engineering")?;
        assert_eq!(report.decrypted, 2);
        assert_eq!(report.rejected, 1);
        assert_eq!(bob.rejected_history("engineering")?, 1);
        let history = bob.history("engineering", 10, None)?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].plaintext.as_deref(), Some(b"first".as_slice()));
        assert_eq!(history[1].plaintext.as_deref(), Some(b"second".as_slice()));
        assert_eq!(history[0].sequence, Some(2));
        assert_eq!(bob.history("engineering", 1, Some(4))?[0].sequence, Some(2));
        assert!(bob.history("engineering", 0, None).is_err());
        assert_eq!(bob.process_history("engineering")?.decrypted, 0);
        drop(bob); // Simulates decryption commit before display.
        let bob = IdentityStore::open(b.path())?;
        let unread = bob.unread("engineering")?.context("unread lost")?;
        assert_eq!(unread.plaintext.as_deref(), Some(b"first".as_slice()));
        bob.mark_displayed(unread.id)?;
        assert_eq!(
            bob.unread("engineering")?
                .context("second unread lost")?
                .plaintext
                .as_deref(),
            Some(b"second".as_slice())
        );
        assert_eq!(bob.history("engineering", 10, None)?.len(), 2);
        Ok(())
    }
    #[test]
    fn transcript_failure_rolls_back_ratchet_and_delivery_progress() -> Result<()> {
        let (_a, _b, alice, bob) = pair()?;
        let subject = alice.group("engineering")?.subject("message");
        let ciphertext = alice.encrypt_message("engineering", b"must survive storage error")?;
        bob.stage_chat(1, &subject, &ciphertext)?;
        bob.connection.execute_batch("CREATE TRIGGER fail_transcript BEFORE INSERT ON transcript BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;")?;
        assert!(bob.process_history("engineering").is_err());
        assert_eq!(bob.rejected_history("engineering")?, 0);
        bob.connection
            .execute_batch("DROP TRIGGER fail_transcript;")?;
        assert_eq!(bob.process_history("engineering")?.decrypted, 1);
        assert_eq!(
            bob.history("engineering", 10, None)?[0]
                .plaintext
                .as_deref(),
            Some(b"must survive storage error".as_slice())
        );
        // The same failure at send time must roll back encryption AND the outbox.
        alice.connection.execute_batch("CREATE TRIGGER fail_transcript BEFORE INSERT ON transcript BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;")?;
        assert!(
            alice
                .encrypt_message("engineering", b"retry this send")
                .is_err()
        );
        alice
            .connection
            .execute_batch("DROP TRIGGER fail_transcript;")?;
        let next = alice.encrypt_message("engineering", b"retry this send")?;
        bob.stage_chat(2, &subject, &next)?;
        assert_eq!(bob.process_history("engineering")?.decrypted, 1);
        Ok(())
    }
    #[test]
    fn legacy_plaintext_gaps_and_other_groups_are_preserved() -> Result<()> {
        let (_a, _b, alice, bob) = pair()?;
        let subject = alice.group("engineering")?.subject("message");
        let old = alice.encrypt_message("engineering", b"legacy message")?;
        bob.decrypt_message("engineering", &old)?;
        // Model Milestone 7: ratchet/dedup existed, but plaintext was not retained.
        bob.connection.execute("DELETE FROM transcript", [])?;
        bob.stage_chat(1, &subject, &old)?;
        bob.create_group("other")?;
        assert_eq!(bob.process_history("other")?.decrypted, 0);
        assert!(bob.history("engineering", 10, None)?.is_empty());
        assert_eq!(bob.process_history("engineering")?.unavailable, 1);
        assert!(bob.history("engineering", 10, None)?[0].plaintext.is_none());
        let next = alice.encrypt_message("engineering", b"new message")?;
        // A misrouted copy must not poison the correctly routed ciphertext.
        bob.stage_chat(2, &bob.group("other")?.subject("message"), &next)?;
        assert_eq!(bob.process_history("other")?.rejected, 1);
        bob.stage_chat(3, &subject, &next)?;
        assert_eq!(bob.process_history("engineering")?.decrypted, 1);
        Ok(())
    }
}
