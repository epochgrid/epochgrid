use crate::{identity::IdentityStore, messaging::InvalidMessage, wire};
use anyhow::{Result, anyhow, ensure};
use openmls::prelude::{tls_codec::Deserialize as _, *};

impl IdentityStore {
    pub(crate) fn before_join(&self, name: &str, bytes: &[u8]) -> Result<bool> {
        ensure!(bytes.len() <= wire::MAX_WIRE, InvalidMessage);
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| InvalidMessage)?;
        ensure!(
            message.wire_format() == WireFormat::PrivateMessage,
            InvalidMessage
        );
        let message = message
            .try_into_protocol_message()
            .map_err(|_| InvalidMessage)?;
        let group = self.group(name)?;
        ensure!(
            message.group_id().as_slice() == group.mls_id,
            InvalidMessage
        );
        let epoch: u64 = self.connection.query_row(
            "SELECT epoch FROM group_join_epochs WHERE gid=?1",
            [group.gid],
            |r| r.get(0),
        )?;
        Ok(message.epoch().as_u64() < epoch)
    }
    pub(crate) fn process_handshake(&self, name: &str, bytes: &[u8], sequence: u64) -> Result<()> {
        let descriptor = self.group(name)?;
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| InvalidMessage)?;
        ensure!(
            message.wire_format() == WireFormat::PrivateMessage,
            InvalidMessage
        );
        let message = message
            .try_into_protocol_message()
            .map_err(|_| InvalidMessage)?;
        ensure!(
            message.group_id().as_slice() == descriptor.mls_id
                && message.content_type() == ContentType::Commit,
            InvalidMessage
        );
        let known: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM received WHERE payload=?1 UNION ALL SELECT 1 FROM outbox WHERE payload=?1)", [bytes], |r| r.get(0))?;
        if known {
            return Ok(());
        }
        let mut group = self.load_group(&descriptor)?;
        let processed =
            group
                .process_message(&self.provider, message)
                .map_err(|error| match error {
                    ProcessMessageError::StorageError(error) => {
                        anyhow!("MLS storage failure: {error:?}")
                    }
                    ProcessMessageError::LibraryError(error) => {
                        anyhow!("MLS library failure: {error:?}")
                    }
                    ProcessMessageError::GroupStateError(error) => {
                        anyhow!("MLS group state failure: {error:?}")
                    }
                    _ => InvalidMessage.into(),
                })?;
        let Sender::Member(index) = processed.sender() else {
            return Err(InvalidMessage.into());
        };
        let index = *index;
        let ProcessedMessageContent::StagedCommitMessage(commit) = processed.into_content() else {
            return Err(InvalidMessage.into());
        };
        self.validate_commit_author(&descriptor, index, &commit, sequence)?;
        self.block_revoked_outbox()?;
        group
            .merge_staged_commit(&self.provider, *commit)
            .map_err(|e| anyhow!("persist MLS commit: {e:?}"))?;
        self.refresh_coordinator(&group)?;
        self.connection
            .execute("INSERT INTO received(payload) VALUES(?1)", [bytes])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn queued(store: &IdentityStore, suffix: &str) -> Result<Vec<u8>> {
        Ok(store.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE ?1 ORDER BY id DESC LIMIT 1",
            [format!("%{suffix}")],
            |r| r.get(0),
        )?)
    }
    #[test]
    fn third_device_commit_rollback_epoch_floor_and_restart() -> Result<()> {
        let a = tempfile::tempdir()?;
        let b = tempfile::tempdir()?;
        let d = tempfile::tempdir()?;
        let mut alice = IdentityStore::open(a.path())?;
        let mut bob = IdentityStore::open(b.path())?;
        let mut desktop = IdentityStore::open(d.path())?;
        let ar = alice.init("alice", "laptop")?;
        let br = bob.init("bob", "laptop")?;
        let dr = desktop.init("alice", "desktop")?;
        let group = alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &br)?;
        bob.accept_welcome(&queued(&alice, "inbox")?, &ar)?;
        let old = alice.encrypt_message("engineering", b"before desktop joined")?;
        bob.decrypt_message("engineering", &old)?;
        assert!(bob.prepare_invitation("engineering", &dr).is_err());
        alice.prepare_invitation("engineering", &dr)?;
        let commit = queued(&alice, "handshake")?;
        desktop.accept_welcome(&queued(&alice, "inbox")?, &ar)?;
        let mut tampered = commit.clone();
        let last = tampered.last_mut().ok_or_else(|| anyhow!("empty Commit"))?;
        *last ^= 1;
        bob.stage_chat(1, &group.subject("handshake"), &tampered)?;
        assert_eq!(bob.process_history("engineering")?.rejected, 1);
        assert_eq!(bob.rejected_history("engineering")?, 1);
        assert_eq!(bob.group_epoch("engineering")?, 1);
        bob.stage_chat(2, &group.subject("handshake"), &commit)?;
        bob.connection.execute_batch("CREATE TRIGGER fail_received BEFORE INSERT ON received BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;")?;
        assert!(bob.process_history("engineering").is_err());
        assert_eq!(bob.group_epoch("engineering")?, 1);
        bob.connection
            .execute_batch("DROP TRIGGER fail_received;")?;
        bob.process_history("engineering")?;
        assert_eq!(bob.group_epoch("engineering")?, 2);
        assert_eq!(bob.users("engineering")?, vec!["alice", "bob"]);
        assert_eq!(bob.members("engineering")?.len(), 3);
        desktop.stage_chat(1, &group.subject("message"), &old)?;
        desktop.stage_chat(2, &group.subject("handshake"), &commit)?;
        assert_eq!(desktop.process_history("engineering")?.rejected, 0);
        assert!(desktop.history("engineering", 10, None)?.is_empty());
        let message = alice.encrypt_message("engineering", b"both Alice devices")?;
        for store in [&bob, &desktop] {
            store.stage_chat(3, &group.subject("message"), &message)?;
            assert_eq!(store.process_history("engineering")?.decrypted, 1);
        }
        drop(alice);
        drop(bob);
        drop(desktop);
        let alice = IdentityStore::open(a.path())?;
        let bob = IdentityStore::open(b.path())?;
        let desktop = IdentityStore::open(d.path())?;
        let reply = desktop.encrypt_message("engineering", b"desktop reply")?;
        for store in [&alice, &bob] {
            assert_eq!(
                store
                    .decrypt_message("engineering", &reply)?
                    .ok_or_else(|| anyhow!("missing reply"))?
                    .sender,
                "alice/desktop"
            );
            assert_eq!(store.group_epoch("engineering")?, 2);
        }
        assert_ne!(alice.nkey()?.public_key(), desktop.nkey()?.public_key());
        // Emulate the unversioned M11 schema, then verify an additive checkpoint migration.
        bob.connection
            .execute_batch("DROP TABLE group_join_epochs; DROP TABLE epochgrid_migrations; DROP TABLE device_trust; DROP TABLE transparency_state; DROP TABLE trust_alert; DROP TABLE revoked_devices; DROP TABLE revocation_checkpoint; DROP TABLE blocked_outbox; DROP TABLE group_coordinators; DROP TABLE recovery_metadata;")?;
        let count = bob.history("engineering", 10, None)?.len();
        drop(bob);
        let bob = IdentityStore::open(b.path())?;
        assert_eq!(bob.group_epoch("engineering")?, 2);
        assert_eq!(bob.history("engineering", 10, None)?.len(), count);
        assert_eq!(bob.registration()?, br);
        let next = alice.encrypt_message("engineering", b"after migration")?;
        assert!(bob.decrypt_message("engineering", &next)?.is_some());
        Ok(())
    }
}
