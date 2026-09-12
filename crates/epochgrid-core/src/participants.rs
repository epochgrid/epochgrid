//! Explicit MLS service participants. No backend credential or plaintext bypass.
use crate::{
    identity::IdentityStore,
    relationships::{ApplicationEvent, Relation},
    wire::validate_id,
};
use anyhow::{Context, Result, anyhow, ensure};
use openmls::prelude::*;
use rusqlite::params;

pub const STATUS_RESPONSE: &str = "EpochGrid service online\nNATS connected\nMLS group active";
/// The device component is covered by the signed registration and MLS credential.
pub fn member_label(identity: &str) -> String {
    match identity.split_once('/') {
        Some((user, "service")) => format!("@{user} [service]"),
        Some((user, _)) => user.into(),
        None => identity.into(),
    }
}
impl IdentityStore {
    pub(crate) fn migrate_participants(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=8)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
                self.connection.execute_batch("CREATE TABLE participant_events(gid TEXT NOT NULL,message_id TEXT NOT NULL,PRIMARY KEY(gid,message_id)); INSERT INTO epochgrid_migrations VALUES(8);")?;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub fn group_active(&self, name: &str) -> Result<bool> {
        Ok(self.load_group(&self.group(name)?)?.is_active())
    }
    /// Process at most 100 retained events. Caller must complete an online catch-up
    /// first. The caller flushes the normal ciphertext outbox after this commits.
    pub fn respond_status(&self, name: &str) -> Result<usize> {
        ensure!(
            self.registration()?.payload.device_id == "service",
            "participant requires a dedicated USER/service identity"
        );
        let descriptor = self.group(name)?;
        self.ensure_can_send(&self.load_group(&descriptor)?)?;
        let mut statement = self.connection.prepare("SELECT e.message_id,t.sender,e.event FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE e.gid=?1 AND NOT EXISTS(SELECT 1 FROM participant_events p WHERE p.gid=e.gid AND p.message_id=e.message_id) ORDER BY t.id LIMIT 100")?;
        let rows = statement
            .query_map([&descriptor.gid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut replies = 0;
        for (id, sender, bytes) in rows {
            replies += self.transaction(|| {
                let inserted = self.connection.execute(
                    "INSERT OR IGNORE INTO participant_events VALUES(?1,?2)",
                    params![descriptor.gid, id],
                )?;
                if inserted == 0 {
                    return Ok(0);
                }
                let event: ApplicationEvent = postcard::from_bytes(&bytes)?;
                let (_, device) = sender
                    .split_once('/')
                    .context("invalid authenticated sender")?;
                if device == "service" || event.relation.is_some() || event.content != b"/status" {
                    return Ok(0);
                }
                let target = self.resolve_message(name, &id)?;
                let response = ApplicationEvent::new(
                    self,
                    name,
                    STATUS_RESPONSE.as_bytes(),
                    Some(Relation::ReplyTo(target)),
                )?;
                self.encrypt_event_inner(name, &response)?;
                Ok(1)
            })?;
        }
        Ok(replies)
    }
    /// Group-specific removal, distinct from fabric-wide identity revocation.
    pub fn remove_member(&self, name: &str, user: &str, device: &str) -> Result<()> {
        validate_id(user)?;
        validate_id(device)?;
        let descriptor = self.group(name)?;
        let (signer, _) = self.signer()?;
        self.transaction(|| {
            let mut group = self.load_group(&descriptor)?;
            self.ensure_can_send(&group)?;
            ensure!(self.coordinator(&group)? == Some(group.own_leaf_index()), "only the active group coordinator can remove members");
            let identity = format!("{user}/{device}");
            let mut target = None;
            for member in group.members() {
                let credential = BasicCredential::try_from(member.credential)
                    .map_err(|e| anyhow!("invalid member credential: {e:?}"))?;
                if credential.identity() == identity.as_bytes() {
                    target = Some(member.index);
                }
            }
            let target = target.context("device is not a member of this channel")?;
            ensure!(target != group.own_leaf_index(), "coordinator self-removal is not supported");
            // Never retry old-epoch application ciphertext after local removal.
            self.connection.execute("INSERT OR IGNORE INTO blocked_outbox(id) SELECT id FROM outbox WHERE sent=0 AND subject=?1", [descriptor.subject("message")])?;
            let (commit, welcome, _) = group.remove_members(&self.provider, &signer, &[target]).map_err(|e| anyhow!("MLS member removal: {e:?}"))?;
            ensure!(welcome.is_none(), "unexpected removal Welcome");
            self.queue(&descriptor.subject("handshake"), &commit.to_bytes()?)?;
            group.merge_pending_commit(&self.provider).map_err(|e| anyhow!("persist removal Commit: {e:?}"))?;
            self.refresh_coordinator(&group)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
