//! Deterministic removal coordinator and MLS transaction boundaries.
use crate::{groups::Group, identity::IdentityStore};
use anyhow::{Result, anyhow, ensure};
use openmls::prelude::*;
use rusqlite::{OptionalExtension, params};

impl IdentityStore {
    pub(crate) fn revoked_leaves(&self, group: &MlsGroup) -> Result<Vec<LeafNodeIndex>> {
        group
            .members()
            .filter_map(|member| match self.revoked_mls_key(&member.signature_key) {
                Ok(Some(_)) => Some(Ok(member.index)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }
    fn stored_coordinator(&self, group: &MlsGroup) -> Result<Option<Vec<u8>>> {
        Ok(self.connection.query_row("SELECT mls_key FROM group_coordinators WHERE gid=(SELECT gid FROM groups WHERE mls_id=?1)",[group.group_id().as_slice()],|r|r.get(0)).optional()?)
    }
    pub(crate) fn coordinator(&self, group: &MlsGroup) -> Result<Option<LeafNodeIndex>> {
        let revoked = self.revoked_leaves(group)?;
        if let Some(key) = self.stored_coordinator(group)?
            && let Some(member) = group.members().find(|m| m.signature_key == key)
            && !revoked.contains(&member.index)
        {
            return Ok(Some(member.index));
        }
        Ok(group
            .members()
            .map(|m| m.index)
            .filter(|i| !revoked.contains(i))
            .min())
    }
    pub(crate) fn refresh_coordinator(&self, group: &MlsGroup) -> Result<()> {
        // Keep the historical coordinator until its leaf is actually removed.
        if let Some(key) = self.stored_coordinator(group)?
            && group.members().any(|member| member.signature_key == key)
        {
            return Ok(());
        }
        if let Some(index) = self.coordinator(group)?
            && let Some(member) = group.members().find(|m| m.index == index)
        {
            let descriptor = Group::from_mls_id(group.group_id())?;
            self.connection.execute("INSERT INTO group_coordinators VALUES(?1,?2) ON CONFLICT(gid) DO UPDATE SET mls_key=excluded.mls_key",params![descriptor.gid,member.signature_key])?;
        }
        Ok(())
    }
    pub fn rekey_pending(&self, name: &str) -> Result<bool> {
        Ok(!self
            .revoked_leaves(&self.load_group(&self.group(name)?)?)?
            .is_empty())
    }
    pub(crate) fn ensure_can_send(&self, group: &MlsGroup) -> Result<()> {
        ensure!(
            !self.is_revoked(&self.nkey()?.public_key())? && group.is_active(),
            "this device is revoked or removed from the group"
        );
        ensure!(
            self.revoked_leaves(group)?.is_empty(),
            "group rekey pending; its active coordinator must sync before sending"
        );
        Ok(())
    }
    pub fn reconcile_revocations(&self, name: &str) -> Result<bool> {
        let descriptor = self.group(name)?;
        let group = self.load_group(&descriptor)?;
        if !group.is_active()
            || self.is_revoked(&self.nkey()?.public_key())?
            || self.coordinator(&group)? != Some(group.own_leaf_index())
        {
            return Ok(false);
        }
        let removed = self.revoked_leaves(&group)?;
        if removed.is_empty() {
            return Ok(false);
        }
        let (signer, _) = self.signer()?;
        self.transaction(|| {
            self.block_revoked_outbox()?;
            let mut group = self.load_group(&descriptor)?;
            let (commit, welcome, _) = group
                .remove_members(&self.provider, &signer, &removed)
                .map_err(|e| anyhow!("MLS remove revoked leaves: {e:?}"))?;
            ensure!(welcome.is_none(), "removal unexpectedly produced a Welcome");

            group
                .merge_pending_commit(&self.provider)
                .map_err(|e| anyhow!("persist removal Commit: {e:?}"))?;
            self.refresh_coordinator(&group)?;
            self.queue_policy(&group)?;
            self.queue(&descriptor.subject("handshake"), &commit.to_bytes()?)?;
            Ok(true)
        })
    }
    /// Never publish queued application ciphertext under a known revoked epoch
    /// or after this installation has been removed from a group.
    pub(crate) fn block_revoked_outbox(&self) -> Result<()> {
        for descriptor in self.groups()? {
            let group = self.load_group(&descriptor)?;
            if group.is_active() && self.revoked_leaves(&group)?.is_empty() {
                continue;
            }
            self.connection.execute("INSERT OR IGNORE INTO blocked_outbox(id) SELECT id FROM outbox WHERE sent=0 AND subject=?1", [descriptor.subject("message")])?;
        }
        Ok(())
    }
    pub(crate) fn validate_commit_author(
        &self,
        descriptor: &Group,
        index: LeafNodeIndex,
        commit: &StagedCommit,
        sequence: u64,
    ) -> Result<()> {
        use crate::messaging::InvalidMessage;
        let group = self.load_group(descriptor)?;
        let sender = group
            .members()
            .find(|m| m.index == index)
            .ok_or(InvalidMessage)?;
        // Identity replacement is not supported. Keep the directory binding stable
        // even when a custom client supplies a valid MLS self-update Commit.
        if let Some(leaf) = commit.update_path_leaf_node() {
            ensure!(
                leaf.signature_key().as_slice() == sender.signature_key
                    && leaf.credential() == &sender.credential,
                InvalidMessage
            );
        }
        ensure!(
            commit.queued_proposals().count()
                == commit.add_proposals().count() + commit.remove_proposals().count(),
            InvalidMessage
        );
        if let Some(cutoff) = self.revoked_mls_key(&sender.signature_key)? {
            ensure!(sequence <= cutoff, InvalidMessage);
        }
        let key = self.stored_coordinator(&group)?;
        let leader = group
            .members()
            .find(|m| Some(&m.signature_key) == key.as_ref())
            .map(|m| m.index);
        if leader == Some(index) {
            return Ok(());
        }
        let expected = self.revoked_leaves(&group)?;
        let removed: Vec<_> = commit
            .remove_proposals()
            .map(|p| p.remove_proposal().removed())
            .collect();
        ensure!(
            self.coordinator(&group)? == Some(index)
                && !expected.is_empty()
                && removed.len() == expected.len()
                && expected.iter().all(|i| removed.contains(i))
                && commit.queued_proposals().count() == removed.len(),
            InvalidMessage
        );
        Ok(())
    }
}
