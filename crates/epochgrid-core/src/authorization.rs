//! Non-secret group authorization projection; MLS still owns cryptographic membership.
use crate::identity_model::AuthRegistry;
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const SUBJECT: &str = "epochgrid.v1.channel.policy";

const DOMAIN: &[u8] = b"epochgrid/group-authorization/v1\0";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub nkey: String,
    pub leaf: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyUpdate {
    pub version: u16,
    pub gid: String,
    pub expected_generation: u64,
    pub epoch: u64,
    pub signer: String,
    pub members: Vec<Member>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicy {
    pub update: PolicyUpdate,
    pub signature: Vec<u8>,
}
impl PolicyUpdate {
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(postcard::to_allocvec(self)?);
        Ok(bytes)
    }
    pub fn sign(self, key: &nkeys::KeyPair) -> Result<SignedPolicy> {
        ensure!(self.signer == key.public_key(), "policy signer mismatch");
        Ok(SignedPolicy {
            signature: key.sign(&self.bytes()?)?,
            update: self,
        })
    }
}
impl AuthRegistry {
    /// Apply an authenticated coordinator snapshot atomically. Returns its generation.
    pub fn apply_policy(&mut self, signed: &SignedPolicy) -> Result<u64> {
        let update = &signed.update;
        ensure!(update.version == 1, "unsupported policy version");
        validate_gid(&update.gid)?;
        ensure!(
            !update.members.is_empty() && update.members.len() <= 128,
            "invalid policy size"
        );
        ensure!(
            update.epoch <= i64::MAX as u64 && update.expected_generation < i64::MAX as u64,
            "policy counter overflow"
        );
        nkeys::KeyPair::from_public_key(&update.signer)?
            .verify(&update.bytes()?, &signed.signature)?;
        let bytes = postcard::to_allocvec(update)?;
        // IMMEDIATE excludes concurrent enrollment/revocation/policy writers during checks.
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.authorize(&update.signer)?;
            let mut keys = BTreeSet::new();
            let mut previous = None;
            for member in &update.members {
                ensure!(keys.insert(&member.nkey), "duplicate policy device");
                ensure!(
                    previous.is_none_or(|leaf| leaf < member.leaf),
                    "policy leaves must be unique and ordered"
                );
                previous = Some(member.leaf);
                self.authorize(&member.nkey)?;
            }
            let current: Option<(u64,u64,String,Vec<u8>)> = self.db.query_row(
                "SELECT generation,epoch,coordinator,last_update FROM authorization_groups WHERE gid=?1",
                [&update.gid], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            match current {
                Some((generation, epoch, coordinator, last)) => {
                    if generation == update.expected_generation + 1 && last == bytes {
                        return Ok(generation);
                    }
                    ensure!(
                        generation == update.expected_generation,
                        "stale policy generation"
                    );
                    ensure!(
                        coordinator == update.signer,
                        "only coordinator may change policy"
                    );
                    ensure!(update.epoch > epoch, "policy requires a newer MLS epoch");
                }
                None => {
                    ensure!(
                        update.expected_generation == 0
                            && update.epoch == 0
                            && update.members.len() == 1
                            && update.members[0].nkey == update.signer
                            && update.members[0].leaf == 0,
                        "new policy must contain only creator at epoch zero"
                    );
                }
            }
            // Coordinator removal is a separate lifecycle operation, not implicit delegation.
            ensure!(
                keys.contains(&update.signer),
                "coordinator must remain a member"
            );
            self.db.execute("UPDATE devices SET authorization_generation=authorization_generation+1 WHERE nkey IN (SELECT nkey FROM authorization_members WHERE gid=?1)", [&update.gid])?;
            let generation = update.expected_generation + 1;
            self.db.execute("INSERT INTO authorization_groups(gid,generation,epoch,coordinator,last_update) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(gid) DO UPDATE SET generation=excluded.generation,epoch=excluded.epoch,coordinator=excluded.coordinator,last_update=excluded.last_update", params![update.gid,generation,update.epoch,update.signer,bytes])?;
            self.db.execute(
                "DELETE FROM authorization_members WHERE gid=?1",
                [&update.gid],
            )?;
            for member in &update.members {
                self.db.execute(
                    "INSERT INTO authorization_members VALUES(?1,?2,?3)",
                    params![update.gid, member.nkey, member.leaf],
                )?;
                self.db.execute("UPDATE devices SET authorization_generation=authorization_generation+1 WHERE nkey=?1", [&member.nkey])?;
            }
            Ok(generation)
        })();
        match result {
            Ok(generation) => {
                self.db.execute_batch("COMMIT")?;
                Ok(generation)
            }
            Err(error) => {
                self.db
                    .execute_batch("ROLLBACK")
                    .context("rollback rejected policy")?;
                Err(error)
            }
        }
    }
    pub fn authorized_groups(&self, key: &str) -> Result<Vec<String>> {
        self.authorize(key)?;
        let mut query = self
            .db
            .prepare("SELECT gid FROM authorization_members WHERE nkey=?1 ORDER BY gid")?;
        Ok(query
            .query_map([key], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?)
    }
}
pub fn validate_gid(gid: &str) -> Result<()> {
    ensure!(
        gid.len() == 32
            && gid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid authorization group ID"
    );
    Ok(())
}

#[cfg(test)]
mod tests;

mod delivery;
pub use delivery::*;
