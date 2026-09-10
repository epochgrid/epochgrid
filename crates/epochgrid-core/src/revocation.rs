//! Signed irreversible revocation intent and local cryptographic exclusion state.
use crate::{
    identity::IdentityStore,
    transparency::{self, Checkpoint, Snapshot},
    wire::{self, Body},
};
use anyhow::{Context, Result, ensure};
use async_nats::jetstream::kv::Store;
use openmls::prelude::{KeyPackageIn, tls_codec::Deserialize as _};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub version: u16,
    pub user: String,
    pub device: String,
    pub nkey: String,
    pub author: String,
    pub signature: Vec<u8>,
}
impl RevokeRequest {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"EpochGrid device revocation v1\0".to_vec();
        bytes.extend(postcard::to_allocvec(&(
            self.version,
            &self.user,
            &self.device,
            &self.nkey,
            &self.author,
        ))?);
        Ok(bytes)
    }
    pub fn signed(user: &str, device: &str, nkey: &str, key: &nkeys::KeyPair) -> Result<Self> {
        wire::validate_id(user)?;
        wire::validate_id(device)?;
        let mut request = Self {
            version: 1,
            user: user.into(),
            device: device.into(),
            nkey: nkey.into(),
            author: key.public_key(),
            signature: Vec::new(),
        };
        request.signature = key.sign(&request.signing_bytes()?)?;
        Ok(request)
    }
    pub fn validate(&self, registrations: &Snapshot, previous: &[Revocation]) -> Result<()> {
        wire::validate_id(&self.user)?;
        wire::validate_id(&self.device)?;
        ensure!(self.version == 1, "unsupported revocation version");
        nkeys::KeyPair::from_public_key(&self.author)?
            .verify(&self.signing_bytes()?, &self.signature)?;
        ensure!(
            registrations
                .entries
                .iter()
                .any(|r| r.payload.user_id == self.user
                    && r.payload.device_id == self.device
                    && r.payload.nats_public_key == self.nkey),
            "revocation endpoint/key not registered"
        );
        ensure!(
            !previous.iter().any(|r| r.request.nkey == self.author),
            "revoked device cannot authorize revocation"
        );
        ensure!(
            self.author == registrations.checkpoint.signer
                || registrations
                    .entries
                    .iter()
                    .any(|r| r.payload.nats_public_key == self.author
                        && r.payload.user_id == self.user),
            "only an active device of this user or the operator may revoke"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    pub request: RevokeRequest,
    pub chat_cutoff: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationLog {
    pub checkpoint: Checkpoint,
    pub entries: Vec<Revocation>,
}
fn root(entries: &[Revocation]) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    match entries.len() {
        0 => (),
        1 => {
            bytes.push(0);
            bytes.extend(postcard::to_allocvec(&entries[0])?);
        }
        n => {
            let split = n.next_power_of_two() / 2;
            bytes.push(1);
            bytes.extend(root(&entries[..split])?);
            bytes.extend(root(&entries[split..])?);
        }
    }
    transparency::hash(&bytes)
}
fn checkpoint_bytes(cp: &Checkpoint) -> Result<Vec<u8>> {
    let mut bytes = b"EpochGrid revocation checkpoint v1\0".to_vec();
    bytes.extend(postcard::to_allocvec(&(
        cp.version, cp.size, cp.root, &cp.signer,
    ))?);
    Ok(bytes)
}
impl RevocationLog {
    pub fn signed(entries: Vec<Revocation>, key: &nkeys::KeyPair) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            version: 1,
            size: entries.len() as u64,
            root: root(&entries)?,
            signer: key.public_key(),
            signature: Vec::new(),
        };
        checkpoint.signature = key.sign(&checkpoint_bytes(&checkpoint)?)?;
        let log = Self {
            checkpoint,
            entries,
        };
        wire::encode(Body::RevocationLog(log.clone()))?;
        Ok(log)
    }
    pub fn validate(&self, registrations: &Snapshot) -> Result<()> {
        registrations.validate()?;
        ensure!(
            self.entries.len() <= 256
                && self.checkpoint.size == self.entries.len() as u64
                && self.checkpoint.version == 1,
            "invalid revocation log size/version"
        );
        ensure!(
            self.checkpoint.signer == registrations.checkpoint.signer,
            "revocation signer differs from directory"
        );
        nkeys::KeyPair::from_public_key(&self.checkpoint.signer)?.verify(
            &checkpoint_bytes(&self.checkpoint)?,
            &self.checkpoint.signature,
        )?;
        ensure!(
            root(&self.entries)? == self.checkpoint.root,
            "revocation root mismatch"
        );
        wire::encode(Body::RevocationLog(self.clone()))?;
        let mut keys = BTreeSet::new();
        for (i, entry) in self.entries.iter().enumerate() {
            entry.request.validate(registrations, &self.entries[..i])?;
            ensure!(keys.insert(&entry.request.nkey), "duplicate revocation");
            ensure!(
                entry.chat_cutoff <= i64::MAX as u64,
                "invalid revocation CHAT cutoff"
            );
        }
        Ok(())
    }
    pub fn keys(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .map(|r| r.request.nkey.clone())
            .collect()
    }
}
pub async fn read(store: &Store, registrations: &Snapshot) -> Result<RevocationLog> {
    let bytes = store
        .get("revocations")
        .await?
        .context("revocation log missing; upgrade service")?;
    let Body::RevocationLog(log) = wire::decode(&bytes)? else {
        anyhow::bail!("invalid revocation envelope")
    };
    log.validate(registrations)?;
    Ok(log)
}
pub async fn initialize(
    store: &Store,
    registrations: &Snapshot,
    key: &nkeys::KeyPair,
) -> Result<()> {
    if store.get("revocations").await?.is_none() {
        let bytes = wire::encode(Body::RevocationLog(RevocationLog::signed(Vec::new(), key)?))?;
        let _ = store.create("revocations", bytes.into()).await;
    }
    read(store, registrations).await?;
    Ok(())
}
pub async fn append(
    store: &Store,
    registrations: &Snapshot,
    key: &nkeys::KeyPair,
    request: RevokeRequest,
    cutoff: u64,
) -> Result<RevocationLog> {
    for _ in 0..4 {
        let current = store
            .entry("revocations")
            .await?
            .context("revocation log missing")?;
        let Body::RevocationLog(mut log) = wire::decode(&current.value)? else {
            anyhow::bail!("invalid revocation log")
        };
        log.validate(registrations)?;
        request.validate(registrations, &log.entries)?;
        if log.entries.iter().any(|r| r.request.nkey == request.nkey) {
            return Ok(log);
        }
        log.entries.push(Revocation {
            request: request.clone(),
            chat_cutoff: cutoff,
        });
        let log = RevocationLog::signed(log.entries, key)?;
        log.validate(registrations)?;
        if store
            .update(
                "revocations",
                wire::encode(Body::RevocationLog(log.clone()))?.into(),
                current.revision,
            )
            .await
            .is_ok()
        {
            return Ok(log);
        }
    }
    anyhow::bail!("revocation could not be confirmed; retry")
}
impl IdentityStore {
    pub(crate) fn migrate_revocation(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=3)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
            self.connection.execute_batch("CREATE TABLE revoked_devices(nkey TEXT PRIMARY KEY,user TEXT NOT NULL,device TEXT NOT NULL,mls_key BLOB NOT NULL,cutoff INTEGER NOT NULL);
                CREATE TABLE group_coordinators(gid TEXT PRIMARY KEY,mls_key BLOB NOT NULL);
                CREATE TABLE blocked_outbox(id INTEGER PRIMARY KEY);
                CREATE TABLE revocation_checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),checkpoint BLOB NOT NULL);
                INSERT INTO epochgrid_migrations VALUES(3);")?;
            for descriptor in self.groups()? {
                self.refresh_coordinator(&self.load_group(&descriptor)?)?;
            }
            Ok(())
        })?;
        }
        Ok(())
    }
    pub fn revocation_checkpoint(&self) -> Result<Option<Checkpoint>> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT checkpoint FROM revocation_checkpoint WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| postcard::from_bytes(&bytes).map_err(Into::into))
            .transpose()
    }
    pub fn is_revoked(&self, nkey: &str) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_devices WHERE nkey=?1)",
            [nkey],
            |r| r.get(0),
        )?)
    }
    pub(crate) fn revoked_mls_key(&self, key: &[u8]) -> Result<Option<u64>> {
        Ok(self
            .connection
            .query_row(
                "SELECT cutoff FROM revoked_devices WHERE mls_key=?1",
                [key],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn accept_revocations(&self, log: &RevocationLog, registrations: &Snapshot) -> Result<()> {
        log.validate(registrations)?;
        self.transaction(|| {
            let previous: Option<Vec<u8>> = self.connection.query_row("SELECT checkpoint FROM revocation_checkpoint WHERE id=1",[],|r|r.get(0)).optional()?;
            if let Some(bytes) = previous {
                let previous: Checkpoint = postcard::from_bytes(&bytes)?;
                ensure!(previous.signer == log.checkpoint.signer && log.entries.len() as u64 >= previous.size, "REVOCATION FAILURE: signer changed or log truncated");
                ensure!(root(&log.entries[..previous.size as usize])? == previous.root, "REVOCATION FAILURE: history rewritten");
            }
            for revoked in &log.entries {
                let registration = registrations.entries.iter().find(|r| r.payload.nats_public_key == revoked.request.nkey).context("revoked registration missing")?;
                let key = KeyPackageIn::tls_deserialize_exact(&registration.payload.mls_key_package)?.unverified_credential().signature_key;
                self.connection.execute("INSERT OR IGNORE INTO revoked_devices VALUES(?1,?2,?3,?4,?5)",params![revoked.request.nkey,revoked.request.user,revoked.request.device,key.as_slice(),revoked.chat_cutoff])?;
            }
            self.connection.execute("INSERT INTO revocation_checkpoint VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET checkpoint=excluded.checkpoint",[postcard::to_allocvec(&log.checkpoint)?])?;
            Ok(())
        })
    }
}

pub async fn chat_cutoff(client: &async_nats::Client) -> Result<u64> {
    let mut chat = async_nats::jetstream::new(client.clone())
        .get_stream("CHAT")
        .await?;
    Ok(chat.info().await?.state.last_sequence)
}
pub async fn revoke(
    client: &async_nats::Client,
    local: &IdentityStore,
    user: &str,
    device: &str,
) -> Result<()> {
    let snapshot = transparency::audit(client, local).await?;
    let record = snapshot
        .entries
        .iter()
        .find(|r| r.payload.user_id == user && r.payload.device_id == device)
        .context("device not registered")?;
    let request = RevokeRequest::signed(
        user,
        device,
        &record.payload.nats_public_key,
        &local.nkey()?,
    )?;
    let reply = client
        .request(wire::REVOKE, wire::encode(Body::Revoke(request))?.into())
        .await?;
    ensure!(
        matches!(wire::decode(&reply.payload)?, Body::Revoked),
        "revocation not completed; intent may be durable, inspect status and retry"
    );
    transparency::audit(client, local).await?;
    for group in local.groups()? {
        crate::history::resume(local, client, &group.name).await?;
    }
    Ok(())
}
