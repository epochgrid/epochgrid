//! Bounded, signed Merkle snapshots. Full snapshots provide inclusion and prefix evidence.
use crate::{
    identity,
    wire::{self, Body, DeviceRegistration},
};
use anyhow::{Context, Result, anyhow, ensure};
use async_nats::jetstream::kv::Store;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::HashType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub version: u16,
    pub size: u64,
    pub root: [u8; 32],
    pub signer: String,
    pub signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub checkpoint: Checkpoint,
    pub entries: Vec<DeviceRegistration>,
}
pub fn hash(bytes: &[u8]) -> Result<[u8; 32]> {
    RustCrypto::default()
        .hash(HashType::Sha2_256, bytes)
        .map_err(|e| anyhow!("SHA-256 failed: {e:?}"))?
        .try_into()
        .map_err(|_| anyhow!("unexpected SHA-256 length"))
}
pub fn root(entries: &[DeviceRegistration]) -> Result<[u8; 32]> {
    match entries.len() {
        0 => hash(&[]),
        1 => {
            let mut bytes = vec![0];
            bytes.extend(wire::encode(Body::Register(entries[0].clone()))?);
            hash(&bytes)
        }
        n => {
            let split = n.next_power_of_two() / 2;
            let mut bytes = vec![1];
            bytes.extend(root(&entries[..split])?);
            bytes.extend(root(&entries[split..])?);
            hash(&bytes)
        }
    }
}
impl Checkpoint {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"EpochGrid transparency checkpoint v1\0".to_vec();
        bytes.extend(postcard::to_allocvec(&(
            self.version,
            self.size,
            self.root,
            &self.signer,
        ))?);
        Ok(bytes)
    }
}
impl Snapshot {
    pub fn signed(entries: Vec<DeviceRegistration>, key: &nkeys::KeyPair) -> Result<Self> {
        let mut checkpoint = Checkpoint {
            version: 1,
            size: entries.len() as u64,
            root: root(&entries)?,
            signer: key.public_key(),
            signature: Vec::new(),
        };
        checkpoint.signature = key.sign(&checkpoint.signing_bytes()?)?;
        let snapshot = Self {
            checkpoint,
            entries,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.entries.len() <= 256,
            "transparency entry limit exceeded"
        );
        wire::encode(Body::AuditLog(self.clone()))?;
        let cp = &self.checkpoint;
        ensure!(
            cp.version == 1 && cp.size == self.entries.len() as u64,
            "invalid transparency version/size"
        );
        ensure!(
            cp.signer.starts_with('U'),
            "transparency signer must be a user NKey"
        );
        nkeys::KeyPair::from_public_key(&cp.signer)?.verify(&cp.signing_bytes()?, &cp.signature)?;
        ensure!(
            root(&self.entries)? == cp.root,
            "transparency root mismatch"
        );
        let mut endpoints = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for entry in &self.entries {
            // Historical packages may expire. Admission verifies OpenMLS validity;
            // auditing checks the unchanged signed public record, not present usability.
            identity::verify_signature(entry)?;
            ensure!(
                endpoints.insert(entry.payload.key())
                    && keys.insert(&entry.payload.nats_public_key),
                "duplicate transparency identity"
            );
        }
        Ok(())
    }
    pub fn extends(&self, previous: &Checkpoint) -> Result<()> {
        ensure!(
            self.checkpoint.signer == previous.signer,
            "TRANSPARENCY FAILURE: directory signer changed"
        );
        ensure!(
            self.entries.len() as u64 >= previous.size,
            "TRANSPARENCY FAILURE: log truncated"
        );
        ensure!(
            root(&self.entries[..previous.size as usize])? == previous.root,
            "TRANSPARENCY FAILURE: registration history rewritten"
        );
        Ok(())
    }
}
/// One KV CAS publishes entries and signed checkpoint together. No partial log append.
pub async fn append(
    store: &Store,
    key: &nkeys::KeyPair,
    registration: DeviceRegistration,
) -> Result<()> {
    identity::verify(&registration)?;
    for _ in 0..4 {
        let current = store
            .entry("snapshot")
            .await?
            .context("transparency log missing; restart service")?;
        let mut snapshot = decode(&current.value)?;
        ensure!(
            snapshot.checkpoint.signer == key.public_key(),
            "directory signer changed"
        );
        if let Some(existing) = snapshot
            .entries
            .iter()
            .find(|r| r.payload.key() == registration.payload.key())
        {
            ensure!(
                existing == &registration,
                "immutable transparency registration conflict"
            );
            return Ok(());
        }
        snapshot.entries.push(registration.clone());
        let snapshot = Snapshot::signed(snapshot.entries, key)?;
        let bytes = wire::encode(Body::AuditLog(snapshot))?;
        if store
            .update("snapshot", bytes.into(), current.revision)
            .await
            .is_ok()
        {
            return Ok(());
        }
        // Re-read after a competing append or an ambiguous acknowledgment.
    }
    anyhow::bail!("transparency append could not be confirmed; retry registration")
}
pub fn decode(bytes: &[u8]) -> Result<Snapshot> {
    let Body::AuditLog(snapshot) = wire::decode(bytes)? else {
        anyhow::bail!("transparency response missing or unsupported")
    };
    snapshot.validate()?;
    Ok(snapshot)
}
pub async fn read(store: &Store) -> Result<Snapshot> {
    decode(
        &store
            .get("snapshot")
            .await?
            .context("transparency log missing")?,
    )
}
pub async fn initialize(store: &Store, key: &nkeys::KeyPair) -> Result<()> {
    if store.get("snapshot").await?.is_none() {
        let empty = wire::encode(Body::AuditLog(Snapshot::signed(Vec::new(), key)?))?;
        // A competing initializer must be validated below, not overwritten.
        let _ = store.create("snapshot", empty.into()).await;
    }
    ensure!(
        read(store).await?.checkpoint.signer == key.public_key(),
        "directory signer differs from persisted log"
    );
    Ok(())
}
pub async fn audit(
    client: &async_nats::Client,
    local: &identity::IdentityStore,
) -> Result<Snapshot> {
    let result = async {
        let reply =
            crate::transport::request_idempotent(client, wire::AUDIT, Body::RegistrationAudit)
                .await?;
        let snapshot = decode(&reply.payload)?;
        let reply =
            crate::transport::request_idempotent(client, wire::REVOCATIONS, Body::RevocationAudit)
                .await?;
        let Body::RevocationLog(revocations) = wire::decode(&reply.payload)? else {
            anyhow::bail!("revocation audit missing; upgrade service")
        };
        revocations.validate(&snapshot)?;
        local.accept_checkpoint(&snapshot)?;
        local.accept_revocations(&revocations, &snapshot)?;
        local.clear_transparency_warning()?;
        Ok::<_, anyhow::Error>(snapshot)
    }
    .await;
    if let Err(error) = &result {
        local.transparency_failure(&format!("TRANSPARENCY FAILURE: {error}"))?;
    }
    result
}
pub async fn lookup(
    client: &async_nats::Client,
    local: &identity::IdentityStore,
    user: &str,
    device: &str,
) -> Result<DeviceRegistration> {
    wire::validate_id(user)?;
    wire::validate_id(device)?;
    let snapshot = audit(client, local).await?;
    let record = snapshot
        .entries
        .into_iter()
        .find(|r| r.payload.user_id == user && r.payload.device_id == device)
        .context("device not found in authenticated registration log")?;
    ensure!(
        !local.is_revoked(&record.payload.nats_public_key)?,
        "device is revoked"
    );
    identity::verify(&record)?;
    local.observe_device(&record)?;
    Ok(record)
}
pub async fn devices(
    client: &async_nats::Client,
    local: &identity::IdentityStore,
    user: &str,
) -> Result<Vec<DeviceRegistration>> {
    wire::validate_id(user)?;
    let snapshot = audit(client, local).await?;
    let mut records: Vec<_> = snapshot
        .entries
        .into_iter()
        .filter(|r| r.payload.user_id == user)
        .collect();
    for record in &records {
        identity::verify(record)?;
        local.observe_device(record)?;
    }
    records.sort_by(|a, b| a.payload.device_id.cmp(&b.payload.device_id));
    Ok(records)
}

pub async fn provision(
    client: async_nats::Client,
    directory: &Store,
    enrollment: &crate::transport::Enrollment,
    key: &nkeys::KeyPair,
) -> Result<Store> {
    let js = async_nats::jetstream::new(client);
    let log = match js.get_key_value("TRANSPARENCY").await {
        Ok(store) => store,
        Err(_) => {
            js.create_key_value(async_nats::jetstream::kv::Config {
                bucket: "TRANSPARENCY".into(),
                history: 1,
                max_value_size: wire::MAX_WIRE as i32,
                ..Default::default()
            })
            .await?
        }
    };
    initialize(&log, key).await?;
    let existing = read(&log).await?;
    // Import the existing immutable M12 directory; no device reinitialization.
    for endpoint in enrollment.keys() {
        if let Some(bytes) = directory.get(endpoint).await? {
            let Body::Register(registration) = wire::decode(&bytes)? else {
                anyhow::bail!("invalid legacy registration")
            };
            ensure!(
                registration.payload.key() == *endpoint,
                "legacy directory endpoint mismatch"
            );
            if let Some(logged) = existing
                .entries
                .iter()
                .find(|r| r.payload.key() == *endpoint)
            {
                ensure!(
                    logged == &registration,
                    "directory projection differs from authenticated log"
                );
            } else {
                register(&log, directory, enrollment, key, registration).await?;
            }
        }
    }
    // Repair a crash after atomic log append but before writing its directory projection.
    for record in read(&log).await?.entries {
        crate::transport::project_registration(directory, enrollment, record).await?;
    }
    Ok(log)
}
pub async fn register(
    log: &Store,
    directory: &Store,
    enrollment: &crate::transport::Enrollment,
    key: &nkeys::KeyPair,
    registration: DeviceRegistration,
) -> Result<()> {
    identity::verify(&registration)?;
    ensure!(
        enrollment.get(&registration.payload.key()) == Some(&registration.payload.nats_public_key),
        "device not enrolled"
    );
    if let Some(existing) = directory.get(registration.payload.key()).await? {
        ensure!(
            wire::decode(&existing)? == Body::Register(registration.clone()),
            "directory registration conflict"
        );
    }
    append(log, key, registration.clone()).await?;
    crate::transport::accept(directory, enrollment, registration).await
}
