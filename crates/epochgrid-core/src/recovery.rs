//! Identity-administration recovery, deliberately excluding all MLS private state.
use crate::{
    identity::{self, IdentityStore},
    transparency::Checkpoint,
    trust::{self, DeviceTrust},
    wire::{DeviceRegistration, validate_id},
};
use anyhow::{Context, Result, anyhow, ensure};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::AeadType};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// Fixed-width magic, version and algorithm; all authenticated as associated data.
const HEADER: &[u8; 10] = b"EGRECOV\0\x01\x01";
const NONCE_LEN: usize = 12;
pub const MAX_PACKAGE: usize = 1_048_576;
pub const MAX_SECRET_FILE: usize = 128;

/// No Debug/Display: expose only explicitly when saving a separate private file.
pub struct RecoverySecret(Zeroizing<[u8; 32]>);
impl RecoverySecret {
    fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(
            RustCrypto::default()
                .random_array()
                .map_err(|_| anyhow!("recovery randomness unavailable"))?,
        )))
    }
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let hex = text
            .strip_prefix("EG1-")
            .context("invalid recovery secret format")?;
        ensure!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid recovery secret format"
        );
        let mut key = Zeroizing::new([0u8; 32]);
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self(key))
    }
    pub fn encode(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let mut text = Zeroizing::new(String::with_capacity(69));
        text.push_str("EG1-");
        for byte in self.0.iter() {
            // Writing into a String cannot fail.
            let _ = write!(text, "{byte:02X}");
        }
        text.push('\n');
        text
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupHint {
    pub name: String,
    pub gid: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub exported_at: i64,
    pub restored_at: i64,
    pub fingerprint: String,
    pub groups: Vec<GroupHint>,
}
#[derive(Serialize, Deserialize)]
struct RevokedDevice {
    nkey: String,
    user: String,
    device: String,
    mls_key: Vec<u8>,
    cutoff: u64,
}
#[derive(Serialize, Deserialize)]
struct Evidence {
    devices: Vec<DeviceTrust>,
    directory_key: Option<String>,
    checkpoint: Option<Checkpoint>,
    revocation_checkpoint: Option<Checkpoint>,
    revoked: Vec<RevokedDevice>,
    alert: Option<String>,
}
/// Not a generic database snapshot. Adding any private MLS material changes the
/// security contract and requires a new format and explicit review.
#[derive(Serialize, Deserialize)]
pub struct RecoveryArchive {
    version: u16,
    exported_at: i64,
    registration: DeviceRegistration,
    seed: Zeroizing<String>,
    evidence: Evidence,
    groups: Vec<GroupHint>,
}
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
impl RecoveryArchive {
    /// Authenticate before parsing or performing any local writes. Reject trailing bytes.
    pub fn decrypt(bytes: &[u8], secret: &RecoverySecret) -> Result<Self> {
        ensure!(
            (HEADER.len() + NONCE_LEN + 16..=MAX_PACKAGE).contains(&bytes.len()),
            "invalid recovery package size"
        );
        ensure!(
            bytes.starts_with(HEADER),
            "unsupported recovery format, version or algorithm"
        );
        let nonce_end = HEADER.len() + NONCE_LEN;
        let plaintext = Zeroizing::new(
            RustCrypto::default()
                .aead_decrypt(
                    AeadType::Aes256Gcm,
                    secret.0.as_ref(),
                    &bytes[nonce_end..],
                    &bytes[HEADER.len()..nonce_end],
                    HEADER,
                )
                .map_err(|_| {
                    anyhow!("recovery authentication failed: wrong secret or damaged package")
                })?,
        );
        let (archive, remaining): (Self, _) =
            postcard::take_from_bytes(&plaintext).context("invalid recovery payload")?;
        ensure!(remaining.is_empty(), "trailing recovery payload");
        archive.validate()?;
        Ok(archive)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.exported_at > 0,
            "unsupported recovery payload"
        );
        identity::verify_signature(&self.registration)?;
        trust::fingerprint(&self.registration)?;
        ensure!(
            nkeys::KeyPair::from_seed(&self.seed)?.public_key()
                == self.registration.payload.nats_public_key,
            "recovery identity binding mismatch"
        );
        // Historical KeyPackage expiry is intentionally irrelevant: no Welcome can
        // be processed by the restored home and no MLS private key is exported.
        ensure!(
            self.groups.len() <= 1024
                && self.evidence.devices.len() <= 1024
                && self.evidence.revoked.len() <= 256,
            "recovery metadata limit exceeded"
        );
        for group in &self.groups {
            validate_id(&group.name)?;
            ensure!(
                group.gid.len() == 32 && group.gid.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid recovery group hint"
            );
        }
        for device in &self.evidence.devices {
            validate_id(&device.user)?;
            validate_id(&device.device)?;
            for fingerprint in [&device.fingerprint, &device.latest_fingerprint] {
                ensure!(
                    fingerprint.len() == 64 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid recovered fingerprint"
                );
            }
            ensure!(
                ["verified", "unverified", "changed"].contains(&device.state.as_str()),
                "invalid recovered trust state"
            );
        }
        if let Some(key) = &self.evidence.directory_key {
            ensure!(key.starts_with('U'), "invalid recovered directory key");
            nkeys::KeyPair::from_public_key(key)?;
        }
        for cp in [
            &self.evidence.checkpoint,
            &self.evidence.revocation_checkpoint,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(
                cp.version == 1
                    && cp.size <= 256
                    && Some(&cp.signer) == self.evidence.directory_key.as_ref(),
                "invalid recovered checkpoint"
            );
        }
        for device in &self.evidence.revoked {
            validate_id(&device.user)?;
            validate_id(&device.device)?;
            ensure!(
                device.nkey.starts_with('U')
                    && device.mls_key.len() == 32
                    && device.cutoff <= i64::MAX as u64,
                "invalid recovered revocation"
            );
            nkeys::KeyPair::from_public_key(&device.nkey)?;
        }
        Ok(())
    }
    /// Restores control authority only. A transaction commits the identity, trust
    /// evidence and recovery-only marker together; never overwrites an identity.
    pub fn restore(&self, store: &IdentityStore) -> Result<RecoveryStatus> {
        self.validate()?;
        let status = RecoveryStatus {
            exported_at: self.exported_at,
            restored_at: now()?,
            fingerprint: trust::fingerprint(&self.registration)?,
            groups: self.groups.clone(),
        };
        store.transaction(|| {
            let count: u64 = store.connection.query_row("SELECT (SELECT COUNT(*) FROM local_identity) + (SELECT COUNT(*) FROM groups) + (SELECT COUNT(*) FROM recovery_metadata) + (SELECT COUNT(*) FROM device_trust) + (SELECT COUNT(*) FROM transparency_state) + (SELECT COUNT(*) FROM revoked_devices) + (SELECT COUNT(*) FROM revocation_checkpoint) + (SELECT COUNT(*) FROM trust_alert) + (SELECT COUNT(*) FROM transcript) + (SELECT COUNT(*) FROM outbox) + (SELECT COUNT(*) FROM chat_deliveries) + (SELECT COUNT(*) FROM welcomes) + (SELECT COUNT(*) FROM received) + (SELECT COUNT(*) FROM attachments) + (SELECT COUNT(*) FROM receipt_messages) + (SELECT COUNT(*) FROM device_receipts)", [], |r| r.get(0))?;
            ensure!(count == 0, "recovery requires an uninitialized home; existing identity/trust state cannot be overwritten");
            store.connection.execute("INSERT INTO local_identity VALUES(1,?1,?2)", params![self.seed.as_str(), postcard::to_allocvec(&self.registration)?])?;
            for device in &self.evidence.devices {
                store.connection.execute("INSERT INTO device_trust VALUES(?1,?2,?3,?4,?5)", params![device.user,device.device,device.fingerprint,device.latest_fingerprint,device.state])?;
            }
            if let Some(key) = &self.evidence.directory_key {
                store.connection.execute("INSERT INTO transparency_state VALUES(1,?1,?2)", params![key, self.evidence.checkpoint.as_ref().map(postcard::to_allocvec).transpose()?])?;
            }
            if let Some(cp) = &self.evidence.revocation_checkpoint {
                store.connection.execute("INSERT INTO revocation_checkpoint VALUES(1,?1)", [postcard::to_allocvec(cp)?])?;
            }
            for device in &self.evidence.revoked {
                store.connection.execute("INSERT INTO revoked_devices VALUES(?1,?2,?3,?4,?5)", params![device.nkey,device.user,device.device,device.mls_key,device.cutoff])?;
            }
            if let Some(alert) = &self.evidence.alert {
                store.connection.execute("INSERT INTO trust_alert VALUES(1,?1)", [alert])?;
            }
            store.connection.execute("INSERT INTO recovery_metadata VALUES(1,?1)", [postcard::to_allocvec(&status)?])?;
            Ok(status)
        })
    }
}
impl IdentityStore {
    pub(crate) fn migrate_recovery(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=4)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
                self.connection.execute_batch("CREATE TABLE recovery_metadata(id INTEGER PRIMARY KEY CHECK(id=1), metadata BLOB NOT NULL); INSERT INTO epochgrid_migrations VALUES(4);")?;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub fn recovery_status(&self) -> Result<Option<RecoveryStatus>> {
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT metadata FROM recovery_metadata WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| postcard::from_bytes(&bytes).map_err(Into::into))
            .transpose()
    }
    pub fn ensure_messaging_identity(&self) -> Result<()> {
        ensure!(
            self.recovery_status()?.is_none(),
            "recovery-only home: enroll a fresh device and obtain a new invitation to resume messaging"
        );
        Ok(())
    }
    /// No network or filesystem output; callers must keep the secret separate.
    pub fn export_recovery(&self) -> Result<(Vec<u8>, RecoverySecret)> {
        self.ensure_messaging_identity()?;
        let registration = self.registration()?;
        ensure!(
            !["service", "system"].contains(&registration.payload.user_id.as_str()),
            "operator/system recovery is outside the device recovery scope"
        );
        ensure!(
            !self.is_revoked(&registration.payload.nats_public_key)?,
            "cannot export a known revoked device"
        );
        let devices = self.connection.prepare("SELECT user,device,fingerprint,latest_fingerprint,state FROM device_trust ORDER BY user,device")?
            .query_map([], |r| Ok(DeviceTrust { user:r.get(0)?, device:r.get(1)?, fingerprint:r.get(2)?, latest_fingerprint:r.get(3)?, state:r.get(4)? }))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let revoked = self
            .connection
            .prepare("SELECT nkey,user,device,mls_key,cutoff FROM revoked_devices ORDER BY nkey")?
            .query_map([], |r| {
                Ok(RevokedDevice {
                    nkey: r.get(0)?,
                    user: r.get(1)?,
                    device: r.get(2)?,
                    mls_key: r.get(3)?,
                    cutoff: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let seed = Zeroizing::new(self.connection.query_row(
            "SELECT seed FROM local_identity WHERE id=1",
            [],
            |r| r.get::<_, String>(0),
        )?);
        let archive = RecoveryArchive {
            version: 1,
            exported_at: now()?,
            registration,
            seed,
            evidence: Evidence {
                devices,
                directory_key: self.directory_key()?,
                checkpoint: self.checkpoint()?,
                revocation_checkpoint: self.revocation_checkpoint()?,
                revoked,
                alert: self
                    .connection
                    .query_row("SELECT message FROM trust_alert WHERE id=1", [], |r| {
                        r.get(0)
                    })
                    .optional()?,
            },
            groups: self
                .groups()?
                .into_iter()
                .map(|g| GroupHint {
                    name: g.name,
                    gid: g.gid,
                })
                .collect(),
        };
        archive.validate()?;
        let plaintext = Zeroizing::new(postcard::to_allocvec(&archive)?);
        ensure!(
            plaintext.len() <= MAX_PACKAGE - HEADER.len() - NONCE_LEN - 16,
            "recovery package exceeds size limit"
        );
        let secret = RecoverySecret::generate()?;
        let nonce: [u8; NONCE_LEN] = RustCrypto::default()
            .random_array()
            .map_err(|_| anyhow!("recovery randomness unavailable"))?;
        let ciphertext = RustCrypto::default()
            .aead_encrypt(
                AeadType::Aes256Gcm,
                secret.0.as_ref(),
                &plaintext,
                &nonce,
                HEADER,
            )
            .map_err(|_| anyhow!("recovery encryption failed"))?;
        let mut bytes = Vec::with_capacity(HEADER.len() + NONCE_LEN + ciphertext.len());
        bytes.extend_from_slice(HEADER);
        bytes.extend_from_slice(&nonce);
        bytes.extend(ciphertext);
        Ok((bytes, secret))
    }
}

#[cfg(test)]
mod tests;
