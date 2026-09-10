//! Installation-local TOFU pins and explicit, out-of-band device verification.
use crate::{
    identity::{self, IdentityStore},
    transparency::{self, Checkpoint, Snapshot},
    wire::DeviceRegistration,
};
use anyhow::{Context, Result, ensure};
use openmls::prelude::{
    KeyPackageIn,
    tls_codec::{Deserialize as _, Serialize as _},
};
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTrust {
    pub user: String,
    pub device: String,
    pub fingerprint: String,
    pub latest_fingerprint: String,
    pub state: String,
}
pub fn fingerprint(registration: &DeviceRegistration) -> Result<String> {
    identity::verify_signature(registration)?;
    let p = &registration.payload;
    // The NKey signature binds these bytes even when a historical package expired.
    // Actual invitation/discovery still performs full OpenMLS KeyPackage validation.
    let credential =
        KeyPackageIn::tls_deserialize_exact(&p.mls_key_package)?.unverified_credential();
    ensure!(
        credential.credential.tls_serialize_detached()? == p.mls_credential,
        "fingerprint credential mismatch"
    );
    let mut bytes = b"EpochGrid device fingerprint v1\0".to_vec();
    bytes.extend(postcard::to_allocvec(&(
        p.protocol_version,
        &p.user_id,
        &p.device_id,
        &p.nats_public_key,
        &p.mls_credential,
        credential.signature_key.as_slice(),
    ))?);
    Ok(transparency::hash(&bytes)?
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}
pub fn display_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c))
        .collect::<Vec<_>>()
        .join(" ")
}
impl IdentityStore {
    pub(crate) fn migrate_trust(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=2)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
                self.connection.execute_batch("CREATE TABLE device_trust(
                    user TEXT NOT NULL, device TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    latest_fingerprint TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('unverified','verified','changed')),
                    PRIMARY KEY(user,device));
                    CREATE TABLE transparency_state(id INTEGER PRIMARY KEY CHECK(id=1), signer TEXT NOT NULL, checkpoint BLOB);
                    CREATE TABLE trust_alert(id INTEGER PRIMARY KEY CHECK(id=1), message TEXT NOT NULL);
                    INSERT INTO epochgrid_migrations VALUES(2);")?;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub fn device_trust(&self, user: &str, device: &str) -> Result<Option<DeviceTrust>> {
        Ok(self.connection.query_row("SELECT fingerprint,latest_fingerprint,state FROM device_trust WHERE user=?1 AND device=?2", params![user,device], |r| Ok(DeviceTrust { user:user.into(), device:device.into(), fingerprint:r.get(0)?, latest_fingerprint:r.get(1)?, state:r.get(2)? })).optional()?)
    }
    pub fn observe_device(&self, registration: &DeviceRegistration) -> Result<()> {
        let fingerprint = fingerprint(registration)?;
        let p = &registration.payload;
        let changed = self.transaction(|| {
            if let Some(previous) = self.device_trust(&p.user_id, &p.device_id)? {
                if previous.state == "changed" && previous.fingerprint == fingerprint {
                    // Preserve the last differing identity if the old view reappears.
                    return Ok(true);
                }
                if previous.fingerprint != fingerprint || previous.state == "changed" {
                    self.connection.execute("UPDATE device_trust SET latest_fingerprint=?3,state='changed' WHERE user=?1 AND device=?2", params![p.user_id,p.device_id,fingerprint])?;
                    return Ok(true);
                }
            } else {
                self.connection.execute("INSERT INTO device_trust VALUES(?1,?2,?3,?3,'unverified')", params![p.user_id,p.device_id,fingerprint])?;
            }
            Ok(false)
        })?;
        ensure!(
            !changed,
            "DEVICE IDENTITY CHANGED: {}/{}; operation blocked; inspect device fingerprint",
            p.user_id,
            p.device_id
        );
        Ok(())
    }
    /// Compare the complete fingerprint received independently, not a directory assertion.
    pub fn verify_device(&self, user: &str, device: &str, expected: &str) -> Result<()> {
        let expected: String = expected
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>()
            .to_ascii_uppercase();
        ensure!(
            expected.len() == 64 && expected.bytes().all(|c| c.is_ascii_hexdigit()),
            "supply the complete 64-digit fingerprint from an independent channel"
        );
        let observed = self
            .device_trust(user, device)?
            .context("device not observed; look it up first")?;
        ensure!(
            observed.state != "changed",
            "changed identity is blocked; replacement authorization is not implemented"
        );
        ensure!(
            observed.fingerprint == expected,
            "fingerprint does not match observed device; verification refused"
        );
        self.connection.execute(
            "UPDATE device_trust SET state='verified' WHERE user=?1 AND device=?2",
            params![user, device],
        )?;
        Ok(())
    }
    pub fn directory_key(&self) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT signer FROM transparency_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn checkpoint(&self) -> Result<Option<Checkpoint>> {
        let bytes: Option<Option<Vec<u8>>> = self
            .connection
            .query_row(
                "SELECT checkpoint FROM transparency_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .flatten()
            .map(|b| postcard::from_bytes(&b).map_err(Into::into))
            .transpose()
    }
    pub fn pin_directory(&self, signer: &str) -> Result<()> {
        ensure!(signer.starts_with('U'), "directory user NKey required");
        nkeys::KeyPair::from_public_key(signer)?;
        let previous: Option<String> = self
            .connection
            .query_row(
                "SELECT signer FROM transparency_state WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            previous.as_deref().is_none_or(|p| p == signer),
            "directory key already pinned; refusing replacement"
        );
        self.connection.execute(
            "INSERT OR IGNORE INTO transparency_state(id,signer) VALUES(1,?1)",
            [signer],
        )?;
        Ok(())
    }
    pub fn accept_checkpoint(&self, snapshot: &Snapshot) -> Result<()> {
        snapshot.validate()?;
        self.pin_directory(&snapshot.checkpoint.signer)?;
        // Persist changed-device evidence even when prefix verification subsequently fails.
        for registration in &snapshot.entries {
            self.observe_device(registration)?;
        }
        if let Some(previous) = self.checkpoint()? {
            snapshot.extends(&previous)?;
        }
        self.connection.execute(
            "UPDATE transparency_state SET checkpoint=?1 WHERE id=1",
            [postcard::to_allocvec(&snapshot.checkpoint)?],
        )?;
        Ok(())
    }
    pub fn transparency_failure(&self, message: &str) -> Result<()> {
        // Failures before first contact still need a persistent, visible diagnostic.
        self.connection.execute("INSERT INTO trust_alert VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET message=excluded.message", [message])?;
        Ok(())
    }
    pub fn trust_warning(&self) -> Result<Option<String>> {
        if let Ok(identity) = self.registration()
            && self.is_revoked(&identity.payload.nats_public_key)?
        {
            return Ok(Some(
                "DEVICE REVOKED: revocation recorded; new sends are disabled".into(),
            ));
        }
        let changed: Option<String> = self.connection.query_row("SELECT user || '/' || device FROM device_trust WHERE state='changed' ORDER BY user,device LIMIT 1", [], |r| r.get(0)).optional()?;
        if let Some(device) = changed {
            return Ok(Some(format!(
                "DEVICE IDENTITY CHANGED: {device}; new invitations blocked"
            )));
        }
        let alert: Option<String> = self
            .connection
            .query_row("SELECT message FROM trust_alert WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if alert.is_some() {
            return Ok(alert);
        }
        let blocked: u64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM blocked_outbox", [], |r| r.get(0))?;
        if blocked > 0 {
            return Ok(Some(format!(
                "{blocked} queued messages blocked after revocation; retained locally, resend after rekey"
            )));
        }
        Ok(None)
    }
    pub fn clear_transparency_warning(&self) -> Result<()> {
        self.connection.execute("DELETE FROM trust_alert", [])?;
        Ok(())
    }
}
