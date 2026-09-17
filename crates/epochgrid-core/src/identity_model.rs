//! Provider-neutral users and dynamic device admission, separate from client MLS storage.
use crate::{identity, transport::Enrollment, wire::DeviceRegistration};
use anyhow::{Context, Result, ensure};
use openmls_traits::random::OpenMlsRand;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserId(String);
impl TryFrom<String> for UserId {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        let suffix = value
            .strip_prefix("egusr-")
            .context("canonical EpochGrid UserId required")?;
        let bytes = data_encoding::BASE32_NOPAD.decode(suffix.to_ascii_uppercase().as_bytes())?;
        ensure!(
            bytes.len() == 16
                && data_encoding::BASE32_NOPAD
                    .encode(&bytes)
                    .to_ascii_lowercase()
                    == suffix,
            "invalid canonical UserId"
        );
        Ok(Self(value))
    }
}
impl From<UserId> for String {
    fn from(id: UserId) -> String {
        id.0
    }
}
impl UserId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBinding {
    pub provider: String,
    pub subject: String,
}
pub trait IdentityProvider {
    /// Produces a verified provider binding, not permissions or an MLS identity.
    fn authenticate(&self, registry: &AuthRegistry, credential: &str) -> Result<IdentityBinding>;
}
pub struct LocalIdentityProvider;
impl IdentityProvider for LocalIdentityProvider {
    fn authenticate(&self, registry: &AuthRegistry, credential: &str) -> Result<IdentityBinding> {
        let uid = token_user(credential)?;
        let subject: String = registry.db.query_row("SELECT b.subject FROM enrollment_tokens t JOIN identity_bindings b ON b.user_id=t.user_id JOIN users u ON u.id=b.user_id WHERE t.digest=?1 AND t.user_id=?2 AND t.expires>?3 AND t.used_key IS NULL AND b.provider='local' AND u.enabled=1",params![crate::transparency::hash(credential.as_bytes())?,uid.as_str(),now()?],|r|r.get(0)).context("invalid or expired enrollment credential")?;
        Ok(IdentityBinding {
            provider: "local".into(),
            subject,
        })
    }
}
pub fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    openmls_rust_crypto::RustCrypto::default()
        .random_array()
        .map_err(|_| anyhow::anyhow!("identity randomness unavailable"))
}
pub fn token_user(token: &str) -> Result<UserId> {
    ensure!(token.len() <= 256, "oversized enrollment token");
    let fields: Vec<_> = token.split('.').collect();
    ensure!(
        fields.len() == 3 && fields[0] == "EG1" && fields[2].len() == 52,
        "invalid enrollment token"
    );
    UserId::try_from(fields[1].to_owned())
}
#[derive(Clone)]
pub struct DeviceAuthorization {
    pub user: UserId,
    pub device: String,
    pub nkey: String,
    pub generation: u64,
}
pub struct AuthRegistry {
    pub(crate) db: Connection,
}
impl AuthRegistry {
    pub fn open(home: &Path) -> Result<Self> {
        std::fs::create_dir_all(home)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))?;
        }
        let path = home.join("auth.sqlite");
        let db = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        db.busy_timeout(Duration::from_secs(1))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS auth_migrations(version INTEGER PRIMARY KEY);")?;
        let version: i64 = db.query_row(
            "SELECT COALESCE(MAX(version),0) FROM auth_migrations",
            [],
            |r| r.get(0),
        )?;
        ensure!(version <= 1, "auth registry is newer than this service");
        if version == 0 {
            db.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE users(id TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)));
CREATE TABLE identity_bindings(provider TEXT NOT NULL,subject TEXT NOT NULL,user_id TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(provider,subject));
CREATE TABLE enrollment_tokens(digest BLOB PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires INTEGER NOT NULL,used_key TEXT);
CREATE TABLE devices(nkey TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),device_id TEXT NOT NULL,registration BLOB NOT NULL,ready INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,authorization_generation INTEGER NOT NULL DEFAULT 1,UNIQUE(user_id,device_id));
INSERT INTO auth_migrations VALUES(1); COMMIT;")?;
        }
        Ok(Self { db })
    }
    pub fn resolve(&self, binding: &IdentityBinding) -> Result<UserId> {
        UserId::try_from(self.db.query_row(
            "SELECT user_id FROM identity_bindings WHERE provider=?1 AND subject=?2",
            params![binding.provider, binding.subject],
            |r| r.get::<_, String>(0),
        )?)
    }
    pub fn invite(&mut self, handle: &str, ttl: u64) -> Result<Zeroizing<String>> {
        crate::wire::validate_id(handle)?;
        ensure!(
            (1..=3600).contains(&ttl),
            "enrollment lifetime must be 1–3600 seconds"
        );
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let uid = tx
            .query_row(
                "SELECT user_id FROM identity_bindings WHERE provider='local' AND subject=?1",
                [handle],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        let uid = match uid {
            Some(id) => id,
            None => {
                let id = format!(
                    "egusr-{}",
                    data_encoding::BASE32_NOPAD
                        .encode(&random::<16>()?)
                        .to_ascii_lowercase()
                );
                tx.execute("INSERT INTO users VALUES(?1,1)", [&id])?;
                tx.execute(
                    "INSERT INTO identity_bindings VALUES('local',?1,?2)",
                    params![handle, id],
                )?;
                id
            }
        };
        let enabled: bool = tx.query_row("SELECT enabled FROM users WHERE id=?1", [&uid], |r| {
            r.get(0)
        })?;
        ensure!(enabled, "user disabled");
        let token = Zeroizing::new(format!(
            "EG1.{uid}.{}",
            data_encoding::BASE32_NOPAD.encode(&random::<32>()?)
        ));
        tx.execute(
            "INSERT INTO enrollment_tokens VALUES(?1,?2,?3,NULL)",
            params![
                crate::transparency::hash(token.as_bytes())?,
                uid,
                now()? + ttl as i64
            ],
        )?;
        tx.commit()?;
        Ok(token)
    }
    /// A consumed token can only retry its original key's enrollment, within expiry.
    pub fn enrollment_admission(&self, token: &str, key: &str) -> Result<UserId> {
        if let Ok(binding) = LocalIdentityProvider.authenticate(self, token) {
            return self.resolve(&binding);
        }
        let uid = token_user(token)?;
        let allowed: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM enrollment_tokens t JOIN devices d ON d.nkey=t.used_key JOIN users u ON u.id=d.user_id WHERE t.digest=?1 AND t.used_key=?2 AND t.user_id=?3 AND t.expires>?4 AND d.revoked=0 AND u.enabled=1)", params![crate::transparency::hash(token.as_bytes())?,key,uid.as_str(),now()?], |r|r.get(0))?;
        ensure!(allowed, "enrollment credential not admitted");
        Ok(uid)
    }
    pub fn enroll(&mut self, token: &str, registration: &DeviceRegistration) -> Result<()> {
        identity::verify(registration)?;
        let uid = token_user(token)?;
        ensure!(
            registration.payload.user_id == uid.as_str() && registration.payload.generation == 1,
            "enrollment identity mismatch"
        );
        let digest = crate::transparency::hash(token.as_bytes())?;
        let encoded = crate::wire::encode(crate::wire::Body::Register(registration.clone()))?;
        let key = &registration.payload.nats_public_key;
        // Exact retries after a lost response are idempotent, not a second enrollment.
        let previous: Option<String> = self
            .db
            .query_row(
                "SELECT used_key FROM enrollment_tokens WHERE digest=?1",
                [digest],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        if let Some(previous) = previous {
            ensure!(previous == *key, "enrollment token already consumed");
            let old: Vec<u8> = self.db.query_row(
                "SELECT d.registration FROM devices d JOIN users u ON u.id=d.user_id WHERE d.nkey=?1 AND d.revoked=0 AND u.enabled=1",
                [key],
                |r| r.get(0),
            )?;
            ensure!(old == encoded, "enrollment retry changed device binding");
            return Ok(());
        }
        let binding = LocalIdentityProvider.authenticate(self, token)?;
        ensure!(self.resolve(&binding)? == uid, "provider binding mismatch");
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let used=tx.execute("UPDATE enrollment_tokens SET used_key=?1 WHERE digest=?2 AND used_key IS NULL AND expires>?3 AND EXISTS(SELECT 1 FROM users WHERE id=user_id AND enabled=1)",params![key,digest,now()?])?;
        ensure!(used == 1, "enrollment token expired or consumed");
        tx.execute(
            "INSERT INTO devices(nkey,user_id,device_id,registration) VALUES(?1,?2,?3,?4)",
            params![key, uid.as_str(), registration.payload.device_id, encoded],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn activate(&self, key: &str) -> Result<()> {
        ensure!(
            self.db.execute(
                "UPDATE devices SET ready=1 WHERE nkey=?1 AND revoked=0",
                [key]
            )? == 1,
            "device cannot be activated"
        );
        Ok(())
    }
    pub fn authorize(&self, key: &str) -> Result<DeviceAuthorization> {
        let (user,device,generation,bytes):(String,String,u64,Vec<u8>)=self.db.query_row("SELECT d.user_id,d.device_id,d.authorization_generation,d.registration FROM devices d JOIN users u ON u.id=d.user_id WHERE d.nkey=?1 AND d.ready=1 AND d.revoked=0 AND u.enabled=1",[key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).context("device not admitted")?;
        let crate::wire::Body::Register(registration) = crate::wire::decode(&bytes)? else {
            anyhow::bail!("invalid admission registration")
        };
        identity::verify_signature(&registration)?;
        ensure!(
            registration.payload.nats_public_key == key
                && registration.payload.user_id == user
                && registration.payload.device_id == device,
            "admission registration binding mismatch"
        );
        ensure!(generation > 0, "invalid authorization generation");
        Ok(DeviceAuthorization {
            user: UserId::try_from(user)?,
            device,
            nkey: key.into(),
            generation,
        })
    }
    pub fn revoke(&self, key: &str) -> Result<()> {
        self.db.execute("UPDATE devices SET revoked=1,authorization_generation=authorization_generation+1 WHERE nkey=?1 AND revoked=0",[key])?;
        Ok(())
    }
    pub fn enrollment(&self) -> Result<Enrollment> {
        self.enrollment_records(false)
    }
    /// Historical bindings remain necessary to authenticate the append-only log.
    pub fn historical_enrollment(&self) -> Result<Enrollment> {
        self.enrollment_records(true)
    }
    fn enrollment_records(&self, include_revoked: bool) -> Result<Enrollment> {
        let mut stmt = self
            .db
            .prepare("SELECT user_id,device_id,nkey FROM devices WHERE ?1 OR revoked=0")?;
        Ok(stmt
            .query_map([include_revoked], |r| {
                Ok((
                    format!(
                        "users.{}.devices.{}",
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?
                    ),
                    r.get(2)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?)
    }
    pub fn registrations(&self) -> Result<Vec<DeviceRegistration>> {
        let mut stmt = self
            .db
            .prepare("SELECT registration FROM devices WHERE revoked=0")?;
        stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?
            .map(|row| match crate::wire::decode(&row?)? {
                crate::wire::Body::Register(r) => Ok(r),
                _ => anyhow::bail!("invalid registry registration"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
