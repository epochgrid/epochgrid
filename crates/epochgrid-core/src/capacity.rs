//! Public, bounded capacity policy. Limits never authorize deletion or truncation.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Instant};

pub const FILE: &str = "capacity.json";
pub const REGISTRATION_BYTES: u64 = 1536;
pub const SUBSCRIPTION_MESSAGES: usize = 64;
pub const OUTBOX_BATCH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capacity {
    pub version: u32,
    pub retained_users: u64,
    pub retained_devices: u64,
    pub devices_per_user: u64,
    pub retained_tokens: u64,
    pub retained_groups: u64,
    pub membership_edges: u64,
    pub groups_per_device: u64,
    pub pending_messages: u64,
    pub pending_bytes: u64,
    pub database_bytes: u64,
    pub recovery_bytes: u64,
    pub requests_per_second: u32,
    pub request_burst: u32,
    pub chat_bytes: u64,
    pub mailbox_bytes: u64,
    pub directory_bytes: u64,
    pub channels_bytes: u64,
    pub transparency_bytes: u64,
}
impl Default for Capacity {
    fn default() -> Self {
        Self {
            version: 1,
            retained_users: 32,
            retained_devices: 32,
            devices_per_user: 8,
            retained_tokens: 256,
            retained_groups: 32,
            membership_edges: 512,
            groups_per_device: 16,
            pending_messages: 256,
            pending_bytes: 4 * 1024 * 1024,
            database_bytes: 256 * 1024 * 1024,
            recovery_bytes: 16 * 1024 * 1024,
            requests_per_second: 32,
            request_burst: 64,
            chat_bytes: 64 * 1024 * 1024,
            mailbox_bytes: 16 * 1024 * 1024,
            directory_bytes: 1024 * 1024,
            channels_bytes: 1024 * 1024,
            transparency_bytes: 1024 * 1024,
        }
    }
}
impl Capacity {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported capacity version");
        for (value, ceiling) in [
            (self.retained_users, 32),
            (self.retained_devices, 32),
            (self.devices_per_user, 32),
            (self.retained_tokens, 4096),
            (self.retained_groups, 128),
            (self.membership_edges, 4096),
            (self.groups_per_device, 16),
            (self.pending_messages, 4096),
            (self.pending_bytes, 64 * 1024 * 1024),
            (self.database_bytes, 16 * 1024 * 1024 * 1024),
            (self.recovery_bytes, 1024 * 1024 * 1024),
            (u64::from(self.requests_per_second), 1024),
            (u64::from(self.request_burst), 1024),
        ] {
            ensure!(value > 0 && value <= ceiling, "capacity range invalid");
        }
        ensure!(
            self.devices_per_user <= self.retained_devices,
            "device capacity inconsistent"
        );
        ensure!(
            self.recovery_bytes < self.database_bytes,
            "recovery reserve must fit database budget"
        );
        for bytes in [
            self.chat_bytes,
            self.mailbox_bytes,
            self.directory_bytes,
            self.channels_bytes,
            self.transparency_bytes,
        ] {
            ensure!(
                (262144..=1024 * 1024 * 1024 * 1024).contains(&bytes),
                "broker byte budget out of range"
            );
        }
        Ok(())
    }
    pub fn load(home: &Path) -> Result<Self> {
        let bytes = std::fs::read(home.join(FILE))?;
        ensure!(bytes.len() <= 8192, "capacity file too large");
        let policy: Self = serde_json::from_slice(&bytes)?;
        policy.validate()?;
        Ok(policy)
    }
    /// Legacy development fixtures use bounded defaults. Production admission
    /// separately requires an explicitly installed policy.
    pub fn load_or_default(home: &Path) -> Result<Self> {
        if home.join(FILE).try_exists()? {
            Self::load(home)
        } else {
            Ok(Self::default())
        }
    }
    pub fn check_client(&self, db: &rusqlite::Connection, reserve: bool) -> Result<()> {
        let groups: u64 = db.query_row("SELECT COUNT(*) FROM groups", [], |r| r.get(0))?;
        ensure!(
            groups <= self.retained_groups,
            "capacity exhausted: local groups"
        );
        let (messages, bytes): (u64, u64) = db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM outbox WHERE sent=0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let extra = if reserve { 32 } else { 0 };
        ensure!(
            messages <= self.pending_messages + extra
                && bytes <= self.pending_bytes + extra * crate::wire::MAX_WIRE as u64,
            "capacity below retained pending outbox usage"
        );
        self.check_database(db, reserve)
    }
    /// Explicit local policy change: existing encrypted state only, under the
    /// same exclusive device lock used by every client process.
    pub fn install_client(home: &Path, policy: &Path) -> Result<()> {
        let bytes = std::fs::read(policy)?;
        ensure!(bytes.len() <= 8192, "capacity file too large");
        let capacity: Self = serde_json::from_slice(&bytes)?;
        capacity.validate()?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(home.join("device.lock"))?;
        lock.try_lock()?;
        let db = crate::database::inspection::inspect(home, "identity")?;
        capacity.check_client(&db, false)?;
        for path in [home.join(FILE), home.join("capacity.pending")] {
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink(),
                    "capacity policy must be a regular file"
                );
            }
        }
        crate::secrets::save(&home.join(FILE), &capacity)
    }
    pub fn inspect_registry(&self, home: &Path) -> Result<()> {
        self.validate()?;
        let db = crate::database::inspection::inspect(home, "auth")?;
        self.check_registry(&db)
    }
    pub fn check_registry(&self, db: &rusqlite::Connection) -> Result<()> {
        for (query, limit) in [
            ("SELECT COUNT(*) FROM users", self.retained_users),
            ("SELECT COUNT(*) FROM devices", self.retained_devices),
            (
                "SELECT COUNT(*) FROM enrollment_tokens",
                self.retained_tokens,
            ),
            (
                "SELECT COUNT(*) FROM authorization_groups",
                self.retained_groups,
            ),
            (
                "SELECT COUNT(*) FROM authorization_members",
                self.membership_edges,
            ),
            (
                "SELECT COALESCE(MAX(n),0) FROM (SELECT COUNT(*) n FROM devices WHERE revoked=0 GROUP BY user_id)",
                self.devices_per_user,
            ),
            (
                "SELECT COALESCE(MAX(n),0) FROM (SELECT COUNT(*) n FROM authorization_members GROUP BY nkey)",
                self.groups_per_device,
            ),
            (
                "SELECT COALESCE(MAX(length(registration)),0) FROM devices",
                REGISTRATION_BYTES,
            ),
        ] {
            let count: u64 = db.query_row(query, [], |r| r.get(0))?;
            ensure!(
                count <= limit,
                "capacity exhausted: registry; increase declared limits within representation ceilings"
            );
        }
        self.check_database(db, true)
    }
    /// SQLite page accounting is a logical high-water check, not a filesystem quota.
    pub fn check_database(&self, db: &rusqlite::Connection, reserve: bool) -> Result<()> {
        let pages: u64 = db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size = match db.query_row("PRAGMA page_size", [], |r| {
            r.get::<_, rusqlite::types::Value>(0)
        })? {
            rusqlite::types::Value::Integer(n) => u64::try_from(n)?,
            rusqlite::types::Value::Text(n) => n.parse::<u64>()?,
            _ => anyhow::bail!("invalid database page size"),
        };
        let limit = self.database_bytes - if reserve { 0 } else { self.recovery_bytes };
        ensure!(
            pages.checked_mul(size).is_some_and(|bytes| bytes <= limit),
            "capacity exhausted: database; operator storage increase required"
        );
        Ok(())
    }
}

/// Integer token bucket with caller-controlled time for deterministic tests.
/// State is constant-sized; no unauthenticated identity map is allocated.
pub struct RateLimit {
    tokens: u64,
    last: Instant,
    rate: u64,
    burst: u64,
}
impl RateLimit {
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        Self {
            tokens: u64::from(burst) * 1_000_000_000,
            last: now,
            rate: u64::from(rate),
            burst: u64::from(burst) * 1_000_000_000,
        }
    }
    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_nanos();
        let credit = elapsed
            .saturating_mul(u128::from(self.rate))
            .min(u128::from(self.burst)) as u64;
        self.tokens = self.tokens.saturating_add(credit).min(self.burst);
        self.last = now.max(self.last);
        if self.tokens < 1_000_000_000 {
            return false;
        }
        self.tokens -= 1_000_000_000;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rate_boundaries_and_clock_regression() {
        let now = Instant::now();
        let mut rate = RateLimit::new(2, 2, now);
        assert!(rate.allow(now));
        assert!(rate.allow(now));
        assert!(!rate.allow(now));
        assert!(!rate.allow(now + std::time::Duration::from_millis(499)));
        assert!(rate.allow(now + std::time::Duration::from_millis(500)));
        assert!(!rate.allow(now));
        assert!(rate.allow(now + std::time::Duration::from_secs(3600)));
        assert!(rate.allow(now + std::time::Duration::from_secs(3600)));
        assert!(!rate.allow(now + std::time::Duration::from_secs(3600)));
    }
    #[test]
    fn strict_capacity_ranges() -> Result<()> {
        let policy = Capacity::default();
        policy.validate()?;
        let mut bad = serde_json::to_value(&policy)?;
        bad["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Capacity>(bad).is_err());
        let mut bad = policy.clone();
        bad.retained_devices = 33;
        assert!(bad.validate().is_err());
        let mut bad = policy.clone();
        bad.pending_bytes = u64::MAX;
        assert!(bad.validate().is_err());
        let mut bad = policy;
        bad.recovery_bytes = bad.database_bytes;
        assert!(bad.validate().is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "capacity/tests.rs"]
mod integration_tests;
