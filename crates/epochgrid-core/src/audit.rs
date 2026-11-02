//! Bounded evidence in the encrypted authority registry. No arbitrary text fields.
use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path, sync::OnceLock};

pub const MAX_EVENTS: u64 = 100_000;
pub const MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const RESERVE_EVENTS: u64 = 1024;
pub const RESERVE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_EVENT_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    TokenIssued,
    DeviceEnrolled,
    DeviceActivated,
    DeviceRevoked,
    PolicyCommitted,
    PolicyRejected,
    Admission,
    ResponseConstructed,
    Reconciliation,
    RegistrationPublication,
    RevocationPublication,
    AuthorityStarted,
    WorkerSessionStarted,
    WorkerSessionEnded,
    AdmissionGate,
    ObservationLoss,
    StorageRecovered,
    Export,
    Prune,
    RetentionChanged,
    DenialSummary,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Committed,
    Intent,
    Result,
    Observation,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    Unknown,
    Denied,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    LocalOperator,
    VerifiedDevice,
    BoundWorker,
    Authority,
    Unverified,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Verified,
    Rejected,
    ExternalEffect,
    LocalArtifact,
    ExplicitPrune,
    CoverageUncertain,
    IdempotentRetry,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub kind: Kind,
    pub stage: Stage,
    pub outcome: Outcome,
    pub reason: Reason,
    pub actor: Actor,
    pub count: u64,
    pub actor_reference: Option<Reference>,
    pub target_reference: Option<Reference>,
    pub generation: Option<u64>,
    pub window_seconds: Option<u64>,
    pub sequence_boundary: Option<u64>,
}
impl Event {
    pub fn committed(kind: Kind) -> Self {
        Self {
            kind,
            stage: Stage::Committed,
            outcome: Outcome::Succeeded,
            reason: Reason::Verified,
            actor: Actor::Authority,
            count: 1,
            actor_reference: None,
            target_reference: None,
            generation: None,
            window_seconds: None,
            sequence_boundary: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Reference(String);
impl TryFrom<String> for Reference {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value.len() == 32
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid audit reference"
        );
        Ok(Self(value))
    }
}
impl From<Reference> for String {
    fn from(value: Reference) -> Self {
        value.0
    }
}
pub(crate) fn reference(
    db: &Connection,
    table: &str,
    column: &str,
    key: &str,
) -> Result<Reference> {
    // Only compile-time table/column names may call this internal helper.
    Reference::try_from(db.query_row(
        &format!("SELECT audit_ref FROM {table} WHERE {column}=?1"),
        [key],
        |r| r.get::<_, String>(0),
    )?)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u32,
    pub store_id: String,
    pub sequence: u64,
    pub process_instance: String,
    pub operation: String,
    pub wall_seconds: Option<i64>,
    pub timestamp_quality: TimestampQuality,
    pub event: Event,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampQuality {
    UntrustedWallClock,
    Unavailable,
}
pub(crate) fn opaque() -> Result<String> {
    use openmls_traits::random::OpenMlsRand;
    let bytes: [u8; 16] = openmls_rust_crypto::RustCrypto::default()
        .random_array()
        .map_err(|_| anyhow::anyhow!("audit randomness unavailable"))?;
    Ok(data_encoding::HEXLOWER.encode(&bytes))
}
fn instance() -> Result<String> {
    static INSTANCE: OnceLock<String> = OnceLock::new();
    if let Some(value) = INSTANCE.get() {
        return Ok(value.clone());
    }
    let value = opaque()?;
    Ok(INSTANCE.get_or_init(|| value).clone())
}

pub(crate) fn migrate(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    let version: u32 =
        tx.query_row("SELECT MAX(version) FROM auth_migrations", [], |r| r.get(0))?;
    ensure!((2..=3).contains(&version), "unsupported audit schema");
    if version == 2 {
        tx.execute_batch("CREATE TABLE audit_state(id INTEGER PRIMARY KEY CHECK(id=1),store_id TEXT NOT NULL,next_sequence INTEGER NOT NULL,retained_from INTEGER NOT NULL,events INTEGER NOT NULL,bytes INTEGER NOT NULL,gaps INTEGER NOT NULL,policy_version INTEGER NOT NULL,prune_through INTEGER NOT NULL,degraded INTEGER NOT NULL);
CREATE TABLE audit_pending(kind TEXT PRIMARY KEY,operation TEXT NOT NULL);
CREATE TABLE audit_events(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL CHECK(length(CAST(payload AS BLOB))<=2048));
ALTER TABLE users ADD COLUMN audit_ref TEXT;
ALTER TABLE devices ADD COLUMN audit_ref TEXT;
ALTER TABLE authorization_groups ADD COLUMN audit_ref TEXT;
UPDATE users SET audit_ref=lower(hex(randomblob(16)));
UPDATE devices SET audit_ref=lower(hex(randomblob(16)));
UPDATE authorization_groups SET audit_ref=lower(hex(randomblob(16)));
CREATE TRIGGER audit_user_reference AFTER INSERT ON users BEGIN UPDATE users SET audit_ref=lower(hex(randomblob(16))) WHERE id=NEW.id; END;
CREATE TRIGGER audit_device_reference AFTER INSERT ON devices BEGIN UPDATE devices SET audit_ref=lower(hex(randomblob(16))) WHERE nkey=NEW.nkey; END;
CREATE TRIGGER audit_group_reference AFTER INSERT ON authorization_groups BEGIN UPDATE authorization_groups SET audit_ref=lower(hex(randomblob(16))) WHERE gid=NEW.gid; END;
INSERT INTO auth_migrations VALUES(3);")?;
        // Existing activity and volatile observations cannot be reconstructed.
        tx.execute(
            "INSERT INTO audit_state VALUES(1,?1,1,1,0,0,1,1,0,0)",
            [opaque()?],
        )?;
    }
    tx.commit()?;
    Ok(())
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub schema: u32,
    pub store_id: String,
    pub retained_from: u64,
    pub upper_sequence: u64,
    pub events: u64,
    pub bytes: u64,
    pub event_limit: u64,
    pub byte_limit: u64,
    pub known_coverage_gaps: bool,
    pub policy_version: u64,
    pub prune_through: u64,
    pub unresolved_effects: u64,
    pub degraded: bool,
}
pub(crate) fn info(db: &Connection) -> Result<Info> {
    ensure!(
        db.query_row("SELECT MAX(version) FROM auth_migrations", [], |r| r
            .get::<_, u32>(0))?
            == 3,
        "unsupported audit schema"
    );
    let state = db.query_row("SELECT store_id,retained_from,next_sequence-1,events,bytes,gaps,policy_version,prune_through,(SELECT COUNT(*) FROM audit_pending),degraded FROM audit_state WHERE id=1", [], |r| Ok(Info {
        schema: 1, store_id: r.get(0)?, retained_from: r.get(1)?, upper_sequence: r.get(2)?, events: r.get(3)?, bytes: r.get(4)?, known_coverage_gaps: r.get(5)?, policy_version: r.get(6)?, prune_through: r.get(7)?, unresolved_effects: r.get(8)?, degraded: r.get(9)?, event_limit: MAX_EVENTS, byte_limit: MAX_BYTES,
    }))?;
    Reference::try_from(state.store_id.clone())?;
    ensure!(
        state.retained_from > 0
            && state.retained_from <= state.upper_sequence.saturating_add(1)
            && state.upper_sequence < i64::MAX as u64
            && state.events <= MAX_EVENTS
            && state.bytes <= MAX_BYTES
            && state.policy_version > 0
            && state.prune_through <= state.upper_sequence
            && state.unresolved_effects <= 256,
        "invalid audit metadata"
    );
    Ok(state)
}
/// Caller owns the transaction, including any associated registry mutation.
pub(crate) fn append(db: &Connection, event: Event, reserve: bool) -> Result<u64> {
    append_operation(db, event, reserve, &opaque()?)
}
fn append_operation(db: &Connection, event: Event, reserve: bool, operation: &str) -> Result<u64> {
    Reference::try_from(operation.to_owned())?;
    ensure!(
        !db.is_autocommit(),
        "audit insertion requires a transaction"
    );
    let state = info(db)?;
    ensure!(
        reserve || !state.degraded,
        "audit storage requires recovery"
    );
    let sequence = state
        .upper_sequence
        .checked_add(1)
        .filter(|v| *v < i64::MAX as u64)
        .ok_or_else(|| anyhow::anyhow!("audit sequence exhausted"))?;
    let wall_seconds = crate::identity_model::now().ok();
    let record = Record {
        version: 1,
        store_id: state.store_id,
        sequence,
        process_instance: instance()?,
        operation: operation.into(),
        wall_seconds,
        timestamp_quality: if wall_seconds.is_some() {
            TimestampQuality::UntrustedWallClock
        } else {
            TimestampQuality::Unavailable
        },
        event,
    };
    let payload = serde_json::to_string(&record)?;
    ensure!(
        payload.len() <= MAX_EVENT_BYTES,
        "audit event exceeds limit"
    );
    ensure!(
        state.events < MAX_EVENTS - if reserve { 0 } else { RESERVE_EVENTS }
            && state.bytes + payload.len() as u64
                <= MAX_BYTES - if reserve { 0 } else { RESERVE_BYTES },
        "audit capacity exhausted"
    );
    db.execute(
        "INSERT INTO audit_events VALUES(?1,?2)",
        params![sequence, payload],
    )?;
    db.execute(
        "UPDATE audit_state SET next_sequence=?1,events=events+1,bytes=bytes+?2 WHERE id=1",
        params![sequence + 1, payload.len()],
    )?;
    Ok(sequence)
}
/// Audit failure must not roll back enforceable security reduction.
pub(crate) fn repair(db: &Connection, event: Event, capacity: &crate::capacity::Capacity) {
    if db.execute_batch("SAVEPOINT audit_repair").is_err() {
        return;
    }
    if append(db, event, true)
        .and_then(|_| capacity.check_database(db, true))
        .is_err()
    {
        let _ = db.execute_batch("ROLLBACK TO audit_repair");
        let _ = db.execute("UPDATE audit_state SET gaps=1,degraded=1 WHERE id=1", []);
        tracing::error!("audit coverage degraded");
    }
    let _ = db.execute_batch("RELEASE audit_repair");
}
impl crate::identity_model::AuthRegistry {
    pub fn audit_batch(&self, events: &[Event]) -> Result<()> {
        ensure!(events.len() <= 256, "audit batch exceeds bound");
        let tx = self.db.unchecked_transaction()?;
        for event in events {
            append(&tx, event.clone(), false)?;
        }
        self.capacity.check_database(&tx, false)?;
        tx.commit()?;
        Ok(())
    }
    pub fn audit_info(&self) -> Result<Info> {
        info(&self.db)
    }
    pub(crate) fn audit_correlated(&self, event: Event, operation: &str) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        append_operation(&tx, event, false, operation)?;
        self.capacity.check_database(&tx, false)?;
        tx.commit()?;
        Ok(())
    }
    pub fn audit_event(&self, event: Event) -> Result<u64> {
        let tx = self.db.unchecked_transaction()?;
        let sequence = append(&tx, event, false)?;
        self.capacity.check_database(&tx, false)?;
        tx.commit()?;
        Ok(sequence)
    }
    /// Records a repair attempt without preventing the repair if storage is unavailable.
    pub fn audit_repair(&self, event: Event) {
        if let Ok(tx) = self.db.unchecked_transaction() {
            repair(&tx, event, &self.capacity);
            if tx.commit().is_err() {
                tracing::error!("audit coverage degraded");
            }
        }
    }
}
/// Non-provisioning, non-migrating inspection through the encrypted boundary.
pub fn inspect(home: &Path) -> Result<Info> {
    let db = crate::database::inspection::inspect(home, "auth")?;
    info(&db)
}

#[derive(Serialize)]
struct Manifest<'a> {
    kind: &'static str,
    version: u32,
    store_id: &'a str,
    requested_after: u64,
    retained_from: u64,
    upper_sequence: u64,
    count: u64,
    continuation_cursor: u64,
    complete: bool,
    known_coverage_gaps: bool,
}
/// The caller must hold the authority runtime lock. Read-only and never provisions state.
pub fn export(
    home: &Path,
    output: &Path,
    store: &str,
    after: u64,
    upper: u64,
    limit: u64,
) -> Result<()> {
    ensure!(
        (1..=10_000).contains(&limit),
        "export count must be 1–10000"
    );
    let db = crate::database::inspection::inspect(home, "auth")?;
    // Inspection already owns a read-only snapshot transaction.
    let tx = &db;
    let state = info(tx)?;
    ensure!(
        store == state.store_id,
        "audit cursor belongs to another store"
    );
    ensure!(
        after >= state.retained_from - 1 && after <= upper && upper <= state.upper_sequence,
        "audit cursor outside retained snapshot"
    );
    ensure!(
        std::fs::symlink_metadata(output).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "audit output already exists or is inaccessible"
    );
    let mut pending_name = output.as_os_str().to_owned();
    pending_name.push(".partial");
    let pending = std::path::PathBuf::from(pending_name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // O_EXCL with O_CREAT rejects an existing final-component symlink too.
    let mut file = options.open(&pending)?;
    let mut manifest = Manifest {
        kind: "manifest",
        version: 1,
        store_id: store,
        requested_after: after,
        retained_from: state.retained_from,
        upper_sequence: upper,
        count: 0,
        continuation_cursor: after,
        complete: false,
        known_coverage_gaps: state.known_coverage_gaps,
    };
    serde_json::to_writer(&mut file, &manifest)?;
    writeln!(file)?;
    while manifest.count < limit {
        let batch = (limit - manifest.count).min(256);
        let mut query = tx.prepare("SELECT sequence,payload FROM audit_events WHERE sequence>?1 AND sequence<=?2 ORDER BY sequence LIMIT ?3")?;
        let mut rows = query.query(params![manifest.continuation_cursor, upper, batch])?;
        let before = manifest.count;
        while let Some(row) = rows.next()? {
            let sequence: u64 = row.get(0)?;
            ensure!(
                sequence == manifest.continuation_cursor + 1,
                "audit snapshot contains a sequence gap"
            );
            let payload: String = row.get(1)?;
            ensure!(payload.len() <= MAX_EVENT_BYTES, "invalid audit record");
            let record: Record = serde_json::from_str(&payload)?;
            Reference::try_from(record.store_id.clone())?;
            Reference::try_from(record.operation.clone())?;
            Reference::try_from(record.process_instance.clone())?;
            ensure!(
                record.version == 1 && record.store_id == store && record.sequence == sequence,
                "invalid audit record binding"
            );
            writeln!(file, "{payload}")?;
            manifest.count += 1;
            manifest.continuation_cursor = sequence;
        }
        if before == manifest.count {
            ensure!(
                manifest.continuation_cursor == upper,
                "audit snapshot ends before its declared boundary"
            );
            break;
        }
    }
    db.execute_batch("COMMIT")?;
    file.sync_all()?;
    manifest.complete = true;
    manifest.kind = "completion";
    serde_json::to_writer(&mut file, &manifest)?;
    writeln!(file)?;
    file.sync_all()?;
    // Publish only a fully written, synced file; hard_link never overwrites a destination.
    std::fs::hard_link(&pending, output)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    std::fs::remove_file(pending)?;
    Ok(())
}

/// Explicit retention authorization; no age-based deletion or automatic overwrite.
pub fn set_retention(home: &Path, through: u64) -> Result<()> {
    inspect(home)?;
    let registry = crate::identity_model::AuthRegistry::open(home)?;
    let tx = registry.db.unchecked_transaction()?;
    let state = info(&tx)?;
    ensure!(
        through <= state.upper_sequence,
        "retention boundary exceeds history"
    );
    tx.execute(
        "UPDATE audit_state SET prune_through=?1,policy_version=policy_version+1 WHERE id=1",
        [through],
    )?;
    let mut event = Event::committed(Kind::RetentionChanged);
    event.actor = Actor::LocalOperator;
    event.generation = Some(state.policy_version + 1);
    event.sequence_boundary = Some(through);
    append(&tx, event, true)?;
    registry.capacity.check_database(&tx, true)?;
    tx.commit()?;
    Ok(())
}
#[derive(Serialize)]
pub struct PruneSummary {
    pub eligible: u64,
    pub deleted: u64,
    pub retained_from: u64,
}
/// One bounded transaction per invocation, including the durable boundary marker.
pub fn prune(home: &Path, through: u64, apply: bool) -> Result<PruneSummary> {
    let db = crate::database::inspection::inspect(home, "auth")?;
    let state = info(&db)?;
    ensure!(
        through <= state.prune_through,
        "prune exceeds explicit retention policy"
    );
    let eligible: u64 = db.query_row(
        "SELECT COUNT(*) FROM audit_events WHERE sequence<=?1",
        [through],
        |r| r.get(0),
    )?;
    drop(db);
    let mut summary = PruneSummary {
        eligible,
        deleted: 0,
        retained_from: state.retained_from,
    };
    if !apply || eligible == 0 {
        return Ok(summary);
    }
    let registry = crate::identity_model::AuthRegistry::open(home)?;
    let tx = registry.db.unchecked_transaction()?;
    let (last, count, bytes): (u64,u64,u64) = tx.query_row("SELECT MAX(sequence),COUNT(*),SUM(length(CAST(payload AS BLOB))) FROM (SELECT sequence,payload FROM audit_events WHERE sequence<=?1 ORDER BY sequence LIMIT 256)", [through], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    tx.execute("DELETE FROM audit_events WHERE sequence<=?1", [last])?;
    tx.execute(
        "UPDATE audit_state SET retained_from=?1,events=events-?2,bytes=bytes-?3 WHERE id=1",
        params![last + 1, count, bytes],
    )?;
    let mut event = Event::committed(Kind::Prune);
    event.reason = Reason::ExplicitPrune;
    event.actor = Actor::LocalOperator;
    event.count = count;
    event.sequence_boundary = Some(last);
    event.generation = Some(state.policy_version);
    append(&tx, event, true)?;
    tx.commit()?;
    summary.deleted = count;
    summary.retained_from = last + 1;
    Ok(summary)
}

/// One constant-size aggregate, no attacker-selected labels or identity retention.
/// A fixed 60-second window is flushed only on a subsequent observation.
pub struct Denials {
    started: std::time::Instant,
    count: u64,
}
impl Default for Denials {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
            count: 0,
        }
    }
}
impl Denials {
    pub fn observe(&mut self, registry: &crate::identity_model::AuthRegistry) {
        if self.started.elapsed() < std::time::Duration::from_secs(60) {
            self.count = self.count.saturating_add(1);
            return;
        }
        let mut event = Event::committed(Kind::DenialSummary);
        event.stage = Stage::Observation;
        event.outcome = Outcome::Denied;
        event.reason = Reason::Rejected;
        event.actor = Actor::Unverified;
        event.count = self.count;
        event.window_seconds = Some(60);
        // Ordinary budget only: hostile traffic cannot use the repair reserve.
        let _ = registry.audit_event(event);
        self.count = 1;
        self.started = std::time::Instant::now();
    }
}

impl crate::identity_model::AuthRegistry {
    /// Reuses retained intent for idempotent state reconciliation only. No request replay.
    pub fn audit_effect(&self, kind: Kind) -> Option<String> {
        self.audit_effect_inner(kind, None, true, None).ok()
    }
    pub fn audit_effect_target(
        &self,
        kind: Kind,
        key: &str,
        required: bool,
    ) -> Result<Option<String>> {
        let target = match reference(&self.db, "devices", "nkey", key) {
            Ok(target) => target,
            Err(_) if !required => return Ok(None),
            Err(error) => return Err(error),
        };
        let result = self.audit_effect_inner(kind, Some(target), !required, None);
        if required {
            result.map(Some)
        } else {
            Ok(result.ok())
        }
    }
    pub fn audit_revocation_intent(&self, target: &str, author: &str) -> Option<String> {
        self.audit_effect_inner(
            Kind::RevocationPublication,
            reference(&self.db, "devices", "nkey", target).ok(),
            true,
            reference(&self.db, "devices", "nkey", author).ok(),
        )
        .ok()
    }
    fn audit_effect_inner(
        &self,
        kind: Kind,
        target: Option<Reference>,
        reserve: bool,
        actor: Option<Reference>,
    ) -> Result<String> {
        let result = (|| -> Result<String> {
            use rusqlite::OptionalExtension;
            let tx = self.db.unchecked_transaction()?;
            let label = format!(
                "{}:{}",
                serde_json::to_string(&kind)?,
                target.as_ref().map_or("", |r| r.0.as_str())
            );
            if let Some(operation) = tx
                .query_row(
                    "SELECT operation FROM audit_pending WHERE kind=?1",
                    [&label],
                    |r| r.get(0),
                )
                .optional()?
            {
                return Ok(operation);
            }
            let pending: u64 =
                tx.query_row("SELECT COUNT(*) FROM audit_pending", [], |r| r.get(0))?;
            ensure!(pending < 256, "audit pending capacity exhausted");
            let operation = opaque()?;
            let mut event = Event::committed(kind);
            event.stage = Stage::Intent;
            event.outcome = Outcome::Unknown;
            event.reason = Reason::ExternalEffect;
            event.target_reference = target;
            if actor.is_some() {
                event.actor = Actor::VerifiedDevice;
                event.actor_reference = actor;
            }
            append_operation(&tx, event, reserve, &operation)?;
            tx.execute(
                "INSERT INTO audit_pending VALUES(?1,?2)",
                params![label, operation],
            )?;
            self.capacity.check_database(&tx, reserve)?;
            tx.commit()?;
            Ok(operation)
        })();
        if result.is_err() {
            let _ = self
                .db
                .execute("UPDATE audit_state SET gaps=1,degraded=1 WHERE id=1", []);
            tracing::error!("audit coverage degraded");
        }
        result
    }
    pub fn audit_export_start(&self) -> Result<String> {
        let tx = self.db.unchecked_transaction()?;
        let operation = opaque()?;
        let mut event = Event::committed(Kind::Export);
        event.stage = Stage::Intent;
        event.outcome = Outcome::Unknown;
        event.actor = Actor::LocalOperator;
        event.reason = Reason::LocalArtifact;
        append_operation(&tx, event, true, &operation)?;
        self.capacity.check_database(&tx, true)?;
        tx.commit()?;
        Ok(operation)
    }
    pub fn audit_effect_result(&self, kind: Kind, operation: Option<String>, success: bool) {
        let Some(operation) = operation else {
            return;
        };
        let result = (|| -> Result<()> {
            let tx = self.db.unchecked_transaction()?;
            let mut event = Event::committed(kind);
            event.stage = Stage::Result;
            event.outcome = if success {
                Outcome::Succeeded
            } else {
                Outcome::Failed
            };
            event.reason = if kind == Kind::Export {
                Reason::LocalArtifact
            } else {
                Reason::ExternalEffect
            };
            if kind == Kind::Export {
                event.actor = Actor::LocalOperator;
            }
            append_operation(&tx, event, true, &operation)?;
            if success || kind == Kind::Export {
                tx.execute("DELETE FROM audit_pending WHERE operation=?1", [&operation])?;
            }
            self.capacity.check_database(&tx, true)?;
            tx.commit()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = self
                .db
                .execute("UPDATE audit_state SET gaps=1,degraded=1 WHERE id=1", []);
            tracing::error!("audit coverage degraded");
        }
    }
}

/// Explicit additive upgrade of established encrypted state; caller holds runtime lock.
pub fn upgrade(home: &Path) -> Result<()> {
    let db = crate::database::inspection::inspect(home, "auth")?;
    let version: u32 =
        db.query_row("SELECT MAX(version) FROM auth_migrations", [], |r| r.get(0))?;
    ensure!((2..=3).contains(&version), "unsupported auth schema");
    drop(db);
    crate::identity_model::AuthRegistry::open(home)?;
    Ok(())
}

/// Explicitly reopen ordinary recording after capacity/storage repair, preserving gaps.
pub fn recover(home: &Path) -> Result<()> {
    inspect(home)?;
    let registry = crate::identity_model::AuthRegistry::open(home)?;
    let tx = registry.db.unchecked_transaction()?;
    let state = info(&tx)?;
    ensure!(
        state.events + 1 < MAX_EVENTS - RESERVE_EVENTS
            && state.bytes + MAX_EVENT_BYTES as u64 <= MAX_BYTES - RESERVE_BYTES,
        "audit ordinary capacity still exhausted"
    );
    let mut event = Event::committed(Kind::StorageRecovered);
    event.actor = Actor::LocalOperator;
    append(&tx, event, true)?;
    registry.capacity.check_database(&tx, false)?;
    tx.execute("UPDATE audit_state SET degraded=0 WHERE id=1", [])?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn database() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE auth_migrations(version INTEGER PRIMARY KEY); INSERT INTO auth_migrations VALUES(1),(2);
CREATE TABLE users(id TEXT PRIMARY KEY,enabled INTEGER);
CREATE TABLE devices(nkey TEXT PRIMARY KEY);
CREATE TABLE authorization_groups(gid TEXT PRIMARY KEY);")?;
        migrate(&db)?;
        Ok(db)
    }
    #[test]
    fn rollback_reserve_sequence_and_schema() -> Result<()> {
        let db = database()?;
        let id = info(&db)?.store_id;
        {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "INSERT INTO users(id,enabled) VALUES('sentinel-name',1)",
                [],
            )?;
            append(&tx, Event::committed(Kind::TokenIssued), false)?;
            // Simulate failure/crash before transaction commit.
        }
        assert_eq!(info(&db)?.events, 0);
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?,
            0
        );
        let tx = db.unchecked_transaction()?;
        append(&tx, Event::committed(Kind::TokenIssued), false)?;
        tx.commit()?;
        assert_eq!(info(&db)?.upper_sequence, 1);
        db.execute(
            "UPDATE audit_state SET events=?1",
            [MAX_EVENTS - RESERVE_EVENTS],
        )?;
        let tx = db.unchecked_transaction()?;
        assert!(append(&tx, Event::committed(Kind::TokenIssued), false).is_err());
        append(&tx, Event::committed(Kind::DeviceRevoked), true)?;
        tx.commit()?;
        assert_eq!(info(&db)?.upper_sequence, 2);
        db.execute("UPDATE audit_state SET events=?1", [MAX_EVENTS])?;
        let tx = db.unchecked_transaction()?;
        tx.execute("INSERT INTO users(id,enabled) VALUES('repair',0)", [])?;
        repair(
            &tx,
            Event::committed(Kind::DeviceRevoked),
            &crate::capacity::Capacity::default(),
        );
        tx.commit()?;
        assert_eq!(
            db.query_row("SELECT enabled FROM users WHERE id='repair'", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
        assert!(info(&db)?.known_coverage_gaps);
        migrate(&db)?;
        assert_eq!(info(&db)?.store_id, id);
        db.execute("INSERT INTO auth_migrations VALUES(4)", [])?;
        assert!(migrate(&db).is_err());
        assert!(info(&db).is_err());
        Ok(())
    }
    #[test]
    fn migration_is_atomic_and_references_are_opaque() -> Result<()> {
        let db = database()?;
        db.execute(
            "INSERT INTO users(id,enabled) VALUES('secret-sentinel',1)",
            [],
        )?;
        let reference = reference(&db, "users", "id", "secret-sentinel")?;
        assert_eq!(reference.0.len(), 32);
        assert_ne!(reference.0, "secret-sentinel");
        assert!(Reference::try_from("secret-sentinel".to_owned()).is_err());
        let tx = db.unchecked_transaction()?;
        let mut event = Event::committed(Kind::TokenIssued);
        event.target_reference = Some(reference);
        append(&tx, event, false)?;
        tx.commit()?;
        let payload: String = db.query_row("SELECT payload FROM audit_events", [], |r| r.get(0))?;
        assert!(!payload.contains("secret-sentinel"));
        assert!(payload.len() <= MAX_EVENT_BYTES);
        let record: Record = serde_json::from_str(&payload)?;
        assert!(matches!(
            record.timestamp_quality,
            TimestampQuality::UntrustedWallClock
        ));
        Ok(())
    }
    #[test]
    fn encrypted_restart_export_and_retention() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("authority");
        let mut registry = crate::identity_model::AuthRegistry::open(&home)?;
        registry.invite("secret-sentinel", 60)?;
        let state = registry.audit_info()?;
        drop(registry);
        assert_eq!(inspect(&home)?.store_id, state.store_id);
        let output = root.path().join("export.jsonl");
        export(
            &home,
            &output,
            &state.store_id,
            0,
            state.upper_sequence,
            1000,
        )?;
        let contents = std::fs::read_to_string(&output)?;
        assert!(!contents.contains("secret-sentinel"));
        assert!(
            contents
                .lines()
                .last()
                .unwrap()
                .contains("\"complete\":true")
        );
        assert!(
            export(
                &home,
                &output,
                &state.store_id,
                0,
                state.upper_sequence,
                1000
            )
            .is_err()
        );
        assert_eq!(std::fs::read_to_string(&output)?, contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};
            assert_eq!(
                std::fs::metadata(&output)?.permissions().mode() & 0o777,
                0o600
            );
            let link = root.path().join("link");
            symlink(&output, &link)?;
            assert!(export(&home, &link, &state.store_id, 0, state.upper_sequence, 1000).is_err());
        }
        assert!(
            export(
                &home,
                &root.path().join("wrong"),
                "wrong",
                0,
                state.upper_sequence,
                1000
            )
            .is_err()
        );
        assert!(prune(&home, state.upper_sequence, true).is_err());
        set_retention(&home, state.upper_sequence)?;
        assert_eq!(prune(&home, state.upper_sequence, false)?.deleted, 0);
        assert_eq!(prune(&home, state.upper_sequence, true)?.deleted, 1);
        assert!(
            export(
                &home,
                &root.path().join("stale"),
                &state.store_id,
                0,
                state.upper_sequence,
                1000
            )
            .is_err()
        );
        let after = inspect(&home)?;
        assert!(after.upper_sequence > state.upper_sequence);
        assert_eq!(after.retained_from, 2);
        let missing = root.path().join("missing");
        assert!(inspect(&missing).is_err());
        assert!(!missing.exists());
        Ok(())
    }
    #[test]
    fn activation_policy_and_revocation_under_write_failure() -> Result<()> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("registry");
        let mut registry = crate::identity_model::AuthRegistry::open(&home)?;
        let token = registry.invite("alice", 60)?;
        let mut device = crate::identity::IdentityStore::open(&root.path().join("device"))?;
        let registration = device.init(
            crate::identity_model::token_user(&token)?.as_str(),
            "laptop",
        )?;
        let key = &registration.payload.nats_public_key;
        registry.db.execute_batch("CREATE TRIGGER fail_enrollment BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
        assert!(registry.enroll(&token, &registration).is_err());
        assert_eq!(
            registry
                .db
                .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, u64>(0))?,
            0
        );
        assert_eq!(
            registry.db.query_row(
                "SELECT COUNT(*) FROM enrollment_tokens WHERE used_key IS NOT NULL",
                [],
                |r| r.get::<_, u64>(0)
            )?,
            0
        );
        registry.db.execute_batch("DROP TRIGGER fail_enrollment")?;
        registry.enroll(&token, &registration)?;
        registry.db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
        assert!(registry.activate(key).is_err());
        assert!(registry.authorize(key).is_err());
        registry.db.execute_batch("DROP TRIGGER fail_audit")?;
        registry.activate(key)?;
        let signed = crate::authorization::PolicyUpdate {
            version: 1,
            gid: "a".repeat(32),
            expected_generation: 0,
            epoch: 0,
            signer: key.clone(),
            members: vec![crate::authorization::Member {
                nkey: key.clone(),
                leaf: 0,
            }],
        }
        .sign(&device.nkey()?)?;
        registry.db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
        assert!(registry.apply_policy(&signed).is_err());
        assert!(registry.policy_state(&signed.update.gid)?.is_none());
        registry.revoke(key)?;
        assert!(registry.authorize(key).is_err());
        assert!(registry.audit_info()?.degraded);
        registry.db.execute_batch("DROP TRIGGER fail_audit")?;
        assert!(registry.invite("bob", 60).is_err());
        drop(registry);
        recover(&home)?;
        assert!(!inspect(&home)?.degraded);
        Ok(())
    }
    #[test]
    fn incomplete_effect_survives_restart_and_denials_are_bounded() -> Result<()> {
        let root = tempfile::tempdir()?;
        let registry = crate::identity_model::AuthRegistry::open(root.path())?;
        let operation = registry.audit_effect(Kind::Reconciliation).unwrap();
        assert_eq!(registry.audit_info()?.unresolved_effects, 1);
        let mut denials = Denials::default();
        for _ in 0..100_000 {
            denials.observe(&registry);
        }
        assert_eq!(registry.audit_info()?.events, 1);
        denials.count = u64::MAX;
        denials.started -= std::time::Duration::from_secs(61);
        denials.observe(&registry);
        assert_eq!(registry.audit_info()?.events, 2);
        assert_eq!(denials.count, 1);
        drop(registry);
        let registry = crate::identity_model::AuthRegistry::open(root.path())?;
        assert_eq!(
            registry.audit_effect(Kind::Reconciliation).as_deref(),
            Some(operation.as_str())
        );
        registry.audit_effect_result(Kind::Reconciliation, Some(operation), true);
        assert_eq!(registry.audit_info()?.unresolved_effects, 0);
        Ok(())
    }
    #[test]
    fn interrupted_migration_rolls_back_all_schema_changes() -> Result<()> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE auth_migrations(version INTEGER PRIMARY KEY); INSERT INTO auth_migrations VALUES(1),(2); CREATE TABLE audit_events(sequence INTEGER);")?;
        assert!(migrate(&db).is_err());
        assert!(db.is_autocommit());
        assert_eq!(
            db.query_row("SELECT MAX(version) FROM auth_migrations", [], |r| r
                .get::<_, u32>(0))?,
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='audit_state'",
                [],
                |r| r.get::<_, u32>(0)
            )?,
            0
        );
        Ok(())
    }
    #[test]
    fn corrupt_metadata_and_byte_quota_fail_closed() -> Result<()> {
        let db = database()?;
        db.execute("UPDATE audit_state SET retained_from=0", [])?;
        assert!(info(&db).is_err());
        db.execute(
            "UPDATE audit_state SET retained_from=1,store_id='PRIVATE_SENTINEL'",
            [],
        )?;
        assert!(info(&db).is_err());
        db.execute(
            "UPDATE audit_state SET store_id=?1,bytes=?2",
            params![opaque()?, MAX_BYTES - RESERVE_BYTES],
        )?;
        let tx = db.unchecked_transaction()?;
        assert!(append(&tx, Event::committed(Kind::TokenIssued), false).is_err());
        append(&tx, Event::committed(Kind::DeviceRevoked), true)?;
        tx.commit()?;
        Ok(())
    }
    #[test]
    fn export_uses_reserve_and_survives_total_audit_exhaustion() -> Result<()> {
        let root = tempfile::tempdir()?;
        let registry = crate::identity_model::AuthRegistry::open(root.path())?;
        registry.db.execute(
            "UPDATE audit_state SET events=?1",
            [MAX_EVENTS - RESERVE_EVENTS],
        )?;
        assert!(registry.audit_export_start().is_ok());
        registry
            .db
            .execute("UPDATE audit_state SET events=?1", [MAX_EVENTS])?;
        assert!(registry.audit_export_start().is_err());
        let state = registry.audit_info()?;
        export(
            root.path(),
            &root.path().join("evidence.jsonl"),
            &state.store_id,
            0,
            state.upper_sequence,
            1000,
        )?;
        assert!(
            std::fs::read_to_string(root.path().join("evidence.jsonl"))?
                .lines()
                .last()
                .unwrap()
                .contains("\"complete\":true")
        );
        Ok(())
    }
    #[test]
    fn missing_export_tail_leaves_only_incomplete_artifact() -> Result<()> {
        let root = tempfile::tempdir()?;
        let registry = crate::identity_model::AuthRegistry::open(root.path())?;
        registry.audit_event(Event::committed(Kind::AuthorityStarted))?;
        registry.audit_event(Event::committed(Kind::AuthorityStarted))?;
        registry
            .db
            .execute("DELETE FROM audit_events WHERE sequence=2", [])?;
        let state = registry.audit_info()?;
        let output = root.path().join("broken.jsonl");
        assert!(
            export(
                root.path(),
                &output,
                &state.store_id,
                0,
                state.upper_sequence,
                1000
            )
            .is_err()
        );
        assert!(!output.exists());
        let partial = std::fs::read_to_string(root.path().join("broken.jsonl.partial"))?;
        assert!(partial.contains("\"complete\":false"));
        assert!(!partial.contains("\"complete\":true"));
        Ok(())
    }
    #[test]
    fn issuance_rolls_back_when_audit_insert_fails() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut registry = crate::identity_model::AuthRegistry::open(root.path())?;
        registry.db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected'); END;")?;
        assert!(registry.invite("alice", 60).is_err());
        assert_eq!(
            registry
                .db
                .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, u64>(0))?,
            0
        );
        assert_eq!(
            registry
                .db
                .query_row("SELECT COUNT(*) FROM enrollment_tokens", [], |r| r
                    .get::<_, u64>(0))?,
            0
        );
        Ok(())
    }
}
