//! Bounded operational observations. These counters are not an audit trail.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_REPORT: usize = 16 * 1024;
pub const VERSION: u16 = 1;
pub const STALE_MS: u64 = 30_000;
pub const REFRESH_SECONDS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Authority,
    Control,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    Ready,
    NotReady,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    ConfigurationInvalid,
    AuthorityUnavailable,
    ObservationTimeout,
    UnsupportedResponse,
    ReconciliationPending,
    WorkerAbsent,
    WorkerLeaseExpired,
    LeaseUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Current,
    Stale,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Connection {
    Connected,
    Disconnected,
    Pending,
}

#[derive(Default)]
pub struct Counter(AtomicU64);
impl Counter {
    pub fn increment(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}
#[derive(Default)]
pub struct Counters {
    pub received: Counter,
    pub accepted: Counter,
    pub denied: Counter,
    pub rate_limited: Counter,
    pub malformed: Counter,
    pub timeout: Counter,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub received: u64,
    pub accepted: u64,
    pub denied: u64,
    pub rate_limited: u64,
    pub malformed: u64,
    pub timeout: u64,
}
impl Counters {
    pub fn snapshot(&self) -> Counts {
        Counts {
            received: self.received.get(),
            accepted: self.accepted.get(),
            denied: self.denied.get(),
            rate_limited: self.rate_limited.get(),
            malformed: self.malformed.get(),
            timeout: self.timeout.get(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub used: u64,
    pub limit: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub users: Budget,
    pub devices: Budget,
    pub tokens: Budget,
    pub groups: Budget,
    pub memberships: Budget,
    pub database_bytes: Budget,
    pub recovery_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityObservation {
    pub availability: Availability,
    pub age_ms: Option<u64>,
    pub usage: Option<Usage>,
    pub collection_ms: Option<u64>,
}
impl CapacityObservation {
    pub fn unavailable() -> Self {
        Self {
            availability: Availability::Unavailable,
            age_ms: None,
            usage: None,
            collection_ms: None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observations {
    pub reconciled: bool,
    pub worker_live: bool,
    pub worker_lease_age_ms: Option<u64>,
    pub worker_lease_limit_ms: u64,
    pub auth_requests: Counts,
    pub control_requests: Counts,
    pub ipc_disconnects: u64,
    pub reconciliation_success: u64,
    pub reconciliation_failure: u64,
    pub reconciliation_age_ms: Option<u64>,
    pub control_queue_used: usize,
    pub control_queue_limit: usize,
    pub auth_connection: Option<Connection>,
    pub control_connection: Option<Connection>,
    pub permission_denied_observed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity: Option<CapacityObservation>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub broker_resources: bool,
    pub worker_network: bool,
    pub keyring: bool,
    pub physical_capacity: bool,
    pub audit_trail: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u16,
    pub role: Role,
    pub readiness: Readiness,
    pub reasons: Vec<Reason>,
    pub instance: Option<String>,
    pub uptime_ms: Option<u64>,
    pub observations: Option<Observations>,
    pub coverage: Coverage,
}
impl Report {
    pub fn unknown(role: Role, reason: Reason) -> Self {
        Self {
            version: VERSION,
            role,
            readiness: Readiness::Unknown,
            reasons: vec![reason],
            instance: None,
            uptime_ms: None,
            observations: None,
            coverage: Coverage::default(),
        }
    }
    pub fn exit_code(&self) -> i32 {
        match self.readiness {
            Readiness::Ready => 0,
            Readiness::NotReady => 1,
            Readiness::Unknown => 2,
        }
    }
    pub fn parse(bytes: &[u8], role: Role) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() <= MAX_REPORT, "diagnostic response too large");
        let report: Self = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            report.version == VERSION && report.role == role,
            "unsupported diagnostic response"
        );
        anyhow::ensure!(
            report.reasons.len() <= 8
                && !report.coverage.broker_resources
                && !report.coverage.worker_network
                && !report.coverage.keyring
                && !report.coverage.physical_capacity
                && !report.coverage.audit_trail,
            "invalid diagnostic coverage"
        );
        if let Some(obs) = &report.observations {
            let instance = report
                .instance
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing instance"))?;
            anyhow::ensure!(
                instance.len() == 32
                    && instance.bytes().all(|b| b.is_ascii_hexdigit())
                    && report.uptime_ms.is_some(),
                "invalid runtime instance"
            );
            anyhow::ensure!(
                role != Role::Control || obs.capacity.is_none(),
                "invalid control view"
            );
            anyhow::ensure!(
                obs.control_queue_limit == 1
                    && obs.control_queue_used <= 1
                    && obs.worker_lease_limit_ms == 5000,
                "invalid runtime bounds"
            );
            let expected = if obs.reconciled && obs.worker_live {
                Readiness::Ready
            } else {
                Readiness::NotReady
            };
            anyhow::ensure!(
                report.readiness == expected
                    && (report.reasons.is_empty() == (expected == Readiness::Ready)),
                "inconsistent readiness"
            );
        } else {
            anyhow::ensure!(
                report.readiness == Readiness::Unknown
                    && report.instance.is_none()
                    && report.uptime_ms.is_none()
                    && !report.reasons.is_empty(),
                "invalid unavailable observation"
            );
        }
        Ok(report)
    }
    pub fn human(&self) -> String {
        // The same typed, allowlisted fields as JSON; no raw error or caller values.
        format!(
            "EpochGrid operational status (snapshot; see coverage):\n{}\n",
            serde_json::to_string_pretty(self).expect("typed diagnostic report")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_versions_unknown_exit_and_saturation() {
        let c = Counter(AtomicU64::new(u64::MAX));
        c.increment();
        assert_eq!(c.get(), u64::MAX);
        assert_eq!(Counter::default().get(), 0);
        let mut report = Report::unknown(Role::Authority, Reason::AuthorityUnavailable);
        assert_eq!(report.exit_code(), 2);
        assert!(Report::parse(&serde_json::to_vec(&report).unwrap(), Role::Authority).is_ok());
        assert!(Report::parse(&serde_json::to_vec(&report).unwrap(), Role::Control).is_err());
        report.version = 999;
        assert!(Report::parse(&serde_json::to_vec(&report).unwrap(), Role::Authority).is_err());
        assert!(Report::parse(&vec![b' '; MAX_REPORT + 1], Role::Authority).is_err());
        assert!(Report::parse(br#"{"private_marker":"SECRET"}"#, Role::Authority).is_err());
    }
}
