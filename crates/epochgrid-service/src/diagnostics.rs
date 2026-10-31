//! Local operational snapshots. No database or keyring work on the status path.
use epochgrid_core::diagnostics::*;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct Runtime {
    pub reconciled: Arc<AtomicBool>,
    pub live: Arc<AtomicBool>,
    pub last_seen: Arc<Mutex<Instant>>,
    pub auth: Arc<Counters>,
    pub control: Counters,
    pub disconnects: Counter,
    pub repair_ok: Counter,
    pub repair_failed: Counter,
    started: Instant,
    instance: String,
    repair_completed: Mutex<Option<Instant>>,
    capacity: Mutex<Option<(Instant, Usage, u64)>>,
    connections: Mutex<
        Option<(
            async_nats::Client,
            async_nats::Client,
            epochgrid_core::validation::PermissionMonitor,
        )>,
    >,
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
impl Runtime {
    pub fn new(reconciled: Arc<AtomicBool>) -> anyhow::Result<Self> {
        use std::io::Read;
        let mut random = [0u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        Ok(Self {
            reconciled,
            live: Arc::new(AtomicBool::new(false)),
            last_seen: Arc::new(Mutex::new(Instant::now())),
            auth: Arc::new(Counters::default()),
            control: Counters::default(),
            disconnects: Counter::default(),
            repair_ok: Counter::default(),
            repair_failed: Counter::default(),
            started: Instant::now(),
            instance: random.iter().map(|b| format!("{b:02x}")).collect(),
            repair_completed: Mutex::new(None),
            capacity: Mutex::new(None),
            connections: Mutex::new(None),
        })
    }
    pub fn ready(&self) -> bool {
        self.state(Instant::now()).0 == Readiness::Ready
    }
    fn state(&self, now: Instant) -> (Readiness, Vec<Reason>, bool, Option<u64>) {
        let reconciled = self.reconciled.load(Ordering::Acquire);
        let live = self.live.load(Ordering::Acquire);
        let age = if live {
            self.last_seen
                .lock()
                .ok()
                .map(|seen| now.saturating_duration_since(*seen))
        } else {
            None
        };
        let worker_live = live && age.is_some_and(|age| age < Duration::from_secs(5));
        let mut reasons = Vec::with_capacity(2);
        if !reconciled {
            reasons.push(Reason::ReconciliationPending);
        }
        if !live {
            reasons.push(Reason::WorkerAbsent);
        } else if age.is_none() {
            reasons.push(Reason::LeaseUnavailable);
        } else if !worker_live {
            reasons.push(Reason::WorkerLeaseExpired);
        }
        (
            if reconciled && worker_live {
                Readiness::Ready
            } else {
                Readiness::NotReady
            },
            reasons,
            worker_live,
            age.map(millis),
        )
    }
    pub fn connections(
        &self,
        auth: async_nats::Client,
        control: async_nats::Client,
        monitor: epochgrid_core::validation::PermissionMonitor,
    ) {
        if let Ok(mut value) = self.connections.lock() {
            *value = Some((auth, control, monitor));
        }
    }
    pub fn repair(&self, success: bool) {
        if success {
            self.repair_ok.increment();
            if let Ok(mut stamp) = self.repair_completed.lock() {
                *stamp = Some(Instant::now());
            }
        } else {
            self.repair_failed.increment();
        }
    }
    pub fn refresh(&self, registry: &epochgrid_core::identity_model::AuthRegistry) {
        let start = Instant::now();
        let value = registry
            .diagnostic_usage()
            .ok()
            .map(|usage| (Instant::now(), usage, millis(start.elapsed())));
        if let Ok(mut cached) = self.capacity.lock() {
            *cached = value;
        }
    }
    pub fn snapshot(&self, role: Role, queued: usize) -> Report {
        self.snapshot_at(role, queued, Instant::now())
    }
    fn snapshot_at(&self, role: Role, queued: usize, now: Instant) -> Report {
        let (readiness, reasons, worker_live, age) = self.state(now);
        let capacity = (role == Role::Authority).then(|| {
            self.capacity
                .lock()
                .ok()
                .and_then(|cache| {
                    cache.as_ref().map(|(stamp, usage, cost)| {
                        let age = millis(now.saturating_duration_since(*stamp));
                        CapacityObservation {
                            availability: if age <= STALE_MS {
                                Availability::Current
                            } else {
                                Availability::Stale
                            },
                            age_ms: Some(age),
                            usage: if age <= STALE_MS {
                                Some(usage.clone())
                            } else {
                                None
                            },
                            collection_ms: Some(*cost),
                        }
                    })
                })
                .unwrap_or_else(CapacityObservation::unavailable)
        });
        let connection = |client: &async_nats::Client| match client.connection_state() {
            async_nats::connection::State::Connected => Connection::Connected,
            async_nats::connection::State::Disconnected => Connection::Disconnected,
            async_nats::connection::State::Pending => Connection::Pending,
        };
        let connections = self.connections.lock().ok();
        let connections = connections.as_ref().and_then(|v| v.as_ref());
        let reconciled = !reasons.contains(&Reason::ReconciliationPending);
        Report {
            version: VERSION,
            role,
            readiness,
            reasons,
            instance: Some(self.instance.clone()),
            uptime_ms: Some(millis(now.saturating_duration_since(self.started))),
            observations: Some(Observations {
                // Derive this from the same sampled state, not a second atomic read.
                reconciled,
                worker_live,
                worker_lease_age_ms: age,
                worker_lease_limit_ms: 5000,
                auth_requests: self.auth.snapshot(),
                control_requests: self.control.snapshot(),
                ipc_disconnects: self.disconnects.get(),
                reconciliation_success: self.repair_ok.get(),
                reconciliation_failure: self.repair_failed.get(),
                reconciliation_age_ms: self
                    .repair_completed
                    .lock()
                    .ok()
                    .and_then(|s| s.map(|s| millis(now.saturating_duration_since(s)))),
                control_queue_used: queued,
                control_queue_limit: 1,
                auth_connection: connections.map(|(a, _, _)| connection(a)),
                control_connection: connections.map(|(_, c, _)| connection(c)),
                permission_denied_observed: connections.is_some_and(|(_, _, m)| m.denied()),
                capacity,
            }),
            coverage: Coverage::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn monotonic_gate_views_and_freshness() -> anyhow::Result<()> {
        let runtime = Runtime::new(Arc::new(AtomicBool::new(false)))?;
        let now = Instant::now();
        let closed = runtime.snapshot_at(Role::Authority, 0, now);
        assert_eq!(closed.exit_code(), 1);
        assert!(closed.reasons.contains(&Reason::WorkerAbsent));
        runtime.reconciled.store(true, Ordering::Release);
        runtime.live.store(true, Ordering::Release);
        *runtime.last_seen.lock().unwrap() = now;
        let ready = runtime.snapshot_at(Role::Control, 0, now);
        assert_eq!(ready.exit_code(), 0);
        let bytes = serde_json::to_vec(&ready)?;
        Report::parse(&bytes, Role::Control)?;
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes)?["observations"]
                .get("capacity")
                .is_none()
        );
        assert_eq!(
            runtime
                .snapshot_at(Role::Control, 0, now + Duration::from_secs(5))
                .reasons,
            vec![Reason::WorkerLeaseExpired]
        );
        let next = Runtime::new(Arc::new(AtomicBool::new(false)))?;
        assert_ne!(runtime.instance, next.instance);
        runtime.auth.received.increment();
        assert_eq!(runtime.auth.received.get(), 1);
        assert_eq!(next.auth.received.get(), 0);
        let b = || Budget { used: 1, limit: 2 };
        *runtime.capacity.lock().unwrap() = Some((
            now,
            Usage {
                users: b(),
                devices: b(),
                tokens: b(),
                groups: b(),
                memberships: b(),
                database_bytes: b(),
                recovery_bytes: 1,
            },
            0,
        ));
        for (seconds, expected) in [(30, Availability::Current), (31, Availability::Stale)] {
            let report =
                runtime.snapshot_at(Role::Authority, 0, now + Duration::from_secs(seconds));
            let capacity = report.observations.unwrap().capacity.unwrap();
            assert_eq!(capacity.availability, expected);
            assert_eq!(capacity.usage.is_some(), seconds == 30);
        }
        Ok(())
    }
}
