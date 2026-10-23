use super::{Check, Report, Status, offline};
use crate::{
    auth_callout::Config,
    deployment::DeploymentManifest,
    secrets::{Kind, Vault},
    transport,
};
use async_nats::{Client, ConnectOptions, jetstream::stream::Info};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const OPERATION: Duration = Duration::from_secs(5);
const OVERALL: Duration = Duration::from_secs(60);

/// Capture asynchronous permission errors without logging server-controlled text.
#[derive(Clone, Default)]
pub struct PermissionMonitor(Arc<AtomicBool>);
impl PermissionMonitor {
    pub fn configure(&self, options: ConnectOptions) -> ConnectOptions {
        let denied = self.0.clone();
        options.event_callback(move |event| {
            let denied = denied.clone();
            async move {
                let permission = match event {
                    async_nats::Event::ServerError(
                        async_nats::ServerError::AuthorizationViolation,
                    ) => true,
                    async_nats::Event::ServerError(async_nats::ServerError::Other(text)) => {
                        text.starts_with("Permissions Violation")
                    }
                    _ => false,
                };
                if permission {
                    denied.store(true, Ordering::Release);
                }
            }
        })
    }
    fn failure(&self, fallback: &'static str) -> &'static str {
        if self.0.load(Ordering::Acquire) {
            "permission_denied"
        } else {
            fallback
        }
    }
}

fn record(report: &mut Report, id: &str, expected: Value, result: Result<Value, &'static str>) {
    let (status, observed) = match result {
        Ok(value) => (Status::Passed, value),
        Err(code) => (Status::Failed, json!({"code":code})),
    };
    report.checks.push(Check {
        id: id.into(), status, required: true, expected, observed,
        remediation: (status == Status::Failed).then(|| "Check endpoint TLS/authentication, the running backend, inspection permissions and operator-provisioned resources; apply the generated contract and rerun. No resources were changed.".into()),
    });
}
fn outcome(report: &mut Report) {
    report.success = report
        .checks
        .iter()
        .filter(|c| c.required)
        .all(|c| c.status == Status::Passed);
}
fn connect_error(error: async_nats::ConnectError) -> &'static str {
    use async_nats::ConnectErrorKind::*;
    match error.kind() {
        AuthorizationViolation | Authentication => "authentication_denied",
        TimedOut => "timeout",
        Tls => "tls_failed",
        ServerParse => "endpoint_invalid",
        _ => "endpoint_unavailable",
    }
}
async fn request(
    client: &Client,
    monitor: &PermissionMonitor,
    subject: String,
) -> Result<Value, &'static str> {
    if monitor.0.load(Ordering::Acquire) {
        return Err("permission_denied");
    }
    let message = tokio::time::timeout(OPERATION, client.request(subject, "{}".into()))
        .await
        .map_err(|_| monitor.failure("timeout"))?
        .map_err(|error| {
            monitor.failure(match error.kind() {
                async_nats::RequestErrorKind::NoResponders => "service_unavailable",
                async_nats::RequestErrorKind::TimedOut => "timeout",
                _ => "request_failed",
            })
        })?;
    let value: Value = serde_json::from_slice(&message.payload).map_err(|_| "response_invalid")?;
    if let Some(error) = value.get("error") {
        return Err(match error.get("code").and_then(Value::as_u64) {
            Some(401 | 403) => "permission_denied",
            Some(404) => "resource_missing",
            Some(503) => "service_unavailable",
            _ => "inspection_failed",
        });
    }
    Ok(value)
}
fn healthy(cluster: Option<&async_nats::jetstream::stream::ClusterInfo>, replicas: usize) -> bool {
    match cluster {
        None => replicas == 1,
        Some(cluster) => {
            cluster.leader.as_ref().is_some_and(|v| !v.is_empty())
                && cluster.replicas.len() == replicas - 1
                && cluster
                    .replicas
                    .iter()
                    .all(|p| p.current && !p.offline && p.lag.unwrap_or(0) == 0)
        }
    }
}
async fn resources(
    report: &mut Report,
    prefix: &str,
    client: &Client,
    manifest: &DeploymentManifest,
    monitor: &PermissionMonitor,
) {
    // An authenticated API round trip is required; INFO alone cannot establish admission.
    let account = request(client, monitor, "$JS.API.INFO".into())
        .await
        .and_then(|value| {
            serde_json::from_value::<async_nats::jetstream::account::Account>(value)
                .map(|_| json!("authenticated JetStream account inspection succeeded"))
                .map_err(|_| "response_invalid")
        });
    record(
        report,
        &format!("{prefix}.jetstream"),
        json!("authenticated account inspection"),
        account,
    );
    let server = client.server_info();
    record(
        report,
        &format!("{prefix}.server"),
        json!({"version":"2.14.5","minimum_max_payload":65536}),
        if server.version == "2.14.5" && server.max_payload >= 65536 {
            Ok(
                json!({"version":"2.14.5","max_payload":server.max_payload,"discovered_endpoint_count":server.connect_urls.len()}),
            )
        } else {
            Err("server_incompatible")
        },
    );
    for expected in manifest.resources() {
        let id = format!("{prefix}.resources.{}", expected.name);
        let response = request(
            client,
            monitor,
            format!("$JS.API.STREAM.INFO.{}", expected.name),
        )
        .await
        .and_then(|value| serde_json::from_value::<Info>(value).map_err(|_| "response_invalid"));
        match response {
            Err(code) => {
                record(
                    report,
                    &id,
                    json!("existing contract-compatible stream/KV backing stream"),
                    Err(code),
                );
                report.skip(
                    &format!("{id}.replicas"),
                    true,
                    "resource inspection failed",
                );
            }
            Ok(info) => {
                let mismatches = manifest
                    .compare(&expected.name, &info.config)
                    .expect("known contract resource");
                let fields: Vec<_> = mismatches.iter().map(|m| &m.field).collect();
                record(
                    report,
                    &id,
                    json!({"contract_version":1,"replicas":manifest.replicas()}),
                    if fields.is_empty() {
                        Ok(json!("compatible"))
                    } else {
                        Err("resource_incompatible")
                    },
                );
                if !fields.is_empty() {
                    // Field names originate in our contract, never in server text or private records.
                    report.checks.last_mut().unwrap().observed =
                        json!({"code":"resource_incompatible","fields":fields});
                }
                record(
                    report,
                    &format!("{id}.replicas"),
                    json!({"replicas":manifest.replicas(),"current":true,"offline":false,"lag":0}),
                    if healthy(info.cluster.as_ref(), manifest.replicas()) {
                        Ok(json!("healthy"))
                    } else {
                        Err("replicas_unhealthy")
                    },
                );
            }
        }
    }
}

/// Lookup-only startup check. The caller must keep admission closed until success.
pub async fn inspect_resources(
    client: &Client,
    manifest: &DeploymentManifest,
    monitor: &PermissionMonitor,
) -> Report {
    let mut report = Report {
        version: 1,
        mode: "startup".into(),
        success: false,
        checks: Vec::new(),
    };
    if tokio::time::timeout(
        OVERALL,
        resources(&mut report, "startup", client, manifest, monitor),
    )
    .await
    .is_err()
    {
        record(
            &mut report,
            "startup.deadline",
            json!("complete within 60 seconds"),
            Err("timeout"),
        );
    }
    outcome(&mut report);
    report
}

/// Validate explicit endpoints independently. Never subscribes to Auth Callout or writes NATS state.
pub async fn online(home: &Path, auth_config: &Path, endpoints: &[String]) -> Report {
    let mut report = offline(home, auth_config, None);
    report.mode = "online".into();
    report
        .checks
        .retain(|c| c.id != "coverage.network" && c.id != "local.transport.endpoint");
    record(
        &mut report,
        "online.endpoints",
        json!("1 to 8 explicit endpoints"),
        if !endpoints.is_empty() && endpoints.len() <= 8 {
            Ok(json!({"supplied":endpoints.len()}))
        } else {
            Err("endpoints_required_or_too_many")
        },
    );
    outcome(&mut report);
    if !report.success {
        report.skip(
            "coverage.network",
            true,
            "local prerequisites failed; no connections attempted",
        );
        outcome(&mut report);
        return report;
    }
    // Re-resolve existing credentials only; no IdentityStore::open or initialization.
    let inputs = (|| -> anyhow::Result<_> {
        let config = Config::load(auth_config)?;
        let manifest: DeploymentManifest =
            serde_json::from_slice(&std::fs::read(home.join(crate::deployment::MANIFEST_FILE))?)?;
        let reference = Vault::new(&home.join("control")).existing("device", Kind::User)?;
        anyhow::ensure!(
            reference.public_key == config.control_nkey,
            "control binding changed"
        );
        let key = nkeys::KeyPair::from_seed(&reference.read()?)?;
        Ok((config, manifest, key))
    })();
    let Ok((config, manifest, key)) = inputs else {
        record(
            &mut report,
            "online.credentials",
            json!("unchanged existing credentials"),
            Err("local_inputs_changed"),
        );
        outcome(&mut report);
        return report;
    };
    let completed = tokio::time::timeout(OVERALL, async {
        for (index, endpoint) in endpoints.iter().enumerate() {
            let prefix = format!("online.endpoints.{index}");
            let monitor = PermissionMonitor::default();
            let connectors = (|| -> anyhow::Result<_> {
                config.check_transport(endpoint)?;
                Ok((
                    config.connection_options(endpoint)?,
                    transport::connection_options(endpoint, &key)?,
                ))
            })();
            let Ok((auth_options, control_options)) = connectors else {
                record(
                    &mut report,
                    &format!("{prefix}.transport"),
                    json!("valid shared TLS policy"),
                    Err("transport_invalid"),
                );
                continue;
            };
            let auth = tokio::time::timeout(
                OPERATION,
                monitor
                    .configure(auth_options)
                    .ignore_discovered_servers()
                    .max_reconnects(0)
                    .connect(endpoint.as_str()),
            )
            .await;
            let auth_result = match auth {
                Ok(Ok(client)) => tokio::time::timeout(OPERATION, client.flush())
                    .await
                    .map_err(|_| "timeout")
                    .and_then(|r| r.map_err(|_| monitor.failure("authentication_failed")))
                    .map(|_| json!("authenticated service connection flushed")),
                Ok(Err(error)) => Err(connect_error(error)),
                Err(_) => Err("timeout"),
            };
            record(
                &mut report,
                &format!("{prefix}.auth"),
                json!("authenticated service connection"),
                auth_result,
            );
            let control = tokio::time::timeout(
                OPERATION,
                monitor
                    .configure(control_options)
                    .ignore_discovered_servers()
                    .max_reconnects(0)
                    .connect(endpoint.as_str()),
            )
            .await;
            match control {
                Ok(Ok(client)) => {
                    resources(&mut report, &prefix, &client, &manifest, &monitor).await
                }
                error => {
                    let code = match error {
                        Ok(Err(e)) => connect_error(e),
                        _ => "timeout",
                    };
                    record(
                        &mut report,
                        &format!("{prefix}.control"),
                        json!("existing control identity admitted by running backend"),
                        Err(code),
                    );
                }
            }
        }
    })
    .await;
    if completed.is_err() {
        record(
            &mut report,
            "online.deadline",
            json!("all endpoints completed within 60 seconds"),
            Err("timeout"),
        );
    }
    report.skip("coverage.discovery", false, "Only explicitly supplied endpoints were inspected individually; discovered endpoints, routes, account isolation, signer scope, resolver lifecycle and capacity remain operator checks. Replica health is a point-in-time observation.");
    outcome(&mut report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::stream::{ClusterInfo, PeerInfo};

    #[test]
    fn replica_health_requires_leader_and_all_current_peers() {
        assert!(healthy(None, 1));
        assert!(!healthy(None, 3));
        let mut cluster: ClusterInfo =
            serde_json::from_value(json!({"leader":"node0","replicas":[]})).unwrap();
        assert!(!healthy(Some(&cluster), 3));
        cluster.replicas = vec![
            PeerInfo {
                name: "node1".into(),
                current: true,
                lag: Some(0),
                ..Default::default()
            },
            PeerInfo {
                name: "node2".into(),
                current: true,
                lag: Some(0),
                ..Default::default()
            },
        ];
        assert!(healthy(Some(&cluster), 3));
        cluster.replicas[0].offline = true;
        assert!(!healthy(Some(&cluster), 3));
        cluster.replicas[0].offline = false;
        cluster.replicas[1].current = false;
        assert!(!healthy(Some(&cluster), 3));
        cluster.replicas[1].current = true;
        cluster.replicas[0].lag = Some(1);
        assert!(!healthy(Some(&cluster), 3));
        cluster.replicas[0].lag = Some(0);
        cluster.leader = None;
        assert!(!healthy(Some(&cluster), 3));
    }

    #[test]
    fn reports_and_connect_errors_are_sanitized_and_versioned() {
        let mut report = Report {
            version: 1,
            mode: "online".into(),
            success: false,
            checks: Vec::new(),
        };
        let error = async_nats::ConnectError::with_source(
            async_nats::ConnectErrorKind::Tls,
            "SECRET JWT AND URL",
        );
        record(
            &mut report,
            "online.endpoints.0.auth",
            json!("authenticated"),
            Err(connect_error(error)),
        );
        outcome(&mut report);
        let bytes = serde_json::to_vec(&report).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SECRET"));
        assert!(!Report::parse(&bytes).unwrap().success);
        assert_eq!(report.checks[0].observed["code"], "tls_failed");
    }
}
