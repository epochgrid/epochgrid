//! Public deployment contract. Inspection never creates or updates broker resources.
use anyhow::{Result, ensure};
use async_nats::jetstream::stream::{Config, DiscardPolicy, RetentionPolicy, StorageType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const MANIFEST_FILE: &str = "deployment.json";

/// Private fields ensure even programmatically constructed manifests are validated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ManifestInput")]
pub struct DeploymentManifest {
    version: u32,
    replicas: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestInput {
    version: u32,
    replicas: usize,
}

impl TryFrom<ManifestInput> for DeploymentManifest {
    type Error = anyhow::Error;

    fn try_from(input: ManifestInput) -> Result<Self> {
        ensure!(
            input.version == 1,
            "unsupported deployment manifest version"
        );
        Self::new(input.replicas)
    }
}

impl DeploymentManifest {
    pub fn new(replicas: usize) -> Result<Self> {
        ensure!(
            matches!(replicas, 1 | 3),
            "deployment replicas must be 1 or 3"
        );
        Ok(Self {
            version: 1,
            replicas,
        })
    }

    pub fn replicas(&self) -> usize {
        self.replicas
    }

    /// Stream CREATE configurations, including the native KV backing streams.
    /// The operator supplies application-account credentials and storage budgets.
    pub fn resources(&self) -> Vec<Config> {
        let mut resources = Vec::new();
        for (name, subjects) in [
            (
                "CHAT",
                vec![
                    "epochgrid.v1.group.*.message",
                    "epochgrid.v1.group.*.handshake",
                ],
            ),
            ("MAILBOX", vec!["epochgrid.v1.user.*.*.inbox"]),
        ] {
            resources.push(Config {
                name: name.into(),
                subjects: subjects.into_iter().map(str::to_owned).collect(),
                storage: StorageType::File,
                retention: RetentionPolicy::Limits,
                num_replicas: self.replicas,
                max_message_size: 65536,
                max_messages: -1,
                max_bytes: -1,
                max_messages_per_subject: -1,
                max_consumers: -1,
                ..Default::default()
            });
        }
        for bucket in ["IDENTITIES", "CHANNELS", "TRANSPARENCY"] {
            resources.push(Config {
                name: format!("KV_{bucket}"),
                subjects: vec![format!("$KV.{bucket}.>")],
                storage: StorageType::File,
                retention: RetentionPolicy::Limits,
                num_replicas: self.replicas,
                max_messages_per_subject: 1,
                max_message_size: if bucket == "TRANSPARENCY" { 65536 } else { -1 },
                max_messages: -1,
                max_bytes: -1,
                max_consumers: -1,
                discard: DiscardPolicy::New,
                allow_rollup: true,
                deny_delete: true,
                allow_direct: true,
                ..Default::default()
            });
        }
        resources
    }

    /// Deterministic public artifacts, suitable for `nats stream add --config`.
    /// Publication/overwrite policy belongs to the setup layer, not this renderer.
    pub fn artifacts(&self) -> Result<BTreeMap<String, String>> {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            MANIFEST_FILE.into(),
            format!("{}\n", serde_json::to_string_pretty(self)?),
        );
        for config in self.resources() {
            artifacts.insert(
                format!("{}.json", config.name),
                format!("{}\n", serde_json::to_string_pretty(&config)?),
            );
        }
        Ok(artifacts)
    }

    /// Compare an INFO response for a separately identified resource. Never trust
    /// the observed name to select its expected contract.
    pub fn compare(&self, resource: &str, observed: &Config) -> Result<Vec<ResourceMismatch>> {
        let expected = self
            .resources()
            .into_iter()
            .find(|c| c.name == resource)
            .ok_or_else(|| anyhow::anyhow!("unknown deployment resource"))?;
        let kv = resource.starts_with("KV_");
        let mut issues = Vec::new();
        macro_rules! check {
            ($field:ident) => {
                if expected.$field != observed.$field {
                    issues.push(ResourceMismatch {
                        resource: resource.into(),
                        field: stringify!($field).into(),
                        expected: json!(expected.$field),
                        observed: json!(observed.$field),
                    });
                }
            };
        }
        check!(name);
        let mut subjects = observed.subjects.clone();
        subjects.sort();
        let mut required = expected.subjects.clone();
        required.sort();
        if subjects != required {
            issues.push(ResourceMismatch {
                resource: resource.into(),
                field: "subjects".into(),
                expected: json!(required),
                observed: json!(subjects),
            });
        }
        check!(storage);
        check!(retention);
        check!(num_replicas);
        check!(discard);
        check!(discard_new_per_subject);
        check!(max_age);
        check!(no_ack);
        if observed.persist_mode == Some(async_nats::jetstream::stream::PersistenceMode::Async) {
            issues.push(ResourceMismatch {
                resource: resource.into(),
                field: "persist_mode".into(),
                expected: json!("default"),
                observed: json!("async"),
            });
        }
        check!(sealed);
        check!(template_owner);
        check!(allow_rollup);
        check!(republish);
        check!(mirror);
        // An absent sources list and an empty sources list are equivalent.
        if observed
            .sources
            .as_ref()
            .is_some_and(|sources| !sources.is_empty())
        {
            issues.push(ResourceMismatch {
                resource: resource.into(),
                field: "sources".into(),
                expected: json!([]),
                observed: json!(observed.sources),
            });
        }
        check!(mirror_direct);
        check!(subject_transform);
        check!(allow_message_ttl);
        check!(subject_delete_marker_ttl);
        check!(pause_until);
        check!(allow_message_schedules);
        check!(allow_message_counter);
        if kv {
            check!(max_messages_per_subject);
            check!(deny_delete);
            check!(deny_purge);
            check!(allow_direct);
        } else if !unlimited(observed.max_messages_per_subject) {
            check!(max_messages_per_subject);
        }
        if resource == "KV_IDENTITIES" || resource == "KV_CHANNELS" {
            if !unlimited(i64::from(observed.max_message_size)) && observed.max_message_size < 65536
            {
                issues.push(ResourceMismatch {
                    resource: resource.into(),
                    field: "max_message_size".into(),
                    expected: json!("unlimited or >= 65536"),
                    observed: json!(observed.max_message_size),
                });
            }
        } else {
            check!(max_message_size);
        }
        // Finite operator quotas are accepted, not certified adequate. Malformed
        // negative values are not a valid unlimited representation.
        for (field, value) in [
            ("max_bytes", observed.max_bytes),
            ("max_messages", observed.max_messages),
            ("max_consumers", i64::from(observed.max_consumers)),
        ] {
            if value < -1 {
                issues.push(ResourceMismatch {
                    resource: resource.into(),
                    field: field.into(),
                    expected: json!(">= -1"),
                    observed: json!(value),
                });
            }
        }
        if let Some(limits) = &observed.consumer_limits
            && (!limits.inactive_threshold.is_zero() || limits.max_ack_pending < -1)
        {
            issues.push(ResourceMismatch {
                resource: resource.into(),
                field: "consumer_limits".into(),
                expected: json!("no inactivity eviction; max_ack_pending >= -1"),
                observed: json!(limits),
            });
        }
        Ok(issues)
    }
}

fn unlimited(value: i64) -> bool {
    matches!(value, -1 | 0)
}

/// Public configuration differences; no credentials or application records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResourceMismatch {
    pub resource: String,
    pub field: String,
    pub expected: Value,
    pub observed: Value,
}

#[cfg(test)]
mod tests;
