use crate::{
    identity::{IdentityStore, verify},
    wire::{self, Body, DeviceRegistration},
};
use anyhow::{Result, anyhow, ensure};
use std::{collections::BTreeMap, path::Path, time::Duration};

pub type Enrollment = BTreeMap<String, String>;
pub async fn connect(url: &str, store: &IdentityStore) -> Result<async_nats::Client> {
    let key = store.nkey()?;
    Ok(async_nats::ConnectOptions::with_nkey(key.seed()?)
        .custom_inbox_prefix(format!("_INBOX.{}", key.public_key()))
        .request_timeout(Some(Duration::from_secs(5)))
        .connection_timeout(Duration::from_secs(5))
        .connect(url)
        .await?)
}
pub async fn register(client: &async_nats::Client, registration: DeviceRegistration) -> Result<()> {
    let response = client
        .request(
            wire::REGISTER,
            wire::encode(Body::Register(registration))?.into(),
        )
        .await?;
    ensure!(
        matches!(wire::decode(&response.payload)?, Body::Registered),
        "registration rejected"
    );
    Ok(())
}
/// Validate both the returned signature/package and the requested endpoint.
pub async fn lookup(
    client: &async_nats::Client,
    user: &str,
    device: &str,
) -> Result<DeviceRegistration> {
    wire::validate_id(user)?;
    wire::validate_id(device)?;
    let response = client
        .request(
            wire::LOOKUP,
            wire::encode(Body::Lookup {
                user: user.into(),
                device: device.into(),
            })?
            .into(),
        )
        .await?;
    let Body::Found(registration) = wire::decode(&response.payload)? else {
        anyhow::bail!("device not found or lookup rejected");
    };
    verify(&registration)?;
    ensure!(
        registration.payload.user_id == user && registration.payload.device_id == device,
        "directory returned a different device"
    );
    Ok(registration)
}
pub async fn find(
    store: &async_nats::jetstream::kv::Store,
    enrollment: &Enrollment,
    user: &str,
    device: &str,
) -> Result<Body> {
    wire::validate_id(user)?;
    wire::validate_id(device)?;
    let key = format!("users.{user}.devices.{device}");
    let Some(bytes) = store.get(&key).await? else {
        return Ok(Body::NotFound);
    };
    let Body::Register(registration) = wire::decode(&bytes)? else {
        anyhow::bail!("invalid directory record");
    };
    verify(&registration)?;
    ensure!(
        registration.payload.key() == key
            && enrollment.get(&key) == Some(&registration.payload.nats_public_key),
        "directory enrollment mismatch"
    );
    Ok(Body::Found(registration))
}
pub async fn provision(client: async_nats::Client) -> Result<async_nats::jetstream::kv::Store> {
    let js = async_nats::jetstream::new(client);
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
        js.get_or_create_stream(async_nats::jetstream::stream::Config {
            name: name.into(),
            subjects: subjects.into_iter().map(str::to_owned).collect(),
            max_message_size: wire::MAX_WIRE as i32,
            ..Default::default()
        })
        .await?;
    }
    let mut identities = None;
    for bucket in ["IDENTITIES", "CHANNELS"] {
        let store = match js.get_key_value(bucket).await {
            Ok(store) => store,
            Err(_) => {
                js.create_key_value(async_nats::jetstream::kv::Config {
                    bucket: bucket.into(),
                    history: 1,
                    ..Default::default()
                })
                .await?
            }
        };
        if bucket == "IDENTITIES" {
            identities = Some(store);
        }
    }
    identities.ok_or_else(|| anyhow!("IDENTITIES not provisioned"))
}
pub async fn accept(
    store: &async_nats::jetstream::kv::Store,
    enrollment: &Enrollment,
    registration: DeviceRegistration,
) -> Result<()> {
    verify(&registration)?;
    let key = registration.payload.key();
    ensure!(
        enrollment.get(&key) == Some(&registration.payload.nats_public_key),
        "device is not enrolled"
    );
    let bytes = wire::encode(Body::Register(registration))?;
    match store.create(&key, bytes.clone().into()).await {
        Ok(_) => Ok(()),
        Err(error) => {
            // Exact retries are safe; never overwrite another binding or an existing KeyPackage.
            let existing = store.get(&key).await?;
            ensure!(
                existing.as_deref() == Some(bytes.as_slice()),
                "registration conflict: {error}"
            );
            Ok(())
        }
    }
}
/// Generate public server configuration and enrollment from pre-created local devices.
pub fn dev_config(root: &Path, port: u16) -> Result<()> {
    dev_config_with_enrollment(root, port, &[])
}

/// Operator-provided PUBLIC bindings; no private installation state is imported.
pub fn dev_config_with_enrollment(root: &Path, port: u16, additions: &[String]) -> Result<()> {
    let mut all = Enrollment::new();
    for user in ["alice", "bob", "service"] {
        let mut store = IdentityStore::open(&root.join(user))?;
        let registration = match store.registration() {
            Ok(r) => r,
            Err(_) => store.init(user, "laptop")?,
        };
        all.insert(
            registration.payload.key(),
            registration.payload.nats_public_key,
        );
    }
    let path = root.join("additional-enrollment.json");
    let mut extra: Enrollment = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Enrollment::new(),
        Err(error) => return Err(error.into()),
    };
    for addition in additions {
        let (endpoint, key) = addition
            .split_once('=')
            .ok_or_else(|| anyhow!("use USER/DEVICE=NKEY"))?;
        let (user, device) = endpoint
            .split_once('/')
            .ok_or_else(|| anyhow!("use USER/DEVICE=NKEY"))?;
        wire::validate_id(user)?;
        wire::validate_id(device)?;
        let endpoint = format!("users.{user}.devices.{device}");
        ensure!(
            extra.get(&endpoint).is_none_or(|old| old == key),
            "enrollment replacement requires a future revocation workflow"
        );
        extra.insert(endpoint, key.into());
    }
    for (endpoint, key) in &extra {
        let parts: Vec<_> = endpoint.split('.').collect();
        ensure!(
            parts.len() == 4 && parts[0] == "users" && parts[2] == "devices",
            "invalid enrollment endpoint"
        );
        wire::validate_id(parts[1])?;
        wire::validate_id(parts[3])?;
        ensure!(
            parts[1] != "service" && !all.contains_key(endpoint),
            "reserved enrollment endpoint"
        );
        ensure!(key.starts_with('U'), "user NKey required");
        nkeys::KeyPair::from_public_key(key)?;
        all.insert(endpoint.clone(), key.clone());
    }
    ensure!(
        all.values()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == all.len(),
        "each device needs an independent NKey"
    );
    let mut enrollment = all.clone();
    enrollment.remove("users.service.devices.laptop");
    let mut entries = Vec::new();
    for (endpoint, key) in all {
        let inbox = format!("_INBOX.{}.>", key);
        let permissions = if endpoint == "users.service.devices.laptop" {
            format!(
                r#"publish: ["$JS.API.>", "$KV.IDENTITIES.>", "$KV.CHANNELS.>"]
subscribe: ["{inbox}", "epochgrid.v1.identity.*"]
allow_responses: {{max: 1, expires: "5s"}}"#
            )
        } else {
            format!(
                r#"publish: ["epochgrid.v1.identity.register", "epochgrid.v1.identity.lookup", "epochgrid.v1.identity.keypackage", "epochgrid.v1.identity.devices", "epochgrid.v1.group.*.handshake", "epochgrid.v1.group.*.message", "epochgrid.v1.user.*.*.inbox", "$JS.API.CONSUMER.INFO.MAILBOX.device_{key}", "$JS.API.CONSUMER.MSG.NEXT.MAILBOX.device_{key}", "$JS.ACK.MAILBOX.device_{key}.>", "$JS.API.CONSUMER.INFO.CHAT.device_{key}", "$JS.API.CONSUMER.MSG.NEXT.CHAT.device_{key}", "$JS.ACK.CHAT.device_{key}.>"]
subscribe: ["{inbox}", "epochgrid.v1.group.*.message"]"#,
                key = key
            )
        };
        entries.push(format!(
            "{{nkey: \"{}\", permissions: {{{permissions}}}}}",
            key
        ));
    }
    std::fs::write(path, serde_json::to_vec_pretty(&extra)?)?;
    std::fs::write(
        root.join("enrollment.json"),
        serde_json::to_vec_pretty(&enrollment)?,
    )?;
    std::fs::write(
        root.join("nats.conf"),
        format!(
            "listen: 127.0.0.1:{port}\nmax_payload: 65536\njetstream {{store_dir: \"{}\"}}\nauthorization {{users: [{}]}}\n",
            root.canonicalize()?.join("jetstream").display(),
            entries.join(",\n")
        ),
    )?;
    // Container path and listener differ; host port is bound to loopback by Compose.
    let host = std::fs::read_to_string(root.join("nats.conf"))?;
    std::fs::write(
        root.join("nats-compose.conf"),
        host.replace(&format!("127.0.0.1:{port}"), "0.0.0.0:4222")
            .replace(
                &root.canonicalize()?.join("jetstream").display().to_string(),
                "/data",
            ),
    )?;
    Ok(())
}

/// Initial KeyPackages are single-use. Retrying the same group's claim is idempotent.
pub async fn claim(
    store: &async_nats::jetstream::kv::Store,
    enrollment: &Enrollment,
    user: &str,
    device: &str,
    group: &str,
) -> Result<Body> {
    wire::validate_id(group)?;
    let found = find(store, enrollment, user, device).await?;
    ensure!(matches!(found, Body::Found(_)), "device not found");
    let key = format!("claims.{user}.{device}");
    if store.create(&key, group.to_owned().into()).await.is_err() {
        ensure!(
            store.get(&key).await?.as_deref() == Some(group.as_bytes()),
            "KeyPackage already reserved for another group"
        );
    }
    Ok(found)
}
pub async fn claim_keypackage(
    client: &async_nats::Client,
    user: &str,
    device: &str,
    group: &str,
) -> Result<DeviceRegistration> {
    wire::validate_id(user)?;
    wire::validate_id(device)?;
    wire::validate_id(group)?;
    let response = client
        .request(
            wire::KEYPACKAGE,
            wire::encode(Body::ClaimKeyPackage {
                user: user.into(),
                device: device.into(),
                group: group.into(),
            })?
            .into(),
        )
        .await?;
    let Body::Found(registration) = wire::decode(&response.payload)? else {
        anyhow::bail!(
            "KeyPackage unavailable (one invitation per device until replenishment is implemented)"
        );
    };
    verify(&registration)?;
    ensure!(
        registration.payload.user_id == user && registration.payload.device_id == device,
        "directory endpoint mismatch"
    );
    Ok(registration)
}
pub async fn provision_mailboxes(
    client: async_nats::Client,
    enrollment: &Enrollment,
) -> Result<()> {
    let js = async_nats::jetstream::new(client);
    let stream = js.get_stream("MAILBOX").await?;
    for (endpoint, key) in enrollment {
        let parts: Vec<_> = endpoint.split('.').collect();
        ensure!(
            parts.len() == 4 && parts[0] == "users" && parts[2] == "devices",
            "invalid enrollment endpoint"
        );
        wire::validate_id(parts[1])?;
        wire::validate_id(parts[3])?;
        nkeys::KeyPair::from_public_key(key)?;
        stream
            .get_or_create_consumer(
                &format!("device_{key}"),
                async_nats::jetstream::consumer::pull::Config {
                    durable_name: Some(format!("device_{key}")),
                    filter_subject: format!("epochgrid.v1.user.{}.{}.inbox", parts[1], parts[3]),
                    ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                    ack_wait: Duration::from_secs(5),
                    max_ack_pending: 1,
                    max_batch: 1,
                    ..Default::default()
                },
            )
            .await?;
    }
    Ok(())
}

/// One durable consumer per device in the existing shared development namespace.
/// Only the service can create consumers; clients cannot alter filters or progress.
pub async fn provision_chat_consumers(
    client: async_nats::Client,
    enrollment: &Enrollment,
) -> Result<()> {
    let stream = async_nats::jetstream::new(client)
        .get_stream("CHAT")
        .await?;
    for key in enrollment.values() {
        stream
            .create_consumer(async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(format!("device_{key}")),
                filter_subject: "epochgrid.v1.group.*.*".into(),
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                ack_wait: Duration::from_secs(2),
                max_ack_pending: 1,
                max_batch: 1,
                ..Default::default()
            })
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod enrollment_tests {
    use super::*;

    #[test]
    fn public_enrollment_preserves_bindings_and_rejects_aliases() -> Result<()> {
        let root = tempfile::tempdir()?;
        dev_config(root.path(), 4222)?;
        let first = nkeys::KeyPair::new_user();
        let second = nkeys::KeyPair::new_user();
        let binding = format!("alice/desktop={}", first.public_key());
        dev_config_with_enrollment(root.path(), 4222, &[binding])?;
        let public_file = root.path().join("additional-enrollment.json");
        let original = std::fs::read(&public_file)?;
        dev_config(root.path(), 4222)?;
        assert_eq!(std::fs::read(&public_file)?, original);
        for invalid in [
            format!("alice/desktop={}", second.public_key()),
            format!("alice/other={}", first.public_key()),
            format!("service/desktop={}", second.public_key()),
            format!("alice/laptop={}", second.public_key()),
            format!("alice/*={}", second.public_key()),
            format!("alice/other={}", first.seed()?),
        ] {
            assert!(dev_config_with_enrollment(root.path(), 4222, &[invalid]).is_err());
            assert_eq!(std::fs::read(&public_file)?, original);
        }
        for file in ["additional-enrollment.json", "enrollment.json", "nats.conf"] {
            assert!(!std::fs::read_to_string(root.path().join(file))?.contains(&first.seed()?));
        }
        Ok(())
    }
}
