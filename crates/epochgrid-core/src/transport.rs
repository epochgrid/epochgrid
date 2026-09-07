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
    let mut entries = Vec::new();
    let mut enrollment = Enrollment::new();
    for user in ["alice", "bob", "service"] {
        let mut store = IdentityStore::open(&root.join(user))?;
        let registration = match store.registration() {
            Ok(r) => r,
            Err(_) => store.init(user, "laptop")?,
        };
        let p = registration.payload;
        if user != "service" {
            enrollment.insert(p.key(), p.nats_public_key.clone());
        }
        let inbox = format!("_INBOX.{}.>", p.nats_public_key);
        let permissions = if user == "service" {
            format!(
                r#"publish: ["$JS.API.>", "$KV.IDENTITIES.>", "$KV.CHANNELS.>"]
subscribe: ["{inbox}", "epochgrid.v1.identity.*"]
allow_responses: {{max: 1, expires: "5s"}}"#
            )
        } else {
            format!(
                r#"publish: ["epochgrid.v1.identity.register", "epochgrid.v1.identity.lookup", "epochgrid.v1.identity.keypackage", "epochgrid.v1.group.*.handshake", "epochgrid.v1.user.*.*.inbox", "$JS.API.CONSUMER.INFO.MAILBOX.device_{key}", "$JS.API.CONSUMER.MSG.NEXT.MAILBOX.device_{key}", "$JS.ACK.MAILBOX.device_{key}.>"]
subscribe: ["{inbox}"]"#,
                key = p.nats_public_key
            )
        };
        entries.push(format!(
            "{{nkey: \"{}\", permissions: {{{permissions}}}}}",
            p.nats_public_key
        ));
    }
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
