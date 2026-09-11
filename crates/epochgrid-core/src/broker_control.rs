//! Single-broker development actuator. Public configuration plus a restricted system NKey.
use crate::{
    identity::IdentityStore,
    revocation::RevocationLog,
    transport::{self, Enrollment},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub struct BrokerControl {
    root: PathBuf,
    client: async_nats::Client,
    applied: BTreeSet<String>,
    _lock: File,
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
impl BrokerControl {
    pub async fn connect(root: &Path, url: &str) -> Result<Self> {
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("revocation.lock"))?;
        lock.try_lock()
            .context("another service owns this broker's revocation actuator")?;
        let identity = IdentityStore::open(&root.join("system"))?;
        let client = transport::connect(url, &identity)
            .await
            .context("run bootstrap to provision the restricted system identity")?;
        Ok(Self {
            root: root.into(),
            client,
            applied: Default::default(),
            _lock: lock,
        })
    }
    pub async fn enforce(
        &mut self,
        log: &RevocationLog,
        data_client: &async_nats::Client,
        force: bool,
    ) -> Result<()> {
        let revoked = log.keys();
        if !force && revoked == self.applied {
            return Ok(());
        }
        let all: Enrollment =
            serde_json::from_slice(&std::fs::read(self.root.join("public-enrollment.json"))?)?;
        // A bootstrap must never restore keys after an acknowledged revocation.
        atomic_write(
            &self.root.join("revoked-nkeys.json"),
            &serde_json::to_vec_pretty(&revoked)?,
        )?;
        atomic_write(
            &self.root.join("auth/users.conf"),
            transport::render_users(&all, &revoked).as_bytes(),
        )?;
        let server = self.client.server_info().server_id;
        let reply = self
            .client
            .request(format!("$SYS.REQ.SERVER.{server}.RELOAD"), "{}".into())
            .await?;
        let response: serde_json::Value = serde_json::from_slice(&reply.payload)?;
        ensure!(
            response.get("error").is_none_or(|e| e.is_null()),
            "NATS rejected authorization reload: {}",
            response.get("error").unwrap_or(&serde_json::Value::Null)
        );
        ensure!(
            response.get("server").is_some(),
            "invalid NATS reload acknowledgment"
        );
        let js = async_nats::jetstream::new(data_client.clone());
        for stream in ["CHAT", "MAILBOX"] {
            let stream = js.get_stream(stream).await?;
            for key in &revoked {
                // Delete is idempotent; absence is success, other failures are not.
                let name = format!("device_{key}");
                let result = stream.delete_consumer(&name).await;
                if let Err(error) = result
                    && !matches!(error.kind(), async_nats::jetstream::stream::ConsumerErrorKind::JetStream(ref error) if error.error_code() == async_nats::jetstream::ErrorCode::CONSUMER_NOT_FOUND)
                {
                    return Err(error.into());
                }
            }
        }
        self.applied = revoked;
        Ok(())
    }
}
