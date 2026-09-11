//! Client-encrypted NATS Object Store files. Only opaque manifests cross MLS.
use crate::{history, identity::IdentityStore, messaging, transparency::hash};
use anyhow::{Context, Result, anyhow, ensure};
use async_nats::jetstream::{self, object_store::ObjectMetadata};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::AeadType};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const BUCKET: &str = "ATTACHMENTS";
pub const STREAM: &str = "OBJ_ATTACHMENTS";
pub const HARD_MAX_BYTES: usize = 64 * 1024 * 1024;
const CHUNK: usize = 32 * 1024;
const PREFIX: &[u8] = b"\xffEGATT";
const VERSION: u8 = 1;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub ttl_seconds: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 8 * 1024 * 1024,
            ttl_seconds: 604800,
        }
    }
}
impl Limits {
    pub fn from_env() -> Result<Self> {
        let defaults = Self::default();
        let max_bytes = env_number("EPOCHGRID_ATTACHMENT_MAX_BYTES", defaults.max_bytes)?;
        let ttl_seconds = env_number("EPOCHGRID_ATTACHMENT_TTL_SECONDS", defaults.ttl_seconds)?;
        let limits = Self {
            max_bytes,
            ttl_seconds,
        };
        limits.validate()?;
        Ok(limits)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=HARD_MAX_BYTES).contains(&self.max_bytes),
            "attachment size limit must be 1–67108864 bytes"
        );
        ensure!(
            (1..=31_536_000).contains(&self.ttl_seconds),
            "attachment lifetime must be 1–31536000 seconds"
        );
        Ok(())
    }
}
fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow!("invalid {name}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => anyhow::bail!("invalid {name}"),
    }
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn object_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid attachment ID"
    );
    Ok(())
}
/// No Debug: the key is secret and must never enter logs or UI formatting.
#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub filename: String,
    pub mime: String,
    pub size: u64,
    pub ciphertext_size: u64,
    pub expires_at: u64,
    hash: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
}
impl Manifest {
    fn validate(&self) -> Result<()> {
        object_id(&self.id)?;
        ensure!(
            !self.filename.is_empty()
                && self.filename.len() <= 255
                && ![".", ".."].contains(&self.filename.as_str())
                && !self
                    .filename
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\'),
            "invalid attachment filename"
        );
        ensure!(
            !self.mime.is_empty()
                && self.mime.len() <= 127
                && self.mime.contains('/')
                && self
                    .mime
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"/.-+_".contains(&c)),
            "invalid attachment MIME type"
        );
        ensure!(
            self.size <= HARD_MAX_BYTES as u64
                && self.ciphertext_size == self.size + 16
                && self.expires_at > 0,
            "invalid attachment size or expiration"
        );
        Ok(())
    }
    fn aad(&self, gid: &str) -> Result<Vec<u8>> {
        let mut aad = b"EpochGrid attachment v1\0".to_vec();
        aad.extend(postcard::to_allocvec(&(gid, &self.id))?);
        Ok(aad)
    }
    pub fn summary(&self) -> String {
        format!(
            "[attachment {}] {} ({} bytes, {})",
            self.id, self.filename, self.size, self.mime
        )
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(PREFIX.to_vec());
        bytes.push(VERSION);
        let encoded = Zeroizing::new(postcard::to_allocvec(self)?);
        bytes.extend_from_slice(&encoded);
        ensure!(
            bytes.len() <= messaging::MAX_PLAINTEXT,
            "attachment manifest too large"
        );
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Option<Self>> {
        if !bytes.starts_with(PREFIX) {
            return Ok(None);
        }
        ensure!(
            bytes.len() <= messaging::MAX_PLAINTEXT && bytes.get(PREFIX.len()) == Some(&VERSION),
            "unsupported attachment manifest version"
        );
        let (manifest, rest): (Self, _) = postcard::take_from_bytes(&bytes[PREFIX.len() + 1..])?;
        ensure!(rest.is_empty(), "trailing attachment manifest bytes");
        manifest.validate()?;
        Ok(Some(manifest))
    }
    fn decrypt(&self, gid: &str, ciphertext: &[u8], limits: Limits) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        limits.validate()?;
        ensure!(
            self.size <= limits.max_bytes as u64 && ciphertext.len() as u64 == self.ciphertext_size,
            "attachment exceeds size limit or is truncated"
        );
        ensure!(now()? < self.expires_at, "attachment expired");
        let plaintext = Zeroizing::new(
            RustCrypto::default()
                .aead_decrypt(
                    AeadType::Aes256Gcm,
                    self.key.as_ref(),
                    ciphertext,
                    &self.nonce,
                    &self.aad(gid)?,
                )
                .map_err(|_| anyhow!("attachment authentication failed"))?,
        );
        ensure!(
            plaintext.len() as u64 == self.size && hash(&plaintext)? == self.hash,
            "attachment content hash mismatch"
        );
        Ok(plaintext)
    }
}
/// Safe for CLI/TUI rendering: never display encoded manifests (which contain DEKs).
pub fn display(bytes: &[u8]) -> String {
    match Manifest::decode(bytes) {
        Ok(Some(manifest)) => manifest.summary(),
        Ok(None) => String::from_utf8_lossy(bytes).into_owned(),
        Err(_) => "[unsupported or invalid attachment]".into(),
    }
}
fn encrypt(
    gid: &str,
    filename: &str,
    mime: &str,
    bytes: &[u8],
    limits: Limits,
) -> Result<(Manifest, Vec<u8>)> {
    limits.validate()?;
    ensure!(
        bytes.len() <= limits.max_bytes,
        "attachment exceeds configured size limit"
    );
    let crypto = RustCrypto::default();
    let random: [u8; 16] = crypto
        .random_array()
        .map_err(|_| anyhow!("attachment randomness unavailable"))?;
    let manifest = Manifest {
        id: random.iter().map(|b| format!("{b:02x}")).collect(),
        filename: filename.into(),
        mime: mime.into(),
        size: bytes.len() as u64,
        ciphertext_size: bytes.len() as u64 + 16,
        expires_at: now()?
            .checked_add(limits.ttl_seconds)
            .context("attachment expiration overflow")?,
        hash: hash(bytes)?,
        key: Zeroizing::new(
            crypto
                .random_array()
                .map_err(|_| anyhow!("attachment randomness unavailable"))?,
        ),
        nonce: crypto
            .random_array()
            .map_err(|_| anyhow!("attachment randomness unavailable"))?,
    };
    manifest.validate()?;
    let ciphertext = crypto
        .aead_encrypt(
            AeadType::Aes256Gcm,
            manifest.key.as_ref(),
            bytes,
            &manifest.nonce,
            &manifest.aad(gid)?,
        )
        .map_err(|_| anyhow!("attachment encryption failed"))?;
    Ok((manifest, ciphertext))
}
impl IdentityStore {
    pub(crate) fn migrate_attachments(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=5)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
                self.connection.execute_batch("CREATE TABLE attachments(gid TEXT NOT NULL, object_id TEXT NOT NULL, manifest BLOB NOT NULL, PRIMARY KEY(gid,object_id)); INSERT INTO epochgrid_migrations VALUES(5);")?;
                Ok(())
            })?;
        }
        Ok(())
    }
    pub(crate) fn index_attachment(&self, gid: &str, bytes: &[u8]) -> Result<()> {
        let Some(manifest) = Manifest::decode(bytes).map_err(|_| messaging::InvalidMessage)? else {
            return Ok(());
        };
        let previous: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT manifest FROM attachments WHERE gid=?1 AND object_id=?2",
                params![gid, manifest.id],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            previous.as_deref().is_none_or(|old| old == bytes),
            messaging::InvalidMessage
        );
        self.connection.execute(
            "INSERT OR IGNORE INTO attachments VALUES(?1,?2,?3)",
            params![gid, manifest.id, bytes],
        )?;
        Ok(())
    }
    pub fn attachments(&self, name: &str) -> Result<Vec<Manifest>> {
        let gid = self.group(name)?.gid;
        let rows = self
            .connection
            .prepare("SELECT manifest FROM attachments WHERE gid=?1 ORDER BY object_id LIMIT 1000")?
            .query_map([gid], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|bytes| Manifest::decode(&bytes)?.context("invalid stored attachment"))
            .collect()
    }
    pub fn attachment(&self, name: &str, id: &str) -> Result<Manifest> {
        object_id(id)?;
        let bytes: Vec<u8> = self
            .connection
            .query_row(
                "SELECT manifest FROM attachments WHERE gid=?1 AND object_id=?2",
                params![self.group(name)?.gid, id],
                |r| r.get(0),
            )
            .context(
                "attachment not found in authenticated local history; sync the channel first",
            )?;
        Manifest::decode(&bytes)?.context("invalid stored attachment")
    }
}

pub async fn provision(client: async_nats::Client, retention: u64, max_bytes: i64) -> Result<()> {
    ensure!(
        (60..=31_536_000).contains(&retention) && max_bytes >= 1_048_576,
        "invalid attachment retention or bucket capacity"
    );
    let js = jetstream::new(client);
    match js.get_stream(STREAM).await {
        Ok(mut stream) => {
            let mut config = stream.info().await?.config.clone();
            let mut subjects = config.subjects.clone();
            subjects.sort();
            ensure!(
                subjects == vec!["$O.ATTACHMENTS.C.>", "$O.ATTACHMENTS.M.>"],
                "unexpected attachment stream subjects"
            );
            config.max_age = Duration::from_secs(retention);
            config.max_bytes = max_bytes;
            js.update_stream(config).await?;
        }
        Err(error) if matches!(error.kind(), jetstream::context::GetStreamErrorKind::JetStream(ref e) if e.code() == 404) =>
        {
            js.create_object_store(jetstream::object_store::Config {
                bucket: BUCKET.into(),
                max_age: Duration::from_secs(retention),
                max_bytes,
                ..Default::default()
            })
            .await?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub async fn send_file(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    path: &Path,
    mime: &str,
    limits: Limits,
) -> Result<String> {
    limits.validate()?;
    store.ensure_messaging_identity()?;
    let gid = store.group(name)?.gid;
    ensure!(
        store.members(name)?.len() >= 2,
        "invite a peer before sending attachments"
    );
    ensure!(
        std::fs::metadata(path)?.is_file(),
        "attachment must be a regular file"
    );
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= limits.max_bytes as u64,
        "attachment exceeds configured size limit or is not a regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((limits.max_bytes + 1) as u64)
        .read_to_end(&mut bytes)?;
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("attachment filename must be UTF-8")?;
    tokio::time::timeout(TRANSFER_TIMEOUT, async {
        history::resume(store, client, name).await?;
        let js = jetstream::new(client.clone());
        let mut stream = js.get_stream(STREAM).await?;
        let retention = stream.info().await?.config.max_age.as_secs();
        ensure!(retention > 0, "attachment bucket requires finite retention");
        let limits = Limits { ttl_seconds:limits.ttl_seconds.min(retention), ..limits };
        let (manifest, ciphertext) = encrypt(&gid, filename, mime, &bytes, limits)?;
        let bucket = js.get_object_store(BUCKET).await?;
        bucket.put(ObjectMetadata { name:manifest.id.clone(), chunk_size:Some(CHUNK), ..Default::default() }, &mut ciphertext.as_slice()).await?;
        // Membership may have changed during upload. Ordinary send audits/rekeys again.
        messaging::send(store, client, name, &manifest.encode()?).await?;
        Ok(manifest.id)
    }).await.context("attachment send timed out; sync pending messages before retrying (uploaded ciphertext may expire unused)")?
}

pub async fn download(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    id: &str,
    limits: Limits,
) -> Result<Zeroizing<Vec<u8>>> {
    limits.validate()?;
    store.ensure_messaging_identity()?;
    let manifest = store.attachment(name, id)?;
    ensure!(
        manifest.size <= limits.max_bytes as u64 && now()? < manifest.expires_at,
        "attachment expired or exceeds configured size limit"
    );
    let gid = store.group(name)?.gid;
    tokio::time::timeout(TRANSFER_TIMEOUT, async {
        let js = jetstream::new(client.clone());
        let bucket = js.get_object_store(BUCKET).await?;
        let info = bucket.info(id).await?;
        ensure!(
            !info.deleted
                && info.bucket == BUCKET
                && info.name == id
                && info.options.as_ref().is_none_or(|o| o.link.is_none()),
            "invalid attachment object or unsupported link"
        );
        ensure!(
            info.size as u64 == manifest.ciphertext_size
                && info.chunks > 0
                && info.chunks <= (HARD_MAX_BYTES + 16).div_ceil(CHUNK),
            "invalid attachment object size/chunk count"
        );
        ensure!(
            !info.nuid.is_empty()
                && info.nuid.len() <= 64
                && info.nuid.bytes().all(|b| b.is_ascii_alphanumeric()),
            "invalid attachment chunk ID"
        );
        let stream = js.get_stream(STREAM).await?;
        let subject = format!("$O.{BUCKET}.C.{}", info.nuid);
        let mut next = 1;
        let mut ciphertext = Vec::with_capacity(info.size);
        for _ in 0..info.chunks {
            let chunk = stream
                .get_first_raw_message_by_subject(&subject, next)
                .await?;
            ensure!(
                chunk.subject.as_str() == subject
                    && chunk.sequence >= next
                    && !chunk.payload.is_empty()
                    && chunk.payload.len() <= CHUNK
                    && ciphertext.len() + chunk.payload.len() <= info.size,
                "invalid attachment chunk"
            );
            next = chunk
                .sequence
                .checked_add(1)
                .context("attachment sequence overflow")?;
            ciphertext.extend_from_slice(&chunk.payload);
        }
        manifest.decrypt(&gid, &ciphertext, limits)
    })
    .await
    .context("attachment download timed out; no output was written")?
}

pub async fn save_file(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    id: &str,
    output: &Path,
    limits: Limits,
) -> Result<()> {
    let plaintext = download(store, client, name, id, limits).await?;
    // Authenticate all bytes before creating a plaintext file. The supplied path,
    // never the received filename, chooses the destination. Refuse overwrite/symlinks.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(output)
        .context("attachment output must be a new file")?;
    let result = file.write_all(&plaintext).and_then(|()| file.sync_all());
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests;
