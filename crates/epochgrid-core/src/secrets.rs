//! Standalone credentials and database keys in Linux Secret Service.
//! Metadata is public; secret bytes never enter EpochGrid's persistent files.
use anyhow::{Context, Result, ensure};
use openmls_traits::random::OpenMlsRand;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    User,
    Account,
    XKey,
    Database,
}
impl Kind {
    fn generate(self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(match self {
            Self::User => nkeys::KeyPair::new_user().seed()?,
            Self::Account => nkeys::KeyPair::new_account().seed()?,
            Self::XKey => nkeys::XKey::new().seed()?,
            Self::Database => {
                let bytes = Zeroizing::new(
                    openmls_rust_crypto::RustCrypto::default()
                        .random_array::<32>()
                        .map_err(|_| anyhow::anyhow!("database randomness unavailable"))?,
                );
                data_encoding::HEXLOWER.encode(bytes.as_ref())
            }
        }))
    }
    fn public(self, secret: &str) -> Result<String> {
        if self == Self::Database {
            ensure!(
                secret.len() == 64
                    && secret
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid database key"
            );
            // A fingerprint of a uniformly random key, not an asymmetric public key.
            return Ok(
                data_encoding::HEXLOWER.encode(&crate::transparency::hash(secret.as_bytes())?)
            );
        }
        if self == Self::XKey {
            return nkeys::XKey::from_seed(secret)
                .map(|key| key.public_key())
                .map_err(|_| anyhow::anyhow!("invalid XKey credential"));
        }
        let key = nkeys::KeyPair::from_seed(secret)
            .map_err(|_| anyhow::anyhow!("invalid NKey credential"))?;
        let expected = if self == Self::User {
            nkeys::KeyPairType::User
        } else {
            nkeys::KeyPairType::Account
        };
        ensure!(key.key_pair_type() == expected, "credential type mismatch");
        Ok(key.public_key())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Secret Service unavailable; start a Linux Secret Service session")]
    Unavailable,
    #[error("keyring is locked; unlock it with your OS keyring manager, then retry")]
    Locked,
    #[error("credential missing from keyring; restore the keyring or enroll a fresh device")]
    Missing,
    #[error("duplicate credential items; resolve the duplicate in your keyring manager")]
    Duplicate,
    #[error("Secret Service operation timed out; check your session and retry")]
    Timeout,
    #[error("Secret Service denied or failed the operation")]
    Backend,
}

/// Opaque item ID plus checked public key (or random database-key fingerprint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub id: String,
    pub kind: Kind,
    pub public_key: String,
}
impl SecretRef {
    pub fn read(&self) -> Result<Zeroizing<String>> {
        self.read_with(&LinuxKeyring)
    }
    fn read_with(&self, backend: &dyn Backend) -> Result<Zeroizing<String>> {
        validate_id(&self.id)?;
        let secret = backend.read(&self.id)?.ok_or(Error::Missing)?;
        ensure!(
            self.kind.public(&secret)? == self.public_key,
            "credential public binding mismatch"
        );
        Ok(secret)
    }
}
fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 56
            && id.starts_with('U')
            && id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
        "invalid credential reference"
    );
    Ok(())
}

pub trait Backend: Send + Sync {
    fn read(&self, id: &str) -> Result<Option<Zeroizing<String>>>;
    /// Must never replace an existing item.
    fn create(&self, id: &str, secret: &str) -> Result<()>;
}

#[derive(Clone, Copy)]
pub struct LinuxKeyring;
enum Operation {
    Read,
    Create(Zeroizing<String>),
}
impl LinuxKeyring {
    fn run(id: &str, operation: Operation) -> Result<Option<Zeroizing<String>>> {
        ensure!(
            cfg!(target_os = "linux"),
            "protected credentials currently require Linux Secret Service"
        );
        validate_id(id)?;
        let id = id.to_owned();
        // Separate runtime: safe from both ordinary and Tokio callers, including
        // current-thread runtimes. A single deadline includes connection/session setup.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    Self::operate(&id, operation),
                )
                .await
                .map_err(|_| Error::Timeout)?
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("credential worker failed"))?
    }
    async fn operate(id: &str, operation: Operation) -> Result<Option<Zeroizing<String>>> {
        use secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;
        let service = SecretService::connect(EncryptionType::Dh)
            .await
            .map_err(|_| Error::Unavailable)?;
        let attributes =
            HashMap::from([("application", "org.epochgrid.credentials.v1"), ("id", id)]);
        let found = service
            .search_items(attributes.clone())
            .await
            .map_err(|_| Error::Backend)?;
        ensure!(
            found.locked.len() + found.unlocked.len() <= 1,
            Error::Duplicate
        );
        ensure!(found.locked.is_empty(), Error::Locked);
        match operation {
            Operation::Read => {
                if let Some(item) = found.unlocked.first() {
                    let bytes =
                        Zeroizing::new(item.get_secret().await.map_err(|_| Error::Backend)?);
                    let value =
                        std::str::from_utf8(&bytes).context("invalid credential encoding")?;
                    Ok(Some(Zeroizing::new(value.to_owned())))
                } else {
                    Ok(None)
                }
            }
            Operation::Create(secret) => {
                ensure!(found.unlocked.is_empty(), Error::Duplicate);
                let collection = service
                    .get_default_collection()
                    .await
                    .map_err(|_| Error::Unavailable)?;
                ensure!(
                    !collection.is_locked().await.map_err(|_| Error::Backend)?,
                    Error::Locked
                );
                // No unlock/create-collection prompt: unattended callers fail promptly.
                collection
                    .create_item(
                        "EpochGrid credential",
                        attributes,
                        secret.as_bytes(),
                        false,
                        "text/plain",
                    )
                    .await
                    .map_err(|_| Error::Backend)?;
                Ok(None)
            }
        }
    }
}
impl Backend for LinuxKeyring {
    fn read(&self, id: &str) -> Result<Option<Zeroizing<String>>> {
        Self::run(id, Operation::Read)
    }
    fn create(&self, id: &str, secret: &str) -> Result<()> {
        Self::run(id, Operation::Create(Zeroizing::new(secret.to_owned())))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Slot {
    id: String,
    kind: Kind,
    public_key: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    version: u32,
    slots: BTreeMap<String, Slot>,
}

pub struct Vault {
    root: PathBuf,
    backend: Arc<dyn Backend>,
}
impl Vault {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.into(),
            backend: Arc::new(LinuxKeyring),
        }
    }
    /// Retain a pending public reference across crashes; never overwrite a key.
    /// The per-vault file lock serializes provisioning by cooperating processes.
    pub fn provision(&self, role: &str, kind: Kind) -> Result<SecretRef> {
        self.ensure(role, kind, None)
    }
    pub fn import(&self, role: &str, kind: Kind, secret: &str) -> Result<SecretRef> {
        self.ensure(role, kind, Some(secret))
    }
    fn ensure(&self, role: &str, kind: Kind, imported: Option<&str>) -> Result<SecretRef> {
        ensure!(
            !role.is_empty() && role.len() <= 64,
            "invalid credential role"
        );
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock = private_file(&self.root.join("credentials.lock"), false)?;
        lock.try_lock()
            .context("credential initialization already in progress")?;
        let path = self.root.join("credentials.json");
        let mut metadata = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Metadata>(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Metadata {
                version: 1,
                slots: BTreeMap::new(),
            },
            Err(e) => return Err(e.into()),
        };
        ensure!(
            metadata.version == 1,
            "unsupported credential metadata version; use fresh state"
        );
        if !metadata.slots.contains_key(role) {
            metadata.slots.insert(
                role.into(),
                Slot {
                    id: nkeys::KeyPair::new_user().public_key(),
                    kind,
                    public_key: None,
                },
            );
            save(&path, &metadata)?;
        }
        let slot = metadata.slots.get_mut(role).unwrap();
        ensure!(slot.kind == kind, "credential role type mismatch");
        validate_id(&slot.id)?;
        let secret = match self.backend.read(&slot.id)? {
            Some(secret) => secret,
            None => {
                ensure!(slot.public_key.is_none(), Error::Missing);
                let secret = match imported {
                    Some(value) => Zeroizing::new(value.to_owned()),
                    None => kind.generate()?,
                };
                kind.public(&secret)?;
                self.backend.create(&slot.id, &secret)?;
                let readback = self.backend.read(&slot.id)?.ok_or(Error::Missing)?;
                ensure!(*secret == *readback, "credential readback mismatch");
                readback
            }
        };
        let public_key = kind.public(&secret)?;
        if let Some(expected) = &slot.public_key {
            ensure!(
                expected == &public_key,
                "credential public binding mismatch"
            );
        }
        if let Some(value) = imported {
            ensure!(
                kind.public(value)? == public_key,
                "pending restore belongs to a different identity"
            );
        }
        slot.public_key = Some(public_key.clone());
        let reference = SecretRef {
            id: slot.id.clone(),
            kind,
            public_key,
        };
        save(&path, &metadata)?;
        Ok(reference)
    }
}
pub(crate) fn private_file(path: &Path, truncate: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
pub(crate) fn save(path: &Path, metadata: &impl Serialize) -> Result<()> {
    let temporary = path.with_extension("pending");
    let mut file = private_file(&temporary, true)?;
    file.write_all(&serde_json::to_vec(metadata)?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(path.parent().context("credential directory")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
