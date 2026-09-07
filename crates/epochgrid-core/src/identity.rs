use crate::wire::{DeviceRegistration, RegistrationPayload, VERSION, validate_id};
use anyhow::{Context, Result, anyhow, ensure};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    rc::Rc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
#[derive(Default)]
pub struct JsonCodec;
impl Codec for JsonCodec {
    type Error = serde_json::Error;
    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }
    fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(bytes)
    }
}
pub struct Provider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Rc<Connection>>,
}
impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Rc<Connection>>;
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}
/// Development-only key boundary. The private directory contains unencrypted SQLite.
pub struct IdentityStore {
    pub(crate) connection: Rc<Connection>,
    _lock: File,
    pub provider: Provider,
}
impl IdentityStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(dir.join("device.lock"))?;
        lock.try_lock()
            .context("device is already in use by another process")?;
        let path = dir.join("identity.sqlite");
        let connection = Connection::open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        connection.execute_batch("CREATE TABLE IF NOT EXISTS local_identity (id INTEGER PRIMARY KEY CHECK(id=1), seed TEXT NOT NULL, registration BLOB NOT NULL);")?;
        let mut storage = SqliteStorageProvider::<JsonCodec, _>::new(connection);
        storage.run_migrations()?;
        // Migrate before sharing the connection: OpenMLS and application writes
        // then participate in the same SQLite transaction.
        drop(storage);
        let connection = Rc::new(Connection::open(path)?);
        connection.execute_batch("CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY, gid TEXT NOT NULL UNIQUE, mls_id BLOB NOT NULL UNIQUE);")?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS outbox (id INTEGER PRIMARY KEY, subject TEXT NOT NULL, payload BLOB NOT NULL UNIQUE, sent INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS welcomes (payload BLOB PRIMARY KEY, name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS received (payload BLOB PRIMARY KEY);")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS chat_deliveries (
            sequence INTEGER PRIMARY KEY CHECK(sequence > 0), subject TEXT NOT NULL,
            payload BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'pending'
            CHECK(state IN ('pending','processed','rejected')));
        CREATE INDEX IF NOT EXISTS chat_pending ON chat_deliveries(subject,state,sequence);
        CREATE TABLE IF NOT EXISTS transcript (
            id INTEGER PRIMARY KEY, gid TEXT NOT NULL, payload BLOB NOT NULL UNIQUE,
            sender TEXT, plaintext BLOB, outgoing INTEGER NOT NULL,
            stream_sequence INTEGER UNIQUE, displayed INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS transcript_group ON transcript(gid,stream_sequence,id);",
        )?;
        let storage = SqliteStorageProvider::new(Rc::clone(&connection));
        Ok(Self {
            connection,
            _lock: lock,
            provider: Provider {
                crypto: RustCrypto::default(),
                storage,
            },
        })
    }
    pub(crate) fn transaction<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        match action() {
            Ok(value) => {
                if let Err(error) = self.connection.execute_batch("COMMIT") {
                    let _ = self.connection.execute_batch("ROLLBACK");
                    return Err(error.into());
                }
                Ok(value)
            }
            Err(error) => {
                self.connection.execute_batch("ROLLBACK")?;
                Err(error)
            }
        }
    }
    pub fn init(&mut self, user: &str, device: &str) -> Result<DeviceRegistration> {
        self.transaction(|| self.initialize(user, device))
    }
    fn initialize(&self, user: &str, device: &str) -> Result<DeviceRegistration> {
        validate_id(user)?;
        validate_id(device)?;
        ensure!(
            self.connection
                .query_row("SELECT COUNT(*) FROM local_identity", [], |r| r
                    .get::<_, i64>(0))?
                == 0,
            "identity already initialized"
        );
        let nkey = nkeys::KeyPair::new_user();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|e| anyhow!("MLS signing key: {e:?}"))?;
        let credential: Credential =
            BasicCredential::new(format!("{user}/{device}").into_bytes()).into();
        signer
            .store(self.provider.storage())
            .map_err(|e| anyhow!("MLS signer storage: {e:?}"))?;
        let package = KeyPackage::builder()
            .build(
                SUITE,
                &self.provider,
                &signer,
                CredentialWithKey {
                    credential: credential.clone(),
                    signature_key: signer.to_public_vec().into(),
                },
            )
            .map_err(|e| anyhow!("MLS KeyPackage: {e:?}"))?;
        let payload = RegistrationPayload {
            protocol_version: VERSION,
            user_id: user.into(),
            device_id: device.into(),
            nats_public_key: nkey.public_key(),
            mls_credential: credential.tls_serialize_detached()?,
            mls_key_package: package.key_package().tls_serialize_detached()?,
            generation: 1,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs()
                .try_into()?,
        };
        let registration = DeviceRegistration {
            signature: nkey.sign(&payload.signing_bytes()?)?,
            payload,
        };
        self.connection.execute(
            "INSERT INTO local_identity VALUES(1, ?1, ?2)",
            rusqlite::params![nkey.seed()?, postcard::to_allocvec(&registration)?],
        )?;
        Ok(registration)
    }
    pub fn registration(&self) -> Result<DeviceRegistration> {
        let bytes: Vec<u8> = self
            .connection
            .query_row(
                "SELECT registration FROM local_identity WHERE id=1",
                [],
                |r| r.get(0),
            )
            .context("run identity init first")?;
        Ok(postcard::from_bytes(&bytes)?)
    }
    pub fn nkey(&self) -> Result<nkeys::KeyPair> {
        let seed: String =
            self.connection
                .query_row("SELECT seed FROM local_identity WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        Ok(nkeys::KeyPair::from_seed(&seed)?)
    }
}
pub fn verify(registration: &DeviceRegistration) -> Result<()> {
    let p = &registration.payload;
    validate_id(&p.user_id)?;
    validate_id(&p.device_id)?;
    ensure!(
        p.protocol_version == VERSION && p.generation == 1 && p.created_at > 0,
        "invalid registration version/generation/time"
    );
    ensure!(p.nats_public_key.starts_with('U'), "NATS user key required");
    let key = nkeys::KeyPair::from_public_key(&p.nats_public_key)?;
    key.verify(&p.signing_bytes()?, &registration.signature)?;
    let package = KeyPackageIn::tls_deserialize_exact(&p.mls_key_package)?
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .map_err(|e| anyhow!("invalid MLS KeyPackage: {e:?}"))?;
    ensure!(package.ciphersuite() == SUITE, "unsupported ciphersuite");
    ensure!(
        package.leaf_node().credential().tls_serialize_detached()? == p.mls_credential,
        "credential mismatch"
    );
    let basic = BasicCredential::try_from(package.leaf_node().credential().clone())
        .map_err(|e| anyhow!("invalid basic credential: {e:?}"))?;
    ensure!(
        basic.identity() == format!("{}/{}", p.user_id, p.device_id).as_bytes(),
        "MLS identity mismatch"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use openmls_traits::storage::StorageProvider;
    #[test]
    fn persisted_identity_and_binding() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let original = {
            let mut store = IdentityStore::open(dir.path())?;
            let r = store.init("alice", "laptop")?;
            assert!(store.init("alice", "laptop").is_err());
            r
        };
        let store = IdentityStore::open(dir.path())?;
        assert_eq!(original, store.registration()?);
        assert_eq!(original.payload.nats_public_key, store.nkey()?.public_key());
        verify(&original)?;
        let package = KeyPackageIn::tls_deserialize_exact(&original.payload.mls_key_package)?
            .validate(store.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("{e:?}"))?;
        assert!(
            SignatureKeyPair::read(
                store.provider.storage(),
                package.leaf_node().signature_key().as_slice(),
                SUITE.signature_algorithm()
            )
            .is_some()
        );
        let reference = package
            .hash_ref(store.provider.crypto())
            .map_err(|e| anyhow!("{e:?}"))?;
        let bundle: Option<KeyPackageBundle> = store
            .provider
            .storage()
            .key_package(&reference)
            .map_err(|e| anyhow!("{e:?}"))?;
        assert!(
            bundle.is_some(),
            "private KeyPackage bundle must survive restart"
        );
        let mut bad = original.clone();
        bad.payload.user_id = "bob".into();
        assert!(verify(&bad).is_err());
        let mut bad = original.clone();
        bad.payload.mls_key_package[10] ^= 1;
        bad.signature = store.nkey()?.sign(&bad.payload.signing_bytes()?)?;
        assert!(verify(&bad).is_err());
        assert_eq!(
            crate::wire::decode(&crate::wire::encode(crate::wire::Body::Register(
                original.clone()
            ))?)?,
            crate::wire::Body::Register(original)
        );
        Ok(())
    }
}
