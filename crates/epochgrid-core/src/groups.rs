use crate::{
    identity::{IdentityStore, SUITE},
    wire::validate_id,
};
use anyhow::{Context, Result, anyhow, ensure};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: String,
    pub gid: String,
    pub(crate) mls_id: Vec<u8>,
}
impl Group {
    pub(crate) fn from_mls_id(id: &GroupId) -> Result<Self> {
        let text = std::str::from_utf8(id.as_slice())?;
        let fields: Vec<_> = text.split('/').collect();
        ensure!(
            fields.len() == 4 && fields[0] == "epochgrid" && fields[1] == "v1",
            "invalid EpochGrid group ID"
        );
        validate_id(fields[2])?;
        ensure!(
            fields[3].len() == 32
                && fields[3]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid group subject ID"
        );
        Ok(Self {
            name: fields[2].into(),
            gid: fields[3].into(),
            mls_id: id.as_slice().to_vec(),
        })
    }
    pub fn subject(&self, kind: &str) -> String {
        format!("epochgrid.v1.group.{}.{kind}", self.gid)
    }
}
impl IdentityStore {
    pub(crate) fn signer(&self) -> Result<(SignatureKeyPair, CredentialWithKey)> {
        self.ensure_messaging_identity()?;
        let registration = self.registration()?;
        let package = KeyPackageIn::tls_deserialize_exact(&registration.payload.mls_key_package)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("invalid own KeyPackage: {e:?}"))?;
        let signer = SignatureKeyPair::read(
            self.provider.storage(),
            package.leaf_node().signature_key().as_slice(),
            SUITE.signature_algorithm(),
        )
        .context("MLS signing key missing")?;
        let credential = CredentialWithKey {
            credential: package.leaf_node().credential().clone(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok((signer, credential))
    }
    pub fn create_group(&self, name: &str) -> Result<Group> {
        validate_id(name)?;
        let random = self
            .provider
            .rand()
            .random_array::<16>()
            .map_err(|e| anyhow!("group randomness: {e:?}"))?;
        let gid: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let id = GroupId::from_slice(format!("epochgrid/v1/{name}/{gid}").as_bytes());
        let descriptor = Group::from_mls_id(&id)?;
        let (signer, credential) = self.signer()?;
        self.transaction(|| {
            self.insert_group(&descriptor)?;
            MlsGroup::new_with_group_id(
                &self.provider,
                &signer,
                &MlsGroupCreateConfig::builder()
                    .ciphersuite(SUITE)
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                    .build(),
                id,
                credential,
            )
            .map_err(|e| anyhow!("create MLS group: {e:?}"))?;
            self.refresh_coordinator(&self.load_group(&descriptor)?)?;
            Ok(descriptor)
        })
    }
    pub(crate) fn insert_group(&self, group: &Group) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO groups(name,gid,mls_id) VALUES(?1,?2,?3)",
                rusqlite::params![group.name, group.gid, group.mls_id],
            )
            .context("channel name or group ID already exists")?;
        self.connection.execute(
            "INSERT INTO group_join_epochs(gid,epoch) VALUES(?1,0)",
            [&group.gid],
        )?;
        Ok(())
    }
    pub fn group_epoch(&self, name: &str) -> Result<u64> {
        Ok(self.load_group(&self.group(name)?)?.epoch().as_u64())
    }
    pub fn users(&self, name: &str) -> Result<Vec<String>> {
        self.members(name)?
            .into_iter()
            .map(|member| {
                let (user, device) = member.split_once('/').context("invalid member identity")?;
                validate_id(user)?;
                validate_id(device)?;
                Ok(user.to_owned())
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()
            .map(|users| users.into_iter().collect())
    }
    pub fn groups(&self) -> Result<Vec<Group>> {
        let mut statement = self
            .connection
            .prepare("SELECT name,gid,mls_id FROM groups ORDER BY name")?;
        Ok(statement
            .query_map([], |row| {
                Ok(Group {
                    name: row.get(0)?,
                    gid: row.get(1)?,
                    mls_id: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }
    pub fn group(&self, name: &str) -> Result<Group> {
        self.connection
            .query_row(
                "SELECT name,gid,mls_id FROM groups WHERE name=?1",
                [name],
                |row| {
                    Ok(Group {
                        name: row.get(0)?,
                        gid: row.get(1)?,
                        mls_id: row.get(2)?,
                    })
                },
            )
            .context("unknown channel")
    }
    pub(crate) fn load_group(&self, group: &Group) -> Result<MlsGroup> {
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(&group.mls_id))
            .map_err(|e| anyhow!("load MLS state: {e:?}"))?
            .context("MLS group state missing")
    }
    pub fn members(&self, name: &str) -> Result<Vec<String>> {
        self.load_group(&self.group(name)?)?
            .members()
            .map(|member| {
                let credential = BasicCredential::try_from(member.credential)
                    .map_err(|e| anyhow!("invalid member credential: {e:?}"))?;
                Ok(std::str::from_utf8(credential.identity())?.to_owned())
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_persists_and_creation_is_atomic() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let mut store = IdentityStore::open(dir.path())?;
        store.init("alice", "laptop")?;
        assert!(IdentityStore::open(dir.path()).is_err());
        let group = store.create_group("engineering")?;
        assert!(store.create_group("engineering").is_err());
        assert!(store.create_group("bad.subject").is_err());
        assert_eq!(store.groups()?.len(), 1);
        drop(store);
        let store = IdentityStore::open(dir.path())?;
        assert_eq!(store.group("engineering")?, group);
        assert_eq!(store.members("engineering")?, vec!["alice/laptop"]);
        assert_eq!(store.load_group(&group)?.epoch().as_u64(), 0);
        Ok(())
    }
}
