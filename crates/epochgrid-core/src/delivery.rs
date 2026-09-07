use crate::{
    groups::Group,
    identity::{IdentityStore, verify},
    transport,
    wire::{self, Body, DeviceRegistration},
};
use anyhow::{Context, Result, anyhow, ensure};
use futures_util::StreamExt;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;

impl IdentityStore {
    pub(crate) fn queue(&self, subject: &str, payload: &[u8]) -> Result<()> {
        ensure!(
            payload.len() <= wire::MAX_WIRE,
            "MLS message exceeds transport limit"
        );
        self.connection.execute(
            "INSERT INTO outbox(subject,payload) VALUES(?1,?2)",
            rusqlite::params![subject, payload],
        )?;
        Ok(())
    }
    pub fn prepare_invitation(&self, name: &str, recipient: &DeviceRegistration) -> Result<()> {
        verify(recipient)?;
        let descriptor = self.group(name)?;
        let (signer, _) = self.signer()?;
        let package = KeyPackageIn::tls_deserialize_exact(&recipient.payload.mls_key_package)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("invalid recipient KeyPackage: {e:?}"))?;
        self.transaction(|| {
            let mut group = self.load_group(&descriptor)?;
            ensure!(
                group.members().count() == 1,
                "this slice supports one invitation per group"
            );
            ensure!(
                recipient.payload.nats_public_key != self.registration()?.payload.nats_public_key,
                "cannot invite this device to itself"
            );
            let (commit, welcome, _) = group
                .add_members(&self.provider, &signer, &[package])
                .map_err(|e| anyhow!("MLS add member: {e:?}"))?;
            // Queue encrypted Commit before Welcome; both are committed with MLS state.
            self.queue(&descriptor.subject("handshake"), &commit.to_bytes()?)?;
            self.queue(
                &format!(
                    "epochgrid.v1.user.{}.{}.inbox",
                    recipient.payload.user_id, recipient.payload.device_id
                ),
                &wire::encode(Body::Welcome {
                    payload: welcome.to_bytes()?,
                })?,
            )?;
            group
                .merge_pending_commit(&self.provider)
                .map_err(|e| anyhow!("merge local commit: {e:?}"))?;
            Ok(())
        })
    }
    pub fn accept_welcome(&self, bytes: &[u8], inviter: &DeviceRegistration) -> Result<Group> {
        verify(inviter)?;
        let Body::Welcome { payload } = wire::decode(bytes)? else {
            anyhow::bail!("mailbox message is not a Welcome");
        };
        let package = KeyPackageIn::tls_deserialize_exact(&inviter.payload.mls_key_package)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("invalid inviter: {e:?}"))?;
        self.transaction(|| {
            // Byte-identical redelivery must not consume the private KeyPackage twice.
            let previous = self.connection.query_row(
                "SELECT name FROM welcomes WHERE payload=?1",
                [bytes],
                |row| row.get::<_, String>(0),
            );
            if let Ok(name) = previous {
                return self.group(&name);
            }
            let MlsMessageBodyIn::Welcome(welcome) =
                MlsMessageIn::tls_deserialize_exact(&payload)?.extract()
            else {
                anyhow::bail!("expected MLS Welcome");
            };
            let staged = StagedWelcome::new_from_welcome(
                &self.provider,
                &MlsGroupJoinConfig::builder()
                    .use_ratchet_tree_extension(true)
                    .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                    .build(),
                welcome,
                None,
            )
            .map_err(|e| anyhow!("validate MLS Welcome: {e:?}"))?;
            let sender = staged
                .welcome_sender()
                .map_err(|e| anyhow!("Welcome sender missing: {e:?}"))?;
            ensure!(
                sender.signature_key() == package.leaf_node().signature_key()
                    && sender.credential() == package.leaf_node().credential(),
                "Welcome signer is not the expected inviter"
            );
            ensure!(
                staged.members().count() == 2,
                "this slice only accepts two-device groups"
            );
            let descriptor = Group::from_mls_id(staged.group_context().group_id())?;
            self.insert_group(&descriptor)?;
            staged
                .into_group(&self.provider)
                .map_err(|e| anyhow!("join MLS group: {e:?}"))?;
            self.connection.execute(
                "INSERT INTO welcomes(payload,name) VALUES(?1,?2)",
                rusqlite::params![bytes, descriptor.name],
            )?;
            Ok(descriptor)
        })
    }
}
pub async fn flush_outbox(store: &IdentityStore, client: &async_nats::Client) -> Result<()> {
    let js = async_nats::jetstream::new(client.clone());
    let mut statement = store
        .connection
        .prepare("SELECT id,subject,payload FROM outbox WHERE sent=0 ORDER BY id")?;
    let rows = statement
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, subject, payload) in rows {
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(
            "Nats-Msg-Id",
            format!("{}:{id}", store.nkey()?.public_key()),
        );
        let ack = js
            .publish_with_headers(subject, headers, payload.clone().into())
            .await?
            .await?;
        store.transaction(|| {
            store.connection.execute("UPDATE outbox SET sent=1 WHERE id=?1", [id])?;
            if ack.stream == "CHAT" {
                store.connection.execute("UPDATE transcript SET stream_sequence=COALESCE(stream_sequence,?1) WHERE payload=?2", rusqlite::params![ack.sequence, payload])?;
            }
            Ok(())
        })?;
    }
    Ok(())
}
pub async fn invite(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    user: &str,
    device: &str,
) -> Result<()> {
    wire::validate_id(user)?;
    wire::validate_id(device)?;
    let descriptor = store.group(name)?;
    let members = store.members(name)?;
    if members.len() == 1 {
        let recipient = transport::claim_keypackage(client, user, device, &descriptor.gid).await?;
        store.prepare_invitation(name, &recipient)?;
    } else {
        ensure!(
            members.contains(&format!("{user}/{device}")),
            "group already has another invitee"
        );
    }
    flush_outbox(store, client).await
}
pub async fn join_next(
    store: &IdentityStore,
    client: &async_nats::Client,
    inviter: &str,
    device: &str,
) -> Result<Group> {
    let inviter = transport::lookup(client, inviter, device).await?;
    let js = async_nats::jetstream::new(client.clone());
    let consumer: async_nats::jetstream::consumer::PullConsumer = js
        .get_consumer_from_stream(format!("device_{}", store.nkey()?.public_key()), "MAILBOX")
        .await?;
    let mut batch = consumer
        .fetch()
        .max_messages(1)
        .expires(std::time::Duration::from_secs(2))
        .messages()
        .await?;
    let message = batch
        .next()
        .await
        .context("no invitation available; run channel join again after an invite")?
        .map_err(|e| anyhow!("mailbox delivery: {e}"))?;
    let descriptor = store.accept_welcome(&message.payload, &inviter)?;
    message
        .ack()
        .await
        .map_err(|e| anyhow!("acknowledge Welcome: {e}"))?;
    client.flush().await?;
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn welcome_authentication_rollback_and_retry() -> Result<()> {
        let a = tempfile::tempdir()?;
        let b = tempfile::tempdir()?;
        let mut alice = IdentityStore::open(a.path())?;
        let mut bob = IdentityStore::open(b.path())?;
        let alice_registration = alice.init("alice", "laptop")?;
        let bob_registration = bob.init("bob", "laptop")?;
        alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &bob_registration)?;
        let welcome: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
            [],
            |r| r.get(0),
        )?;
        let commit: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%handshake'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(
            MlsMessageIn::tls_deserialize_exact(&commit)?.wire_format(),
            WireFormat::PrivateMessage
        );
        assert!(bob.accept_welcome(&welcome, &bob_registration).is_err());
        assert!(bob.groups()?.is_empty());
        let mut tampered = welcome.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(bob.accept_welcome(&tampered, &alice_registration).is_err());
        let group = bob.accept_welcome(&welcome, &alice_registration)?;
        assert_eq!(bob.accept_welcome(&welcome, &alice_registration)?, group);
        assert_eq!(alice.members("engineering")?, bob.members("engineering")?);
        drop(bob);
        let bob = IdentityStore::open(b.path())?;
        assert_eq!(
            bob.members("engineering")?,
            vec!["alice/laptop", "bob/laptop"]
        );
        assert_eq!(bob.load_group(&group)?.epoch().as_u64(), 1);
        Ok(())
    }
}
