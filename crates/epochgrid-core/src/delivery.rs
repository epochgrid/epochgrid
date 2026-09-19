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
use rusqlite::OptionalExtension;

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
        ensure!(
            !self.is_revoked(&recipient.payload.nats_public_key)?,
            "cannot invite a revoked device"
        );
        let descriptor = self.group(name)?;
        let (signer, _) = self.signer()?;
        let package = KeyPackageIn::tls_deserialize_exact(&recipient.payload.mls_key_package)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("invalid recipient KeyPackage: {e:?}"))?;
        self.transaction(|| {
            let mut group = self.load_group(&descriptor)?;
            self.ensure_can_send(&group)?;
            ensure!(
                Some(group.own_leaf_index()) == self.coordinator(&group)?,
                "only the active group coordinator can add members"
            );
            ensure!(
                recipient.payload.nats_public_key != self.registration()?.payload.nats_public_key,
                "cannot invite this device to itself"
            );
            ensure!(
                !self.members(name)?.contains(&format!(
                    "{}/{}",
                    recipient.payload.user_id, recipient.payload.device_id
                )),
                "device is already a member"
            );
            let (commit, welcome, _) = group
                .add_members(&self.provider, &signer, &[package])
                .map_err(|e| anyhow!("MLS add member: {e:?}"))?;
            group
                .merge_pending_commit(&self.provider)
                .map_err(|e| anyhow!("merge local commit: {e:?}"))?;
            self.refresh_coordinator(&group)?;
            self.queue_policy(&group)?;
            self.queue(&descriptor.subject("handshake"), &commit.to_bytes()?)?;
            self.queue_welcome(
                &group,
                recipient,
                wire::encode(Body::Welcome {
                    payload: welcome.to_bytes()?,
                })?,
            )?;
            Ok(())
        })
    }
    pub fn accept_welcome(&self, bytes: &[u8], inviter: &DeviceRegistration) -> Result<Group> {
        self.ensure_messaging_identity()?;
        verify(inviter)?;
        let Body::Welcome { payload } = wire::decode(bytes)? else {
            anyhow::bail!("mailbox message is not a Welcome");
        };
        let package = KeyPackageIn::tls_deserialize_exact(&inviter.payload.mls_key_package)?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow!("invalid inviter: {e:?}"))?;
        self.transaction(|| {
            // Byte-identical redelivery must not consume the private KeyPackage twice.
            let previous = self
                .connection
                .query_row(
                    "SELECT name FROM welcomes WHERE payload=?1",
                    [bytes],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            if let Some(name) = previous {
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
            let coordinator_key = sender.signature_key().as_slice().to_vec();
            ensure!(
                staged.members().count() >= 2,
                "Welcome must include at least two devices"
            );
            let descriptor = Group::from_mls_id(staged.group_context().group_id())?;
            self.insert_group(&descriptor)?;
            self.connection.execute(
                "INSERT INTO group_coordinators VALUES(?1,?2)",
                rusqlite::params![descriptor.gid, coordinator_key],
            )?;
            self.connection.execute(
                "UPDATE group_join_epochs SET epoch=?1 WHERE gid=?2",
                rusqlite::params![staged.group_context().epoch().as_u64(), descriptor.gid],
            )?;
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
    let snapshot = crate::transparency::audit(client, store).await?;
    ensure!(
        !store.is_revoked(&store.nkey()?.public_key())?,
        "this device is revoked"
    );
    store.block_revoked_outbox()?;
    let js = async_nats::jetstream::new(client.clone());
    let mut statement = store
        .connection
        .prepare("SELECT id,subject,payload FROM outbox WHERE sent=0 AND id NOT IN (SELECT id FROM blocked_outbox) ORDER BY id")?;
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
        if crate::authorization::dispatch(store, client, &snapshot, id, &subject, &payload).await? {
            store
                .connection
                .execute("UPDATE outbox SET sent=1 WHERE id=?1", [id])?;
            continue;
        }
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
                store.connection.execute("UPDATE transcript SET stream_sequence=CASE WHEN stream_sequence IS NULL OR stream_sequence>?1 THEN ?1 ELSE stream_sequence END WHERE payload=?2", rusqlite::params![ack.sequence, payload])?;
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
    crate::history::resume(store, client, name).await?;
    let members = store.members(name)?;
    if !members.contains(&format!("{user}/{device}")) {
        ensure!(
            Some(store.load_group(&descriptor)?.own_leaf_index())
                == store.coordinator(&store.load_group(&descriptor)?)?,
            "only the active group coordinator can invite"
        );
        let expected = crate::transparency::lookup(client, store, user, device).await?;
        let recipient = transport::claim_keypackage(client, user, device, &descriptor.gid).await?;
        ensure!(
            recipient == expected,
            "KeyPackage differs from authenticated log; invitation blocked"
        );
        store.prepare_invitation(name, &recipient)?;
    }
    flush_outbox(store, client).await
}
pub async fn join_next(
    store: &IdentityStore,
    client: &async_nats::Client,
    inviter: &str,
    device: &str,
) -> Result<Group> {
    let inviter = crate::transparency::lookup(client, store, inviter, device).await?;
    let consumer = transport::device_consumer(store, client, "MAILBOX").await?;
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
        .double_ack()
        .await
        .map_err(|e| anyhow!("acknowledge Welcome: {e}"))?;
    if store.dynamic_authorization()? {
        transport::refresh_authorization(client).await?;
    }
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
