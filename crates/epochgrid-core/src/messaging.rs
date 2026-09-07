use crate::{delivery::flush_outbox, identity::IdentityStore, wire};
use anyhow::{Result, anyhow, ensure};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

#[derive(Debug, thiserror::Error)]
#[error("invalid or no-longer-decryptable MLS application message")]
pub(crate) struct InvalidMessage;

pub const MAX_PLAINTEXT: usize = 16_384;
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptedMessage {
    pub sender: String,
    pub plaintext: Vec<u8>,
}
impl IdentityStore {
    /// Persist the advanced sending ratchet and ciphertext together before network I/O.
    pub fn encrypt_message(&self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !plaintext.is_empty() && plaintext.len() <= MAX_PLAINTEXT,
            "message must contain 1–16384 bytes"
        );
        let descriptor = self.group(name)?;
        let (signer, _) = self.signer()?;
        self.transaction(|| {
            let mut group = self.load_group(&descriptor)?;
            ensure!(
                group.members().count() == 2,
                "invite a peer before sending messages"
            );
            let bytes = group
                .create_message(&self.provider, &signer, plaintext)
                .map_err(|e| anyhow!("encrypt MLS application: {e:?}"))?
                .to_bytes()?;
            self.queue(&descriptor.subject("message"), &bytes)?;
            let identity = self.registration()?.payload;
            self.connection.execute("INSERT INTO transcript(gid,payload,sender,plaintext,outgoing,displayed) VALUES(?1,?2,?3,?4,1,1)",
                rusqlite::params![descriptor.gid, bytes, format!("{}/{}", identity.user_id, identity.device_id), plaintext])?;
            Ok(bytes)
        })
    }
    /// Persist authenticated plaintext with the receive ratchet, never to NATS.
    pub fn decrypt_message(&self, name: &str, bytes: &[u8]) -> Result<Option<DecryptedMessage>> {
        self.transaction(|| self.decrypt_inner(name, bytes))
    }
    pub(crate) fn decrypt_inner(
        &self,
        name: &str,
        bytes: &[u8],
    ) -> Result<Option<DecryptedMessage>> {
        ensure!(bytes.len() <= wire::MAX_WIRE, InvalidMessage);
        let descriptor = self.group(name)?;
        let message = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| InvalidMessage)?;
        ensure!(
            message.wire_format() == WireFormat::PrivateMessage,
            InvalidMessage
        );
        let protocol = message
            .try_into_protocol_message()
            .map_err(|_| InvalidMessage)?;
        ensure!(
            protocol.group_id().as_slice() == descriptor.mls_id
                && protocol.content_type() == ContentType::Application,
            InvalidMessage
        );
        let known: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM received WHERE payload=?1 UNION ALL SELECT 1 FROM outbox WHERE payload=?1)", [bytes], |r| r.get(0))?;
        if known {
            return Ok(None);
        }
        let mut group = self.load_group(&descriptor)?;
        let processed =
            group
                .process_message(&self.provider, protocol)
                .map_err(|error| match error {
                    ProcessMessageError::StorageError(error) => {
                        anyhow!("MLS storage failure: {error:?}")
                    }
                    ProcessMessageError::LibraryError(error) => {
                        anyhow!("MLS library failure: {error:?}")
                    }
                    ProcessMessageError::GroupStateError(error) => {
                        anyhow!("MLS group state failure: {error:?}")
                    }
                    _ => InvalidMessage.into(),
                })?;
        let credential = BasicCredential::try_from(processed.credential().clone())
            .map_err(|_| InvalidMessage)?;
        let sender = std::str::from_utf8(credential.identity())
            .map_err(|_| InvalidMessage)?
            .to_owned();
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            return Err(InvalidMessage.into());
        };
        let plaintext = message.into_bytes();
        ensure!(plaintext.len() <= MAX_PLAINTEXT, InvalidMessage);
        self.connection
            .execute("INSERT INTO received(payload) VALUES(?1)", [bytes])?;
        self.connection.execute(
            "INSERT INTO transcript(gid,payload,sender,plaintext,outgoing) VALUES(?1,?2,?3,?4,0)",
            rusqlite::params![descriptor.gid, bytes, sender, plaintext],
        )?;
        Ok(Some(DecryptedMessage { sender, plaintext }))
    }
}

pub async fn subscribe(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
) -> Result<async_nats::Subscriber> {
    let subscription = client
        .subscribe(store.group(name)?.subject("message"))
        .await?;
    client.flush().await?;
    Ok(subscription)
}
pub async fn send(
    store: &IdentityStore,
    client: &async_nats::Client,
    name: &str,
    plaintext: &[u8],
) -> Result<()> {
    store.encrypt_message(name, plaintext)?;
    flush_outbox(store, client).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_ciphertext_tampering_replay_and_restart() -> Result<()> {
        let a = tempfile::tempdir()?;
        let b = tempfile::tempdir()?;
        let mut alice = IdentityStore::open(a.path())?;
        let mut bob = IdentityStore::open(b.path())?;
        let alice_registration = alice.init("alice", "laptop")?;
        let bob_registration = bob.init("bob", "laptop")?;
        alice.create_group("engineering")?;
        assert!(alice.encrypt_message("engineering", b"too soon").is_err());
        alice.prepare_invitation("engineering", &bob_registration)?;
        let welcome: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
            [],
            |r| r.get(0),
        )?;
        bob.accept_welcome(&welcome, &alice_registration)?;
        let secret = b"EPOCHGRID_TEST_SECRET_91F3";
        let ciphertext = alice.encrypt_message("engineering", secret)?;
        assert!(!ciphertext.windows(secret.len()).any(|w| w == secret));
        let mut tampered = ciphertext.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(bob.decrypt_message("engineering", &tampered).is_err());
        assert!(bob.decrypt_message("engineering", secret).is_err());
        bob.create_group("other")?;
        assert!(bob.decrypt_message("other", &ciphertext).is_err());
        assert_eq!(
            bob.decrypt_message("engineering", &ciphertext)?,
            Some(DecryptedMessage {
                sender: "alice/laptop".into(),
                plaintext: secret.to_vec()
            })
        );
        assert!(bob.decrypt_message("engineering", &ciphertext)?.is_none());
        assert!(alice.decrypt_message("engineering", &ciphertext)?.is_none());
        drop(alice);
        drop(bob);
        let alice = IdentityStore::open(a.path())?;
        let bob = IdentityStore::open(b.path())?;
        let reply = bob.encrypt_message("engineering", b"confirmed")?;
        assert_eq!(
            alice
                .decrypt_message("engineering", &reply)?
                .map(|m| m.plaintext),
            Some(b"confirmed".to_vec())
        );
        let next = alice.encrypt_message("engineering", b"after restart")?;
        assert_eq!(
            bob.decrypt_message("engineering", &next)?
                .map(|m| m.plaintext),
            Some(b"after restart".to_vec())
        );
        Ok(())
    }
}
