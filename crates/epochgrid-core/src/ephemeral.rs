//! Loss-tolerant, signed MLS-exporter application events; never persisted.
use crate::{
    identity::{IdentityStore, SUITE},
    wire::validate_id,
};
use anyhow::{Context, Result, anyhow, ensure};
use openmls::prelude::BasicCredential;
use openmls_traits::{
    OpenMlsProvider, crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer,
    types::AeadType,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const TTL_MS: u64 = 8000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EphemeralEvent {
    TypingStarted,
    TypingStopped,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u16,
    epoch: u64,
    leaf: u32,
    id: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Body {
    issued: u64,
    event: EphemeralEvent,
    signature: Vec<u8>,
}
pub struct AuthenticatedEvent {
    pub sender: String,
    epoch: u64,
    issued: u64,
    event: EphemeralEvent,
    expires: Instant,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, remaining) = postcard::take_from_bytes(bytes)?;
    ensure!(remaining.is_empty(), "trailing ephemeral data");
    Ok(value)
}
impl Envelope {
    fn context(&self, gid: &str) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(&(
            "epochgrid ephemeral v1",
            gid,
            self.version,
            self.epoch,
            self.leaf,
            self.id,
            self.nonce,
        ))?)
    }
    fn signing(&self, gid: &str, body: &Body) -> Result<Vec<u8>> {
        Ok(postcard::to_allocvec(&(
            "epochgrid ephemeral signature v1",
            self.context(gid)?,
            body.issued,
            body.event,
        ))?)
    }
}
impl IdentityStore {
    pub fn seal_ephemeral(&self, name: &str, event: EphemeralEvent) -> Result<Vec<u8>> {
        let descriptor = self.group(name)?;
        let group = self.load_group(&descriptor)?;
        self.ensure_can_send(&group)?;
        ensure!(group.members().count() > 1, "ephemeral event needs a peer");
        let crypto = self.provider.crypto();
        let mut envelope = Envelope {
            version: 1,
            epoch: group.epoch().as_u64(),
            leaf: group.own_leaf_index().u32(),
            id: self
                .provider
                .rand()
                .random_array()
                .map_err(|e| anyhow!("event randomness: {e:?}"))?,
            nonce: self
                .provider
                .rand()
                .random_array()
                .map_err(|e| anyhow!("event randomness: {e:?}"))?,
            ciphertext: Vec::new(),
        };
        let mut body = Body {
            issued: now()?,
            event,
            signature: Vec::new(),
        };
        body.signature = self
            .signer()?
            .0
            .sign(&envelope.signing(&descriptor.gid, &body)?)
            .map_err(|e| anyhow!("event signature: {e:?}"))?;
        let context = envelope.context(&descriptor.gid)?;
        let key = Zeroizing::new(
            group
                .export_secret(crypto, "epochgrid ephemeral v1", &context, 32)
                .map_err(|e| anyhow!("MLS exporter: {e:?}"))?,
        );
        envelope.ciphertext = crypto
            .aead_encrypt(
                AeadType::Aes256Gcm,
                &key,
                &postcard::to_allocvec(&body)?,
                &envelope.nonce,
                &context,
            )
            .map_err(|e| anyhow!("event encryption: {e:?}"))?;
        Ok(postcard::to_allocvec(&envelope)?)
    }
    pub fn open_ephemeral(&self, name: &str, bytes: &[u8]) -> Result<AuthenticatedEvent> {
        self.open_ephemeral_at(name, bytes, now()?)
    }
    fn open_ephemeral_at(
        &self,
        name: &str,
        bytes: &[u8],
        clock: u64,
    ) -> Result<AuthenticatedEvent> {
        ensure!(bytes.len() <= 1024, "oversized ephemeral event");
        let envelope: Envelope = decode(bytes)?;
        ensure!(envelope.version == 1, "unsupported ephemeral version");
        let descriptor = self.group(name)?;
        let group = self.load_group(&descriptor)?;
        self.ensure_can_send(&group)?;
        ensure!(
            envelope.epoch == group.epoch().as_u64(),
            "obsolete ephemeral epoch"
        );
        let member = group
            .members()
            .find(|m| m.index.u32() == envelope.leaf)
            .context("unknown ephemeral sender")?;
        ensure!(
            self.revoked_mls_key(&member.signature_key)?.is_none(),
            "revoked ephemeral sender"
        );
        let context = envelope.context(&descriptor.gid)?;
        let crypto = self.provider.crypto();
        let key = Zeroizing::new(
            group
                .export_secret(crypto, "epochgrid ephemeral v1", &context, 32)
                .map_err(|e| anyhow!("MLS exporter: {e:?}"))?,
        );
        let plaintext = Zeroizing::new(
            crypto
                .aead_decrypt(
                    AeadType::Aes256Gcm,
                    &key,
                    &envelope.ciphertext,
                    &envelope.nonce,
                    &context,
                )
                .map_err(|_| anyhow!("invalid ephemeral ciphertext"))?,
        );
        let body: Body = decode(&plaintext)?;
        ensure!(
            body.issued <= clock.saturating_add(1000) && clock < body.issued.saturating_add(TTL_MS),
            "expired or future ephemeral event"
        );
        crypto
            .verify_signature(
                SUITE.signature_algorithm(),
                &envelope.signing(&descriptor.gid, &body)?,
                &member.signature_key,
                &body.signature,
            )
            .map_err(|_| anyhow!("invalid ephemeral signature"))?;
        let credential = BasicCredential::try_from(member.credential)
            .map_err(|_| anyhow!("invalid sender credential"))?;
        let sender = std::str::from_utf8(credential.identity())?.to_owned();
        let (user, device) = sender.split_once('/').context("invalid sender identity")?;
        validate_id(user)?;
        validate_id(device)?;
        Ok(AuthenticatedEvent {
            sender,
            epoch: envelope.epoch,
            issued: body.issued,
            event: body.event,
            expires: Instant::now()
                + Duration::from_millis(
                    body.issued
                        .saturating_add(TTL_MS)
                        .saturating_sub(clock)
                        .min(TTL_MS),
                ),
        })
    }
}
/// Bounded device state, including stop tombstones. Duplicate/older events cannot
/// refresh expiry. State is deliberately lost at process exit.
#[derive(Default)]
pub struct TypingState {
    entries: BTreeMap<(String, String), AuthenticatedEvent>,
}
impl TypingState {
    pub fn accept(&mut self, gid: &str, event: AuthenticatedEvent) {
        let now = Instant::now();
        self.entries.retain(|_, e| e.expires > now);
        let key = (gid.to_owned(), event.sender.clone());
        if let Some(old) = self.entries.get(&key) {
            if old.epoch > event.epoch
                || (old.epoch == event.epoch
                    && (old.issued > event.issued
                        || (old.issued == event.issued
                            && (old.event == EphemeralEvent::TypingStopped
                                || event.event == EphemeralEvent::TypingStarted))))
            {
                return;
            }
        } else if self.entries.len() >= 256 {
            return;
        }
        self.entries.insert(key, event);
    }
    pub fn active(&self, gid: &str, epoch: u64) -> Vec<(String, Instant)> {
        self.entries
            .iter()
            .filter(|((g, _), e)| {
                g == gid
                    && e.epoch == epoch
                    && e.expires > Instant::now()
                    && e.event == EphemeralEvent::TypingStarted
            })
            .map(|((_, s), e)| (s.clone(), e.expires))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_events_loss_and_restart_leave_durable_ratchets_intact() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut alice = IdentityStore::open(&root.path().join("alice"))?;
        let mut bob = IdentityStore::open(&root.path().join("bob"))?;
        let ar = alice.init("alice", "laptop")?;
        let br = bob.init("bob", "laptop")?;
        alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &br)?;
        let welcome: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%inbox'",
            [],
            |r| r.get(0),
        )?;
        bob.accept_welcome(&welcome, &ar)?;
        alice.encrypt_message("engineering", b"before ephemeral loss")?;
        let old: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%message' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        let changes = alice.connection.total_changes();
        let bytes = alice.seal_ephemeral("engineering", EphemeralEvent::TypingStarted)?;
        let opened = bob.open_ephemeral("engineering", &bytes)?;
        assert_eq!(opened.sender, "alice/laptop");
        assert_eq!(opened.event, EphemeralEvent::TypingStarted);
        let mut state = TypingState::default();
        state.accept("g", opened);
        let first = state.active("g", 1);
        state.accept("g", bob.open_ephemeral("engineering", &bytes)?);
        assert_eq!(state.active("g", 1), first);
        let envelope: Envelope = decode(&bytes)?;
        let issued = bob.open_ephemeral("engineering", &bytes)?.issued;
        assert!(
            bob.open_ephemeral_at("engineering", &bytes, issued + TTL_MS)
                .is_err()
        );
        assert!(
            bob.open_ephemeral_at("engineering", &bytes, issued - 1001)
                .is_err()
        );
        for position in [0, bytes.len() - 1] {
            let mut corrupted = bytes.clone();
            corrupted[position] ^= 1;
            assert!(bob.open_ephemeral("engineering", &corrupted).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(bob.open_ephemeral("engineering", &trailing).is_err());
        assert!(bob.open_ephemeral("engineering", &[0; 1025]).is_err());
        // A member knows the exporter key but still cannot impersonate Alice.
        let descriptor = bob.group("engineering")?;
        let group = bob.load_group(&descriptor)?;
        let context = envelope.context(&descriptor.gid)?;
        let key = Zeroizing::new(
            group
                .export_secret(
                    bob.provider.crypto(),
                    "epochgrid ephemeral v1",
                    &context,
                    32,
                )
                .map_err(|e| anyhow!("{e:?}"))?,
        );
        let mut forged = Body {
            issued,
            event: EphemeralEvent::TypingStarted,
            signature: Vec::new(),
        };
        forged.signature = bob
            .signer()?
            .0
            .sign(&envelope.signing(&descriptor.gid, &forged)?)
            .map_err(|e| anyhow!("{e:?}"))?;
        let mut envelope = envelope;
        envelope.ciphertext = bob
            .provider
            .crypto()
            .aead_encrypt(
                AeadType::Aes256Gcm,
                &key,
                &postcard::to_allocvec(&forged)?,
                &envelope.nonce,
                &context,
            )
            .map_err(|e| anyhow!("{e:?}"))?;
        assert!(
            bob.open_ephemeral("engineering", &postcard::to_allocvec(&envelope)?)
                .is_err()
        );
        // More dropped events than the default MLS forward window.
        for _ in 0..1100 {
            alice.seal_ephemeral("engineering", EphemeralEvent::TypingStarted)?;
        }
        assert_eq!(alice.connection.total_changes(), changes);
        let subject = alice.group("engineering")?.subject("message");
        bob.stage_chat(10, &subject, &old)?;
        assert_eq!(bob.process_history("engineering")?.rejected, 0);
        drop(bob);
        let bob = IdentityStore::open(&root.path().join("bob"))?;
        alice.encrypt_message("engineering", b"after ephemeral loss")?;
        let next: Vec<u8> = alice.connection.query_row(
            "SELECT payload FROM outbox WHERE subject LIKE '%message' ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )?;
        bob.stage_chat(11, &subject, &next)?;
        assert_eq!(bob.process_history("engineering")?.rejected, 0);
        assert_eq!(bob.history("engineering", 10, None)?.len(), 2);
        Ok(())
    }
    #[test]
    fn typing_stop_reordering_expiry_epoch_and_capacity() {
        let mut state = TypingState::default();
        let make = |issued, event| AuthenticatedEvent {
            sender: "alice/laptop".into(),
            epoch: 1,
            issued,
            event,
            expires: Instant::now() + Duration::from_secs(8),
        };
        state.accept("g", make(2, EphemeralEvent::TypingStopped));
        state.accept("g", make(1, EphemeralEvent::TypingStarted));
        state.accept("g", make(2, EphemeralEvent::TypingStarted));
        assert!(state.active("g", 1).is_empty());
        state.accept("g", make(3, EphemeralEvent::TypingStarted));
        assert_eq!(state.active("g", 1).len(), 1);
        assert!(state.active("g", 2).is_empty());
        for event in state.entries.values_mut() {
            event.expires = Instant::now();
        }
        assert!(state.active("g", 1).is_empty());
        for i in 0..300 {
            state.accept(&i.to_string(), make(4, EphemeralEvent::TypingStarted));
        }
        assert_eq!(state.entries.len(), 256);
    }
}
