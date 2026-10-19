//! Restart-safe local authorization intents and authenticated Welcome relay.
use super::*;
use crate::{
    identity::IdentityStore,
    transparency::Snapshot,
    wire::{self, Body},
};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{KeyPackageIn, MlsGroup, tls_codec::Deserialize as _};

pub const RELAY: &str = "epochgrid.v1.channel.welcome";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyState {
    pub generation: u64,
    pub epoch: u64,
    pub coordinator: String,
    pub members: Vec<Member>,
}
#[derive(Serialize, Deserialize)]
struct Intent {
    version: u16,
    gid: String,
    epoch: u64,
    leaves: Vec<(u32, Vec<u8>, Vec<u8>)>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeRelay {
    pub version: u16,
    pub gid: String,
    pub epoch: u64,
    pub recipient: String,
    pub sender: String,
    pub id: i64,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl WelcomeRelay {
    fn bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = b"epochgrid/welcome-relay/v1\0".to_vec();
        bytes.extend(postcard::to_allocvec(&(
            self.version,
            &self.gid,
            self.epoch,
            &self.recipient,
            &self.sender,
            self.id,
            &self.payload,
        ))?);
        Ok(bytes)
    }
    pub fn validate(&self, registry: &AuthRegistry) -> Result<String> {
        ensure!(self.version == 1 && self.id > 0, "invalid Welcome relay");
        nkeys::KeyPair::from_public_key(&self.sender)?.verify(&self.bytes()?, &self.signature)?;
        registry.authorize(&self.sender)?;
        let recipient = registry.authorize(&self.recipient)?;
        let state = registry.policy_state(&self.gid)?.context("unknown group")?;
        ensure!(
            state.coordinator == self.sender
                && state.epoch == self.epoch
                && state.members.iter().any(|m| m.nkey == self.recipient),
            "Welcome relay is not authorized by current membership"
        );
        let Body::Welcome { payload } = wire::decode(&self.payload)? else {
            anyhow::bail!("expected Welcome envelope")
        };
        ensure!(
            matches!(
                openmls::prelude::MlsMessageIn::tls_deserialize_exact(&payload)?.extract(),
                openmls::prelude::MlsMessageBodyIn::Welcome(_)
            ),
            "expected MLS Welcome"
        );
        Ok(format!(
            "epochgrid.v1.user.{}.{}.inbox",
            recipient.user.as_str(),
            recipient.device
        ))
    }
}
impl AuthRegistry {
    pub fn policy_state(&self, gid: &str) -> Result<Option<PolicyState>> {
        validate_gid(gid)?;
        let state = self
            .db
            .query_row(
                "SELECT generation,epoch,coordinator FROM authorization_groups WHERE gid=?1",
                [gid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((generation, epoch, coordinator)) = state else {
            return Ok(None);
        };
        let mut stmt = self
            .db
            .prepare("SELECT nkey,leaf FROM authorization_members WHERE gid=?1 ORDER BY leaf")?;
        let members = stmt
            .query_map([gid], |r| {
                Ok(Member {
                    nkey: r.get(0)?,
                    leaf: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<_, _>>()?;
        Ok(Some(PolicyState {
            generation,
            epoch,
            coordinator,
            members,
        }))
    }
}
impl IdentityStore {
    pub fn dynamic_authorization(&self) -> Result<bool> {
        Ok(crate::identity_model::UserId::try_from(self.registration()?.payload.user_id).is_ok())
    }
    pub(crate) fn queue_policy(&self, group: &MlsGroup) -> Result<()> {
        if self.dynamic_authorization()? {
            let intent = Intent {
                version: 1,
                gid: crate::groups::Group::from_mls_id(group.group_id())?.gid,
                epoch: group.epoch().as_u64(),
                leaves: group
                    .members()
                    .map(|m| {
                        Ok((
                            m.index.u32(),
                            m.signature_key,
                            m.credential.tls_serialize_detached()?,
                        ))
                    })
                    .collect::<Result<_>>()?,
            };
            self.queue(SUBJECT, &postcard::to_allocvec(&intent)?)?;
        }
        Ok(())
    }
    pub(crate) fn queue_welcome(
        &self,
        group: &MlsGroup,
        recipient: &wire::DeviceRegistration,
        payload: Vec<u8>,
    ) -> Result<()> {
        if self.dynamic_authorization()? {
            let relay = WelcomeRelay {
                version: 1,
                gid: crate::groups::Group::from_mls_id(group.group_id())?.gid,
                epoch: group.epoch().as_u64(),
                recipient: recipient.payload.nats_public_key.clone(),
                sender: self.nkey()?.public_key(),
                id: 0,
                payload,
                signature: Vec::new(),
            };
            self.queue(RELAY, &postcard::to_allocvec(&relay)?)
        } else {
            self.queue(
                &format!(
                    "epochgrid.v1.user.{}.{}.inbox",
                    recipient.payload.user_id, recipient.payload.device_id
                ),
                &payload,
            )
        }
    }
}
pub async fn dispatch(
    store: &IdentityStore,
    client: &async_nats::Client,
    snapshot: &Snapshot,
    id: i64,
    subject: &str,
    payload: &[u8],
) -> Result<bool> {
    if subject == SUBJECT {
        let intent: Intent = postcard::from_bytes(payload)?;
        ensure!(intent.version == 1, "unsupported authorization intent");
        let members = intent
            .leaves
            .iter()
            .map(|(leaf, signature, credential)| {
                // The append-only snapshot authenticates this historical binding.
                // Do not require an already-used KeyPackage to be unexpired to rekey.
                let mut matches = Vec::new();
                for record in &snapshot.entries {
                    if record.payload.mls_credential != *credential {
                        continue;
                    }
                    let identity =
                        KeyPackageIn::tls_deserialize_exact(&record.payload.mls_key_package)?
                            .unverified_credential();
                    if identity.signature_key.as_slice() == signature {
                        matches.push(record);
                    }
                }
                ensure!(
                    matches.len() == 1,
                    "MLS member must have one authenticated directory binding"
                );
                let record = matches[0];
                Ok(Member {
                    nkey: record.payload.nats_public_key.clone(),
                    leaf: *leaf,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let reply = crate::transport::request_idempotent(
            client,
            SUBJECT,
            Body::PolicyQuery {
                gid: intent.gid.clone(),
            },
        )
        .await?;
        let Body::PolicyState(state) = wire::decode(&reply.payload)? else {
            anyhow::bail!("policy query rejected")
        };
        let signer = store.nkey()?.public_key();
        if !state.as_ref().is_some_and(|s| {
            s.epoch == intent.epoch && s.members == members && s.coordinator == signer
        }) {
            let policy = PolicyUpdate {
                version: 1,
                gid: intent.gid,
                expected_generation: state.map_or(0, |s| s.generation),
                epoch: intent.epoch,
                signer: store.nkey()?.public_key(),
                members,
            }
            .sign(&store.nkey()?)?;
            let reply =
                crate::transport::request_idempotent(client, SUBJECT, Body::GroupPolicy(policy))
                    .await?;
            ensure!(
                matches!(wire::decode(&reply.payload)?, Body::PolicyApplied { .. }),
                "group policy rejected; queued work retained"
            );
        }
        crate::transport::refresh_authorization(client).await?;
        return Ok(true);
    }
    if subject == RELAY {
        let mut relay: WelcomeRelay = postcard::from_bytes(payload)?;
        relay.id = id;
        relay.signature = store.nkey()?.sign(&relay.bytes()?)?;
        let reply =
            crate::transport::request_idempotent(client, RELAY, Body::RelayWelcome(relay)).await?;
        ensure!(
            matches!(wire::decode(&reply.payload)?, Body::WelcomeRelayed),
            "Welcome relay rejected; invitation retained"
        );
        return Ok(true);
    }
    Ok(false)
}

/// Reconcile from durable policy before issuing new device claims. Removed filters
/// must not retain unacknowledged redeliveries; replace instead of updating in place.
pub async fn reconcile_consumers(
    registry: &AuthRegistry,
    client: &async_nats::Client,
) -> Result<()> {
    let active = registry.enrollment()?;
    crate::transport::provision_mailboxes(client.clone(), &active).await?;
    let js = async_nats::jetstream::new(client.clone());
    let chat = js.get_stream("CHAT").await?;
    let mailbox = js.get_stream("MAILBOX").await?;
    for key in registry.historical_enrollment()?.values() {
        let name = format!("device_{key}");
        let existing = match chat.consumer_info(&name).await {
            Ok(c) => Some(c),
            Err(e) => {
                // The structured server error code distinguishes absence from outages.
                if matches!(
                    e.kind(),
                    async_nats::jetstream::context::ConsumerInfoErrorKind::NotFound
                ) {
                    None
                } else {
                    return Err(anyhow::anyhow!("consumer lookup failed: {e}"));
                }
            }
        };
        if !active.values().any(|value| value == key) {
            if existing.is_some() {
                chat.delete_consumer(&name).await?;
            }
            match mailbox.delete_consumer(&name).await {
                Ok(_) => (),
                Err(e) if matches!(e.kind(), async_nats::jetstream::stream::ConsumerErrorKind::JetStream(ref server) if server.code() == 404) =>
                    {}
                Err(e) => return Err(e.into()),
            }
            continue;
        }
        let mut filters: Vec<_> = registry
            .authorized_groups(key)?
            .iter()
            .flat_map(|gid| {
                [
                    format!("epochgrid.v1.group.{gid}.handshake"),
                    format!("epochgrid.v1.group.{gid}.message"),
                ]
            })
            .collect();
        if filters.is_empty() {
            filters.push("epochgrid.v1.group._none_.message".into());
        }
        if let Some(consumer) = existing {
            if consumer.config.filter_subjects == filters
                && consumer.config.filter_subject.is_empty()
                && consumer.config.max_ack_pending == 1
                && consumer.config.max_batch == 1
                && consumer.config.ack_policy
                    == async_nats::jetstream::consumer::AckPolicy::Explicit
                && consumer.config.deliver_subject.is_none()
            {
                continue;
            }
            chat.delete_consumer(&name).await?;
        }
        chat.create_consumer(async_nats::jetstream::consumer::pull::Config {
            durable_name: Some(name),
            filter_subjects: filters,
            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::All,
            ack_wait: std::time::Duration::from_secs(2),
            max_ack_pending: 1,
            max_batch: 1,
            ..Default::default()
        })
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_epoch_order_and_relay_authentication() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut registry = AuthRegistry::open(&root.path().join("registry"))?;
        let mut stores = Vec::new();
        for user in ["alice", "bob", "mallory"] {
            let token = registry.invite(user, 60)?;
            let mut local = IdentityStore::open(&root.path().join(user))?;
            let registration = local.init(
                crate::identity_model::token_user(&token)?.as_str(),
                "laptop",
            )?;
            registry.enroll(&token, &registration)?;
            registry.activate(&local.nkey()?.public_key())?;
            stores.push(local);
        }
        let alice = &stores[0];
        let group = alice.create_group("engineering")?;
        alice.prepare_invitation("engineering", &stores[1].registration()?)?;
        let rows = alice
            .connection
            .prepare("SELECT id,subject,payload FROM outbox ORDER BY id")?
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(
            rows.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
            [SUBJECT, SUBJECT, group.subject("handshake").as_str(), RELAY]
        );
        for (index, row) in rows.iter().take(2).enumerate() {
            let intent: Intent = postcard::from_bytes(&row.2)?;
            assert_eq!(intent.epoch, index as u64);
            let policy = PolicyUpdate {
                version: 1,
                gid: group.gid.clone(),
                epoch: intent.epoch,
                expected_generation: index as u64,
                signer: alice.nkey()?.public_key(),
                members: stores
                    .iter()
                    .take(index + 1)
                    .enumerate()
                    .map(|(leaf, s)| {
                        Ok(Member {
                            leaf: leaf as u32,
                            nkey: s.nkey()?.public_key(),
                        })
                    })
                    .collect::<Result<_>>()?,
            }
            .sign(&alice.nkey()?)?;
            registry.apply_policy(&policy)?;
        }
        let mut relay: WelcomeRelay = postcard::from_bytes(&rows[3].2)?;
        relay.id = rows[3].0;
        relay.signature = alice.nkey()?.sign(&relay.bytes()?)?;
        assert!(relay.validate(&registry)?.ends_with(".laptop.inbox"));
        let bytes = wire::encode(Body::RelayWelcome(relay.clone()))?;
        assert_eq!(wire::decode(&bytes)?, Body::RelayWelcome(relay.clone()));
        let mut forged = relay.clone();
        forged.signature[0] ^= 1;
        assert!(forged.validate(&registry).is_err());
        let mut outsider = relay.clone();
        outsider.recipient = stores[2].nkey()?.public_key();
        outsider.signature = alice.nkey()?.sign(&outsider.bytes()?)?;
        assert!(outsider.validate(&registry).is_err());
        let mut stale = relay.clone();
        stale.epoch = 0;
        stale.signature = alice.nkey()?.sign(&stale.bytes()?)?;
        assert!(stale.validate(&registry).is_err());
        let mut wrong_kind = relay.clone();
        wrong_kind.payload = wire::encode(Body::Registered)?;
        wrong_kind.signature = alice.nkey()?.sign(&wrong_kind.bytes()?)?;
        assert!(wrong_kind.validate(&registry).is_err());
        registry.revoke(&relay.recipient)?;
        assert!(relay.validate(&registry).is_err());
        drop(stores);
        let restored = IdentityStore::open(&root.path().join("alice"))?;
        assert_eq!(restored.group_epoch("engineering")?, 1);
        assert_eq!(
            restored
                .connection
                .query_row("SELECT COUNT(*) FROM outbox WHERE sent=0", [], |r| r
                    .get::<_, u64>(0))?,
            4
        );
        assert_eq!(
            restored.connection.query_row(
                "SELECT payload FROM outbox WHERE id=?1",
                [relay.id],
                |r| r.get::<_, Vec<u8>>(0)
            )?,
            rows[3].2
        );
        Ok(())
    }
}
