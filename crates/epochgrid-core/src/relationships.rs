//! Immutable application events and deterministic conversation projection.
use crate::{
    attachments, history::HistoryEntry, identity::IdentityStore, messaging::MAX_PLAINTEXT,
    transparency::hash,
};
use anyhow::{Context, Result, anyhow, ensure};
use openmls_traits::{OpenMlsProvider, random::OpenMlsRand};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const PREFIX: &[u8] = b"\xffEGMSG";
pub(crate) const MAX_APPLICATION: usize = MAX_PLAINTEXT + 512;
pub type MessageId = [u8; 32];
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Relation {
    ReplyTo(MessageId),
    Replace(MessageId),
    Reaction {
        target: MessageId,
        value: String,
        add: bool,
    },
}
impl Relation {
    fn target(&self) -> &MessageId {
        match self {
            Self::ReplyTo(id) | Self::Replace(id) => id,
            Self::Reaction { target, .. } => target,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ApplicationEvent {
    nonce: [u8; 16],
    counter: u64,
    pub content: Vec<u8>,
    pub relation: Option<Relation>,
}
impl ApplicationEvent {
    pub(crate) fn new(
        store: &IdentityStore,
        name: &str,
        content: &[u8],
        relation: Option<Relation>,
    ) -> Result<Self> {
        let own = store.registration()?.payload;
        let counter: u64 = store.connection.query_row("SELECT COALESCE(MAX(e.counter),0) FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE e.gid=?1 AND t.sender=?2",params![store.group(name)?.gid,format!("{}/{}",own.user_id,own.device_id)],|r|r.get(0))?;
        let event = Self {
            counter: counter
                .checked_add(1)
                .context("application counter exhausted")?,
            nonce: store
                .provider
                .rand()
                .random_array()
                .map_err(|e| anyhow!("message randomness: {e:?}"))?,
            content: content.to_vec(),
            relation,
        };
        event.validate()?;
        Ok(event)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=i64::MAX as u64).contains(&self.counter),
            "invalid application counter"
        );
        match &self.relation {
            Some(Relation::Reaction { value, .. }) => ensure!(
                self.content.is_empty()
                    && !value.is_empty()
                    && value.len() <= 32
                    && !value.chars().any(|c| c.is_control() || c.is_whitespace()),
                "reaction must contain 1–32 non-whitespace UTF-8 bytes and no content"
            ),
            _ => ensure!(
                !self.content.is_empty() && self.content.len() <= MAX_PLAINTEXT,
                "message content must contain 1–16384 bytes"
            ),
        }
        if matches!(self.relation, Some(Relation::Replace(_))) {
            std::str::from_utf8(&self.content).context("replacement must be text")?;
        }
        Ok(())
    }
    pub(crate) fn wire(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = PREFIX.to_vec();
        bytes.push(1);
        bytes.extend(postcard::to_allocvec(self)?);
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>> {
        if !bytes.starts_with(PREFIX) {
            ensure!(bytes.len() <= MAX_PLAINTEXT, "oversized legacy message");
            return Ok(None);
        }
        ensure!(
            bytes.len() <= MAX_APPLICATION && bytes.get(PREFIX.len()) == Some(&1),
            "unsupported application envelope"
        );
        let (event, rest): (Self, _) = postcard::take_from_bytes(&bytes[PREFIX.len() + 1..])?;
        ensure!(rest.is_empty(), "trailing application bytes");
        event.validate()?;
        ensure!(event.wire()? == bytes, "noncanonical application envelope");
        Ok(Some(event))
    }
    pub(crate) fn root(&self) -> bool {
        matches!(self.relation, None | Some(Relation::ReplyTo(_)))
    }
    pub(crate) fn transcript(&self) -> Vec<u8> {
        match &self.relation {
            None | Some(Relation::ReplyTo(_)) => self.content.clone(),
            Some(Relation::Replace(id)) => format!(
                "[edit {}] {}",
                &id_text(id)[..12],
                String::from_utf8_lossy(&self.content)
            )
            .into_bytes(),
            Some(Relation::Reaction { target, value, add }) => format!(
                "[reaction {} {} {}]",
                if *add { "add" } else { "remove" },
                &id_text(target)[..12],
                value
            )
            .into_bytes(),
        }
    }
}
pub fn id_text(id: &MessageId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
fn parse_id(text: &str) -> Result<MessageId> {
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "message ID must be 64 lowercase hexadecimal characters"
    );
    let mut id = [0; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(id)
}
struct Record {
    row: i64,
    sender: String,
    id: String,
    event: ApplicationEvent,
}
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, String, String, Vec<u8>)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}
fn unpack((row, sender, id, bytes): (i64, String, String, Vec<u8>)) -> Result<Record> {
    Ok(Record {
        row,
        sender,
        id,
        event: postcard::from_bytes(&bytes)?,
    })
}
pub struct ConversationEntry {
    pub entry: HistoryEntry,
    pub message_id: Option<String>,
}
impl IdentityStore {
    pub(crate) fn migrate_relationships(&self) -> Result<()> {
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM epochgrid_migrations WHERE version=7)",
            [],
            |r| r.get(0),
        )?;
        if !exists {
            self.transaction(|| {
            self.connection.execute_batch("CREATE TABLE message_events(transcript_id INTEGER PRIMARY KEY, gid TEXT NOT NULL, message_id TEXT NOT NULL, target TEXT, kind INTEGER NOT NULL, counter INTEGER NOT NULL, event BLOB NOT NULL); CREATE INDEX event_identity ON message_events(gid,message_id); CREATE INDEX event_target ON message_events(gid,target,kind);")?;
            let mut statement = self.connection.prepare("SELECT id,gid,sender,payload,plaintext FROM transcript WHERE sender IS NOT NULL AND plaintext IS NOT NULL")?;
            let rows = statement.query_map([], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?)))?;
            for row in rows { let (id,gid,sender,payload,plaintext) = row?; self.index_application(id,&gid,&sender,&payload,None,&plaintext)?; }
            self.connection.execute("INSERT INTO epochgrid_migrations VALUES(7)", [])?; Ok(())
        })?;
        }
        Ok(())
    }
    pub(crate) fn index_application(
        &self,
        row: i64,
        gid: &str,
        sender: &str,
        ciphertext: &[u8],
        event: Option<&ApplicationEvent>,
        plaintext: &[u8],
    ) -> Result<()> {
        let (id, event) = if let Some(event) = event {
            (
                hash(&postcard::to_allocvec(&(
                    "epochgrid application id v1",
                    gid,
                    sender,
                    event.wire()?,
                ))?)?,
                event.clone(),
            )
        } else {
            (
                hash(&postcard::to_allocvec(&(
                    "epochgrid legacy id v1",
                    gid,
                    ciphertext,
                ))?)?,
                ApplicationEvent {
                    nonce: [0; 16],
                    counter: 0,
                    content: plaintext.to_vec(),
                    relation: None,
                },
            )
        };
        let target = event.relation.as_ref().map(|r| id_text(r.target()));
        let kind = match &event.relation {
            None => 0,
            Some(Relation::ReplyTo(_)) => 1,
            Some(Relation::Replace(_)) => 2,
            Some(Relation::Reaction { .. }) => 3,
        };
        self.connection.execute("INSERT INTO message_events(transcript_id,gid,message_id,target,kind,counter,event) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![row,gid,id_text(&id),target,kind,event.counter,postcard::to_allocvec(&event)?])?;
        // A retransmission of the identical application event inherits presentation.
        self.connection.execute("UPDATE transcript SET displayed=1 WHERE id=?1 AND EXISTS(SELECT 1 FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE e.gid=?2 AND e.message_id=?3 AND t.displayed=1)",params![row,gid,id_text(&id)])?;
        Ok(())
    }
    pub fn application_id(&self, row: i64) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT message_id FROM message_events WHERE transcript_id=?1",
                [row],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn resolve_message(&self, name: &str, prefix: &str) -> Result<MessageId> {
        ensure!(
            (8..=64).contains(&prefix.len())
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "use at least eight lowercase hexadecimal ID characters"
        );
        let mut statement = self.connection.prepare("SELECT DISTINCT message_id FROM message_events WHERE gid=?1 AND message_id LIKE ?2 LIMIT 2")?;
        let ids = statement
            .query_map(params![self.group(name)?.gid, format!("{prefix}%")], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(ids.len() == 1, "unknown or ambiguous message ID");
        parse_id(&ids[0])
    }
    fn application(&self, gid: &str, id: &MessageId) -> Result<Option<Record>> {
        self.connection.query_row("SELECT e.transcript_id,t.sender,e.message_id,e.event FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE e.gid=?1 AND e.message_id=?2 ORDER BY t.stream_sequence IS NULL,t.stream_sequence,e.transcript_id LIMIT 1",params![gid,id_text(id)],record).optional()?.map(unpack).transpose()
    }
    pub(crate) fn validate_relation(&self, name: &str, relation: &Relation) -> Result<()> {
        let target = self
            .application(&self.group(name)?.gid, relation.target())?
            .context("target message is not available locally")?;
        ensure!(
            target.event.root(),
            "relationships must target a message or reply"
        );
        if matches!(relation, Relation::Replace(_)) {
            let own = self.registration()?.payload;
            ensure!(
                target.sender == format!("{}/{}", own.user_id, own.device_id),
                "only the original sending device can edit a message"
            );
            ensure!(
                std::str::from_utf8(&target.event.content).is_ok(),
                "only text messages can be edited"
            );
        }
        Ok(())
    }
    fn projected(&self, gid: &str, root: &Record) -> Result<String> {
        if !root.event.root() {
            let relation = root
                .event
                .relation
                .as_ref()
                .context("control relation missing")?;
            let Some(target) = self.application(gid, relation.target())? else {
                return Ok(format!(
                    "[unresolved {}] {}",
                    &id_text(relation.target())[..12],
                    String::from_utf8_lossy(&root.event.transcript())
                ));
            };
            if !target.event.root()
                || (matches!(relation, Relation::Replace(_))
                    && (target.sender != root.sender
                        || std::str::from_utf8(&target.event.content).is_err()))
            {
                return Ok(format!(
                    "[ignored relationship to {}: unauthorized or invalid target]",
                    &target.id[..12]
                ));
            }
            return Ok(String::from_utf8(root.event.transcript())?);
        }
        let mut statement = self.connection.prepare("SELECT e.transcript_id,t.sender,e.message_id,e.event FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE e.gid=?1 AND e.target=?2 AND e.kind IN (2,3) ORDER BY e.counter,e.message_id,e.transcript_id")?;
        let rows = statement.query_map(params![gid, root.id], record)?;
        let mut seen = BTreeSet::new();
        let mut content = root.event.content.clone();
        let mut edited = false;
        let mut reactions = BTreeMap::new();
        for row in rows {
            let update = unpack(row?)?;
            if !seen.insert(update.id) {
                continue;
            }
            match update.event.relation {
                Some(Relation::Replace(_))
                    if update.sender == root.sender
                        && std::str::from_utf8(&root.event.content).is_ok() =>
                {
                    content = update.event.content;
                    edited = true;
                }
                Some(Relation::Reaction { value, add, .. }) => {
                    reactions.insert((update.sender, value), add);
                }
                _ => {}
            }
        }
        let mut text = attachments::display(&content);
        if edited {
            text.push_str(" [edited]");
        }
        if let Some(Relation::ReplyTo(parent)) = root.event.relation {
            let parent = self
                .application(gid, &parent)?
                .filter(|p| p.event.root())
                .map_or_else(|| "unavailable".into(), |p| p.sender);
            text = format!(
                "[reply to {parent} {}]\n{text}",
                &id_text(
                    root.event
                        .relation
                        .as_ref()
                        .context("reply missing")?
                        .target()
                )[..12]
            );
        }
        let mut users: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for ((device, value), active) in reactions {
            if active {
                users.entry(value).or_default().insert(
                    device
                        .split_once('/')
                        .map_or(device.as_str(), |(u, _)| u)
                        .to_owned(),
                );
            }
        }
        for (value, users) in users {
            text.push_str(&format!(
                "\n[reaction {value}: {}]",
                users.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        Ok(text)
    }
    /// View-only projection; original transcript and ciphertext remain unchanged.
    pub fn conversation(
        &self,
        name: &str,
        limit: u32,
        before: Option<u64>,
    ) -> Result<Vec<ConversationEntry>> {
        let gid = self.group(name)?.gid;
        let mut output = Vec::new();
        for mut entry in self.history(name, limit, before)? {
            let id = self.application_id(entry.id)?;
            if let Some(id) = &id {
                let event = self
                    .application(&gid, &parse_id(id)?)?
                    .context("event index missing")?;
                if event.row != entry.id {
                    continue;
                }
                entry.plaintext = Some(self.projected(&gid, &event)?.into_bytes());
            }
            output.push(ConversationEntry {
                entry,
                message_id: id,
            });
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
