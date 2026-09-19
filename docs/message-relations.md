# Message relationships — Milestone 19

Current deployment and milestone status: [status index](milestones.md). Local
plaintext examples require `EPOCHGRID_PROFILE=development`; the complete messaging
walkthrough still uses development fixtures. See [production TLS](operator/tls.md)
for secure transport and the remaining dynamic-deployment limits.

Each new application event has a random nonce, persistent per-device/group counter, content bytes and an optional typed
relation: ReplyTo, Replace, or Reaction { target, value, add }. The versioned binary
envelope is inside MLS PrivateMessage. Stable IDs are SHA-256 commitments to a
domain-separated canonical envelope and its group and authenticated MLS device identity.
Including the sender prevents another member from claiming its ID. A nonce makes
identical messages distinct; retransmitting the same event preserves its ID.
Legacy message IDs are domain-separated ciphertext hashes. IDs and relationships
never enter NATS subjects. Receipt delivery references remain ciphertext-based.

SQLite migration 7 adds an immutable application event log with ID/target indexes
alongside the existing transcript. New
transcript content remains the original application content; control rows carry
readable summaries. Legacy rows are backfilled without changing ciphertext or MLS
state. Encryption/decryption, transcript insertion and event indexing share a
transaction. The index can reconstruct the same display regardless of insertion
order. Projection reads indexed relations for each displayed target, rather than
mutating historical plaintext or loading an entire channel on each frame.

A reply is a new message whose parent remains independently addressable. Missing
parents show an unresolved reference, resolved when the parent is available.
Only the original sending device may replace a text message, including a reply.
Attachment bodies and relationship-control events cannot be replaced. Reactions
apply to original messages/replies, including attachment messages. Each device's
latest add/remove for a reaction value wins; the UI collapses active devices into
logical usernames. Removal affects only that device's reaction.

Competing edits and per-device reaction updates are ordered by the authenticated
application counter, then event ID (lexicographically greatest wins ties). Counters
advance from locally committed events for that sender/group, atomically with the
MLS ratchet, event and ciphertext. An event from another sender cannot advance a
device's counter. Legacy rows have counter zero. JetStream sequence orders the
timeline, but cannot override the author's edit/reaction ordering. Duplicate IDs
represent the same event and are collapsed; the earliest known stream sequence
anchors their timeline position. Duplicate copies inherit logical presentation.

Semantic validation is deferred until the target exists: unauthorized edits remain
authenticated historical events but never change the target. Relations to control
events are ignored. No recursive reply expansion or cycles are followed. Reply
labels identify the parent sender/ID without recursively quoting its contents.

The UI displays the current target content and reaction summary while retaining
separate, labeled immutable edit/reaction rows. This keeps changes inspectable and
preserves existing per-event unread/read-receipt behavior. Viewing a projection is
not a claim that every historical revision was read. Inspection of original event
content remains available separately. Message deletion and cross-device editing
are outside this milestone.

## Commands and display

The TUI displays a 12-character ID prefix beside each message. Commands accept any
unambiguous lowercase hexadecimal prefix of at least eight characters; ambiguous
or unknown prefixes are rejected before encryption.

```text
/reply MESSAGE_ID reply text
/edit MESSAGE_ID replacement text
/react MESSAGE_ID 👍
/unreact MESSAGE_ID 👍
```

The scripting equivalents take quoted text as an argument:

```bash
epochgrid message events engineering --offline
epochgrid message reply engineering MESSAGE_ID "confirmed"
epochgrid message edit engineering MESSAGE_ID "deploy tomorrow"
epochgrid message react engineering MESSAGE_ID "👍"
epochgrid message react engineering MESSAGE_ID "👍" --remove
epochgrid message history engineering --offline
```

`message events` prints full IDs and immutable original event content (the latest
100 rows), without marking them read. `message history` and the TUI show current
projections plus labeled control rows. The line-oriented `chat` and `message receive`
commands continue to emit individual immutable events; already printed terminal
output is not rewritten. Reaction values compare exact UTF-8 bytes, with no Unicode
normalization: 1–32 bytes, no whitespace/control characters. Reactions have no text
body. A reply or edit retains the existing 16,384-byte text limit.

Pagination remains based on immutable stream positions. Duplicate application copies
are collapsed within the selected event page; a page containing only duplicates
may therefore have fewer visible rows. Replies to messages unavailable because of
pre-join history or retention remain explicitly unresolved. Invalid control targets
and unauthorized edits are labeled ignored rather than silently changing content.

## Upgrade and security

Upgrade all participants before sending Milestone 19 messages. New clients continue
reading older raw text and attachment payloads; older clients cannot interpret the
new application envelope or open a schema-7 database. There is no automatic feature
negotiation in this alpha. Existing ciphertext, MLS state, receipts and attachment
manifests are preserved. No NATS stream, subject, KV bucket, consumer or permission
change is required. No backend flag or environment variable is added.

The full canonical application event is retained in the local event log so projection
replay does not require erased MLS ratchet keys. This log, like the original transcript,
is unencrypted local storage and excluded from recovery packages. Replaying means
folding retained authenticated application events, not decrypting old ciphertext again
after its keys have been erased. The event log must not be discarded as a cache.

Editing never erases old plaintext from devices, backups or other participants, and
never deletes/replaces a JetStream message. MLS protects the content, counter and
relationship metadata. Malicious infrastructure can still suppress events or reorder
the timeline; signed counters only make update selection independent of transport
order for the same known event set. They do not guarantee that every device has seen
the same events. Device compromise permits new edits/reactions as that device.
