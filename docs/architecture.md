# EpochGrid architecture — through Milestone 16

EpochGrid (https://epochgrid.org) uses NATS for
transport, authentication, authorization, request/reply and persistence. OpenMLS
implements RFC 9420 group cryptography; no custom group encryption is introduced.

The workspace has core (wire protocol, SQLite/OpenMLS and NATS operations), a host
CLI, and one NATS-only identity service. NKeys authenticate devices to the fabric;
independent MLS Ed25519 keys authenticate group members. The service handles
public registrations, lookup, one-use KeyPackage reservation and stream/consumer
provisioning. It holds no client secrets or application plaintext. SQLite is local
only. There is no HTTP API and no backend message-decryption path.

Registration binds user/device/NKey/MLS credential/KeyPackage using an NKey-signed
postcard payload. The service validates OpenMLS signatures, lifetime and identity,
then checks explicit enrollment. Core NATS does not tell a subscriber the
requester's authenticated NKey; signing and enrollment are required independently
of subject permissions. Directory records are immutable; exact retries succeed.

Alice creates a local MLS group with an authenticated name and random routing ID.
She reserves Bob's initial KeyPackage, adds him, and queues the encrypted Commit
and Welcome. Bob pulls his durable mailbox and authenticates the Welcome signer
against an explicitly selected inviter's directory registration before joining.
The creator device can add multiple independent device leaves, including multiple
devices belonging to one user. MLS owns membership;
CHANNELS KV is provisioned but unused. Future channel metadata is not authoritative
cryptographic membership.

Application messages use MLS PrivateMessages and NATS group subjects. Publishers
wait for JetStream acknowledgments; durable consumers authenticate/decrypt locally.
CHAT stores raw versioned MLS protocol bytes. MAILBOX stores a small EpochGrid
Welcome envelope. Neither contains application plaintext. Each device has a
service-provisioned CHAT durable filtered to application and handshake subjects in the
existing shared development namespace. It starts at all retained messages. The
CLI uses this one path for offline catch-up and ongoing reception.

OpenMLS's SQLite provider and application tables share one connection. Transactions
cover initialization, group creation, invitation/ratchet changes, ciphertext
outbox/transcript writes and receive deduplication. A file lock prevents concurrent clients
from advancing the same device. Outbox retries reuse exact bytes and stable
Nats-Msg-Id values. This is not a distributed transaction with NATS; acknowledgments
and UI display can fail after local commit. No exactly-once display is claimed.

## Compatibility decisions

OpenMLS 0.9.0 requires Rust 1.91 and self-describing storage. Use RustCrypto 0.6,
basic credential 0.6, traits 0.6, SQLite provider 0.3 and rusqlite 0.37. Its storage
codec uses JSON internally; the wire uses binary postcard and MLS TLS encoding.
Production Welcome parsing uses `MlsMessageIn::extract()`; the convenient
`into_welcome()` from some upstream tests is feature-gated. Groups require the
ratchet-tree extension and use the pure-ciphertext wire policy.

async-nats 0.50 enables nkeys, kv, ring and server_2_10. Cargo.lock records the
tested versions; development/CI pins Rust 1.98.1. Source references inspected:

- https://book.openmls.tech/releases/0.9.0.html
- https://book.openmls.tech/user_manual/application_messages.html
- https://docs.rs/openmls/0.9.0/openmls/group/struct.StagedWelcome.html
- https://docs.rs/openmls_sqlite_storage/0.3.0/
- https://docs.rs/async-nats/0.50.0/async_nats/struct.ConnectOptions.html
- https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/nkey_auth

## Development authorization

Static user NKeys and loopback-only NATS are used without TLS. Clients may call
identity services, publish group message/handshake and inbox traffic, subscribe
to group application subjects and their own reply prefix, and inspect/pull/ack
only their own service-provisioned MAILBOX and CHAT consumers. They cannot create consumers,
read identity KV directly, subscribe to another inbox, or access system subjects.

Group wildcards cover the entire Alice/Bob lab namespace, a documented temporary
limitation. Before supporting mutually untrusted groups, provision exact group
subjects from an authenticated metadata policy (or use account/JWT authorization)
and revoke those permissions with membership changes. MLS still provides content
authentication/confidentiality independently of those permissions. The service's
JetStream provisioning authority should also be separated from runtime permissions.


## Durable history decisions

Milestone 8 deliberately keeps the existing shared lab authorization scope. A
single CHAT consumer per device can be authorized with exact NATS API/ACK subject
permissions; clients cannot create or reconfigure consumers. Per-group consumers
would require a group authorization/provisioning path and are deferred with exact
membership-aware permissions. Mailbox consumers remain separately filtered to
individual inboxes. Milestone 12 extends CHAT consumption to encrypted handshakes
and processes creator Commits together with application messages in stream order.

CHAT uses explicit acknowledgment and at most one unacknowledged delivery. The
client commits raw ciphertext/subject/stream sequence to `chat_deliveries` before
sending a confirmed ACK. Restart after a lost ACK repeats that exact storage check.
A sequence reused with different bytes/subject is rejected rather than overwriting
history. This detects conflicting stream resets, not every possible retention gap.

For a selected channel, pending ciphertext is processed in increasing stream
sequence. OpenMLS receive writes, deduplication, authenticated plaintext in
`transcript`, and the processed marker share a SQLite transaction. Messages for
other or not-yet-joined groups remain pending locally, even after the server ACK.
Authentication failures roll back and are quarantined; storage failures stay
pending and fail the operation. Transcripts also retain local outgoing plaintext,
atomically with encryption/outbox creation, because MLS cannot decrypt own sends.
Publish acknowledgments associate outgoing entries with their stream sequence.

A catch-up call drains the finite pending count observed on entry; later arrivals
remain for the next call. Interactive chat polls every 200 ms. This avoids a
separate live subscription and its replay/handoff race. The server supplies stream
ordering; it remains trusted for availability/sequencing, not plaintext. Per-device
file locking prevents two CLI processes from sharing a durable's ratchet state.

The local display flag is not a network read receipt. History reads do not mark
messages displayed; receive/chat do so after printing. There is no transaction
with a terminal: a crash can repeat output, while the transcript remains readable.
Old Milestone 7 plaintext was not retained and is represented by unavailable rows.
No new wire format, HTTP endpoint or cryptographic primitive was introduced.

## Restart and resume

Milestone 9 makes online sync/history share chat's startup recovery: flush the
device outbox in order, then fetch and process the current backlog. No keys, group
IDs or epochs are regenerated on reopening. A retry after the JetStream dedup
window may store the same ciphertext again; local transcript deduplication keeps
one entry at the earliest observed stream sequence. Welcome acknowledgments now
wait for server confirmation after the local join transaction commits.

Process tests force termination while stores remain open, including inside an
uncommitted receive transaction. Live NATS tests cover ambiguous publishes and
Welcome acknowledgment loss. See [recovery boundaries](recovery.md). This validates
process-crash recovery on the tested filesystem, not hardware power-loss tolerance.

## MVP acceptance

Milestone 10 adds a fresh CLI-driven end-to-end acceptance case and a shared local/CI
verification script. It changes no production wire format, permissions or storage
schema. The test checks key separation, registration/discovery, durable Welcome,
two-way offline traffic and infrastructure/client restart using the same identities
and group. An infrastructure observer checks every stored stream message; offline
scans inspect broker/service files for known test plaintext and client NKey seeds.
CHAT must contain MLS PrivateMessage application/Commit framing, and MAILBOX must
contain an MLS Welcome envelope. Public identity KV remains intentionally readable.
See [the acceptance matrix](mvp-acceptance.md) for evidence and the limits of these
checks. This finishes the scoped MVP, not a production security review.

## Persistent terminal client

Milestone 11 adds a Ratatui frontend while preserving the scripting CLI. A dedicated
worker owns SQLite/OpenMLS and sends immutable snapshots to the rendering loop;
network awaits never block terminal input. Existing durable consumers/outbox drive
history and reconnect. No wire or schema migration is needed. See [TUI decisions](tui.md).


## Multi-device alpha

Milestone 12 retains independent installation state and operator-authorized public
NKey enrollment. Device listing uses NATS request/reply and existing IDENTITIES KV.
The TUI groups MLS device leaves into logical users without merging cryptographic
identities. Creator-only additions serialize membership changes. Migration 1 adds
per-group join epochs; pre-join traffic is skipped and new members gain no historical
keys. CHAT consumer updates preserve acknowledgment progress. See
[multi-device design and upgrade](multi-device.md) for commands, validation, offline
epoch limitations and the required coordinated client/service upgrade.


## Device verification and registration transparency

Milestone 13 adds local SHA-256 identity fingerprints and explicit independent
comparison, backed by migration 2 (`device_trust`, `transparency_state`, `trust_alert`).
A service-NKey-signed Merkle log lives in one bounded TRANSPARENCY KV snapshot;
CAS publishes registrations and checkpoint atomically. IDENTITIES is its public
projection. Clients pin a signer and retain a prefix checkpoint, rejecting rewritten
history and changed observed identities. Full snapshots replace compact proofs for
this small alpha. Audited discovery protects invite/join; TUI polling surfaces trust
failures. See [the design and limits](device-verification.md) for canonical bytes,
upgrade semantics, first-contact/split-view limitations and the capacity bound.

## Device revocation and coordinator succession

Milestone 14 adds a signed revocation journal alongside registration transparency,
a single-broker NATS reload actuator and MLS removal reconciliation. An active
same-user device or operator authorizes an exact device/NKey revocation. Public
intent is durable before credential exclusion; network acknowledgment is separate
from eventual rekeying of offline groups. A restricted system identity preserves
NATS as the authentication/authorization mechanism, with no HTTP control channel.

Migration 3 adds revocation checkpoints, revoked MLS signing-key bindings, blocked
outbox IDs and persisted group coordinator signing keys. The elected coordinator
removes known revoked leaves atomically with the encrypted Commit outbox. A CHAT
cutoff protects historical Commit catch-up while rejecting later revoked-author
changes. New sends wait for rekeying. Native reload, retry boundaries, trust limits,
commands and validation are documented in [device revocation](device-revocation.md).

## Encrypted identity-administration recovery

Milestone 15 exports a device NKey, signed public registration and retained trust
metadata through client-side AES-256-GCM using the existing OpenMLS RustCrypto
provider. Each package has its own uniform 256-bit secret, stored separately. No
MLS private signer, KeyPackage private bundle, epoch, ratchet, delivery state or
transcript is backed up. This avoids restoring stale sending keys and consumed
KeyPackages. The network protocol, broker permissions and directory bindings remain
unchanged; there is no recovery service or remote storage dependency.

Migration 4 adds `recovery_metadata`. Restoration commits identity, trust and a
recovery-only marker together into an empty home. Restored credentials may audit
and revoke while authorized; the CLI and core prevent MLS use. Messaging resumes
through ordinary fresh-device enrollment and a new Welcome, preserving irreversible
revocation and immutable directory history. Secret buffers use zeroize 1.9 (already
in the lockfile), with its serde support for owned secret fields. See the
[format, commands, threat model and acceptance coverage](encrypted-recovery.md).


## Encrypted Object Store attachments

Milestone 16 enables async-nats's existing `object-store` feature. A fresh AES-256-GCM
key protects each bounded file; a binary versioned manifest carries its key, nonce,
content hash and sensitive metadata inside an MLS application message. Standard
Object Store chunks/metadata contain only ciphertext and random identifiers. Native
NATS stream max_age/max_bytes provide retention and capacity bounds.

Migration 5 adds an attachment index atomically with MLS transcript/ratchet writes.
Downloads require a local authenticated manifest, reject object links, read bounded
standard chunks using JetStream APIs, then verify AEAD/hash before creating an explicit
output path. This avoids async-nats 0.50 Object reader panics on consumer errors.
Client permissions add only ATTACHMENTS chunk/metadata publication and stream
info/raw-read APIs. The shared lab lacks per-object access policy; MLS/AEAD provide
content protection. See [attachment design and upgrade](attachments.md).
