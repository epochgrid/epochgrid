# EpochGrid protocol v1 — through Milestone 14

NATS request/reply subject: `epochgrid.v1.identity.register`. Registration uses
this subject exactly; lookup and KeyPackage requests use the fixed subjects
described below. Per-device reply prefixes are
`_INBOX.<NATS-public-key>.>` so one client cannot subscribe to another's replies.

Payloads are postcard 1.x encodings of `Envelope { version: u16, body: Body }`.
Field order is declaration order in `crates/epochgrid-core/src/wire.rs`. Integers
use postcard varints; strings/sequences have length prefixes. Body discriminants
are Register=0, Registered=1, Rejected=2. Maximum total message size is 65,536 bytes.
Unknown versions/types, trailing bytes and malformed payloads are rejected.
The byte sequence `01 01` is the successful v1 response. There is no JSON on the
registration wire. Enum order is protocol ABI and must not be reordered.

Register carries `DeviceRegistration { payload, signature }`. Payload fields, in
order: protocol_version (u16), user_id (UTF-8 String), device_id (String),
nats_public_key (String), mls_credential (byte vector), mls_key_package (byte vector),
generation (u64), created_at (i64 Unix seconds). Signature is an NKey Ed25519 byte
vector. User/device IDs are 1–32 lowercase ASCII letters, digits or hyphens.
Generation must currently be 1. Timestamps must be positive but are informational,
not freshness/authentication evidence.

Signing bytes are the exact ASCII domain separator
`EpochGrid device registration v1` followed by a NUL byte, then postcard encoding
of the payload in the above field order. The service reconstructs those bytes
before verification. Signatures cover every payload field. NATS NKeys are distinct
from independently generated MLS signing keys. Only user NKeys are accepted.

MLS credential and KeyPackage use OpenMLS TLS serialization (RFC 9420). The
credential is BasicCredential with UTF-8 `user/device`; the KeyPackage uses
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519. The service validates the package using
OpenMLS, including lifetime and signatures, then checks ciphersuite, matching
credential and identity. Operator enrollment maps
`users.<user>.devices.<device>` to the authorized NATS public key.

IDENTITIES KV stores the complete public Register envelope under that logical key.
KV create supplies atomic first-write semantics; exact-byte retries succeed,
conflicts fail. No secondary index is needed in this slice. Enrollment changes
require service restart and do not update existing immutable registrations.
The service ignores reply subjects outside `_INBOX.*` to prevent requests from
redirecting service replies into KV or group subjects. Errors return only Rejected; no secrets or detailed validation internals are sent.

Future MLS transport types will carry opaque MLS payloads with explicit version,
group ID and type as needed. CHAT subjects are `epochgrid.v1.group.*.message` and
`.handshake`; MAILBOX uses `epochgrid.v1.user.*.*.inbox`. CHAT carries encrypted Commit/application traffic; MAILBOX carries Welcomes.
Do not send plaintext into these streams. Public registration data is
intentionally readable by the identity service; it is not application ciphertext.

Milestone 4 adds fixed request/reply subject `epochgrid.v1.identity.lookup` with
Lookup=3 { user: String, device: String }, Found=4 { DeviceRegistration },
NotFound=5. Clients revalidate signatures, package lifetime and the requested
endpoint. A fixed subject replaces identity.lookup.<user> to keep routing and
permissions small; the endpoint lives in the binary request. Lookup is read-only.

Milestone 6 adds `epochgrid.v1.identity.keypackage`: ClaimKeyPackage=6 carries
user, device and group (Strings); Found returns the signed registration. A KV
`claims.<user>.<device>` record atomically reserves the initial package for that
group. Exact retries succeed; another group is rejected. This is one-use package
distribution, without rotation/replenishment yet. Authenticated enrolled clients
can exhaust another device's initial package; availability is not protected.

Welcome=7 { payload: Vec<u8> } wraps TLS-serialized MLS Welcome on MAILBOX.
Bob explicitly selects an inviter and verifies the staged Welcome signing key
and credential against the directory before committing the join. The MLS group
ID is UTF-8 `epochgrid/v1/<channel-name>/<32-lowercase-hex-random-id>`; both name
and routing ID are authenticated by MLS. NATS uses only the random ID as gid.
The ratchet tree travels inside the MLS Welcome's authenticated GroupInfo.
CHAT handshake payloads are raw TLS-serialized MLS PrivateMessages, already
versioned and typed by MLS, without a redundant EpochGrid wrapper.

Each enrolled device has a service-provisioned durable pull consumer on MAILBOX,
`device_<NKey>`, filtered to exactly its inbox. Devices may inspect/pull/ack only
their own consumer; they cannot create arbitrary consumers. Welcome acknowledgments
follow the atomic SQLite join and duplicate marker, and wait for server confirmation. Failed validation rolls back
OpenMLS changes and does not acknowledge the mailbox message. A bad or unexpected
invitation can block the mailbox; administrative cleanup is currently required.

SQLite shares one connection between OpenMLS and application state. Local group
creation and invitation commits include metadata and the ciphertext outbox in the
same transaction. Publish retries reuse the exact stored bytes and Nats-Msg-Id;
there is no distributed transaction with NATS. A device file lock prevents
concurrent processes from advancing the same ratchet state.


Milestone 7 application traffic on `epochgrid.v1.group.<gid>.message` is raw
TLS-serialized MLS PrivateMessage, using MLS's version/type fields rather than a
redundant EpochGrid envelope. Maximum plaintext is 16,384 bytes. Receivers require
PrivateMessage/Application and matching MLS group ID before processing. Sender
labels come from authenticated MLS credentials, never NATS headers. Successful
processing and an exact-ciphertext deduplication marker commit together. Own
ciphertexts are recognized from the outbox and are not decrypted again. Plaintext
is displayed and retained locally; no application plaintext is passed to NATS. Received terminal control characters are escaped for display.

Milestone 8 replaces live CLI subscriptions with a service-provisioned CHAT pull
consumer per device, named `device_<NKey>` (consumer names are scoped to streams).
Current filter (extended in Milestone 12): `epochgrid.v1.group.*.*`; DeliverPolicy All, AckPolicy Explicit,
MaxAckPending 1, MaxBatch 1, AckWait 2 seconds. The client can call INFO and
MSG.NEXT for its own consumer and publish its ACK subjects. The backend remains
uninvolved in decryption and transcript storage. No protocol discriminants change.

Each delivery is staged in SQLite with its CHAT stream sequence before a confirmed
ACK. Same-sequence/same-bytes redelivery is idempotent; conflicting sequence reuse
fails. Per-group processing validates the subject's group against authenticated
MLS framing and advances ratchets in stream order. Exact ciphertext copies at
new stream sequences keep one transcript entry at the earliest observed sequence. Invalid
or undecryptable messages are quarantined without advancing the ratchet; storage
errors leave work pending. Unknown/other group ciphertext stays staged.

`message history` pages the local transcript, fetching backlog unless --offline is
set. `--before` is an exclusive stream-sequence bound; default limit is 50, maximum
1000. Outgoing messages awaiting publish confirmation have no sequence and appear
after confirmed messages. Plaintext processed before Milestone 8 is unavailable;
no cryptographic recovery is attempted. Acknowledgment means durable local staging,
not user display. Milestone 12 adds ordered processing of membership Commits.

Milestone 9 changes no wire discriminants. Resuming online sync/history flushes the
persisted outbox before catch-up. Publish retries keep their original bytes and
Nats-Msg-Id even after a process exit. JetStream deduplication is time-bounded;
an overdue retry can produce a second stored copy. Local ciphertext deduplication
still prevents a second decryption/transcript entry. The transcript keeps the
minimum observed sequence, including when an ambiguous outgoing publish is retried.

Milestone 11 introduces no wire changes. The TUI uses the same request/reply,
Welcome and durable CHAT paths as the CLI. Local unread indicators are derived
from transcript display flags and are not transmitted as receipts or presence.


Milestone 12 appends two v1 postcard Body variants without changing existing
indices or registration signing bytes: `ListDevices=8 { user: String }` and
`Devices=9(Vec<DeviceRegistration>)`. Request/reply uses the fixed subject
`epochgrid.v1.identity.devices`. Responses contain only enrolled, registered devices,
ordered by device key, bounded to 32 entries and MAX_WIRE. Oversized responses are
Rejected. Clients verify each registration and reject mismatched users or duplicate
device IDs/NKeys. Empty lists are valid. Old services reject the new request; existing
operation encodings remain unchanged. Public listing grants no enrollment authority.

CHAT consumers now include encrypted Commit traffic. Receivers require MLS
PrivateMessage/Commit with the correct group and authenticate the sender as the pinned coordinator
(initially creator leaf 0) before merging; Milestone 14 succession is described below. Applications and Commits advance local state in stream order;
own/replayed ciphertext is idempotent. Commit failures are quarantined and counted
with application failures; storage failures roll back and remain pending. A persisted
join-epoch floor skips earlier framed group traffic without decrypting/authenticating
it. See [multi-device semantics](multi-device.md). The MLS payload format is unchanged.

Updating the durable filter retains server delivery progress, but requires coordinated
client/service upgrade: Milestone 11 clients validate the old filter and cannot
process subsequent membership changes. Migration 1 is additive and preserves local
keys, ratchets and transcripts; older binaries must not reopen upgraded state.

Milestone 13 appends `Audit=10` and `AuditLog=11(Snapshot)` to Body without changing
prior discriminants or registration signing bytes. Audit uses the fixed request/reply
subject `epochgrid.v1.identity.audit`. `Snapshot` field order is `checkpoint`, then
`entries: Vec<DeviceRegistration>` in registration sequence order (index + 1).
Checkpoint field order is `version: u16`, `size: u64`, `root: [u8;32]`, `signer: String`,
`signature: Vec<u8>`. The checkpoint signature covers ASCII
`EpochGrid transparency checkpoint v1` plus NUL, followed by postcard serialization
of `(version, size, root, signer)` in that order. Version is 1. The signer is the
service's public user NKey. SHA-256 Merkle leaves hash 0x00 plus the canonical v1
Register envelope; internal nodes hash 0x01 plus two 32-byte child hashes. The empty
root is SHA-256 of empty bytes. Split at the largest power of two below the leaf count.

Snapshots contain at most 256 entries and must fit the unchanged MAX_WIRE envelope
limit of 65,536 bytes. All entries and the signed checkpoint publish atomically by
CAS to key `snapshot` in the public TRANSPARENCY KV bucket. Exact retries do not
append duplicates; endpoint replacements are rejected. The service validates full
OpenMLS packages at admission. Historic log validation verifies immutable NKey-signed
records without requiring expired packages to remain usable. Actual peer discovery
still checks OpenMLS validity before use. Capacity errors reject admission without
pruning history. No compact proof or pagination format is introduced.

Clients independently pin a signer or trust it on first use. Subsequent snapshots
must have the same signer and reproduce the old root over their first retained-size
entries. Verification is over the full snapshot, not an unauthenticated root supplied
by the server. Public directory lookup/list operations remain binary-compatible, but
upgraded CLI discovery uses AuditLog records and compares KeyPackage claims with the
logged record. Missing/old audit APIs fail closed; this is a coordinated pre-1.0
upgrade. Stored MLS application/Commit/Welcome bytes remain unchanged.

Migration 2 adds `device_trust`, `transparency_state` and `trust_alert`; it does not
rewrite MLS state. Local trust states are unverified, verified and changed. Fingerprint
v1 and first-contact, split-view, migration and offline-inspection semantics are
specified in [device verification](device-verification.md). No verification state or
manually supplied comparison value is sent to NATS; user/device public identities remain
visible to the fabric.

## Milestone 14: revocation

Existing v1 discriminants and MLS payloads remain unchanged. Added Body variants:

| Tag | Variant | Request/reply subject |
| --- | --- | --- |
| 12 | RegistrationAudit | `epochgrid.v1.identity.audit` |
| 13 | RevocationAudit | `epochgrid.v1.identity.revocations` |
| 14 | RevocationLog | Response to RevocationAudit |
| 15 | Revoke(RevokeRequest) | `epochgrid.v1.identity.revoke` |
| 16 | Revoked | Network-enforcement acknowledgment |

RegistrationAudit returns the existing AuditLog=11. Legacy Audit=10 returns Rejected
once any revocation exists. Current clients require both journals before accepting
an online audit. Raw lookup/list/KeyPackage APIs exclude revoked endpoints; immutable
registration snapshots retain their evidence. This is a coordinated pre-1.0 upgrade.

RevokeRequest field order is `version: u16`, `user: String`, `device: String`,
`nkey: String`, `author: String`, `signature: Vec<u8>`. Version is 1. The signature
covers ASCII `EpochGrid device revocation v1` plus NUL, followed by postcard tuple
`(version, user, device, nkey, author)`. Author must be an active registered NKey for
the target's user or the pinned directory signer. The exact target binding must
exist in the registration log. Requests are irreversible and idempotent per NKey.

RevocationLog fields are `checkpoint: Checkpoint`, `entries: Vec<Revocation>`.
Revocation fields are `request: RevokeRequest`, `chat_cutoff: u64`. The service captures
CHAT's last sequence before appending. Checkpoint fields match registration checkpoints,
but signing uses domain `EpochGrid revocation checkpoint v1` plus NUL. Leaf hashes
are SHA-256 of 0x00 plus postcard Revocation bytes; internal/empty roots and splitting
match the registration Merkle tree. The log is signed and CAS-published as one v1
RevocationLog envelope at TRANSPARENCY key `revocations`, with the same 256-entry and
65,536-byte limits. Clients validate author authority in journal order and retain a
prefix checkpoint. The registration and revocation roots are not interchangeable.

The stored coordinator signing key authorizes normal MLS Commits. Commit update paths
must retain the sender's signing key and credential; only Add/Remove proposals are
supported. Identity rotation needs a future authenticated migration protocol. A revoked sender's
Commit is accepted only at or before its signed CHAT cutoff. The lowest-index active
successor may issue a removal Commit for exactly the known revoked leaves, without
other proposals. Coordinator signing-key persistence prevents vacant leaf-slot reuse from
transferring authority. Raw encrypted MLS Commit and application framing is unchanged.
Migration 3 and the network acknowledgment/retry semantics are specified in
[device revocation](device-revocation.md). No private keys or message plaintext occur
in the revocation API, KV values, authorization include or NATS subjects.

## Milestone 15: encrypted recovery file v1

No NATS subjects, Body discriminants or MLS message formats change. Recovery is a
local, independently versioned binary file, not a new transport message.

| Offset | Length | Value |
| --- | --- | --- |
| 0 | 8 | ASCII `EGRECOV` followed by NUL |
| 8 | 1 | Format version 1 |
| 9 | 1 | Algorithm 1: AES-256-GCM |
| 10 | 12 | Random nonce |
| 22 | remaining | Ciphertext followed by the 16-byte GCM tag |

The first ten bytes are AEAD associated data. Unknown magic/version/algorithm,
truncation, authentication failure and inputs above 1,048,576 bytes are rejected.
A fresh uniform 32-byte secret is used directly as the AES key for each export.
Its separate text encoding is `EG1-` plus 64 hex digits and an optional newline;
parsing accepts upper/lowercase hex and surrounding whitespace, with a 128-byte CLI
input limit. There is no user-password mode or password-derived encryption key.

The encrypted plaintext is one postcard `RecoveryArchive`, in field order:
`version: u16` (1), `exported_at: i64` (UTC Unix seconds),
`registration: DeviceRegistration`, `seed: String`, `evidence: Evidence`,
`groups: Vec<GroupHint>`. Trailing plaintext bytes are rejected. `Evidence` fields:
`devices: Vec<DeviceTrust>`, `directory_key: Option<String>`,
`checkpoint: Option<Checkpoint>`, `revocation_checkpoint: Option<Checkpoint>`,
`revoked: Vec<RevokedDevice>`, `alert: Option<String>`.
`DeviceTrust`: user, device, fingerprint, latest_fingerprint, state (all String).
`RevokedDevice`: nkey/user/device (String), mls_key (public Vec<u8>), cutoff (u64).
`GroupHint`: name/gid (String). Limits are 1024 trust records, 1024 group hints and
256 cached revoked devices, additionally constrained by total package size.

Registration NKey binding is verified during restore, without requiring a historical
public KeyPackage to remain unexpired. The package contains no MLS private state;
its group hints convey neither membership nor decryption ability. Retained signed
checkpoints remain subject to normal online prefix audit. SQLite recovery markers
are local state and are not sent to NATS. See [recovery semantics](encrypted-recovery.md).


## Milestone 16: attachment application payload v1

At Milestone 16, raw UTF-8 application messages remained unchanged. Milestone 19
wraps both text and attachment manifests in the application envelope below.
Attachment manifests use prefix
hex `ff 45 47 41 54 54` (0xff plus ASCII EGATT), then one version byte (1), then
postcard Manifest fields in order: `id: String` (32 lowercase hex digits),
`filename: String` (1–255 UTF-8 bytes, no separators/control characters), `mime: String`
(1–127 ASCII bytes), `size: u64`, `ciphertext_size: u64`, `expires_at: u64`
(UTC Unix seconds), `hash: [u8;32]` (SHA-256 plaintext), `key: [u8;32]`,
`nonce: [u8;12]`. The whole payload is inside MLS PrivateMessage application data
and is limited to 16,384 bytes. Unsupported reserved-prefix versions, invalid
fields and trailing bytes fail closed. Renderers show only a safe summary.

The object is AES-256-GCM ciphertext followed by its 16-byte tag, with no plaintext
header. Associated data is ASCII `EpochGrid attachment v1` plus NUL, followed by
postcard tuple `(group_routing_id: str, object_id: str)`. Each object has independent
CSPRNG-generated ID, key and nonce. The protected manifest's size, content hash and
expiry are authoritative, not public ObjectInfo claims. NATS Object Store metadata
has only a random object name, bucket/chunk IDs, ciphertext size/digest and timestamps;
no filename, MIME, plaintext digest or DEK is included. Standard chunks are at most
32 KiB. The bucket is ATTACHMENTS, its stream OBJ_ATTACHMENTS, and subjects are
`$O.ATTACHMENTS.C.<nuid>` / `$O.ATTACHMENTS.M.<encoded-object-id>`.

No new identity-service Body variant, MLS handshake type or group subject is added.
Migration 5 creates a local `(gid, object_id)` manifest index, committing with the
original transcript and ratchet transaction. Duplicate identical manifests are
idempotent; conflicting reuse of an object ID in one group is rejected. Legacy
text is not backfilled into this new index. Upgrade all clients before sending
attachment manifests; older text-only renderers are unsupported for binary payloads.
See [attachment security and retention](attachments.md).


## Milestone 17: ephemeral application envelope v1

Only Core NATS subject `epochgrid.v1.group.<gid>.ephemeral` carries this format.
The entire payload is canonical postcard fields, in order: `version: u16` (1),
`epoch: u64`, `leaf: u32`, `id: [u8;16]`, `nonce: [u8;12]`, `ciphertext: Vec<u8>`.
The event ID and nonce are independently generated. Maximum envelope size is 1024
bytes. Unsupported versions, trailing data, obsolete epochs and authentication
failures are rejected without advancing MLS state.

Context/AAD is postcard tuple `("epochgrid ephemeral v1", gid, version, epoch,
leaf, id, nonce)`. The AES-256-GCM key is 32 bytes from the current MLS exporter,
label `epochgrid ephemeral v1`, context as above. Ciphertext includes the GCM tag.
Decrypted fields are `issued: u64` (Unix milliseconds), `event` (postcard enum
TypingStarted=0, TypingStopped=1), `signature: Vec<u8>`. The signature covers
postcard tuple `("epochgrid ephemeral signature v1", context_bytes, issued, event)`
and uses the sender leaf's MLS Ed25519 signing key. Receivers verify against the
current leaf, never a sender-supplied public key. Event type, timestamp and signature
are encrypted; epoch and leaf index are visible metadata.

This is an MLS-exporter-protected application envelope, not PrivateMessage framing.
It deliberately avoids advancing the durable application ratchet. It has epoch
secrecy but no per-event forward secrecy. See [design, freshness and replay limits](ephemeral-events.md).
No existing wire Body variant or SQLite schema changes.


## Milestone 18: encrypted receipt events

The ephemeral v1 enum appends `ReceiptRequest { message: [u8;32] }` at index 2
and `Receipt { message: [u8;32], state: ReceiptState }` at index 3. ReceiptState is
postcard enum Delivered=0, Read=1. Typing indices 0/1 and all existing signatures,
AAD, exporter labels, freshness and epoch rules remain unchanged. Older decoders
reject these unsupported variants; they continue handling typing and durable chat.

`message` is SHA-256 of the exact immutable MLS message ciphertext, interpreted
only within the envelope's authenticated group context. The reference and receipt
state are encrypted. The event's authenticated leaf supplies the responding device
identity. Requests are answered only by matching an authenticated incoming transcript
whose original sender is the requesting device. Unknown responses never create
transcript or receipt records. Duplicate responses merge monotonically: Read wins
regardless of arrival order. A response causes no response, preventing receipt loops.

SQLite migration 6 backfills `receipt_messages` from retained ciphertext and adds
`device_receipts` keyed by transcript row/device. No receipt event is put in a durable
NATS stream; missing claims are recovered by bounded online queries. See
[receipt semantics and limits](receipts.md). This delivery reference does not replace
the future application message identity or alter immutable history.


## Milestone 19: immutable application envelope v1

New durable application plaintext, before MLS encryption, has prefix hex
`ff 45 47 4d 53 47` (0xff plus ASCII EGMSG), version byte 1, then canonical postcard
fields in order: `nonce: [u8;16]`, `counter: u64`, `content: Vec<u8>`,
`relation: Option<Relation>`. Relation enum indices are ReplyTo=0 with a `[u8;32]`
target, Replace=1 with a `[u8;32]` target, and Reaction=2 with fields
`target: [u8;32], value: String, add: bool`. None means an original message.

Counters range from 1 through i64::MAX and increase per authenticated device/group
using the highest locally committed counter. Content is 1–16,384 bytes for originals,
replies and edits; edits must be UTF-8 text. Reactions have empty content and an exact
UTF-8 value of 1–32 bytes without whitespace/control characters. Maximum encoded
application size is 16,896 bytes. Invalid versions, malformed/oversized/noncanonical
envelopes and trailing bytes are rejected. Existing non-EGMSG text/attachment payloads
are still accepted with their original 16,384-byte bound. Reserved EGMSG prefixes
are never silently interpreted as legacy text on decode failure.

The application ID is SHA-256 of canonical postcard tuple
`("epochgrid application id v1", group_routing_id, authenticated_sender, envelope_bytes)`.
Legacy IDs hash postcard tuple `("epochgrid legacy id v1", group_routing_id, mls_ciphertext)`.
IDs render as 64 lowercase hexadecimal characters. The random nonce makes repeated
identical content distinct, while identical envelopes from the same sender/group
retain their ID across new MLS ciphertext. IDs, counters and targets remain inside
E2EE payloads or local storage; NATS subjects are unchanged. Receipt references
continue hashing exact ciphertext and do not become application IDs.

Each original/reply can be edited only by its original device and only if its
original content is text. The highest (counter, event ID) valid edit wins. Reaction
state uses the same ordering separately for each (device, value); false removes only
that device's reaction. Reply expansion is nonrecursive. Unknown targets defer
interpretation; invalid targets/unauthorized edits have no projection effect. All
original records remain intact. See [full replay and presentation semantics](message-relations.md).

Migration 7 stores canonical event fields in an immutable `message_events` log,
indexed by group/ID and target/kind; legacy synthetic entries have counter zero.
This log commits with the MLS ratchet, transcript and receipt reference. Full event
retention is needed for local replay after ratchet key erasure. Recovery excludes it.
This is a coordinated pre-1.0 client upgrade: older clients cannot interpret the new
application framing, though MLS framing and existing stored ciphertext are unchanged.
