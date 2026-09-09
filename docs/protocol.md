# EpochGrid protocol v1 — through Milestone 12

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
PrivateMessage/Commit with the correct group and authenticate the sender as creator
leaf 0 before merging. Applications and Commits advance local state in stream order;
own/replayed ciphertext is idempotent. Commit failures are quarantined and counted
with application failures; storage failures roll back and remain pending. A persisted
join-epoch floor skips earlier framed group traffic without decrypting/authenticating
it. See [multi-device semantics](multi-device.md). The MLS payload format is unchanged.

Updating the durable filter retains server delivery progress, but requires coordinated
client/service upgrade: Milestone 11 clients validate the old filter and cannot
process subsequent membership changes. Migration 1 is additive and preserves local
keys, ratchets and transcripts; older binaries must not reopen upgraded state.
