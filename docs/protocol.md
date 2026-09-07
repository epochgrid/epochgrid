# EpochGrid protocol v1 — registration foundation

NATS request/reply subject: `epochgrid.v1.identity.register`. Registration uses
this subject exactly; lookup/group subjects from the architecture are reserved
and have no handlers in this slice. Per-device reply prefixes are
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
`.handshake`; MAILBOX uses `epochgrid.v1.user.*.*.inbox`. They are provisioned but
unused. Do not send plaintext into these streams. Public registration data is
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
follow the atomic SQLite join and duplicate marker. Failed validation rolls back
OpenMLS changes and does not acknowledge the mailbox message. A bad or unexpected
invitation can block the mailbox; administrative cleanup is currently required.

SQLite shares one connection between OpenMLS and application state. Local group
creation and invitation commits include metadata and the ciphertext outbox in the
same transaction. Publish retries reuse the exact stored bytes and Nats-Msg-Id;
there is no distributed transaction with NATS. A device file lock prevents
concurrent processes from advancing the same ratchet state.
