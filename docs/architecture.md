# EpochGrid architecture — through Milestone 7

EpochGrid (https://epochgrid.org; secondary https://epochgrid.net) uses NATS for
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
This slice supports one invitation and two devices per group. MLS owns membership;
CHANNELS KV is provisioned but unused. Future channel metadata is not authoritative
cryptographic membership.

Application messages use MLS PrivateMessages and NATS group subjects. Publishers
wait for JetStream acknowledgments; live subscribers authenticate/decrypt locally.
CHAT stores raw versioned MLS protocol bytes. MAILBOX stores a small EpochGrid
Welcome envelope. Neither contains application plaintext. History retrieval and
offline catch-up are deferred to Milestone 8.

OpenMLS's SQLite provider and application tables share one connection. Transactions
cover initialization, group creation, invitation/ratchet changes, ciphertext
outbox writes and receive deduplication. A file lock prevents concurrent clients
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
only their service-provisioned mailbox consumer. They cannot create consumers,
read identity KV directly, subscribe to another inbox, or access system subjects.

Group wildcards cover the entire Alice/Bob lab namespace, a documented temporary
limitation. Before supporting mutually untrusted groups, provision exact group
subjects from an authenticated metadata policy (or use account/JWT authorization)
and revoke those permissions with membership changes. MLS still provides content
authentication/confidentiality independently of those permissions. The service's
JetStream provisioning authority should also be separated from runtime permissions.
