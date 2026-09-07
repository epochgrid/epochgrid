# EpochGrid architecture — Milestones 0–3

EpochGrid (https://epochgrid.org; secondary https://epochgrid.net) uses NATS for
transport, authentication, authorization, persistence and service request/reply.
OpenMLS implements MLS; no custom group cryptography is planned.

The initial workspace has core (protocol, SQLite identity storage and NATS),
client CLI and a single service. This slice initializes independent NATS user
NKeys and MLS Ed25519 identities, persists a real OpenMLS KeyPackage and its
private bundle, authenticates clients and registers public bindings in IDENTITIES
KV. CHANNELS, CHAT and MAILBOX are provisioned but group operations come later.
The service has no client secrets. SQLite is local only; HTTP is absent.

Registration uses a NKey-signed, domain-separated postcard payload, validates
OpenMLS KeyPackage signatures/lifetime/credential binding, and checks an explicit
operator-provisioned user/device/NKey allowlist. Core NATS does not expose the
requester's authenticated NKey to a subscriber. The signed binding plus enrollment
policy is therefore required; subject permissions alone are insufficient.
Initial registration is immutable and idempotent. Rotation/revocation are deferred.

OpenMLS 0.9.0 requires Rust 1.91 and self-describing storage serialization.
Use RustCrypto 0.6, basic credential 0.6, traits 0.6 and SQLite provider 0.3
(with rusqlite 0.37). The provider uses JSON internally for compatibility; the
wire uses binary postcard, and MLS public objects use TLS serialization.
async-nats 0.50 uses explicit nkeys, kv, ring and server_2_10 features.
Cargo.lock records the tested resolution. Upstream sources inspected:
- https://book.openmls.tech/releases/0.9.0.html
- https://docs.rs/openmls_sqlite_storage/0.3.0/
- https://docs.rs/async-nats/0.50.0/async_nats/struct.ConnectOptions.html
- https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/nkey_auth

Development uses static user NKeys, restrictive registration/reply subjects and
an enrollment file generated from local public registrations. Clients cannot
access JetStream APIs directly. Service provisioning permissions are broader but
restricted to JetStream APIs/KV and service replies; split provisioning later.
TLS is deferred for this loopback-only initial slice. Never expose this setup on
a shared network. Group-specific authorization is deferred with group messaging.
Future CHAT payloads must be opaque MLS protocol bytes; subjects expose metadata.
MLS owns membership; CHANNELS is only a metadata directory.

Milestones 4–6: verified lookup, persistent group creation and authenticated
Welcome join are implemented. The SQLite provider and local tables now share a
connection and transactions. Device directories are locked while in use. Initial
KeyPackages are reserved once; the scope remains one invitation/two devices per
group. Groups and their ciphertext outbox are local; no CHANNELS service is needed
yet. OpenMLS production Welcome extraction uses `MlsMessageIn::extract()`;
`into_welcome()` in upstream examples is test-feature-gated.

Development permissions now allow enrolled clients to publish group handshakes
and device-directed inbox messages. Inbox subscriptions remain isolated. Static
lab group permissions are temporary: provision exact group subjects from an
authorized metadata policy before supporting mutually untrusted groups. MLS
membership remains independent of those transport permissions.
