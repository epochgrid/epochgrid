# Auth Callout contract — Milestone 21

The dynamic admission slice is implemented. This is not yet the complete alpha deployment
quickstart: group authorization, operational hardening and release gates remain. Do not deploy the static development bootstrap as production authentication.

NATS Auth Callout is the production admission model. Operators integrate the callout
in an isolated authentication account and delegate only the EpochGrid application
account. They retain ownership of server/operator/cluster configuration. Static keys
are needed for the callout/backend service identities only, never per client device.

The callout needs an account signing NKey matching the configured issuer, an XKey
private seed matching `auth_callout.xkey`, and a service connection credential listed
in `auth_users`. Protect the private seeds outside public config. The backend directory
signing identity remains separate from the callout issuer and client MLS identities.
Use `allowed_accounts` to constrain configuration-mode delegation in shared fabrics.
No EpochGrid client may subscribe to or publish on `$SYS.REQ.USER.AUTH`.

Encryption is required for callout requests/responses. Decrypt with the configured
XKey, validate the signed request and bind the response to its temporary user key and
server ID. Verify the device NKey nonce signature independently; it is the possession
credential, not the temporary connection key. Enrollment tokens can authorize only
an enrollment endpoint, and are never logged. Unregistered normal connections fail.

Fail closed on invalid signatures, expired requests, identity mismatch, registry
failure, disabled users, revoked devices or unavailable auth service. Bounded claim
expiry limits stale admission after lifecycle changes. No implicit static-user fallback
and no server reload are allowed. The application backend must not hold a system-account
reload credential in dynamic mode. MLS owns cryptographic membership independently.

Upstream references inspected for this implementation:
* [NATS Auth Callout documentation](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout)
* [NATS ADR-26](https://github.com/nats-io/nats-architecture-and-design/blob/main/adr/ADR-26.md)
* [Pinned NATS 2.14.5 implementation](https://github.com/nats-io/nats-server/blob/v2.14.5/server/auth_callout.go)

Rust compatibility: async-nats 0.50 exposes NKey+token CONNECT and request/reply but no
high-level Auth Callout service. `nats-jwt` 0.3 lacks Auth Callout types; `nats-jwt-rs`
0.1.1 provides signed JWT encoding/decoding. Its signature decoder does not enforce
claim freshness or semantic policy; EpochGrid must do those checks explicitly. Use
minimal request types tolerant of omitted optional server fields. Existing nkeys 0.4.5
provides compatible XKey encryption with the `xkeys` feature.


## Commands and configuration

The current tested configuration-mode integration uses NATS Server 2.14.5. Operator
JWT mode and clustered deployment remain to be validated by the BYO-NATS milestone.
Only the fixed auth-service NKey is a static NATS user; the fixed backend integration
NKey is admitted by the configured auth component, never by a device allow-list.
Both are service credentials, separate from arbitrary enrolled devices.

```bash
epochgrid-service --home ./epochgrid-state auth-init
```

This writes private EpochGrid keys, a version-1 `auth.json` and a reference NATS snippet.
It does not contact, write to or restart NATS. Integrate the snippet's dedicated auth
account, application account and callout block with existing operator-owned config,
including TLS. Set `auth.json.target_account` to the chosen account name. Key paths
are relative to that JSON file. `issuer_seed` is the account signing seed;
`encryption_seed` is the callout XKey; `connection_seed` connects the auth listener;
`control_nkey` admits only the backend's fixed possession credential. The backend
keeps its directory-signing NKey in `HOME/control`, independently of the issuer.

`authorization_ttl_seconds` defaults to 30 and accepts 2–60 seconds. NATS expires
connections on this deadline; reconnect requires a new signed, current-state grant.
The backend connection currently uses the same TTL. `development_plaintext` defaults
to false. Setting it true is an explicit, logged development-only exception; it is
never a supported alpha transport profile and also requires
`EPOCHGRID_PROFILE=development`. Production rejects this setting. The shared
[Milestone 23 TLS profile](tls.md) configures trust roots, minimum TLS version and
TLS-first for both service connections and clients. With `development_plaintext`
disabled, the service also requires callout evidence that the requesting client
used TLS. See the [current milestone status](../milestones.md) for deployment limits.

```bash
epochgrid-service --home ./epochgrid-state --server tls://nats.example.org:4222 \
  serve --auth-config ./epochgrid-state/auth.json
```

Issue and deliver a token through a secure channel; avoid shell arguments/logs:

```bash
umask 077
epochgrid-service --home ./epochgrid-state user-invite --handle alice > alice.enrollment
epochgrid --home ./alice-device --server tls://nats.example.org:4222 \
  identity enroll --device laptop < alice.enrollment
```

Remove the enrollment file after successful delivery/use according to your secret
handling policy. Invite lifetimes default to ten minutes and accept `--ttl` 1–3600
seconds. A token binds one canonical user to one device key; exact same-key retries
repair interrupted enrollment without allowing another key to reuse the token. Token
hashes, not bearer credentials, persist in `auth.sqlite`. No password database is used.
Enrollment tokens are redacted in debug formatting and zeroized where held by the
application. Normal reconnects send NKey possession proof, not the enrollment token.

The client prints its canonical UserId. Use canonical IDs for directory lookup and
revocation in this initial slice. Handles remain local-provider aliases; handle-based
UI resolution is not yet implemented. The service can issue another token for an
existing local handle without changing its UserId. Each new device generates separate
NATS and MLS keys. Existing legacy MLS credentials must not be renamed: use a fresh
canonical device installation and re-invitation when migrating an old fabric.

## State and current boundaries

A dedicated, migrated `auth.sqlite` stores users, bindings, token hashes, public device
registrations, readiness/revocation state and authorization generations. Its directory
is 0700, DB 0600, with WAL, foreign keys and a bounded busy timeout. It is currently a
single service-host registry; do not run replicas with independent copies. Broader
backend storage and cluster operation are not yet release-qualified.

Admission begins only after signed revocation history is reconciled. Revocation first
commits to the signed directory log and then denies registry admission. A crash between
these steps is repaired before devices can reconnect. Historical revoked bindings
remain available for log verification but never count as active admission records.
No dynamic code constructs BrokerControl, reads a static device user list, or writes
NATS configuration. Existing connections may remain usable until their claim expires;
this is bounded revocation latency, not immediate disconnection. Devices and backend
fail closed when fresh authorization cannot be obtained.

M21 device grants cover registration/audit/lookup/revocation, the restricted enrollment
endpoint, their own request/reply prefix and their own device inbox subscription.
They grant no cross-device inbox publication, general group subjects, CHAT consumers
or attachments. M22 adds membership-scoped access and MLS/NATS convergence. The previous
chat features remain executable in explicit `--dev-static` fixtures; that mode is
unsupported for alpha deployment. Do not claim the alpha release gates are satisfied.

Auth Callout replay tracking uses the signed server ID and per-connection temporary
user key, the binding NATS itself enforces, rather than assuming a JWT ID is the
connection identity. Denials reveal no enrollment tokens. The protected auth account
and server-enforced request-subject publication deny are required trust boundaries;
a self-signed server JWT alone does not establish membership of a trusted fabric.

Milestone 22 work in progress: admitted devices may send signed coordinator updates
on `epochgrid.v1.channel.policy`. Validated registry membership now grants exact
`.message`, `.handshake` and `.ephemeral` subjects for each authorized group.
There is still no blanket group wildcard, cross-device inbox publish permission or
client consumer-management permission. Normal CLI/TUI dynamic messaging remains
unavailable pending policy/outbox synchronization, filtered durable consumers and
Welcome relay. See [the implementation plan](../architecture/dynamic-authorization.md).
