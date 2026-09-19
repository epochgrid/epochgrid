# Authentication migration: static MVP to dynamic alpha

## Inventory (Milestones 1–20)

* `transport::dev_config_with_enrollment` initializes Alice/Bob/backend identities,
  stores NKeys in `enrollment.json` and `additional-enrollment.json`, and renders
  `nats.conf`, `auth/users.conf`, and `public-enrollment.json` for an owned broker.
* `transport::render_users` grants static device users broad group/Welcome publication
  and per-device consumer access. CHAT consumers expose every group's ciphertext.
* `epochgrid-service` reads the enrollment file at startup. Registration, lookup,
  directory projection and consumer provisioning depend on that fixed allow-list.
* `BrokerControl::enforce` writes `revoked-nkeys.json` and `auth/users.conf`, requests
  `$SYS.REQ.SERVER.<id>.RELOAD`, and deletes revoked device consumers. Startup and a
  two-second retry loop both invoke it. This requires a system identity and an owned
  configuration directory, and assumes one broker.
* Development bootstrap/smoke/reset scripts manage Docker Compose and regenerate
  configuration. Existing revocation acceptance tests intentionally exercise reload.

These are development fixtures, not an alpha deployment contract. The supported
alpha path must neither construct BrokerControl nor accept a per-device NATS users
file. Preserve the old fixtures behind an explicit development mode while replacing
the service admission source with the canonical EpochGrid registry. Never silently
fall back from Auth Callout to the static mode.

## Canonical identity model (before Auth Callout implementation)

`UserId` is immutable and provider-neutral: `egusr-` plus lowercase base32 encoding
of 128 random bits (32 subject-safe characters total). It is not a username, email,
NKey or provider subject. `IdentityBinding(provider, subject, user_id)` associates a
verified provider identity with that user. Only `LocalIdentityProvider` is implemented.
A local handle is a provider-local lookup alias; it is not MLS identity or policy.

New MLS credentials and registrations use canonical `UserId/device_id`. Each device
has independent NATS and MLS keys. The auth registry owns users (enabled), bindings,
registered devices (active/revoked and authorization generation), enrollment token
hashes/expiry/consumption, and explicit authorization state. SQLite migrations must
preserve these records. Existing MLS credentials cannot be renamed in-place: legacy
local installations retain their historical credential/route identity; production
migration requires explicit fresh canonical device enrollment and re-invitation.
Do not reinterpret a legacy handle as a canonical user ID or silently change MLS leaves.

The IdentityProvider boundary yields an authenticated binding; registry resolution
then yields UserId. The authorization engine consumes UserId and device state, never
raw IdP claims. Local invite tokens are random, short-lived and single-use, stored
hashed. Possession allows only a restricted enrollment connection; it grants no chat,
mailbox or attachment access. Signed registration binds the token's UserId to the
new device. Lost-response retries must preserve the original binding rather than
allow reuse for another key. Reconnect thereafter authenticates the device NKey.

## Authentication and authorization lifecycle

Auth Callout requests and responses use NATS XKey encryption and signed JWTs. Verify
server signature, audience/subject, freshness, request type, server/header XKey
agreement and the client's NKey signature over the server nonce. The server-generated
connection user key is NOT the durable device NKey. Responses bind the former;
EpochGrid registry lookup and proof of possession bind the latter.

Issue short-lived user claims containing only calculated permissions. Each decision
reads current enabled/revoked/generation state. Deny unknown, disabled, incomplete or
revoked devices. Never issue wildcard `>` access to devices. Generation changes and
revocation deny future grants; existing grants expire on a bounded TTL, enforced by
NATS. MLS removal continues through authenticated control state and commits. Group
permission/consumer convergence belongs to Milestone 22; do not claim that merely
switching admission to callout fixes the previous shared CHAT consumer exposure.

No normal enrollment/revocation action may edit a NATS file, reload a server, regenerate
operator JWTs, or restart a broker. Integration config is operator-owned. Account
isolation and `allowed_accounts` preserve unrelated workloads; operator/JWT mode needs
its own tested profile before being claimed supported. [Milestone 23 TLS](../operator/tls.md)
is implemented. Protected local secrets, full BYO cluster validation and release
artifacts remain later gates; see the [current status](../milestones.md).
