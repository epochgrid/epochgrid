# Milestone 22 — dynamic authorization

Status: policy registry, signed request/reply updates, exact group grants and
transactional revocation are implemented and tested. Client/consumer/Welcome
integration remains in progress; dynamic CLI/TUI messaging is not yet supported.
[Milestone 23 TLS](../operator/tls.md) is implemented independently; it does not
complete these remaining integration steps. See [current status](../milestones.md).

## Policy authority and migration

MLS owns group secrets and cryptographic membership. The control service maintains
an independent, non-secret authorization projection: group ID, coordinator device
NKey, MLS leaf indices, MLS epoch and monotonic policy generation. Clients may not
turn a directory lookup or an IdP binding directly into a group grant.

An active coordinator signs a domain-separated, versioned policy update with its
NATS device key. The service verifies possession, current admission, current policy
generation and every proposed device binding. Creation requires a singleton creator
leaf. Subsequent updates require the current coordinator and a strictly newer MLS
epoch. Leaf indices determine coordinator succession after device revocation.
Exact retries are idempotent only while the corresponding policy remains current;
stale updates cannot restore removed or revoked devices. Registry changes use
SQLite transactions and a migration, not database replacement.

Revocation atomically denies the device, removes its policy memberships, advances
affected policy generations and increments affected device authorization generations.
It does not itself generate an MLS Commit: remaining clients must still reconcile
the signed revocation log and remove revoked leaves. No registry operation changes
NATS configuration or controls the NATS process.

## Integration sequence

1. Registry policy validation, migration and transactional revocation.
2. Auth Callout grants for exact group subjects from current registry membership.
3. Signed request/reply policy synchronization with the existing client MLS/outbox
   transaction, including restart-safe invitation ordering.
4. Backend-managed per-device CHAT consumer filters and own MAILBOX consumer access.
   Devices must not receive consumer-create/update authority or broad stream reads.
5. Backend relay of authenticated, opaque Welcome messages. Device grants must not
   allow publication to another device's inbox, even for invitations.
6. Live Alice/Bob tests for messaging, revoked active connections, reconnect denial,
   group removal, unrelated group isolation and restart convergence.

Steps 3–6 remain required before dynamic messaging is supported. Do not enable the
legacy all-group consumer or cross-device inbox grants as an interim shortcut.

## Expiry and convergence

Existing grants remain usable until their signed claim expiry (default 30 seconds,
maximum 60). A generation is a registry concurrency/invalidation mechanism, not a
claim that NATS can retrospectively inspect an already issued JWT. Reconnect reads
current policy; honest clients should reconnect after a policy change. Tests must
allow the documented bounded expiry while proving fresh admission is denied.
Consumer filter reconciliation must fail closed before new device admission after
restart. Removing a member must preserve delivery of the removal Commit to the
remaining members without granting the removed device future group traffic.

The service sees metadata and opaque MLS protocol bytes, never group secrets or
application plaintext. A malicious authorization coordinator can misgrant transport
access, but transport access alone cannot create an MLS leaf or decrypt messages.
