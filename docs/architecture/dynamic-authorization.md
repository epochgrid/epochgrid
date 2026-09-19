# Milestone 22 — dynamic authorization

Status: complete for the Milestone 22 acceptance scope. Normal CLI/TUI chat uses
signed policies, exact grants, filtered durable consumers and Welcome relay.
Revocation/rekeying and restart are tested without NATS configuration edits or
reloads. [Milestone 23 TLS](../operator/tls.md) protects the shared transport path.
This is not completion of all [alpha release gates](../milestones.md).

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

All six steps are implemented. Dynamic clients have no all-group consumer, raw
CHAT stream-read, consumer-management or cross-device inbox-publication grants.

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

## Implemented delivery and failure behavior

Canonical UserId installations use the dynamic path; legacy handle installations
remain explicit development fixtures. Persist a versioned authorization intent in
the same SQLite outbox transaction as each locally created MLS epoch. Resolve MLS
public keys against the authenticated directory, synchronize policy before its
Commit/Welcome, and refresh the coordinator's NATS connection before publishing.
Only the control service relays signed, membership-checked Welcome envelopes.

The service owns durable consumer filters. Rebuild a device's CHAT consumer when
membership changes, replaying available matching ciphertext from the beginning;
local sequence deduplication preserves already staged history. This intentionally
prefers safe replay over a crash-prone delete/recreate cursor handoff. Empty
membership uses a reserved non-group filter, never an empty wildcard filter.
Reconcile consumers before opening admission on startup and after mutations;
failed reconciliation closes admission until a bounded retry succeeds. Existing
Core NATS claims remain bounded by their configured lease, including in-flight
requests and ciphertext already delivered to endpoints.

Client control requests that are idempotent (audit, same-group KeyPackage claim,
policy application and identical Welcome relay) retry at most once after a lost
response, renewing authorization first. Each reconnect has a five-second deadline;
the TUI retains its overall network deadline and durable retry loop. A flush is
not treated as proof of reconnection: the client waits for the NATS connection
counter to advance. The privileged control connection also expires, on a fixed
60-second lease independent of the shorter device lease used in stress tests.
