# Documentation map

Use the [roadmap](milestones.md) for milestone status and remaining delivery work.
The [README demo](../README.md#local-development) uses static development fixtures;
operator setup uses dynamic admission and separate backend roles. Main currently
contains milestones through 32; milestone 33 is under separate hosted CI review.

## Operator path

Read these in order for a production-shaped deployment. This remains unaudited
pre-release software; see [security](../SECURITY.md).

1. [Linux binary bundles](operator/linux-artifacts.md): candidate identity,
   supported Ubuntu baseline, verification and installation.
2. [Secret storage](secret-storage.md): host keyring sessions, protected homes,
   missing-key behavior and encrypted-state requirements.
3. [BYO NATS](operator/byo-nats.md) and [TLS](operator/tls.md): broker/account
   ownership, supported configuration/operator-JWT R1/R3 profiles and trust.
4. [Initialization and Auth Callout](operator/auth-callout.md),
   [backend roles](backend-role-contract.md) and [capacity](operator/capacity.md):
   create state explicitly, provision operator resources and bind separate accounts.
5. [Validation](operator/validation.md), [runtime diagnostics](operator/diagnostics.md)
   and [audit](operator/audit.md): inspect, troubleshoot, export and upgrade without
   recreating credentials or silently repairing operator infrastructure.

Runtime-container instructions belong to milestone 33's branch until it merges;
find its exact revision via the [roadmap](milestones.md#current-delivery).

## Client guides

| Topic | Contract |
| --- | --- |
| Terminal operation | [TUI](tui.md), [restart and offline history](recovery.md) |
| Identity | [Independent devices](multi-device.md), [verification](device-verification.md), [revocation](device-revocation.md) |
| Administration recovery | [Encrypted recovery](encrypted-recovery.md); excludes transcript and MLS ratchet backup |
| Messaging features | [Attachments](attachments.md), [receipts](receipts.md), [relationships](message-relations.md), [ephemeral activity](ephemeral-events.md) |
| Service endpoints | [Explicit MLS participants](service-participants.md) |

Each feature guide states its deployment/compatibility limits. Development-fixture
coverage is not proof of dynamic deployment support; typing and short-lease dynamic
messaging retain the limitations in [technical debt](technical-debt.md).

## Design and contribution

- [Architecture](architecture.md), [protocol](protocol.md) and [threat model](threat-model.md).
- [Authentication migration](architecture/auth-migration.md),
  [dynamic authorization](architecture/dynamic-authorization.md) and
  [resource comparison](deployment-resource-contract.md).
- [Contributing](../CONTRIBUTING.md), [development verification](development.md),
  [CI execution](ci-strategy.md) and [optional local hooks](../scripts/hooks/README.md).
- [MVP acceptance mapping](mvp-acceptance.md) for the original two-device baseline.
- [Historical plans and evidence](archive/README.md) for completed acceptance plans,
  earlier local results, CI investigations and old upgrade notes.

Keep current project status in `milestones.md`, open debt/restoration criteria in
`technical-debt.md`, behavior in its owning contract, and dated evidence in the
archive. `HANDOFF.md` should be a short work pointer, not a second roadmap.
