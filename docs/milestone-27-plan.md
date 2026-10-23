# Milestone 27 — initialization and deployment validation

**Implementation started at user request on 2026-10-22.** The first slice adds
the shared resource contract, manifest schema, artifact renderer and comparison
fixtures. The second slice implements explicit initialization, atomic no-clobber
artifact export and generated-artifact BYO fixture provisioning. See
[comparison rules](deployment-resource-contract.md). The third slice implements
non-initializing offline validation and versioned reports. The final slice adds
bounded online inspection and the production startup admission gate. Local
verification is recorded in HANDOFF.md; cold CI remains required before merge.

## Baseline and outcome

Reviewed HANDOFF.md against local `main` at `5256862` (`milestone 26 (#16)`).
The handoff's uncommitted feature-branch description is stale: milestone 26 is
present in the merged checkout. Its recorded local validation remains historical
evidence; this review did not independently inspect GitHub CI or required checks.
The working tree was clean before this planning document was added.

Milestone 27 should give a Linux operator a repeatable path from a fresh backend
home to a validated deployment for the four milestone 26 configurations. Success
means explicit resource replication, actionable setup failures, and refusal to
open production device admission against an incompatible resource configuration.
It does not mean the alpha release is qualified.

Preserve Secret Service credentials, SQLCipher state, fresh-home-only policy,
SQLite-managed format probes, encrypted Auth Callout, and operator ownership of
NATS configuration. TD-001, TD-002 and post-MVP TD-003 remain open and unchanged.

## Proposed operator workflow

`auth-init` choices, `deployment-export` and `validate --offline` (human/JSON) are
implemented, along with online validation and production startup enforcement below.

1. Run the existing `auth-init` under the backend Linux account and unlocked
   Secret Service session. Extend it with explicit authentication mode, target
   account and `--replicas 1|3` inputs. Preserve the current no-argument defaults
   for existing callers; the production walkthrough supplies all deployment
   choices explicitly. Initialization remains offline.
2. Generate public integration artifacts: the configuration-mode snippet or
   operator-JWT delegation instructions, plus resource specifications for CHAT,
   MAILBOX and the three KV buckets. A separate `deployment-export` command can
   regenerate these from established state without regenerating keys or changing
   `auth.json`. Refuse accidental overwrite of edited artifacts.
3. The operator integrates TLS/accounts, provisions resources through their own
   administration tooling, and supplies the signed non-bearer service JWT for
   operator mode. Initial operator-mode output must clearly be incomplete until
   this JWT is supplied; it must never silently fall back to configuration mode.
   EpochGrid never takes operator/account root seeds or a system-account key.
4. Run `validate --auth-config FILE --offline`. This checks local configuration,
   credential bindings, existing encrypted state and transport inputs without
   contacting NATS or initializing missing state.
5. Start `serve --auth-config FILE`. Before device admission opens, the service
   validates existing application-account resources against the deployment
   contract. Missing or incompatible production resources stop startup.
6. Run `validate --auth-config FILE --online` with the backend running. This adds
   bounded TLS/authentication and application-account resource inspections using
   existing backend credentials. It does not start another Auth Callout listener.

Recommended scope: generate resource specifications for operator application,
rather than add an automatic broker-provisioning command. This keeps resource
ownership explicit and avoids needing a second bootstrap authentication path.
If automatic provisioning is desired, decide that before implementation: it adds
credential, partial-failure and concurrent-provisioning design work.

## Implementation work packages

### 1. One deployment resource contract

Add a shared module for expected resources, artifact generation and comparison
with observed JetStream configuration. Use the milestone 26 contract as the
baseline: exact subjects, file storage, limits retention, 65536-byte CHAT/MAILBOX
message size, KV history 1, TRANSPARENCY value size, and explicit R1/R3 replication
for all five resources. Inspect KV backing-stream settings as well as bucket info.

Reject incompatible subject mappings, transforms, eviction/TTL behavior,
retention, mirrors/sources or replication. Preserve compatible operator storage
budgets and unrelated settings; distinguish configuration compatibility from
capacity adequacy, which this milestone cannot establish. Define field-by-field
comparison rules and fixtures before connecting the validator to startup.

Persist expected replication in a versioned public deployment manifest alongside
`auth.json`, so startup can detect accidental R1 in a declared R3 deployment.
Existing milestone 26 homes receive this manifest through explicit export/setup
without key or database migration. Missing manifests produce an actionable
production setup error. Keep the existing auth configuration schema unless an
implementation review demonstrates a necessary change.

### 2. Safe initialization and artifact export

Extend `crates/epochgrid-service/src/dynamic.rs` and CLI parsing. Validate inputs
before provisioning secrets; use the existing initialization locking and resumable
credential metadata. Completed initialization still refuses reinitialization.
Crash/retry paths must preserve existing key identities and encrypted databases.
Publish artifacts atomically with clear completion state, restrictive permissions
and no secret values. Export uses existing references and cannot provision keys.

Generated artifacts must be usable by the qualification fixture, not merely
illustrative text. Document the exact operator application steps for both modes,
including the external JWT-signing step and TLS settings the operator supplies.

### 3. Non-initializing local validation

Separate inspection from the current `AuthRegistry::open`, `IdentityStore::open`
and database provisioning paths, which can create or modify state. Reuse semantic
config/JWT checks and credential binding validation. Add an existing-state
SQLCipher inspection path through the database module; do not read database files
through ordinary file descriptors or use SQLite immutable mode against live WAL.

Check supported schemas, required metadata, database role/key bindings, control
identity binding, keyring availability and file permissions. Missing, locked,
duplicate or swapped credentials, legacy plaintext, partial initialization and
corrupt/mismatched state must produce specific failures without repair, migration,
new credentials, reset or changed application data. Account for SQLite-managed
WAL/SHM bookkeeping when documenting and testing read-only inspection.

### 4. Online validation and startup enforcement

Reuse the shared TLS profile and service credential connectors. Verify successful
authenticated operations, not just the initial connection/INFO result. Bound
each operation and the overall command; permission denial, timeout, unavailable
backend and incompatible configuration must remain distinguishable.

Inspect the connected server version/max payload, JetStream availability,
application resources and reported replica health. Check explicitly supplied
endpoints individually; report discovery/inspection coverage. The qualified
version remains NATS 2.14.5. A single endpoint cannot certify every broker, mutual
route TLS, account import/export isolation, operator signer scope or resolver
lifecycle. Mark these as operator checks, never inferred passes. Live admission
probes involving new users/tokens are left to the qualification tests.

In production `serve`, establish the existing auth/control bootstrap path with
device admission closed, then inspect resources before reconciliation and normal
readiness. Split resource lookup from creation in transport/transparency helpers;
no create-on-error or silent R1 fallback in this path. Preserve the legacy explicit
development fixture behavior and existing reconciliation ordering. Validation
failure tears down the temporary startup tasks and leaves device admission closed.
This is a startup gate, not a continuous configuration-monitoring service.

### 5. Reports, documentation and regression coverage

Provide concise human output and `--format json` with a versioned report schema,
stable check identifiers, expected/observed values, remediation and coverage.
Distinguish passed, failed and not-checked results. Return zero only when requested
checks pass; malformed invocation or failed checks return nonzero. An offline
success explicitly reports that network deployment readiness was not evaluated.
Keep machine output on stdout and sanitized diagnostics on stderr. Never print
seeds, enrollment tokens, database keys, private records or raw credential/JWT
payloads. This report is not milestone 31's structured audit-event system.

Update the BYO-NATS contract, Auth Callout walkthrough, secret-storage documentation,
README, milestone index and handoff when implementation is complete. Document the
new production pre-provisioning requirement and the path for existing encrypted
milestone 26 installations.

## Validation and acceptance criteria

- Unit tests cover resource comparison, deployment manifest/report parsing,
  artifact rendering and invalid inputs. Compare generated resources against
  independently stated contract expectations to avoid testing a shared mistake.
- Isolated Secret Service/SQLCipher tests cover fresh setup, completed reruns,
  interrupted setup, concurrent initialization, missing/locked/duplicate/swapped
  keys, wrong bindings, plaintext rejection and validation without state creation.
  Scan generated artifacts and reports for secret material.
- Extend the four production-TLS BYO cases to provision from generated artifacts,
  run both validation modes, start the service and retain existing enrollment,
  messaging, restart, revocation, failover and account-isolation assertions.
- Inject missing resources, wrong replicas, incompatible subjects/retention/KV
  settings, denied inspection permissions, bad TLS/JWT and unavailable services.
  Assert bounded explicit failures, closed admission on startup failure and
  unchanged operator configuration/resource settings. A running service is not
  stopped merely because a separate validation command fails.
- Repeat initialization/export/validation and restart with established encrypted
  state; preserve public identities, history and operator resource settings.
- Run repository formatting, workspace unit tests, warnings-denied Clippy,
  binaries/examples build, harness regressions, protected-state checks and the
  retained integration/smoke gates required by CONTRIBUTING.md. Preserve existing
  quarantines; add no blanket retries or assertion-suppressing workarounds.
- Keep build and new integration execution in separate bounded phases. Obtain
  cold CI evidence for all four BYO cases before merge; report actual results and
  existing reliability failures without treating local passes as CI qualification.

## Boundaries and review decisions

Excluded: backend privilege separation/HA, root-key or broker configuration
management, plaintext migration, new topologies/server versions, dynamic
attachments, TD-001/TD-002 repairs, broad TD-003 work, capacity planning, general
operational diagnostics, audit pipelines, packaging and release publication.

The principal choices for review are: **operator-applied generated resources**,
**explicit R1/R3 manifest with a production startup gate**, and **online validation
against an already-running backend**. These choices make the bootstrap sequence
concrete while keeping milestone 27 bounded. Implement in the work-package order
above. The user authorized beginning implementation; publication remains separate.
