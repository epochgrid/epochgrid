# Milestone 28 — backend privilege separation

**Implemented at user request; hosted CI remains pending.** See the
[role contract](backend-role-contract.md) for the implementation refinement:
the worker forwards control requests; the authority retains reconciliation and
all resource mutations. This removes worker completion claims from the trust
boundary. The work packages below record the planned acceptance scope; see
[HANDOFF](../HANDOFF.md) for implementation and local verification evidence.

## Baseline and outcome

Plan reviewed against local `main` at `552daa4` (PR #20). Milestone 27 is
merged through `f8f86d0` (PR #17). Its handoff and status index retain historical
pre-merge wording; their local test results are historical evidence, not a new
verification run. GitHub CI was not inspected for this plan.

Today `epochgrid-service/src/dynamic.rs` runs Auth Callout and control handling
in one process. Both open the authorization registry, and an in-memory boolean
coordinates admission. `epochgrid-core/src/auth_callout.rs` grants the control
identity `$JS.API.>` alongside directory/transparency writes and Welcome relay.
Production startup already validates operator-provisioned resources without
creating them, but its runtime credential still has broader authority.

Milestone 28 should remove signing keys and registry access from the network-facing
control worker and remove general broker resource administration from runtime
grants. Success requires an enforced Linux process/credential boundary, explicit
role permissions, and safe recovery across independent process failures. Splitting
Rust modules or launching two processes under the same unrestricted account is
not sufficient evidence of isolation.

Preserve verified TLS, encrypted Auth Callout, Secret Service, SQLCipher, signed
policy validation, revocation semantics, operator resource ownership, and the four
configuration/operator-JWT × standalone/R3 deployment cases. TD-001, TD-002 and
post-MVP TD-003 remain open. This milestone does not qualify the alpha release.

## Proposed architecture

Use two independently launched runtime roles, with a privileged local authority
and a restricted control worker. Keep initialization/export and operator resource
provisioning outside both runtime roles. The role contract records the implemented commands.

| Role | Owns or can access | Must not access |
| --- | --- | --- |
| Authority (`serve-authority`) | Auth Callout connection, issuer and encryption keys; authorization registry and its SQLCipher key; existing signed directory/revocation identity; policy/enrollment validation, grant derivation, resource inspection and reconciliation | Operator/account root seeds, NATS configuration, general resource provisioning |
| Control worker (`serve-control`) | Its own independent NATS connection key; exact control subscriptions and replies; typed local authority API | Issuer/encryption/signing seeds, authority keyring session, registry/database key, arbitrary signing or grant issuance |
| Setup/administration | Explicit initialization/export, role bindings and local invitation issuance under the authority account | Automatic broker edits, secrets in artifacts or worker configuration |

The authority remains trusted: compromise can issue grants and alter authorization
state. The worker still sees metadata and ciphertext and can disrupt permitted
delivery operations. Neither role receives MLS group secrets. Narrow NATS subject
permissions cannot validate every consumer configuration payload, so the worker
receives no consumer-management permission. Those operations stay in the trusted
authority. MLS content protection remains a separate boundary.

The authority independently validates original signed policy, registration,
revocation and relay inputs using current durable state. A worker assertion of
caller identity, membership, readiness or successful mutation is not authorization.
The local API has no raw SQL, arbitrary subject proxy, generic signing method,
caller-selected grants or unrestricted secret lookup. Authority-signed public
records may cross it; private keys and database keys may not.

## Implementation work packages

### 1. Capability and local API contracts

Inventory the actual NATS operations in transport, transparency, revocation,
authorization reconciliation and deployment validation. Write a checked-in matrix
of role, operation, subject, resource and justification before changing grants.
Include request reply subjects, KV backing streams, consumer INFO/create/delete,
stream metadata and any message reads needed for transparency/cutoffs.

Replace `$JS.API.>` with the smallest supported operation/resource allowlists.
Explicitly deny stream create/update/delete/purge, unrelated consumers/resources,
system administration, and raw CHAT/MAILBOX reads unless an individually reviewed
operation requires them. Separate metadata inspection from message retrieval.
Keep consumer management limited to CHAT/MAILBOX and the owned durable namespace;
verify how the pinned client/server encode those subjects in live fixtures.
If subject permissions cannot enforce a desired restriction, record the limitation
and move the operation behind authority validation where necessary. Do not hide it
behind another broad wildcard.

Specify a versioned, length-bounded local protocol: validated operation requests,
public results, reconciliation plans, generation-bound completion and readiness.
Use a Unix-domain socket in an authority-owned directory, checking peer Linux UID
and configured role at connection acceptance. Require finite request deadlines,
bounded in-flight work and strict decoding. These are necessary IPC safeguards;
general quotas and capacity planning remain milestone 29.

### 2. Credential and state isolation

Run the two roles as distinct Linux users with distinct homes and independently
accessible Secret Service sessions. Only the authority may open the authorization
database or resolve signing/encryption credentials. The worker receives a new
connection identity, distinct from the existing identity used to sign public
directory and revocation records; preserve that signing identity.

Split configuration and credential loaders by role. Reject swapped bindings,
missing keys, unsafe socket ownership, unexpected peers and incompatible protocol
versions before admitting devices. Do not initialize missing state during runtime
startup. No common inherited session bus, shared unlocked keyring, secret-bearing
environment, or parent process that resolves all credentials before spawning both
roles may substitute for isolation.

Provide reproducible Linux account/keyring launch instructions and an isolated
fixture exercising the real access boundary. Establish its CI execution needs in
this first implementation slice. Same-user mocks may test protocol logic but
cannot satisfy the credential-isolation acceptance criterion.

### 3. Authority operations and worker extraction

Move registry decisions and all private signing into the authority. Keep original
signature, current-generation, canonical identity and revoked-device checks at
this boundary. Persist lifecycle intent before issuing external work. Preserve
single-use enrollment and idempotency under lost replies, process termination and
duplicate requests. Keep local invitation administration authority-only.

Extract the existing control subscriptions into the worker. Forward only enumerated
requests and their replies. Keep NATS projection/reconciliation in the authority;
it validates relay content and destination before publication. Inventory all
existing signing sites so a convenient helper cannot silently reload the old
control signing key in the worker. Avoid a second independent authorization
projection or registry copy.

### 4. Admission, startup and recovery

Keep reconciliation readiness owned by the authority and require a current worker
session lease in addition. Reject repeated per-session IPC sequences; reconnect
starts a new session. No worker reconciliation acknowledgment crosses the boundary. A mutation closes admission before its durable state changes and remains
closed through required projection/consumer reconciliation.

Startup order: authority validates local state and starts encrypted Auth Callout
with device admission closed; only bound authority/worker bootstrap identities can
connect. The authority validates application resources and executes recovery,
including consumer filters. It opens admission only after those operations succeed
and the worker establishes a current session. Privileged bootstrap credentials must never admit a device
through the closed gate.

Socket disconnect, worker death, expired readiness lease or failed reconciliation
closes new device admission. Define and test a finite liveness-detection bound;
do not describe heartbeat failure detection as instantaneous. Existing grants
remain subject to the documented device lease, and already delivered ciphertext
cannot be recalled. Preserve the worker's bounded connection lease and prevent a
restart from reusing readiness from an old session.

Recover pending operations from durable state with the existing idempotent
projection rules. Test authority-only, worker-only and simultaneous restart, plus
broker failover. No partial recovery may silently reopen admission or reset state.

### 5. Setup, validation and transition

Extend milestone 27 artifacts with versioned role bindings, permission contracts
and launch configuration for both authentication modes. Keep exports public,
atomic and no-clobber. The operator applies broker changes explicitly. Both
runtime roles remain unable to provision the five resources; only the authority
can inspect them and reconcile their application records/consumers.

Provide an explicit stopped-service transition for established encrypted M27
homes: retain authority state and public signing identities, provision the worker
credential in its own account/session, export updated bindings, apply operator
configuration, validate each role, then start authority and worker. Design a
resumable transition record and interruption tests before implementing it. Do not
copy secret files, silently rotate identities or introduce plaintext migration.

If safe preservation cannot be demonstrated, stop that implementation slice and
document the concrete incompatibility before changing the installation policy;
fresh enrollment is not an implicit fallback. Production `serve` must not silently
retain the old combined privilege model. Give it an actionable transition error
or an explicit documented replacement. Legacy static development fixtures remain
development-only.

Make offline validation role-specific and non-initializing. Online validation must
use only the inspected role's credentials; report unavailable cross-role checks
explicitly. Validate IPC binding, worker lease/readiness and effective permission
coverage without exposing secret payloads. Preserve versioned JSON results and
the milestone 27 resource/replica checks. Update operator guides, threat model,
secret-storage documentation, README, milestone index and handoff at completion.

## Validation and acceptance

- Independent permission expectations and live negative tests demonstrate that
  each runtime credential cannot administer streams, unrelated resources or
  system subjects. Assert explicit authorization denial, not merely a timeout or
  an initially successful connection. Retain legitimate consumer/relay operations.
- Under separate Linux accounts, worker attempts to read authority files, open
  its SQLCipher database, use its keyring or impersonate the authority peer fail.
  Check both filesystem and Secret Service access; metadata labels alone are not
  an access-control boundary. Scan worker outputs/artifacts for seeded secrets.
- Exercise malformed/oversized IPC, wrong peers, stale sessions/generations,
  replayed enrollment/policy/revocation requests and requests for arbitrary signing
  or destinations. A compromised-worker test must not bypass authority validation.
- Kill either process before/after durable mutations and external projections.
  Verify closed admission, preserved identities/history, bounded detection and
  restart convergence. Test lost acknowledgments and repeated repair without
  broad retries or weakened revocation assertions.
- Extend all four production-TLS BYO fixtures to launch both isolated roles from
  generated artifacts and retain enrollment, messaging, history, revocation,
  account isolation, broker failover and unchanged operator resource assertions.
  Cover M27 transition, missing role state and resource incompatibility.
- Run the repository's required quality, unit, protected-state, retained NATS,
  Compose/CLI, TUI and focused dynamic-join gates. Build separately from bounded
  integration execution; add a dedicated isolation phase with descendant cleanup.
  Require cold CI evidence for isolation and all four BYO cases before merge.
  Record failures honestly; existing quarantines neither expand nor disappear.

## Delivery order and boundaries

Implement in five reviewable slices matching the packages above: contracts;
role isolation; authority/worker extraction; admission/recovery; deployment
transition and full qualification. Each slice includes its focused tests; the final
slice integrates the complete regression matrix. Resolve the exact capability
matrix, readiness verification protocol and isolated-runner setup in the first
slices, before replacing production startup.

Excluded: backend HA/distributed authority, remote IPC, new NATS versions or
topologies, dynamic attachments, broker/root-key management, general resource
quotas, audit pipelines, packaging/release publication and TD-001/002/003 repairs.
This document plans the milestone; it does not implement or publish it.
