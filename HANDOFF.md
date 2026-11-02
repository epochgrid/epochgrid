## Milestone 31 working tree — implemented, hosted CI pending

Security audit implementation is in `epochgrid-core::audit`, with authority-only
CLI in `epochgrid-service/src/audit.rs`. See `docs/operator/audit.md` for the exact
contract and commands. Auth schema 3 is additive; production schema-2 homes must
run stopped-authority `audit upgrade` first. Existing credentials are preserved.

Registry events commit with issuance/enrollment/activation/expanding policy changes.
Repair uses a savepoint and reserved capacity. External publication/reconciliation
intents survive missing results. The store has finite event/payload budgets and
explicit retention/pruning. Export streams a bounded snapshot to a private partial
artifact and publishes without overwrite only after syncing it. Coverage remains
explicitly incomplete for historical and volatile observations. Status contains
cached aggregate audit health, never records.

Local evidence (2026-10-31): formatting, warnings-denied workspace/all-target/all-feature
Clippy, build/test compilation, doctests and harness checks passed. Workspace units
passed (114 core, 18 service, 14 client), along with protected-state/live Secret
Service tests, all 16 retained NATS cases, all four separate-UID BYO cases, and
compose/TUI/offline-join/relationship/participant smoke suites. The final maintenance
edge-case changes were followed by the full unit suite and a standalone BYO rerun;
both passed. The four-case run preceded those final maintenance-only corrections.

Tests cover audit insertion rollback, enrollment/activation/policy denial on write
failure, continued revocation/reduction and repair leases, metadata/schema refusal,
restart/pending intents, quota reserves, denial aggregation, retention cursors,
private/no-overwrite export, incomplete artifacts, and actual worker/unrelated-UID
audit denial. Operator guide records local append/flood measurements without
worst-case claims. Full-capacity export permits missing lifecycle records with an
explicit warning and conservative coverage rather than forcing evidence deletion.

Cold hosted PR CI remains a merge gate; no hosted run is claimed. TD-001/002/003
remain open; no quarantined tests were restored. No commit, push or release has
been performed.

# Milestone 30 handoff — implementation and local verification

The user authorized implementation of [the plan](docs/milestone-30-plan.md) on
2026-10-30. Starting changes were the three milestone 30 planning documents only.
Milestone 29 merged as `05bb651` (PR #23); its
[hosted CI run 41146465259](https://github.com/epochgrid/epochgrid/actions/runs/41146465259)
passed. Work is on `feature/milestone-30-diagnostics` from that merge, preserving
the planning edits and original milestone 29 planning stash.

Implemented: `status --role authority|control --format human|json`, a separately
versioned diagnostic operation on the existing authenticated status socket,
process counters, monotonic gate/lease observations, authority-only cached registry
usage and the [diagnostics runbook](docs/operator/diagnostics.md). Status does not
open databases/keyrings, connect to NATS, initialize state, repair resources or
renew the worker lease. Existing validation report v1 and minimal status exchange
remain supported. The same reconciliation/lease predicate serves Auth Callout and
status; connection/permission observations remain advisory.

Reports use a 256-byte request limit, 16 KiB framed response limit, one connection
at a time and a five-second total socket deadline. Kernel peer UID selects the
view; the worker cannot request authority capacity fields. Aggregate capacity uses
the existing authority registry handle every 10 seconds and becomes stale after
30 seconds. No new database handle, durable event log or background scan task was
introduced. Structured security audit events remain milestone 31.

Local verification on 2026-10-30 passed formatting, warnings-denied workspace
Clippy, build/doctests, all 135 units (103 core, 14 client, 18 service), harness,
three isolated live Secret Service checks, protected-state lifecycle/CLI checks,
all 16 retained NATS/TLS cases, Compose/CLI, main/relationship/participant TUI and
focused dynamic join/reconnect. All four final BYO cases passed: configuration R1
78.68s, configuration R3 96.73s, operator-JWT R1 90.37s and operator-JWT R3 103.18s.
They include real separate-UID diagnostic privacy/overload checks, quota-blocked
authority reconciliation and recovery of retained intent after operator capacity
restoration, worker loss, authority restart/instance reset, and retained broker
failover/revocation/resource-ownership assertions. All four initial capacity
samples took less than one millisecond at report resolution; sampled authority
RSS was unchanged during each control flood at roughly 37 MiB. Neither observation
establishes a worst-case latency, memory bound or supported deployment size.

Evidence: `/tmp/epochgrid-m30-final-quality.log` records final Clippy/build and
`/tmp/epochgrid-m30-final-unit.log` records the final units. The first general run
passed harness, formatting, build/doctests, units, live Secret Service and
protected-state checks, and the first seven retained NATS cases, then correctly
refused a stale runtime artifact after additional acceptance tests were added.
That evidence remains in `/tmp/epochgrid-m30-verify.log`. After rebuilding, all
remaining TLS/NATS and smoke checks passed in `/tmp/epochgrid-m30-remaining.log`;
the final four-case qualification passed in `/tmp/epochgrid-m30-byo.log`.
Documentation links, Python syntax and patch whitespace pass.

An initial unit assertion searched all JSON for the word capacity and matched the
`physical_capacity` coverage flag. It was corrected to assert the actual worker
observation field set. Separate-UID fixtures check denial to a third account,
worker-view isolation, malformed/oversized/versioned requests, concurrent status
traffic and silent-peer expiry while heartbeats continue. The disposable Docker
fixture grants its test account permission to run the third-account probe; no
production privilege requirement changed. Existing SQLCipher mlock warnings do
not establish a memory-lock guarantee. TD-001/002/003 remain open; no retry or
quarantine was added.

No commit, push, PR, merge or release has been performed for milestone 30. Its own
cold hosted CI remains a pre-merge gate. The prior milestone handoffs follow.

# Milestone 29 handoff — implementation and local verification

The user requested implementing `docs/milestone-29-plan.md`, with a clean workspace
and HANDOFF review before beginning. Both checks were completed. Work is on
`feature/milestone-29-resource-bounds`, based on merged `origin/main` at `df23bb0`
(PR #22). Milestone 28 merged as `a80be2e`; all checks in
[CI run 40032719883](https://github.com/epochgrid/epochgrid/actions/runs/40032719883)
passed. This supersedes the pending-merge/CI statements in the historical handoff.
The original planning stash remains intact; only its plan was restored here.

Implementation and required local verification are complete. See the
[capacity contract and upgrade procedure](docs/operator/capacity.md) and
[default policy](docs/operator/capacity-default.json). This adds validated public
policies, transactional registry/outbox limits, bounded outbox batches, logical
database budgets with recovery space, fixed NATS queues, monotonic global and
verified-principal rate limits, finite broker exports/comparison, and explicit
stopped backend/client policy installation. Original replica manifests remain
stable; exported version-two manifests embed capacity. Runtime never administers
streams. Protocol v1 and separate authority/worker UIDs/keyrings are preserved.

The existing complete-snapshot wire format imposes a ceiling of 32 retained devices,
including revoked identities; registration records are capped at 1536 bytes and
grants at 16 groups per device. The measured maximum-name fixture uses 607 bytes
per registration, 19,519 bytes for a 32-device signed audit and 8,319 bytes for full
revocation. No history/evidence deletion or implicit replacement identities are
used to regain capacity. Existing M28 state outside supported limits is refused,
not truncated. Logical page checks do not establish physical disk/WAL/RSS limits.

Local validation on 2026-10-24 passed formatting, warnings-denied workspace Clippy,
build/doctests, all 130 unit tests (101 core, 14 client, 15 service), harness checks,
three isolated live Secret Service checks, protected-state lifecycle/CLI checks,
all retained NATS/TLS cases, Compose/CLI, main/relationship/participant TUI and
focused dynamic join/reconnect. Final four-case BYO qualification passed:
configuration R1 60.18s, configuration R3 72.84s, operator-JWT R1 71.73s and
operator-JWT R3 84.41s. It includes real separate-UID overload, broker quota
rejection, retained outbox/history, operator capacity restoration, KV replacement,
restart/failover, revocation and unchanged resource ownership checks. Each flood
sample received 40 replies from 512 requests; sampled authority RSS was unchanged
at roughly 37 MiB. This is an observation, not a peak-memory guarantee.

Evidence: `/tmp/epochgrid-m29-verify-complete.log` contains all general gates and
stopped at the initial R3 KV fixture assumption. R3 needs incoming-record headroom
for history-one replacement at a tight quota. The final fixture explicitly checks
quota rejection and the unchanged committed revision, then successful replacement
after an operator increase. All four corrected cases passed in
`/tmp/epochgrid-m29-byo-final.log`. Only that fixture and documentation changed
after the general gates; final Clippy/build also passed in
`/tmp/epochgrid-m29-clippy-final.log` and `/tmp/epochgrid-m29-build-matrix.log`.
Documentation links and patch whitespace pass.

Earlier findings are retained: SQLCipher page size is returned as text; the capacity
check now decodes it. The TLS fixture now explicitly configures `max_payload: 65536`.
A concurrent quota test opens database handles before racing writes, avoiding the
separate setup lock. One full unit run lost its disposable keyring daemon (control
socket refused, followed by D-Bus reactivation), causing credential failures. Its
root cause remains unestablished; log `/tmp/epochgrid-m29-verify-final.log` is kept.
A fresh isolated capacity probe and the subsequent complete unit/protected-state
gates passed. Existing SQLCipher mlock warnings remain; no memory-lock guarantee
is claimed. TD-001/002/003 remain open. No automatic retry or quarantine was added.

Cold hosted CI remains required before merge. On 2026-10-30 the user authorized
staging, committing and pushing milestone 29 and will prepare the PR. No merge or
release is authorized. The historical handoff follows.

# Milestone 28 handoff — implementation and local verification

PR #21 hosted CI follow-up: [run 40030107715](https://github.com/epochgrid/epochgrid/actions/runs/40030107715)
failed in all four BYO cases and the production TLS case in `nats-1`. Every case
failed before worker initialization: Python running as `nobody` could not read
`scripts/dev/role-worker-fixture.py` inside the runner checkout (permission denied).
Aggregate validation failed as a consequence; build, units, secrets, smoke and
the other three NATS groups passed. This was a shared fixture path-access defect,
not evidence of five independent runtime failures.

The fix stages only worker helper/keyring scripts and required executables in the
public temporary exchange and launches with that working directory. Authority
homes/keyrings remain private. Local Docker verification now deliberately makes
the checkout inaccessible to the worker before running the five affected cases.
All five cases passed with the restricted checkout: TLS 12.16s, configuration R1
52.99s, configuration R3 60.52s, operator-JWT R1 64.84s and operator-JWT R3 77.25s.
The log is `/tmp/epochgrid-pr21-fixture-fix.log`. Formatting, warnings-denied Clippy,
runtime build, all 12 harness checks, Python syntax and changed documentation links
also passed. No runtime service behavior or authority permissions were changed.
Hosted CI must verify the fix on PR #21 before merge.

Current work is on `feature/milestone-28-privilege-separation`, based on `main`
at `552daa4` (PR #20). The user authorized milestone 28 implementation after
reviewing `docs/milestone-28-plan.md`. The plan and milestone-index edits were
already present when implementation began. Milestone 28 runtime implementation
is complete; local verification evidence and the remaining hosted CI gate are below.

Milestone 27 merged as `f8f86d0` (PR #17). The subsequent CI redesign merged as
`60e3797` (PR #19): one shared build, isolated execution jobs, bounded NATS groups
and an established-offline TUI readiness fix. These supersede the historical
handoff's branch, publication and pending-CI statements below.

GitHub evidence checked on 2026-10-23:

- [PR #19 CI run 39895205154](https://github.com/epochgrid/epochgrid/actions/runs/39895205154)
  passed on attempt 1, including build, unit/secrets, all four retained NATS
  groups, smoke, all four BYO configurations and aggregate validation.
- [PR #20 CI run 39990763601](https://github.com/epochgrid/epochgrid/actions/runs/39990763601)
  is now completed successfully on attempt 1. The earlier review observed smoke
  still running; the completed run supersedes that observation.

This supports beginning milestone 28; it does not establish a reliability sample
or alpha release qualification. TD-001, TD-002 and TD-003 remain open. Historical
disposable-keyring failures remain unexplained, and SQLCipher mlock warnings do
not establish a memory-lock guarantee. Preserve Secret Service, SQLCipher,
fresh encrypted-state policy, operator-owned resources and all retained gates.

The implementation includes the explicit capability/local IPC contract, real
Linux account/keyring isolation, authority/control extraction, closed-admission
recovery, setup/transition and four-case BYO qualification.
Do not claim credential isolation from same-user mocks or permission labels.
The user authorized committing and pushing this branch and will prepare the PR.
No release has been performed for milestone 28; hosted CI remains a pre-merge gate.

Implementation refinement: `docs/backend-role-contract.md` keeps registry,
signing and reconciliation in the authority. The worker only forwards enumerated
control requests and publishes replies, so worker completion reports are not
trusted for reconciliation. Separate non-root UIDs, private keyrings/homes,
kernel peer credentials, strict bounded IPC, per-session sequences, five-second
worker leases and runtime locks enforce the boundary. Production combined `serve`
is refused; explicit development fixtures remain. Setup adds `worker-init`,
`role-bind`, `worker-configure`, `serve-authority`, `serve-control` and
`validate-control`. Authority validation also checks role readiness online.

Local verification on 2026-10-23: the complete `./scripts/dev/verify.sh` suite
passed, covering formatting, warnings-denied Clippy, build/doctests, units,
Secret Service/protected-state checks, retained NATS/TLS cases, Compose/CLI,
TUI/dynamic-join gates and all four isolated BYO cases. The log is retained at
`/tmp/epochgrid-m28-verify.log`. Actionlint also passed. An earlier TLS fixture
failure was corrected: a TLS-first worker restart had been placed in ordinary
certificate rotation.

Final review then made closed IPC listeners terminal, discarded queued requests
from dead sessions, and separated authenticated NATS readiness from the IPC
handshake deadline. Clippy/build and 117 workspace units (89 core, 14 client,
14 service) passed after those fixes. The production TLS regression (11.96s) and
all four BYO cases passed again: configuration R1 52.96s, configuration R3 65.38s,
operator-JWT R1 64.28s and operator-JWT R3 77.06s. Final logs are
`/tmp/epochgrid-m28-final-unit.log` and `/tmp/epochgrid-m28-final-roles.log`.
Unit output included existing SQLCipher mlock warnings; no memory-lock guarantee
is claimed. No new quarantines or automatic test retries were introduced.

Before merge, obtain a cold hosted CI run for this implementation, including
native separate-UID/keyring isolation and all four BYO cases. Local evidence is
strong enough for review; it does not replace that CI gate or close TD-003.

Host sudo requires interactive authentication. The local fixture image is
`epochgrid-role-tests:local`, built from `scripts/dev/roles.Dockerfile`; it uses
disposable users/keyrings, no external network and read-only executable/script
mounts. `scripts/dev/test-role-isolation.py` validates the runtime artifact against
current sources before execution. Hosted CI uses passwordless sudo to `nobody`
instead, via `EPOCHGRID_ROLE_NATIVE=1`. No production service sudo permission is
required. The four BYO cases retain their existing check names.

# Historical milestone 27 handoff — online validation and startup gate implemented

Work is on `feature/milestone-27-initialization`, based on merged milestone 26
at `5256862`. The user requested implementation on 2026-10-22 using
`docs/milestone-27-plan.md` (which was already untracked in the starting tree).

The first slice implements `epochgrid_core::deployment`: a strict version-one
R1/R3 manifest schema, deterministic public stream/KV artifact rendering, and
non-mutating field-by-field comparison with independent unit fixtures. See
`docs/deployment-resource-contract.md` for the comparison rules. async-nats field
features through 2.14 are enabled to retain TTL/scheduling/counter settings during
INFO decoding. No dependency versions or authentication schema were changed.

The second slice implements offline initialization and export:

- `auth-init --auth-mode configuration|operator-jwt --target-account ...
  --auth-account ... --replicas 1|3`; no-option defaults remain configuration,
  EPOCHGRID and R1. Inputs are validated before state/credential provisioning.
- `auth-init.lock` serializes setup/export; public `auth-init.json` records retry
  choices before provisioning. Existing vault metadata preserves identities.
  Completed initialization refuses reruns. `auth.json` is committed last.
- `deployment.json` is persisted beside `auth.json`. Public files are mode 0600;
  bundles are staged in mode-0700 directories and atomically renamed without
  replacement. Edited bundles are refused; `--output` permits a new destination.
- Operator initialization retains the existing auth schema with an empty
  `operator_jwt.connection_jwt`. Runtime loading explicitly rejects it until the
  operator supplies a signed non-bearer service JWT. No configuration fallback.
- `deployment-export --auth-config FILE [--replicas 1|3] [--output DIR]` resolves
  existing credentials/control-key binding without provisioning or opening a
  database. Existing M26 homes need explicit replicas on first export. Export
  does not change auth.json or the legacy root nats-reference.conf.
- All four BYO fixtures now consume generated native stream configurations and
  configuration snippets/operator delegation specifications. The operator test
  fixture supplies signing, administration users and TLS. Runtime does not.
- Existing tempfile/rustix lockfile versions are now direct service dependencies
  for durable no-clobber publication; serde is a direct dependency for setup options.

The third slice implements `validate --auth-config FILE --offline [--format
human|json]`. It runs before service runtime initialization and never connects to
NATS. Shared TLS policy and trust roots are inspected locally; an omitted endpoint
is explicitly not checked. Existing serve/development endpoint defaults remain.

- New `database::inspection` uses existing-only SQLCipher read-only connections,
  query-only mode and per-database read transactions. No store-opening APIs,
  provisioning, metadata writes, permissions changes, migrations or repairs.
- Format probes stay SQLite-managed. No ordinary database-content descriptors and
  no immutable mode. SQLite-managed WAL/SHM bookkeeping may change, while
  application data/schema do not. Tests cover live snapshots and writer lock safety.
- Checks include ownership/private permissions, configuration/manifest, six
  independent credential roles, database role/key bindings, schema histories and
  required tables/columns, integrity, and signed control identity/config binding.
- Version-one reports expose stable IDs, passed/failed/not_checked statuses,
  expected/observed values, remediation and explicit network/operator coverage.
  Raw errors, JWTs, credentials, URLs and private database rows are excluded.
- Required checks must pass for exit zero. Invalid local TLS input still produces
  a JSON report when requested. Pending operator JWT setup fails explicitly.
- All four BYO cases validate before startup, during operation and after restart;
  missing-manifest validation fails without stopping the running backend.
- An extra isolated Secret Service test covers duplicate, swapped and locked
  credentials through the validator. CLI tests verify no endpoint connection,
  unchanged encrypted state, sanitized failures and missing-key refusal.

See `docs/operator/validation.md` for commands, report semantics and scope.
Final slice implements online validation against an already-running backend and
production startup enforcement. `validate --online` combines local inspection with
existing auth/control credential connections, authenticated JetStream requests,
NATS 2.14.5/max-payload checks, all five stream/KV contracts and replica health.
One to eight explicit endpoints are inspected separately with discovery/reconnect
disabled; operations are bounded to five seconds and network phase to 60 seconds.
Reports distinguish permission denial, authentication, timeout, missing/unavailable,
incompatible resources/server and unhealthy replicas, with no raw server errors.
Production startup runs local validation, bootstraps Auth Callout with admission
closed, validates resources, then uses lookup-only transport/transparency helpers
before existing reconciliation/readiness. Failed checks abort the temporary auth
task. Development fixtures retain explicit provisioning. The older production TLS
fixture now pre-provisions generated resources through its own admin credential.
BYO coverage adds online checks at startup/restart and each supplied endpoint,
missing/incompatible startup refusal, missing manifest with an established device,
wrong declared replicas, subjects/retention/KV-history mismatches, unavailable
backend/endpoint, invalid TLS identity and denied inspection permissions.
Milestone 27 implementation and required local verification are complete. Cold CI
for all four BYO cases is still required before merge. The user requested a
feature-branch commit and push; the user will create the pull request. No merge
or release publication is authorized by that request.

Final-slice local evidence (2026-10-22): formatting, warnings-denied workspace
Clippy, 107 unit tests (87 core, 13 client, 7 service), binaries/examples build,
ten harness regressions, three isolated live Secret Service tests, protected-state
CLI checks, all 16 retained NATS cases, Compose/CLI, main/relationship/participant
TUI and focused dynamic join/reconnect passed. All four expanded BYO cases passed:
configuration standalone 49.47s, configuration cluster 61.86s, operator-JWT
standalone 60.86s and operator-JWT cluster 73.46s. Build and integration execution
remained separate bounded phases. No automatic retry or quarantine rules were
added. Documentation file links, shell syntax and scoped whitespace checks pass.

Evidence is split across `/tmp/epochgrid-m27-finish-verify-final.log` (quality,
unit/build and harness gates) and `/tmp/epochgrid-m27-finish-remaining.log` (final
protected-state, retained integration/smoke and four-case BYO gates). The former
stopped at an outdated protected-state assertion expecting the old startup error
text; it was corrected to assert the new `credential_missing` code and the phase
passed in the latter log. The initial missing-manifest test expectation was also
corrected from generic manifest failure to the existing `state_missing` code.

Earlier attempts encountered disposable Secret Service failures: the first full
run passed core units but lost keyring access in service units; an isolated unit
run then reported keyring operation failures. A disposable-keyring availability
probe and all seven service tests passed, followed by the successful full workspace
unit and protected-state runs above. The keyring-session failure cause was not
established and was not hidden by retries in the test scripts. Retained logs:
`/tmp/epochgrid-m27-finish-{verify,unit,keyring-probe}.log`. Existing SQLCipher
mlock warnings and TD-001/TD-002/TD-003 reliability boundaries remain unchanged.
Preserve Secret Service/SQLCipher, fresh-home-only behavior, encrypted Auth Callout,
operator resource ownership and the existing TD-001/TD-002/TD-003 boundaries.
Separate edits to `docs/technical-debt.md` appeared during this slice and were left
untouched; they are not part of this implementation.

Third-slice local validation on 2026-10-22: the full `./scripts/dev/verify.sh`
passed formatting, warnings-denied Clippy, all 105 workspace unit tests,
binaries/examples build, ten harness regressions, three isolated live Secret
Service tests, protected-state/CLI lifecycle checks, all 16 retained NATS cases,
Compose/CLI, main/relationship/participant TUI, focused dynamic join/reconnect,
and all four BYO cases with offline checks before startup, during operation and
after restart. Targeted protected-state and four-case BYO runs also passed.
Build and final BYO execution remained separate bounded phases; no retries or
quarantines were added. Documentation file links and verifier shell syntax pass.
Implementation-path whitespace checks pass; the separate technical-debt edits
were excluded. Existing SQLCipher mlock warnings remain (no memory-lock guarantee).

Third-slice log: `/tmp/epochgrid-m27-offline-verify.log`; focused logs:
`/tmp/epochgrid-m27-offline-{unit,secrets,byo,clippy,final-build}.log`.
These local results do not replace cold CI evidence. The previous slice's
validation follows for reference.

Second-slice local validation on 2026-10-22: the complete
`./scripts/dev/verify.sh` passed formatting, warnings-denied Clippy, 97 workspace
unit tests (six setup tests and a new non-provisioning credential lookup test),
binaries/examples build, ten harness regressions, protected credential/database
checks, all 16 retained NATS cases, Compose/CLI, main/relationship/participant TUI,
focused dynamic join/reconnect, and all four generated-artifact BYO-NATS cases.
The new protected-state assertions confirm export preserves auth.json, credential
metadata and encrypted database bytes, and cannot recreate a missing key.
Setup tests cover invalid choices before state creation, locking, interrupted
retry, overwrite/symlink refusal, private modes, binding failures, M26 export and
operator-JWT completion. All four artifact-consuming BYO cases also passed in a
preceding targeted run. The final full run kept build and BYO execution in separate
bounded phases. These are local results, not cold CI evidence.

Full log: `/tmp/epochgrid-m27-setup-verify.log`; targeted matrix:
`/tmp/epochgrid-m27-setup-byo.log`. SQLCipher mlock warnings remain; this establishes
no memory-lock guarantee. Existing quarantines remain unchanged. The first-slice
90-unit-test regression log remains `/tmp/epochgrid-m27-verify.log` and predates
generated-artifact BYO provisioning.

No commit, push, PR or release has been performed. Cold CI evidence remains a
merge requirement. The milestone 26 handoff below is historical and predates its
merge; its feature-branch state and next steps are no longer current.

# Historical milestone 26 handoff

## State

Milestone 25 PR #15 merged as `4be5cc4e62914ecdda72461a3ca1049722cdd93c`.
Milestone 26 implementation is on `feature/milestone-26-byo-nats`, based on that
merged `origin/main`. The user approved configuration-mode and operator-JWT,
standalone and three-node cluster qualification. Implementation and local validation
are complete; no commit, push, PR or release has been performed for milestone 26.

Preserve the existing TD-003 post-MVP test-reliability documentation changes. They
were carried from the milestone 25 review and are included in this working tree.
TD-001 typing and TD-002 short-lease dynamic messaging remain deferred; this work
adds no quarantine and does not resolve those debts.

## Implementation and boundaries

- Optional `auth.json.operator_jwt` contains authentication-account public NKey and
  signed, non-bearer auth-service user JWT. Configuration mode remains compatible.
- Validate JWT signature, type/version, connection-key/account binding, expiry and
  not-before. NATS checks the operator's delegated signing authority.
- Operator-mode requests bind the authentication account; user grants carry the
  application's `issuer_account`, signed by the existing generated issuer key
  delegated as an unscoped application-account signing key. All private EpochGrid
  keys stay in Secret Service; no operator/account root seed enters runtime config.
- The pinned NATS 2.14.5 `default_sentinel` routes device NKey connections into
  encrypted Auth Callout. No device-side JWT or static device allow-list is needed.
- Four isolated production-TLS qualification cases cover configuration/operator JWT
  on R1 standalone and R3 clusters. Routes use mutual TLS. Operator fixtures own
  configuration, account JWTs and pre-provisioned stream/KV replication settings.
- Exercise enrollment, messaging, negative TLS/admission/permission checks, account
  isolation, broker leader loss, offline history, backend restart, revocation,
  replica catch-up and preservation of operator config/resource settings.
- `byo-build` compiles separately. `byo-nats [CASE]` runs bounded cases; the default
  local verifier includes them and CI has four independent matrix jobs. Original
  16 NATS cases retain their existing phase/budget; the four new cases run separately.
- Deployment contract: `docs/operator/byo-nats.md`. Other versions/topologies,
  scoped JWT signers, dynamic attachments and backend HA are not qualified.
  Initialization/validation tooling is milestone 27; privilege separation is 28.
  Preserve milestone 25's fresh encrypted-state policy and SQLite-managed probes.

## Final local validation — 2026-10-20 (America/New_York)

Passed: formatting/patch whitespace, 85 workspace unit tests, warnings-denied Clippy, binaries/examples
build, ten harness regressions, protected credential/database lifecycle checks,
all 16 retained NATS cases (252.26 seconds), Compose/CLI, main/relationship/participant
TUI, focused dynamic join/reconnect and all four BYO-NATS configurations. Two
consecutive final fresh-state matrix passes succeeded (eight case executions,
roughly 26–43 seconds per case). Local documentation file links and verifier shell
syntax also pass. No new runtime synchronization fix was needed for this matrix.

Useful retained logs: `/tmp/epochgrid-m26-byo-final.log`,
`/tmp/epochgrid-m26-byo-repeat-{1,2}.log`, `/tmp/epochgrid-m26-clippy.log`, and
`/tmp/epochgrid-m26-{secrets,nats,compose,tui,dynamic-join,relations-tui,participants-tui}.log`.
The unit suite passed but emitted SQLCipher mlock warnings under concurrent local
load; no memory-lock guarantee is established by these tests.

Two test-design findings were corrected during implementation: async-nats can
return a connection on INFO before a later auth rejection (negative tests now
require explicit authorization errors); and each JetStream stream/consumer elects
its own leader (failover readiness now checks all relevant resources). No runtime
membership-sync bypass or assertion-suppressing retry was added.

## Next steps

Review the diff and run cold GitHub CI on the
feature branch before merge. Local fresh-state repetitions are not cold-runner CI
evidence. Ensure the new matrix jobs are included in merge review; adding jobs to
workflow YAML does not itself update protected-branch required-check settings.
Milestone 27 is not started. Do not claim the complete alpha release is qualified.
