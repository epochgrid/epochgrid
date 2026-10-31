# Milestone 30 — operational diagnostics

**Implemented; locally validated. Cold hosted CI required before merge.** The user authorized implementation
on 2026-10-30. Milestone 29 merged as `05bb651` (PR #23), and
[hosted CI run 41146465259](https://github.com/epochgrid/epochgrid/actions/runs/41146465259)
passed. Implementation is on `feature/milestone-30-diagnostics` from that merged
baseline, preserving the planning edits. See the [operator diagnostic contract](operator/diagnostics.md)
for exact fields and behavior and [HANDOFF](../HANDOFF.md) for verification evidence.
The acceptance plan below remains the scope; milestone 30 requires its own cold
hosted CI before merge.

## Outcome and scope

Give an operator a bounded, sanitized answer to: is the authority responding,
is new admission open, why is it closed, is the worker lease current, and which
capacity or dependency needs attention? Expose observations with explicit freshness
and coverage, and provide a troubleshooting path that preserves established state.

Milestone 30 covers backend runtime status, aggregate operational counters,
existing validation diagnostics and an operator runbook. Milestone 31 retains
structured security audit events, durable event storage, export and retention.
No HTTP listener, Prometheus exporter, dashboard, remote diagnostic RPC, automatic
support archive or general log collection is required here. Client/TUI diagnostic
commands, tracing redesign, dynamic attachments, packaging and release work are
outside this milestone. TD-001/002/003 remain open; better observations do not
establish a fix or restore quarantined checks.

Preserve TLS, Secret Service, SQLCipher, separate authority/worker UIDs and
keyrings, existing NATS grants, protocol v1, resource ownership and milestone 29
bounds. Diagnostic failure must never open admission, replay control requests,
initialize state, repair resources or discard pending work.

## Baseline found in the code

| Area | Existing behavior | Milestone 30 gap |
| --- | --- | --- |
| Authority validation | Version-one human/JSON reports, stable checks, sanitized errors, offline inspection and bounded online probes | Deployment checks do not explain ongoing runtime state or transitions |
| Worker validation | Own-state checks and peer-authenticated authority inspection | A failed readiness check collapses several runtime causes into `role_not_ready` |
| Local status | `roles.rs` has a separate `.status` socket, bound-UID peer checks, sequence-zero `Inspect`, and `Status { reconciled, worker_live }` | No explicit freshness, operational reasons, usage or counters |
| Admission | Reconciliation and a live five-second worker lease gate new admission | Observability must use the actual gate, including other denial prerequisites, rather than a parallel readiness model |
| Capacity | Explicit policies, transactional quotas, bounded queues and rate limiting | Need public aggregate usage/limit observations and exhaustion reasons without exposing registry records |
| Logging | Service tracing plus permission-error monitoring; validators already avoid raw error chains | New diagnostic output needs an allowlisted schema and safe failure paths |

Primary paths are `crates/epochgrid-service/src/{main,roles,dynamic}.rs`,
`crates/epochgrid-core/src/{auth_callout,capacity,validation}.rs`,
`crates/epochgrid-core/src/validation/online.rs` and
`crates/epochgrid-core/src/database/inspection.rs`. Reuse their existing inspection
and authorization boundaries. Do not open runtime stores merely to collect status.

## 1. Define the operational report and command contract

Add `epochgrid-service --home HOME status --format human|json`, with an explicit
`--role authority|control` selection. Both roles resolve their existing bindings
and query the same peer-authenticated authority status endpoint. The control view
proves only what that endpoint observed; it is not an independent worker NATS
health probe. Do not require authority credentials in the control account.

Status performs no NATS or Secret Service connection and no database opening.
It reads the minimum existing public binding configuration, then queries the
running authority. Missing setup produces a bounded error report without creating
files or prompting initialization. Keep `validate` and `validate-control` as the
separate offline/online dependency and persisted-state checks.

Define a version-one diagnostic envelope distinct from validation report v1:
schema version, role/view, observation outcome, runtime instance identifier,
monotonic uptime, readiness state, fixed reason codes, observations and coverage.
Use a random per-process instance identifier unrelated to device identities.
Document each field's owner, units, sensitivity, reset behavior and availability.
Use typed enums/fields; do not serialize arbitrary error objects or maps of labels.

The readiness state is `ready`, `not_ready` or `unknown`. A connection failure or
stale/unavailable observation is unknown, not proof the service is stopped. A live
authority reporting closed admission is not ready. Exit codes are 0 for ready,
1 for a valid not-ready report, 2 for argument/configuration/observation failure.
JSON is the only stdout content in JSON mode; human output and stderr must follow
the same sanitization rules. Invalid CLI syntax may use ordinary Clap stderr.

Set concrete limits: one request per invocation, a five-second total socket
deadline, a 16 KiB response ceiling, at most 32 fixed observation entries, and no
automatic retry. Include an observation age or explicit unavailable state for
every cached value; distinguish a fresh socket response from stale cached data.
No wall-clock timestamp may determine lease validity or freshness. The report is
a point-in-time observation, not a readiness guarantee after command completion.

## 2. Instrument the existing state and preserve the trust boundary

Inventory the actual admission predicates and transitions before adding fields.
Read the effective gate used by Auth Callout; preserve separate reasons for
unfinished reconciliation, missing/expired worker lease, known connection loss,
permission failure and capacity-blocked repair where the runtime can prove them.
Do not guess a root cause from a timeout or classify every denial as overload.
If startup fails before the status endpoint exists, report unavailable and direct
the operator to validation and sanitized startup diagnostics.

Expose worker lease age and expiry using the same monotonic clock and source as
admission. Inspection must not renew the lease, replace the active worker, reset
reconciliation, or allow worker claims to establish resource compatibility.
Separate process responsiveness, readiness and dependency coverage. A ready
response does not certify current broker replicas, account quotas, route TLS or
future device admission. Existing online validation remains the explicit probe.

Preserve the existing minimal `Inspect`/`Status` exchange for validators. Add a
separate versioned diagnostic operation on the authenticated status socket;
unsupported peers return an explicit unsupported/unavailable result, with no
fallback that fabricates readiness. Test old inspection and new diagnostics
together. No wire-protocol or authority control-operation change is required.

Only the two bound UIDs may receive reports. Restrict the worker view to readiness,
lease and aggregate operational state; authority registry usage and policy detail
stay in the authority view. Use kernel peer identity to select that view, never a
caller-supplied role field. No identities, registry rows or secret handles cross
the socket. Preserve binding/configuration no-clobber and runtime-lock behavior.

Keep status handling independent of the control/heartbeat path. Bound accepted
work, parsing, lock hold time and output allocation; do not spawn a task per
connection or queue requests without a limit. Slow or flooding inspection peers
may lose diagnostic availability but must not keep admission alive or starve
lease expiry and security repair. Diagnostic listener failure must be surfaced
without broadening runtime privileges or silently changing admission policy.

## 3. Add bounded aggregate observations

Record process-lifetime saturating counters for fixed operation classes and
outcomes: requests received, accepted, denied, rate-limited, malformed/oversized,
operation timeout, IPC disconnect and reconciliation success/failure. Define the
counting point for each; accepted means the documented processing stage, never
implicit durable commit or confirmed client delivery. Count what is observable;
do not infer broker drops or unreceived requests from a missing response.

Expose current bounded queue occupancy where available, configured limits,
reconciliation state and last completion age. Authority-only capacity observations
cover retained registry counts and logical database usage against policy. Obtain
these through bounded existing maintenance work or explicit inspection, not a
database scan on each status request. Cached values carry age and become unknown
when they cannot be refreshed. State exactly which usage is unavailable until
validation; do not present missing values as zero.

Choose and document a finite cache refresh interval and stale threshold in the
first implementation slice, using measured query/lock costs. Do not create a
background task or new database handle without a shutdown and concurrency design.
Status must remain responsive when SQLCipher or Secret Service is unavailable.
No durable counter database, per-user/device/subject labels, unbounded reason
strings, histograms or historical event buffer belongs in this milestone.

Counters reset on restart and are approximate operational measurements, not a
security audit trail. Logical database/broker limits do not establish filesystem,
WAL, RSS or peak-memory bounds. Online resource observations remain in validation;
status must not grant worker or authority new broker inspection permissions.

## 4. Make failures actionable without leaking private data

Create `docs/operator/diagnostics.md` with exact command examples, report schemas,
exit codes, role/coverage differences and a reason-to-action table. Cover authority
unavailable, worker absent/expired, reconciliation pending, broker unavailable,
permission denial, incompatible resources, capacity exhaustion, locked/missing
keyring and busy/unreadable encrypted state. Distinguish status reasons from
failures that only validation can establish.

Link each action to existing TLS, role setup, validation and stopped-capacity
upgrade procedures. Never recommend deleting homes/sidecars, reinitializing keys,
loosening permissions, disabling TLS, purging evidence or replaying an ambiguous
mutation. Explain how to run each command as its owning Linux account and which
facts need separate operator credentials. Collection and sharing remain explicit
operator actions; even aggregate usage can reveal deployment activity.

Allowlist report content and audit all new error paths, including serialization,
socket/parser failures and startup diagnostics touched by this implementation.
Exclude tokens, credentials/JWTs, key material, plaintext messages, group/user/
device names, NKeys, database rows, subjects, URLs, local paths and raw error chains.
Use fixed identifiers and remediation text. Do not claim that unrelated legacy
debug logs are sanitized or encourage unrestricted `RUST_LOG=trace` collection.

## Validation and acceptance

1. Unit fixtures establish schema/version rejection, output and entry limits,
   deterministic monotonic lease/staleness behavior, counter saturation/reset,
   exit-code mapping and human/JSON equivalence. Test unknown and unavailable
   distinctly from false/zero and preserve validation report v1 compatibility.
2. Inject recognizable private markers into malformed inputs and dependency
   failures; assert absence from stdout, stderr and diagnostic logging. Assert
   exact allowed fields in both UID views, not only absence of selected strings.
3. Under real distinct UIDs/keyrings, verify permitted inspection and rejection
   of unrelated UIDs, worker attempts to request authority details, bad versions,
   oversized frames and slow/flooding peers. Retain control-session exclusivity,
   heartbeat/lease expiry, bounded termination and cleanup assertions.
4. Exercise startup, ready state, worker loss/expiry, authority restart, pending
   reconciliation, quota-blocked repair and recovery in the same established
   homes. Assert report/gate agreement and instance/counter reset. A timeout must
   never be reported as proof that a pending mutation was rolled back.
5. Verify status creates no credentials, database, home or configuration, and
   performs no broker operation. Existing validators retain SQLite-managed
   read-only snapshots and live-writer safety; no ordinary database file reads.
6. Extend all four configuration/operator-JWT × R1/R3 BYO cases with readiness,
   worker-loss, quota/recovery and restart observations. Retain account isolation,
   revocation, TLS, broker failover and unchanged operator-resource assertions.
   Reuse lifecycle transitions instead of multiplying expensive fixtures.
7. Run all required formatting, warnings-denied Clippy, units, build/doctests,
   harness, protected-state, NATS/TLS, Compose/CLI, TUI and focused dynamic-join
   gates. Keep build separate from bounded execution. Require cold hosted CI
   before merge; add no blanket retry or quarantine and do not close TD-001/002/003.

## Delivery order and completion

Deliver reviewable slices: predicate/field inventory and public schema; bounded
authenticated runtime snapshots and command; aggregate counters/capacity freshness;
negative and lifecycle qualification; operator runbook and full retained gates.

Update README, milestone index, validation and role contracts, threat model and
HANDOFF with actual fields, costs, limits and verification evidence. The milestone
is complete when operators can distinguish known closed-admission causes from
unknown observations, diagnose dependency/capacity failures through documented
commands, and do so without mutation, secret disclosure or weakened isolation.
This milestone does not authorize merge or release publication.

## Implementation decisions

The report uses fixed typed fields, a 256-byte request limit and a 16 KiB framed
response limit. Capacity collection uses the already-open authority registry
handle in one read transaction, every 10 seconds; usage becomes unavailable to
consumers after 30 seconds without a refresh. Collection duration is measured in
each report. No diagnostic database handle or background scan task was introduced.

Connection state and sticky permission-error observations are advisory fields;
readiness remains the existing reconciliation/worker-lease gate. A generic failed
repair cannot prove broker quota exhaustion: existing transparency append failures
may discard the underlying broker error. Reports preserve that uncertainty and
expose pending reconciliation plus failed-repair counts; the BYO test controls a
quota failure explicitly and verifies closed admission and subsequent recovery.
No raw error-string classifier or new admission predicate was added. Worker fields
are selected by the socket's kernel peer UID, never a requested view. Separate-UID
fixtures also use a third unprivileged account to verify status denial.
