# Milestone 31 — security audit events

**Implemented locally; cold hosted PR CI remains a merge gate.** See the
[operator contract](operator/audit.md) and `HANDOFF.md` for actual coverage and local
verification evidence. This milestone adds structured,
durable security audit events with bounded storage, explicit export, and retention.
It follows [operational diagnostics](operator/diagnostics.md). Diagnostic counters
remain approximate process observations and must not be presented as audit records.

## Outcome and scope

Let an authority operator determine which security-relevant action was attempted,
what the authority verified, which durable transition committed, and whether the
available evidence is complete within its declared coverage and retention window.

Cover backend enrollment, admission, authorization policy changes, revocation,
reconciliation, and audit lifecycle operations. Preserve SQLCipher, Secret Service,
separate authority/worker accounts, existing NATS privileges, protocol v1, and
milestone 29 resource bounds. No client message contents enter audit records.

Remote collection, SIEM integration, a web viewer, compliance certification,
external witnesses, client activity auditing, and release packaging are outside
scope. Do not extend the milestone 13 registration transparency log into a general
audit store. TD-001/002/003 remain open; this work does not restore quarantined tests.

## Existing implementation and integration points

- `crates/epochgrid-core/src/identity_model.rs`: encrypted authority registry,
  enrollment tokens, device enrollment/activation, admission lookup, and revocation.
- `crates/epochgrid-core/src/authorization.rs`: signed policy validation, registry
  mutations, and broker consumer reconciliation.
- `crates/epochgrid-core/src/auth_callout.rs`: admission decisions and response signing.
- `crates/epochgrid-service/src/dynamic.rs`: authority startup, control dispatch,
  revocation propagation, and reconciliation.
- `crates/epochgrid-service/src/roles.rs`: peer-authenticated IPC, worker leases,
  bounded request handling, and the separate diagnostic socket.
- `crates/epochgrid-core/src/database.rs` and `database/inspection.rs`: required
  encrypted connection boundary and non-provisioning inspection.

Inventory every successful mutation, denial, retry, and external side effect before
instrumenting it. In particular, registry commit, broker reconciliation, response
construction, and confirmed delivery are different events. Existing methods such
as activation will need explicit transaction boundaries if their audit record is
to commit atomically with the state change.

## 1. Define the event and coverage contract

Add typed, versioned events with a fixed taxonomy and allowlisted fields. Each
record has a store identifier, monotonically increasing sequence, process instance,
operation/correlation identifier, event type, processing stage, outcome, fixed
reason code, and timestamp quality. Use wall time for human correlation only;
monotonic process time cannot establish order across restarts. Sequence establishes
store-local order. Never claim globally ordered delivery or a trusted clock.

Document the recording point for each class:

| Class | Required distinction |
| --- | --- |
| Enrollment token issuance | Issuance committed; token value and digest excluded |
| Device enrollment and activation | Verified request, committed binding, activation result |
| Auth Callout | Decision and response construction; no claim of client connection success |
| Policy update | Signature/authorization failure, committed generation, broker application result |
| Revocation | Durable revocation intent, registry application, broker exclusion/reconciliation result |
| Reconciliation | Started, completed, failed; no inferred MLS rekey completion |
| Role/runtime lifecycle | Authority start, authenticated worker session changes, admission gate transitions |
| Audit administration | Export attempted/completed, retention change, prune boundary, degraded/recovered storage |

Use authority-assigned opaque references for verified actors and targets. Distinguish
local operator, verified device, bound worker, and unverified input; a supplied
identity is not an authenticated actor. Do not persist arbitrary claimed identities.
Specify reference stability, storage ownership, and deletion behavior. References
remain linkable metadata, not anonymous data.

Exclude tokens, credentials/JWTs, key material, token hashes, message or attachment
content, raw payloads, usernames/device names, NKeys, subjects, URLs, filesystem
paths, and raw error chains. Do not use an unkeyed hash of a low-entropy identity
as a privacy substitute. Publish a field-by-field sensitivity and coverage table.

## 2. Persist evidence with explicit failure semantics

Preferred design: versioned audit tables in the existing encrypted authority auth
registry, using its existing key and connection. This allows registry changes and
their committed events to share a transaction without a second database or a
cross-database atomicity claim. Inspect migration and quota behavior before adopting
this design; record any necessary deviation before implementation proceeds.

Successful enrollment, activation, token issuance, and privilege-expanding policy
changes require their event to commit with the mutation. Failed event persistence
rolls back those changes. For NATS side effects, persist intent before execution
and result afterward. Restart reconciliation must identify unresolved intents;
absence of a result means unknown, not proof the effect did not occur. Reuse
existing idempotency and retained intent rather than replaying ambiguous requests.

Audit exhaustion or failure closes new admission and privilege expansion. It must
not prevent lease expiry, denial, revocation, or privilege-reducing repair. Reserve
capacity for security-reducing transitions and audit-loss metadata. If that reserve
also becomes unavailable, continue enforceable denial/repair, expose degraded
coverage, and never report an unaudited transition as fully audited. A failed
registry commit remains a failed mutation regardless of logging policy.

Do not synchronously write every hostile packet to the registry. Use bounded
aggregation for repeated unauthenticated/malformed/rate-limited inputs, with fixed
window, count, overflow, and loss semantics. State clearly which authenticated
operations have individual records and which attempts are summarized. Unclean
termination can lose in-memory aggregates; the next startup must not claim complete
coverage. Keep this traffic from consuming the security-repair reserve.

## 3. Bound storage and retention

Proposed initial limits, to validate against the existing capacity policy:

- At most 100,000 retained events and 32 MiB of encoded audit payload, subject also
  to the existing total database limit; SQL indexes/pages are additional overhead.
- At most 2 KiB per event; fixed enums and bounded reference fields.
- At most 256 queued best-effort observations; no unbounded task or label creation.
- Reserve 1,024 records and 2 MiB within the audit budget for repair and loss markers;
  confirm compatibility with the existing database recovery reserve.
- Maintenance deletes at most 256 eligible records per transaction; no full scan on
  request handling and no unbounded lock hold while exporting or pruning.

Keep records until explicitly pruned by an authority operator. No silent overwrite
or default age-based deletion. Full storage therefore has the admission consequences
above. Provide explicit retention policy changes and a dry-run prune summary.
Pruning advances durable retained-range metadata atomically with deletion; sequence
numbers are never reused. Export does not implicitly authorize deletion. Document
that pruning cannot guarantee physical erasure from WAL, backups, or prior exports.

Version policy changes explicitly. Existing homes need a supported additive schema
upgrade under the established runtime lock; never reinitialize keys or databases.
Read-only validation/export must refuse missing or unsupported state without
migrating it. Test interrupted migration and compatibility refusal by old binaries.

## 4. Provide local export and inspection

Proposed commands are `epochgrid-service --home HOME audit info`, `audit export`,
and `audit prune`. Final flags must be documented before CLI implementation.
Use the authority Linux account and existing keyring. The control account receives
only aggregate audit health through diagnostics, never audit records or export
privileges. Do not add a remote RPC or broaden the status socket protocol for export.

Start with stopped-authority export/prune using the existing runtime lock. This
makes snapshot boundaries and mutation ownership explicit. `audit info` reports
schema, retained range, storage usage/limits, and known coverage gaps. Runtime
status exposes cached audit health without opening storage or keyrings per request.

Export versioned JSON Lines into a newly created private file with no overwrite or
symlink following. Require an explicit output path, maximum record count (default
1,000, maximum 10,000), sequence cursor, and captured upper sequence bound. Stream
rows in bounded batches; do not materialize the full log. Include a manifest with
store ID, schema, requested/retained range, coverage gaps, count, completion state,
and continuation cursor. Detect cursors predating retention or from another store.

A completed export is plaintext sensitive operational metadata. An interrupted
export is visibly incomplete and must never look finalized. Export completion
means a finalized local artifact, not receipt by an external collector. Account for
the fact that the completion record occurs after the exported snapshot. Exporting
must not initialize missing state, contact NATS, or require worker credentials.

Do not claim tamper-proof or non-repudiable evidence: an authority account with its
keyring can alter local evidence. SQLCipher protects storage confidentiality; a
local checksum or hash chain alone cannot prove that history was not rewritten,
truncated, or rolled back. External anchoring is outside this milestone.

## 5. Verification and documentation

Required focused coverage:

- Typed schema compatibility, sanitization, bounded serialization, verified actor
  attribution, unknown identity handling, and timestamp rollback.
- Atomic mutation/event commit, rollback on audit insertion failure, crash before
  and after commit, and restart with incomplete external-effect intent.
- Denial floods, queue exhaustion, counter saturation, quota/reserve exhaustion,
  busy database, disk/write failure, missing/locked keyring, and corrupted state.
- Revocation and lease expiry under audit failure; no unauthorized admission or
  starvation of worker heartbeats, reconciliation, or status handling.
- Retention boundaries, restart-stable sequence/cursors, no overwrite, interrupted
  export/prune/migration, and rejection of invalid or incompatible policy/schema.
- Real separate-UID tests proving that worker and unrelated accounts cannot inspect
  records or export; plaintext secret sentinels absent from audit output/errors.
- Existing encrypted-state compatibility and preservation of diagnostic/validation
  semantics. Update audit coverage flags to describe actual bounded coverage.

Run the required formatting, warnings-denied Clippy, build/doctests, workspace units,
protected-state and Secret Service tests, retained integration/smoke suites, and all
four BYO-NATS cases. Keep compilation separate from bounded live execution. Measure
audit overhead and flood behavior without converting local measurements into
worst-case latency or memory guarantees. Cold hosted PR CI remains a merge gate.

Add `docs/operator/audit.md` with taxonomy, exact commands, privacy boundaries,
failure/overload behavior, retention/export procedure, and recovery guidance.
Update capacity, diagnostics, validation, role/storage contracts, threat model,
milestone index, and handoff where behavior changes. Keep the primary README
concise: add an audit guide link only when the feature exists.

## Delivery sequence and completion criteria

1. Finalize taxonomy, transaction map, failure matrix, numerical limits, and schema
   upgrade/export contract against existing capacity and role boundaries.
2. Implement encrypted storage and atomic registry events, including migration,
   quota, rollback, restart, and security-repair tests.
3. Instrument admission, control/reconciliation, and role transitions; integrate
   bounded denial aggregation and audit-health admission gating.
4. Implement authority-only inspection/export/prune and operator documentation.
5. Run adversarial and full regression gates; record local and hosted CI evidence.

Complete only when every promised event has a defined recording point and tested
failure behavior, retained evidence survives restart, loss/retention boundaries are
explicit, export stays within the authority trust boundary, and audit failure
neither opens admission nor prevents enforceable security reduction. Implementation is present in the working tree. Commit/push and release work have
not been performed.
