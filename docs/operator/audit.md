# Security audit evidence

The dynamic authority records version-1 JSON events in its existing SQLCipher auth
registry (auth schema 3). The registry key, authority Linux account, runtime lock,
and Secret Service remain the trust boundary. Workers receive aggregate cached
health in status; they cannot request records or export over IPC. Legacy static
fixtures and client message activity are outside this audit store.

Local evidence is editable by an authority account with its keyring. This is not
tamper-proof evidence, a trusted clock, non-repudiation, or a compliance assertion.
The registration transparency log remains a separate protocol facility.

## Stopped-authority commands

Run as the authority account with its existing unlocked keyring. Stop the authority
first; every command takes its runtime lock. No command contacts NATS or needs
worker credentials. Commands fail rather than provision missing state.

```sh
epochgrid-service --home HOME audit upgrade
epochgrid-service --home HOME audit info
epochgrid-service --home HOME audit export --output /PRIVATE/events.jsonl \
  --store STORE_ID --after 0 --upper UPPER_SEQUENCE --max-records 1000
epochgrid-service --home HOME audit retention --through SEQUENCE
epochgrid-service --home HOME audit prune --through SEQUENCE
epochgrid-service --home HOME audit prune --through SEQUENCE --apply
epochgrid-service --home HOME audit recover
```

`upgrade` explicitly migrates established schema 2 under the runtime lock. Migration
is additive and transactional; it preserves credentials and registry bindings.
Old binaries refuse schema 3. Read-only validation, info and export do not migrate.
Upgrade before production startup validation on an existing home.

Copy `store_id` and `upper_sequence` from info. `--after` is exclusive, `--upper`
is inclusive, and both are required. The default export limit is 1,000, maximum
10,000. Continue using the completion manifest's `continuation_cursor` and the same
upper bound. A foreign store or cursor predating retention is rejected.

Export reads an encrypted snapshot in batches of at most 256 rows. It creates a
0600 `OUTPUT.partial` file with exclusive creation, rejecting an existing file or
final-component symlink. A header says incomplete. After writing the bounded
snapshot, a completion footer records count and continuation. Only after syncing
the file is it linked to the requested output without overwrite. Treat **every
`.partial` file as incomplete**, even if it contains a footer. Keep or remove such
artifacts explicitly before retrying. The completed output is sensitive plaintext
metadata; protect its directory, backups and delivery. Completion means a local
artifact, not collector receipt. The export completion event follows the captured
snapshot and is not included in that snapshot. Export lifecycle records use the
repair/administration reserve. If even that reserve or writable storage is
unavailable, export still proceeds from readable established evidence, emits a
fixed warning, and declares incomplete coverage. Artifact completion never implies
that its lifecycle record persisted.

`retention` increments the policy version and explicitly authorizes a sequence
boundary for subsequent pruning. It does not delete. `prune` defaults to a dry run;
`--apply` deletes at most 256 eligible records in one transaction, recording the
new retained boundary atomically. Repeat to process larger ranges. No age policy,
silent overwrite, automatic deletion, or implicit export-to-delete authorization
exists. Sequences are never reused. Pruning does not guarantee physical erasure
from database pages, WAL, backups or prior exports.

## Fields and sensitivity

| Field | Meaning and sensitivity |
| --- | --- |
| version, kind, stage, outcome, reason | Fixed versioned taxonomy; operational security metadata |
| store_id, sequence | Random store identifier and store-local durable order; linkable |
| process_instance, operation | Random 128-bit process/correlation references; linkable |
| wall_seconds, timestamp_quality | Optional untrusted wall time; may move backward |
| actor | Local operator, verified device, bound worker, authority, or unverified input |
| actor_reference, target_reference | Optional random 128-bit references, never claimed names |
| generation | Committed authorization generation when applicable |
| sequence_boundary | Explicit retention or committed prune boundary; linkable sequence metadata |
| count, window_seconds | Bounded aggregate count and declared observation window |

User/device/group references are assigned in encrypted registry rows. They survive
restart and audit pruning, remain stable for that binding, and disappear with the
owning registry. Existing exports retain their references. These are linkable
metadata, not anonymous data. Unverified caller-provided identities never become
references. Absent attribution means unspecified, not an authenticated identity.

Events exclude credentials, JWTs, tokens/digests, key material, message/attachment
contents, payloads, names, NKeys, subjects, endpoints, filesystem paths and raw error
chains. SQLCipher covers records at rest, not plaintext export artifacts.

## Recording points and coverage

| Class | Recording point |
| --- | --- |
| Token issuance | Issuance commit, with local operator and opaque user target |
| Enrollment | Verified binding commit; exact retries have an explicit retry reason |
| Activation | First ready transition commits with its event; repeated ready checks are no-ops |
| Policy | Committed generation and verified signer; authenticated failures have rejection records |
| Admission | Successful decision and constructed encrypted response have correlated records; this does not prove delivery or client connection |
| Revocation | Publication intent/result and applied registry revocation; retries of an already revoked registry row are no-ops |
| Registration publication | Intent before publication and result afterward, separate from binding/activation |
| Reconciliation | Intent before consumer reconciliation, success/failure afterward; no MLS rekey claim |
| Runtime | Authority start, peer-authenticated worker session changes, reconciliation gate changes |
| Administration | Export attempt/result, retention policy version, prune boundary, storage recovery |

External effects use retained intent and existing idempotent reconciliation. Missing
results mean unknown. A failed result means the local call returned an error,
not proof that NATS performed no side effect. Intent is reused when repairing retained state; arbitrary
requests are not replayed from audit records. `unresolved_effects` reports pending
broker repair intents, including interrupted calls. Revocation enforcement and lease expiration do
not depend on successful audit writes.

Repeated unverified/malformed/overload denials are summarized in one constant-size
counter per ingress path, with 60-second windows and no attacker-selected labels.
A later observation flushes a completed window. Counts saturate at `u64::MAX`;
that value means a lower bound. Failed flushes are lost, and the next window starts
without consuming repair reserve. Runtime observations use a queue capped at 256;
maintenance drains at most 16 per batch. Queue losses appear in cached health.
Neither pending aggregates nor queued observations survive an unclean stop.

Coverage is deliberately reported as having known gaps: pre-upgrade activity,
unflushed aggregates, dropped observations and unavailable storage cannot be
reconstructed. `audit info` and export manifests never claim complete historical
coverage. Diagnostic counters remain approximate and their `audit_trail` coverage
flag stays false; a status report is not an audit export. Cached audit health may
be stale, reports its age, and does not open keyrings on status requests.

## Bounds and recovery

The budget is 100,000 retained events and 32 MiB of encoded JSON, with a 2 KiB
per-record maximum. Of this, 1,024 events and 2 MiB are reserved for repair and
administration. Index/page overhead also counts against the existing total database
limit; the default 16 MiB database recovery reserve is separate from the audit
payload reserve. Smaller installed database budgets can bind first.

Issuance, enrollment, activation and privilege-expanding policy updates roll back
if their event cannot persist. Device admission requires both decision and response
records before returning a grant. Authority/worker repair leases remain available
when audit storage fails. Privilege-reducing policy updates and revocation use an
audit savepoint: failure discards the event rather than the enforceable repair.
A failed registry commit is still a failed mutation.

Repair audit failure sets durable degraded metadata when the registry remains
writable, logs a fixed diagnostic, and closes ordinary recording. If storage itself
cannot accept metadata, no durable loss marker can be promised; cached health and
conservative gap coverage must not be interpreted as complete evidence. Restore
storage, explicitly prune eligible evidence if needed, then run `audit recover`.
Recovery verifies ordinary capacity, records recovery and clears the degraded flag;
it never clears historical coverage gaps. Do not reset the database or regenerate
keys to resolve audit exhaustion.

## Local qualification observations

On 2026-10-31, a temporary encrypted registry using the debug build and a disposable
Secret Service session recorded 1,000 standalone audit transactions: median 139 µs,
99th percentile 173 µs, maximum observed 380 µs. A subsequent 100,000 calls to the
in-memory denial aggregator took 2.758 ms and inserted zero rows before its window
elapsed. These measure those paths in a fresh local registry; they are not total
request latency, incremental application overhead, or worst-case guarantees.
Separate-UID BYO flood samples reported unchanged authority RSS around 38 MiB and
capacity collection rounded to 0 ms. Storage contention, full databases, different
hardware and deployment load can produce different results.
