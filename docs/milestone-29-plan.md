# Milestone 29 — resource bounds and overload behavior

**Implemented; locally validated. Cold hosted CI required before merge.** Work began on a clean workspace after consulting
`HANDOFF.md`. PR #21 merged as `a80be2e` on 2026-10-23; all checks in
[CI run 40032719883](https://github.com/epochgrid/epochgrid/actions/runs/40032719883)
passed. The implementation branch starts from `df23bb0`, including the merged
local testing documentation (#22). The plan below remains the acceptance scope;
see the [capacity contract](operator/capacity.md) for implementation choices and
[HANDOFF](../HANDOFF.md) for complete verification evidence and remaining CI gate.

## Outcome and scope

Make production resource consumption explicit and finite at application-owned
queues, state-growth boundaries and broker resources. At capacity, reject or defer
new work predictably, preserve previously accepted state and remain recoverable.
Document which bounds are hard enforcement and which are capacity estimates.
This is not a guarantee against host exhaustion or arbitrary denial of service.

Milestone 29 covers backend admission/control traffic, registry cardinality,
bounded reads and responses, client delivery queues, and operator-owned NATS
storage/consumer budgets. Milestones 30–31 retain operational diagnostics and
structured audit events; only errors and validation fields needed to operate these
limits belong here. Release packaging, dynamic attachments, retention deletion,
backend HA and TD-001/002/003 repairs remain separate work.

Preserve separate authority/worker UIDs and keyrings, narrow broker permissions,
verified TLS, SQLCipher, original request authorization, single-use enrollment,
MLS transaction semantics, revocation and restart repair. No runtime role gains
stream administration. Do not silently prune ciphertext, transparency records,
revocation evidence, MLS state or unacknowledged delivery intent to meet a quota.

## Baseline found in the code

| Area | Existing bound | Gap to address |
| --- | --- | --- |
| Wire/control | `wire::MAX_WIRE` is 65,536 bytes; signed policy membership is at most 128 | Aggregate responses and generated grants also need bounds before allocation/signing and before accepting state that cannot be represented |
| Authority IPC | 512 KiB frame, one queued operation, one in flight, five-second deadlines and worker lease | Broker subscription buffers, connection attempts, overload handling and recovery traffic need a coordinated budget |
| Auth Callout | Replay map capped at 4,096 entries with expiry | Cap is not a rate policy; distinguish overload from replay and bound limiter state without weakening replay rejection |
| Registry | Transactional enrollment/policy/revocation | Users, devices, groups, memberships, tokens and historical records can accumulate; some reads materialize whole collections |
| Client delivery | Durable transactional outbox; broker pull batch/pending limits of one | `delivery::flush_outbox` collects all unsent rows; local pending bytes/rows and durable history need an explicit capacity policy |
| Broker | Five pre-provisioned resources; 65,536-byte CHAT/MAILBOX messages | Generated storage/consumer defaults are unlimited; finite quotas are accepted without sizing certification; CHAT/MAILBOX use default discard behavior |

Primary code paths: `epochgrid-core/src/{auth_callout,identity_model,authorization,
delivery,history,transparency,revocation,deployment,transport}.rs` and
`epochgrid-service/src/{dynamic,roles}.rs`. Inventory the actual client-library
buffers and all query/response growth paths before choosing limit values.

## 1. Define a versioned capacity contract

Add a strict, public capacity configuration with finite production values and
checked units/ranges. Separate authority policy, worker queue limits, client-local
budgets and operator broker budgets; one role's file must not require another
role's secrets. Prefer explicit files integrated with existing initialization,
export and validation over independent environment-variable switches.

The contract must specify each limit's owner, enforcement point, scope, default,
hard ceiling, exhaustion result, restart behavior and upgrade rule. Include:

- Request bytes, response bytes, subscription queue messages/bytes, pending IPC
  work, connection setup and operation deadlines.
- Global request rate/burst and bounded authenticated-principal rate state.
  Unauthenticated requests consume a global budget; never allocate an unbounded
  map keyed by caller-controlled identities. A forwarding worker does not prove
  the identity named inside a request.
- Total retained users/devices/groups and membership edges, active devices per
  user, groups per device, outstanding enrollment tokens and historical evidence.
  Distinguish active counts from retained counts so revoke/re-enroll cannot bypass
  growth limits. Preserve the existing 128-member protocol ceiling.
- Pending client messages/bytes, bounded processing batches, total durable storage
  budget and capacity reserved for security/recovery operations.
- Finite byte budgets for all five broker streams and consumer counts derived
  from admitted devices, with account/server capacity remaining operator-owned.

Choose numerical defaults from measured fixture workloads plus explicit headroom,
then record them in the contract and independent tests. No automatic host-memory
guessing or claim of a supported deployment size before measurement. Small test
profiles must exercise exhaustion quickly without changing production ceilings.
Do not proceed past this slice with unspecified production defaults.

## 2. Bound ingress without weakening authorization or recovery

Apply cheap size/queue checks before decoding or expensive cryptography, and
authoritative per-principal checks only after identity verification. Configure
bounded NATS subscription buffers and measure their overflow behavior. Do not
solve overload by spawning a task per request or moving work to an unbounded queue.

Keep authority checks effective against a compromised worker; worker throttling
alone is not enforcement. Preserve the IPC frame/sequence contract and deny new
admission on lease loss or unfinished reconciliation. Define bounded handling for
socket accept floods and slow clients without allowing them to displace a live
authenticated worker.

Reserve bounded capacity for worker bootstrap/heartbeat, revocation and repair.
New enrollment or policy expansion must not consume the last recovery capacity.
Do not bypass signature checks, replay protection or the readiness gate to create
priority. If resource failure prevents repair, keep admission closed and expose an
actionable failure. Test that a flood cannot keep stale readiness alive.

Specify stable overload outcomes for each API: reject before mutation, retain
already-committed pending work, or fail closed. Do not describe a timeout as proof
that a mutation never happened. Preserve idempotent retries and prohibit automatic
replay of ambiguous operations. If a new wire error variant is needed, define and
test version compatibility before shipping it; do not silently reinterpret v1.

## 3. Enforce durable growth and bounded work

Enforce count/byte reservations in the same transaction as enrollment, group
creation, policy expansion or outbox insertion. Concurrent processes must not
both pass a preflight count and overshoot the quota. Idempotent retries must not
consume capacity twice; rejected enrollment must not consume its token.

Client queue rejection must roll back MLS advancement and delivery intent together.
Bound `flush_outbox` batches and database reads while preserving order, deduplication
and restart recovery. Bound temporary allocations as well as stored bytes. ACK
incoming messages only after required durable state is committed; at capacity,
pause or fail visibly without dropping required history or advancing a cursor.

Audit complete signed snapshots, revocation logs, device lists and generated
permission claims against wire limits. Never return a silently truncated signed
history. Either constrain admitted growth so existing formats remain representable,
including worst-case revocation headroom, or implement a separately versioned,
authenticated pagination protocol with client verification and compatibility tests.
Choose and document that strategy before expanding accepted registry capacity.

Define storage high-water checks and reserve behavior for database/WAL growth, but
do not claim a logical row budget is a hard filesystem-byte bound. Handle actual
disk-full/SQLCipher write failures transactionally, preserve established files and
document required operator disk quotas/headroom. Do not add unsafe automatic
vacuuming or evidence deletion. Revocation must remain possible at normal business
quota exhaustion; physical disk failure must fail closed with explicit recovery.

## 4. Export finite broker budgets and support stopped upgrades

Extend deployment artifacts and comparison rules to cover finite storage and
consumer budgets. For bounded CHAT/MAILBOX history, require explicit reject-new
behavior at capacity rather than eviction of accepted history. Preserve native KV
history-one semantics and verify finite-capacity replacement behavior separately.
Account for stream replicas, overhead and recovery headroom in the sizing guide;
logical `max_bytes` is not a physical disk guarantee.

Exercise actual broker quota rejection and ambiguous publish acknowledgments.
Keep pending outbox/projection work durable; do not report delivery success on
rejection. If required projections cannot be updated, retain closed admission.
Capacity increases are operator actions, followed by validation and reconciliation.
Runtime never edits quotas, deletes history or broadens its NATS grants.

Provide an explicit stopped-service upgrade from established encrypted M28 homes:
export the capacity artifact, inspect existing usage, apply operator resource
changes, validate both roles, then restart. Preserve keys, public identities and
registry state. Use versioned, atomic, no-clobber artifacts with identical retries;
test interruption and edited-artifact refusal. Reject a lower limit that existing
usage exceeds with actionable details rather than deleting data or resetting state.
Do not silently change existing deployment manifest semantics or defaults.

Offline validation checks schema, ranges and local usage without initialization.
Online authority validation checks declared broker budgets using existing narrow
permissions. Worker validation remains limited to its own state and authenticated
authority status; explicitly report checks that require operator credentials.
Capacity errors and diagnostic fields must not expose tokens, keys or plaintext.

## Validation and acceptance

1. Boundary tests at limit minus one, limit and limit plus one; malformed ranges,
   arithmetic overflow, concurrent reservations, idempotent retries, expiry and
   restart. Use deterministic clocks for rate logic.
2. Independent response/claim size fixtures using large valid registrations,
   memberships and revocation history. Verify representability before durable
   acceptance, including recovery headroom.
3. Saturate ingress and slow peers under real distinct UIDs/keyrings. Assert bounded
   queue/map sizes, bounded termination, fresh-admission closure and eventual
   recovery after load stops. Measure memory trends without treating RSS noise as
   a precise allocator guarantee. Assert explicit rejection where supported.
4. Fill local outbox/storage budgets; inject write/publish failures around commit
   and acknowledgment. Prove no MLS/outbox divergence, lost pending work, incorrect
   ACK, history eviction or token reuse. Reopen the same encrypted home to verify
   recovery; do not recreate the fixture to hide state loss.
5. Extend all four configuration/operator-JWT × R1/R3 BYO cases with finite budgets,
   quota exhaustion, operator capacity increase, validation and successful repair.
   Retain TLS, account isolation, broker failover, separate-role permissions,
   revocation and unchanged-operator-resource assertions.
6. Run the complete required quality/unit/protected-state/NATS/Compose/TUI/focused
   dynamic-join gates. Keep build separate from bounded execution. Add focused
   capacity cases with process cleanup, without automatic test retries or expanded
   quarantines. Require cold hosted CI before merge; TD-001/002/003 stay open.

## Delivery order

Deliver reviewable slices: capacity inventory/defaults and representation decision;
ingress/overload enforcement; transactional durable quotas and bounded client work;
broker artifacts/upgrade/validation; full matrix and operator documentation.
Update README, milestone index, role contract, threat model, storage/validation
guides and HANDOFF with measured evidence and limits at completion.

The milestone is complete when configured bounds are enforced at their documented
ownership boundaries, rejected work preserves state, recovery remains possible,
and the retained regression matrix passes. This plan does not implement, publish
or qualify an alpha release.
