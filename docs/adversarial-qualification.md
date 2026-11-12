# Adversarial qualification

Implementation started 2026-11-12; acceptance and scope review remain pending.
This is the evidence register for [milestone 35](milestone-35-plan.md), not an
alpha-readiness or release decision. [Technical debt](technical-debt.md) owns
TD-001/002/003. No risk disposition or narrower support scope is accepted here.

## Review against milestone 34

The plan remains viable. Milestone 34 supplies exact-byte bundle/image qualification,
source-bound native executables, bounded runners, qualification receipts and a
strict aggregate job gate. Reuse those mechanisms; signing and vulnerability scans
cannot qualify runtime behavior. Its pending protected environment, candidate
transport, vulnerability review and publication gates do not prevent local work
or qualification of unpublished candidates. No publication is part of this work.

Keep the proposed five independent first-attempt cold hosted runs, subject to
review before execution. The initial local runs below are diagnostics on Ubuntu
26.04. The separate [lock-repair record](archive/td-003-lock-validation.md) includes
warm Ubuntu 24.04 container verification. Neither counts as the cold hosted
sample. TD-002 remains quarantined even when an individual local run passes.

## Alpha acceptance boundary

The [plan's bounded acceptance rules](milestone-35-plan.md#bounded-alpha-acceptance)
own the stopping criterion. Qualify named invariants with representative hostile
inputs and recovery schedules. Do not promise all-scenario resistance or make every
possible test expansion an alpha gate. The 28 cases below remain required but are
not the final acceptance manifest; inventory the required gaps before freezing it.

| Work class | Alpha obligation | Stopping rule |
| --- | --- | --- |
| Trust boundaries | Named positive/negative and state-invariant cases for each matrix boundary; known security findings resolved | All required IDs pass; no unresolved reachable violation of a mandatory security invariant |
| Mode/topology differences | Four BYO modes; repeat attacks only where authorization/topology/isolation changes behavior | Recorded tests cover each distinct behavior; shared coverage has an equivalence rationale |
| Recovery | Representative pre-commit, committed/lost-response and restart schedules; named R3 quorum loss | Required schedules preserve grants, ratchets and accepted durable work; no exhaustive timing permutations |
| Parser testing | Deterministic edge/semantic tests for all inventoried families; wire and IPC seeded campaigns | Fixed seed, at most 4,096 mutations per target, 180s watchdog each, declared input and process memory limits; exhaustion cannot pass |
| Additional exploration | Up to two engineer-hours on concrete hypotheses after coverage mapping | Record work and findings; unexplored hypotheses become follow-up items, not automatic gates |
| Reliability/artifacts | Proposed five cold native runs with four BYO modes and selected faults; one complete final bundle/image qualification | Reviewed sample and exact-byte gates pass; no claim of statistical availability or security assurance |

A demonstrated reachable weakness, failed invariant or changed support boundary
can expand required coverage. Optional work becoming inconvenient is not grounds
to reclassify a known defect. Timeboxing discovery never waives security findings,
TD-002's restoration criteria or failed required cases. Future alpha reports need
reproduction, disposition and regression coverage; unknown risks remain limitations.

## Required deterministic cases

The executable inventory is [adversarial-cases.json](../scripts/ci/adversarial-cases.json).
It maps each stable ID to an exact libtest name. Build first with
`./scripts/dev/verify.sh build`. Reproduce any row with
`./scripts/dev/verify.sh adversarial ID`, replacing `ID` with its first column.
Each invocation has a 180-second process-group watchdog and temporary test state.
The two parser campaigns run without a keyring under a hard 512 MiB address-space
limit (`RLIMIT_AS`) and disabled core dumps. Other cases use disposable keyrings. Missing binaries, renamed cases and ignored
required cases fail before execution. The ordinary `verify.sh unit` gate checks
the same inventory and executes these tests once alongside retained regressions
(the two campaigns run in separate resource-limited processes within that gate);
there is no duplicate milestone-specific CI test suite.

These cases are topology-independent: their registry/database/parser/IPC invariants
apply to configuration and operator-JWT mode at R1/R3, but do not establish broker
integration in any of those four modes. Expected rejection is a passing assertion;
an assertion failure, timeout or fixture failure is not an expected rejection.

| ID | Actor, precondition and injection | Observable invariant and recovery |
| --- | --- | --- |
| AQ-ENROLL-01 | Enrollment client; valid invite and device; substitute binding, reuse token, disable/revoke identity | No unauthorized admission; exact retries retain binding; revocation survives restart |
| AQ-ENROLL-02 | Two clients with distinct signed registrations; barrier releases two registry connections against one token | Exactly one durable device; loser cannot redeem/admit; winner exact retry works after reopen and still requires activation |
| AQ-GROUP-01 | Admitted member; signed group policy; replay/conflict/remove/revoke | Policy generations and membership cannot broaden; persisted policy survives restart |
| AQ-DIRECTORY-01 | Directory substitute; trusted checkpoint; alter signer, prefix or signature | Reject rollback/tampering; do not accept an untrusted checkpoint |
| AQ-MLS-01 | Ciphertext sender; established MLS state; tamper/replay and reopen | Authentication and duplicate handling preserve ratchet/transcript behavior |
| AQ-TLS-01 | Misconfigured operator; transport options; malformed/insecure settings | Fail closed without insecure fallback |
| AQ-IPC-01 | Compromised worker after real Ready handshake; unknown operation, version, forged response/readiness, extra field, forbidden subject or malformed JSON | Session fails, readiness clears, no request reaches authority queue |
| AQ-IPC-02 | Compromised worker after Ready; send length and one payload byte, leave socket open | Five-second read deadline closes readiness without forwarding; six-second outer assertion deadline |
| AQ-IPC-03 | Compromised worker; replay sequence after Ready | Reject replay and clear readiness |
| AQ-IPC-04 | Worker with outstanding request; disconnect before response | Session/lease invalidated; late completion cannot be accepted |
| AQ-STATE-01 | Local corruption or wrong role/key metadata; established encrypted DB | Reject without resetting or modifying accepted state |
| AQ-CAPACITY-01 | Capacity exhaustion; pending bytes and SQLite full injection | Preserve accepted state and recovery reserve; explicit rejection |
| AQ-AUDIT-01 | Storage failure during activation/policy/revocation | Atomic state/audit behavior; no unaudited grant broadening |
| AQ-AUDIT-02 | Interrupted effect recording; reopen registry and flood denials | Pending evidence survives restart; denial storage stays bounded |
| AQ-DIAGNOSTICS-01 | Status requester; slow/unauthorized reader and status traffic | Private bounded reports; status never renews worker lease |
| AQ-CONFIDENTIALITY-01 | Stopped-file observer; synthetic markers in encrypted pages/WAL/journal | No plaintext markers; independent keys and restart behavior preserved |
| AQ-RECOVERY-01 | Process crash at existing test-only barriers | Invitation, ratchets, transcript and device lock recover without stale-state rollback |
| AQ-LOCK-01 | Unrelated child paused between fork and exec during credential provisioning; success and lost-response paths | Completed operation releases its lock before child exec; real contention rejects; exact retry keeps one protected key |
| AQ-LOCK-02 | Forked child drops a copied lock guard; another acquisition fails while parent owns lock | Child and failed acquisition cannot unlock a live parent; parent drop permits reacquisition |
| AQ-PARSER-01 | Unauthenticated wire bytes; truncation, trailing bytes, overlong lengths, size limits and seeded mutations | No panic; malformed boundaries rejected; accepted syntax round-trips; no storage involved |
| AQ-PARSER-02 | Compromised worker; 4,096 seeded JSON/payload-length mutations through the real Unix socket reader, prefix EOF and maximum valid frame | Framing/version checks hold; decoded semantics match bounded input; errors/panics/resource exhaustion fail the campaign; session authorization remains covered by AQ-IPC cases |
| AQ-APPLICATION-01 | Message sender; malformed relationship envelope, version, trailing bytes, oversized content and invalid IDs | Reject invalid application encoding and content before sending |
| AQ-ATTACHMENT-01 | Attachment sender; tamper, truncate, wrong group, expiry, hostile filename/MIME and limits | Reject unauthenticated or unsafe attachment; no key disclosure in rendering |
| AQ-ATTACHMENT-02 | Storage failure while indexing authenticated attachment | Roll back ratchet/index together, retry once, preserve index across restart |
| AQ-IMPORT-01 | Recovery import; altered header/tag, truncation, trailing bytes, oversized package and invalid secret | Reject before authenticated archive can be restored |
| AQ-IMPORT-02 | Restore into existing identity or injected transaction failure | Existing identity/group unchanged; partial restore rolls back and can be retried |
| AQ-CONFIG-01 | Operator deployment manifest; duplicate/unknown fields, versions and invalid replicas | Strict rejection; parser has no mutation side effects |
| AQ-REPORT-01 | Diagnostic peer; oversized, unknown-version/role or malformed report | Reject incompatible report; counters saturate without overflow |

The new concurrent-redemption and IPC tests assert state/authorization consequences,
not just process survival. They introduce no production fault hooks or wire changes.

## Deployment and fault coverage still required

Retain the existing integration commands, each after `verify.sh build`:

| Scope | Exact command | Budget and existing evidence boundary |
| --- | --- | --- |
| Configuration R1 | `./scripts/dev/verify.sh byo-nats configuration_standalone` | 260s case; production TLS, operator resources and separate UID fixture |
| Configuration R3 | `./scripts/dev/verify.sh byo-nats configuration_cluster` | 260s case; includes broker failover, not backend HA |
| Operator JWT R1 | `./scripts/dev/verify.sh byo-nats operator_jwt_standalone` | 260s case; account/resource and role separation assertions |
| Operator JWT R3 | `./scripts/dev/verify.sh byo-nats operator_jwt_cluster` | 260s case; retained failover-readiness failure remains TD-003 |
| Short leases, development fixture | `./scripts/dev/verify.sh nats-dynamic` | 120s download + 180s execution; admission/isolation/revocation/expiry, intentionally quarantined |
| Short leases, interactive client | `./scripts/dev/verify.sh dynamic-tui` | 180s execution; join, bidirectional send, offline history and ciphertext-only storage; intentionally quarantined |
| AQ-DELIVERY-01: lost publish confirmation | `./scripts/dev/verify.sh nats-security AQ-DELIVERY-01` | 180s case; reuses `resume_pending_invitation_and_ambiguous_publish`: publish before local sent marker, restart after broker dedup expiry, byte-identical resend and single transcript effect |
| AQ-DELIVERY-02: lost ACK | `./scripts/dev/verify.sh nats-security AQ-DELIVERY-02` | 180s case; reuses `durable_history_offline_ack_recovery_and_server_restart`: durable staging before deliberately omitted ACK, reopen/redelivery, no duplicate decryption and no pending ACK |
| Locked/unavailable Secret Service | `./scripts/dev/verify.sh secrets` | Independently bounded 30/60/120s cases; actual keyring boundary |
| TLS certificate rotation/trust | `./scripts/dev/verify.sh nats` | Retained exact TLS integration case, independently bounded 180s |

AQ-DELIVERY-01/02 are now required by retained-NATS discovery: removing either
case fails the partition check. They still execute once in the ordinary NATS gate.
These development fixtures establish local persistence/replay invariants; they do
not establish production dynamic admission across modes. The four BYO cases cover
that different boundary and already include bounded 512-request pressure, explicit
loss/rejection, broker CHAT/KV quota exhaustion, accepted-history preservation and
operator-controlled recovery. No duplicate flood/quota suite is required.

The matrix above maps reusable coverage, not complete milestone acceptance. Bound
the remaining required work as follows; existing cases can close a gap when their
assertions and recorded evidence establish it.

| Required gap | Sufficient alpha evidence | Additional depth deferred by default |
| --- | --- | --- |
| R3 quorum loss/restoration | Implemented in both existing R3 BYO cases: stop two nodes, authenticate to the survivor, require bounded publish failure, restore quorum, flush retained work and check exactly one transcript entry | Every node/route failure ordering and long network-chaos soak |
| Publish/ACK response loss | Mapped to AQ-DELIVERY-01/02 above; retain exact-case evidence on the candidate | Exhaustive timing offsets and simultaneous unrelated faults |
| Short leases | Named join/send/catch-up/revocation assertions and TD-002 investigation/restoration or reviewed enforceable scope decision | Every TTL and reconnect schedule |
| TLS trust | Expired certificate and untrusted discovered endpoint rejection through the actual connector; retain existing CA/name/rotation cases | Every certificate extension, CA product or rotation ordering |
| Quota/overload | Already implemented in all four BYO cases as described above; retain candidate evidence | Load-to-destruction benchmarking and every quota combination |
| Sensitive output | Fixed synthetic markers checked in broker payload/header/subject, service logs, encrypted DB/WAL/stopped files and captured diagnostics; terminal-control regression | Every output string, encoding transformation or side channel |
| Shipped runtime | A named hostile enrollment/request case and worker/role-boundary case through exact bundle/image entry points, with matched native semantic regressions | Repeating all topology-independent unit cases through packaged binaries |

Existing process-crash tests are not physical power-loss proof. Do not infer one
matrix row's four-mode coverage from a topology-independent test. The final
manifest must name the cases that close these gaps before sampling starts.

## Parser campaign

AQ-PARSER-01 uses an in-tree xorshift64 generator (seed `0x3520261112`), 4,096
mutations and five fixed starting inputs in `wire.rs`. Inputs are at most 131,072
bytes, with oversize rejection checked separately; mutated inputs are below 300
bytes. Engine/toolchain: ordinary Rust libtest, pinned workspace Rust 1.98.1.
AQ-PARSER-02 uses seed `0x3520261113`, 4,096 mutations and five JSON seeds.
Its largest payload is the 524,288-byte valid-frame boundary fixture; announced
lengths include `u32::MAX` and are rejected before payload allocation. Each campaign
has its own 180s watchdog and 512 MiB address-space limit. This is a per-process
virtual-memory ceiling, not a measured RSS bound or a system-wide memory guarantee.
Panic, allocation failure and deadline exhaustion fail; exceptions are not swallowed.
The limiter's regression deliberately exceeds a 64 MiB test budget and verifies
nonzero failure. Campaigns are excluded from the ordinary unit process only to run
once in their dedicated bounded processes; they remain mandatory in the same gate.
Successful syntax parsing is not authenticated admission. The local evidence
records source/corpus identity and duration; this small campaign is not a proof of
allocation safety or vulnerability absence.

Reachable parser inventory and coverage priorities. A separate mutation campaign
is not mandatory for every family; existing deterministic tests must still be
checked for their claimed boundary and state assertions.

| Parser | Current regressions | Required gap or optional follow-up |
| --- | --- | --- |
| Public postcard wire | AQ-PARSER-01 with memory/deadline enforcement | Optional: wider Body corpus and allocation profiling |
| Signed registrations/policies/checkpoints | AQ-ENROLL/GROUP/DIRECTORY; auth-callout negative claims | Required: verify mapping of negative semantic/state assertions; optional: seeded signed-record mutations |
| MLS/application/attachment envelopes | AQ-MLS-01, AQ-APPLICATION-01, AQ-ATTACHMENT-01/02 | Optional: additional seeded corpus |
| IPC JSON frames | AQ-PARSER-02 and AQ-IPC-01/02/03; existing oversize test | Optional: additional seeds |
| Configuration JSON | AQ-CONFIG-01; retained strict capacity/TLS tests | Operator-owned config file size is not a remote-frame guarantee; optional: combined mutation campaign |
| Recovery imports | AQ-IMPORT-01/02; authenticated import has no storage access until validated restore | Optional: seeded encrypted-import corpus |
| Machine reports | AQ-REPORT-01; retained release manifest/evidence negative fixtures | Optional: mutation corpus for every reader |

No additional parser exploration has been performed under the two-hour allocation.
Both parser campaigns passed locally under the declared budgets. Hosted acceptance
and the remaining non-parser gaps are still outstanding.

## Findings and scope decisions

| Finding | Severity / affected scope | Reproduction and evidence | Fix or mitigation, regression and disposition |
| --- | --- | --- | --- |
| AQ-F01 / TD-002 | Unresolved reliability/authorization coverage; intended dynamic scope blocked | Exact dynamic commands above; historical failures in [TD-002](technical-debt.md#td-002--dynamic-authorization-live-checks-deferred-during-mvp-work); two local passes do not reproduce cause | Instrument/reproduce exact failing operation, fix, then satisfy cold-run restoration criteria. Open; no scope exclusion or risk acceptance |
| AQ-F02 / TD-003 | Unresolved fixture/reliability; qualification evidence | Milestone 34 keyring failure and milestone 33 failover-readiness timeout retained in [TD-003](technical-debt.md#td-003--test-and-ci-reliability-post-mvp-delivery-focus) | Diagnose retained failures and run agreed cold sample. Open; no added skips |
| AQ-F04 / TD-003 | Initialization-lock lifetime defect; local native qualification | Original unit run: 115 core passed, one failed with `credential initialization already in progress`. Deterministic fork/exec barrier reproduces that error before the fix | Explicit owner-process unlock across all production locks; AQ-LOCK-01/02 required. See [repair evidence](archive/td-003-lock-validation.md). Broader TD-003 and hosted validation remain open; no retries, skips or serialized unit workaround |
| AQ-F03 | Required coverage gaps; all intended configurations | Required gap tables above; the optional follow-up column is not a gate | Close named required gaps, freeze acceptance manifest and retain shipped-byte evidence. Open; broader exploration stays in the backlog unless a concrete finding changes its priority |

No demonstrated new privilege escalation, confidentiality loss or durable-state
corruption has been dispositioned. Any such finding blocks its reachable supported
scope until fixed or explicitly reviewed and safely isolated. Baseline encryption,
TLS and authority/worker separation remain mandatory. TD-001 typing stays deferred.

## Handoff and evidence

See [local implementation evidence](archive/milestone-35-local-validation.md) for
the initial attempts and [bounded coverage evidence](archive/milestone-35-bounded-validation.md)
for the resource-limited campaigns, R3 quorum and delivery tests and retained
credential-lock failure. Both include failures before tests started. `run-bounded.py` distinguishes
watchdog timeout and cancellation from command failure; diagnosis must classify
command failures as assertion, operation timeout or setup failures from sanitized
evidence. No automatic retry is added. Runner cancellation without a receipt is a
missing required result, never success.

The existing CI `tests` job now requires the deterministic inventory through its
unit gate, so the existing milestone 34 aggregate gate also requires these cases.
TD-002 exclusions remain visible; this does not turn ordinary green CI into full
milestone 35 qualification. Final native, five bundle suites, five image suites and
image role-boundary proof plus the reviewed hosted sample remain outstanding.

Milestone 36 can reuse the inventory and seed corpus. This change alters no wire,
configuration or storage semantics. Supported scope is still proposed, not reviewed:
Ubuntu 24.04 x86-64, Secret Service, SQLCipher, separate authority/worker UIDs, local
peer-authenticated IPC, verified TLS, operator-owned NATS configuration/JWT R1/R3.
No feature exclusion has been used to waive a reachable failing path.
