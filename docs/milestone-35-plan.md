# Milestone 35 — adversarial qualification and release scope

**Implementation started; acceptance and supported-scope review remain pending.** The
[roadmap](milestones.md) owns status. This plan precedes the
[milestone 36 compatibility freeze](milestone-36-plan.md): first establish which
behaviors withstand hostile inputs and operational failures, then freeze their
compatibility contracts. Neither plan declares alpha readiness.

### Implementation progress — 2026-11-12

Review against milestone 34 found the plan viable without waiting for publication.
The [qualification register](adversarial-qualification.md) maps 26 required existing
and new regressions, records remaining coverage gaps and keeps findings tied to
TD-002/003. New tests cover concurrent token redemption, malformed/stalled worker
sessions and bounded seeded public-wire mutations. The native unit gate rejects
missing or ignored inventory entries. Both quarantined dynamic commands passed
locally once; this does not establish a fix or satisfy restoration criteria.
See [local evidence](archive/milestone-35-local-validation.md). Hosted sample,
remaining fault/parser coverage, final artifact checks and scope review are pending.

The next implementation pass adds a 4,096-input IPC campaign, mandatory resource-
limited wire/IPC execution (512 MiB address space, 180s each), and R3 quorum-loss
recovery in both BYO auth modes. Existing lost-publish/lost-ACK and quota/flood cases
are mapped rather than duplicated. A new credential-initialization lock failure is
retained as AQ-F04/TD-003; local passing reruns cannot erase it.

## Outcome and boundaries

Deliver a threat-to-test matrix, deterministic fault regressions, bounded hosted
qualification, a findings register and a reviewed supported-scope decision. Tests
must check authorization and state invariants, not merely that processes survive
or eventually return success. Reuse the [threat model](threat-model.md), existing
[CI](ci-strategy.md), and owning operational contracts; correct stale claims when
evidence disagrees with them.

Keep Ubuntu 24.04 x86-64, Secret Service, SQLCipher, separate authority/worker UIDs,
local peer-authenticated IPC, verified TLS and operator-owned NATS. The core matrix
covers configuration and operator-JWT deployments at R1/R3. R3 broker failover
does not imply backend HA. Root/OS compromise, protection of a compromised client,
global transparency consensus, traffic-analysis resistance, remote backend roles,
new platforms and comprehensive power-loss/physical-disk guarantees remain outside
the current threat boundary. A compromised worker is explicitly inside the tested
boundary; authority compromise remains authorization compromise.

Implementation can start before milestone 34 publishes. Hosted tests may use
unpublished candidates with recorded digests; call them candidates, not releases.
Milestone 34 owns signatures, vulnerability review and distribution verification.
Milestone 35 supplies runtime security and reliability evidence; a dependency scan
or valid signature is not a substitute for it. No publication or settings change
is authorized by this planning document.

## 1. Define coverage and findings before running experiments

### Bounded alpha acceptance

The alpha claim is that the named security invariants withstand the recorded
adversarial cases in the supported configurations. It is not that every attack,
fault combination or unknown vulnerability has been ruled out. Completion requires
the finite acceptance set below, not exhaustion of possible scenarios.

- **Required regression coverage:** map every boundary in section 2 and every
  recovery class in section 3 to named tests with explicit state/authorization
  assertions. Reuse existing tests when they establish the invariant. Add cases
  for distinct failure behavior, not every byte value, timing offset or ordering.
  A passing rejection alone is insufficient where durable state or grants could
  have changed: assert the protected state too.
- **Deployment coverage:** run the four configuration/JWT R1/R3 integration modes.
  Repeat individual attacks across modes only when account authorization, broker
  topology or shipped runtime isolation changes the exercised boundary. Record
  the equivalence rationale for shared tests; do not require the Cartesian product
  of attacks, modes, topologies, process roles and fault timings.
- **Parser coverage:** retain deterministic malformed/boundary and authenticated
  semantic tests for each reachable parser family. Require seeded mutation campaigns
  for the public wire decoder and worker IPC framing only for this milestone;
  separate campaigns for every other parser are follow-up work unless evidence
  identifies a missing security invariant.
- **Exploration:** allocate at most two engineer-hours to additional adversarial
  exploration after mapping the required cases. Record targets, attempts and any
  findings. This budget is for discovery, not a deadline after which known defects
  become acceptable. Further exploratory depth goes to the backlog by default.

Before the cold sample, freeze a versioned acceptance manifest in the qualification
register: required IDs, exact commands, mode applicability, budgets and candidate
identity. The current 26-case inventory is a starting subset, not that completed
manifest. Changes require a recorded reason: a failed invariant, a demonstrated
reachable weakness, a newly exposed trust boundary or a changed support claim.
An imaginable scenario alone does not create a new alpha gate. Never remove a
failed required case simply to make the manifest pass.

Stop when this manifest passes the agreed sample and final artifact gates, all
required coverage gaps are closed, and findings have permitted dispositions.
Broader parser campaigns, long soaks, arbitrary multi-fault combinations and attacks
outside the stated threat boundary are not completion requirements. Unknown risks
remain explicit in the alpha limitations and subsequent reports become regression
cases; a claim of adversarial qualification is not a warranty of security.

Create `docs/adversarial-qualification.md` during implementation. Each case needs a
stable ID, threat/actor, supported mode, precondition, injection point, observable
invariant, finite deadline, expected recovery and exact test command. Map existing
tests first, then implement missing coverage; avoid duplicating successful tests
under a new milestone name. Record coverage gaps explicitly.

Create a findings register in that document with severity, reproduction, affected
scope, evidence, proposed fix/mitigation, regression and disposition. Link TD items
instead of forking their status. Distinguish assertion failure, expected rejection,
operation timeout, phase watchdog, fixture/setup failure and runner cancellation.
All attempts count as evidence, including failures before the application starts.

Unresolved privilege escalation, confidentiality loss, unsafe state/ratchet reuse
or corruption of accepted durable state blocks the affected supported scope.
Dispositions are fix-and-verify, explicitly reviewed scope exclusion, or explicitly
reviewed residual risk with rationale and operator consequences. No automatic risk
acceptance; failed tests cannot silently redefine support. Excluding a feature does
not excuse an exploitable reachable path in a supported deployment: disable/isolate
that path safely or fix it. Baseline encryption, TLS and authority/worker separation
cannot be waived to pass qualification.

## 2. Adversarial test matrix

| Boundary | Cases and required invariants |
| --- | --- |
| Enrollment and identity | Forged/expired/reused enrollment token, wrong nonce/key/account/device binding, concurrent redemption, invalid registration signature/KeyPackage and revoked identity. No unauthorized registry entry, claim, consumer or durable admission; legitimate exact retries follow the existing idempotency contract. |
| Group authorization and revocation | Stale/conflicting policy generations, replayed Welcome relay, wrong coordinator, cross-group/inbox/consumer access and revocation during reconnect. No grant broadening; measure existing-claim expiry separately from new-admission rejection and future-epoch MLS exclusion. Already delivered ciphertext cannot be recalled. |
| Directory and MLS processing | Checkpoint rollback/signer substitution, altered signatures, malformed/truncated/oversized ciphertext, wrong group/epoch/sender and invalid membership transitions. No unauthenticated state advancement; quarantine and ACK/staging behavior match the protocol. TOFU and split-view limits remain explicit. |
| TLS and broker trust | Wrong CA/name, expired certificate, reconnect after rotation, untrusted discovered endpoint, incorrect account/resource configuration and attempted insecure fallback. Verification remains enabled; bad setup fails without repairing operator resources. |
| Compromised worker and IPC | Wrong UID, forged readiness/completion, replayed sequence, unknown operation, oversized/partial frame, stalled peer and authority restart. Worker cannot read authority files/keyring, sign, mutate registry or gain broker administration; stale leases cannot open admission. Status traffic cannot renew a lease. |
| Protected local state | Locked/missing keyring, wrong database key/role binding, corrupt/truncated database, concurrent process and write failure. No plaintext fallback, credential regeneration or destructive reset. Read-only validation creates/migrates nothing. |
| Capacity and overload | Registry/outbox/audit limits, request floods, slow consumers, full broker quotas and bounded database-write failure. Finite queues/work, preserved accepted state, explicit rejection and recovery; no partial signed snapshot or silent eviction. Logical bounds are not physical RAM/disk guarantees. |
| Audit and diagnostics | Failed audit persistence, pending-effect recovery, unauthorized export/status, slow status reader and injected sensitive error content. Preserve documented audit coverage/gap semantics and access boundaries; no secrets in captured reports. |
| Confidentiality and output | Synthetic plaintext/key markers across broker payloads/headers/subjects, service logs and stopped files; encrypted database/WAL behavior; terminal-control injection. Markers detect regressions, not all transformed leaks or cryptographic insecurity. |

For each row, identify which assertions depend on NATS mode or topology and cover
those differences. Local parser/database tests need not run four identical times:
the coverage map must state which tests are topology-independent and which
integration cases prove each deployment mode.
Retain development/static regressions without treating them as evidence for dynamic
operator deployments.

## 3. Fault injection and same-version recovery

Inject faults at observable transitions using barriers/test hooks rather than
unbounded sleeps. Keep hooks test-only or inaccessible in production operation.
Use isolated disposable homes, brokers and keyrings; never corrupt operator state.
Bound and clean up every child process, including on failure.

Use one deterministic schedule per materially different persistence or authority
transition below. Cover pre-commit rejection, committed work with lost confirmation,
and recovery after restart; do not enumerate every instruction boundary or combine
independent faults exhaustively. R3 quorum loss/restoration is a named required
compound fault; other combinations require evidence that single-fault coverage
misses a distinct invariant.

- Disconnect before send, after local commit, before/after broker publish response
  and around confirmed ACK. Distinguish volatile retained drafts from durable
  outbox entries. Exact retries preserve stored ciphertext and message identity;
  duplicate delivery must not duplicate local decryption/transcript effects.
- Kill/restart client, authority and worker around transaction/reconciliation
  boundaries. Admission remains closed until real reconciliation and worker lease
  readiness; restart does not grant authority to an untrusted reply.
- Exercise short lease expiry during join, bidirectional send, offline catch-up
  and revocation. Preserve pre-send membership checks; longer waits must not mask
  a draft that requires explicit user retry.
- Restart the standalone broker and interrupt an R3 leader/route, including loss
  of quorum and restoration. Check bounded failure while unavailable, explicit
  readiness and safe resumption; do not infer uninterrupted availability.
- Inject transactional storage failures and interrupted audit/effect recording.
  Assert atomicity, retained evidence and documented recovery without rolling back
  active MLS state to a stale snapshot. Process-kill tests are not power-loss proof.

These cases use one application revision. Milestone 36 owns old/new binary pairs,
schema/configuration migrations, downgrade refusal and version-specific reference
bytes. Share fault hooks and invariant assertions; do not maintain competing suites
or introduce a migration solely to complete milestone 35.

## 4. Malformed input and bounded fuzzing

Inventory reachable parsers: public postcard wire, signed record verification,
application/attachment envelopes, IPC frames, configuration JSON, recovery imports
and machine report readers. Add deterministic malformed/boundary regressions plus
bounded seeded mutation or fuzz targets where they add coverage. Preserve crashing
inputs and minimize them into regression fixtures. A harness must fail on panic,
hang, uncontrolled allocation or unintended mutation, not swallow exceptions.

Set input and execution budgets before runs; record engine/toolchain, corpus hash,
seed, duration and results. Fuzzing supplements authenticated semantic tests and
does not prove absence of vulnerabilities. Reuse the corpus in milestone 36, which
will add independently reviewed canonical expected bytes and historical fixtures.

Initial acceptance budgets are one fixed seed and at most 4,096 generated inputs
per wire/IPC campaign, each under a 180-second watchdog. Record maximum input size
and a finite process memory limit appropriate to the harness before execution;
budget exhaustion is a failed/incomplete campaign, not a pass. Deterministic edge
fixtures are additional to the generated inputs. Expanding seed counts, adding
coverage-guided fuzzing or fuzzing each parser family is optional follow-up unless
a concrete finding requires a regression. Do not describe the existing wire test's
input bound alone as a process memory limit.

## 5. Reliability evidence and existing debt

Honor [technical debt](technical-debt.md) restoration criteria:

- TD-001 typing remains deferred until after alpha milestones. Preserve enabled
  ephemeral security tests and the explicit typing exclusion; this milestone does
  not reopen or close that UI work.
- TD-002 investigation is required because it affects the intended dynamic scope.
  Explicitly run `verify.sh nats-dynamic` and `verify.sh dynamic-tui` after building.
  Reproduce/instrument the race and restore default coverage only after the debt's
  full criteria pass. If unresolved, the intended dynamic scope remains blocked
  unless an explicit narrower scope decision is reviewed and safely enforced.
  Do not simply label short leases unsupported while leaving the same admitted
  configuration or untested expiry/reconnect behavior in the claimed scope.
- TD-003 adds no skips. Investigate retained keyring and failover failures as well
  as disconnect/send and execution budgets. A fixture failure requires a diagnosis
  or an explicit unresolved finding, not deletion from the sample.

Proposed acceptance sample: five independent cold hosted runs on one unchanged
candidate, each with retained regressions and the selected adversarial matrix;
all required cases must pass on their first attempt. Include the four BYO modes
and selected deterministic fault schedules in every run. Record every attempt,
first-attempt failure counts and per-case/phase duration distributions. A failure
blocks that sample: diagnose it, add a regression/fix as appropriate, and start a
new sample on the revised candidate while retaining the old results. A green rerun
alone cannot replace the failed attempt. Review this sample target before execution;
five passes are an acceptance exercise, not a production availability estimate or
automatic closure of TD-003.

Run the fixed native acceptance manifest, four BYO modes and selected fault schedules
in each of those five runs. Qualify the exact final bundle/image once with their
existing complete suite sets and role-boundary proof; do not multiply all artifact
suites by five. Reuse milestone 34 evidence only when candidate identity, commands
and required assertions match. Missing evidence still requires execution.
The sample size remains subject to the pre-execution review; this scope clarification
does not accept findings or authorize publication.

## 6. Delivery, CI and handoff to milestone 36

1. Map threats to current tests and decide the intended supported feature set.
2. Add deterministic security/fault regressions and bounded parser campaigns;
   fix demonstrated defects without weakening authorization assertions.
3. Integrate required cases into the aggregate CI gate, with missing, skipped or
   cancelled required cases failing qualification. Existing quarantines remain
   visible pending their explicit restoration or approved scope decision.
4. Run native regressions and the cold-run sample. Qualify the final exact bundle
   and image with all five suites each and the image role-boundary proof; exercise
   applicable adversarial entry points against shipped binaries too. Record source,
   run/attempt, toolchain/configuration, seeds, archive/image digests and sanitized
   results. Do not reuse earlier candidate evidence after relevant changes.
5. Publish the reviewed scope matrix and finding dispositions in the repository,
   with dated evidence and links to owning debt/contract documents. This is the
   input to milestone 36, not a compatibility freeze or release publication.

The handoff must identify supported/excluded features and configurations, enforced
restrictions, tested invariants, unresolved risks, candidate identities, required
CI cases and any security fix that changes wire/configuration/state semantics.
Milestone 36 must preserve these invariants while defining compatibility. If its
work changes authorization, parser behavior or state handling, rerun affected
milestone 35 checks on the new candidate and update evidence/dispositions. No full
milestone restart is required for unrelated documentation changes.

## Completion checklist

- [ ] Threat-to-test coverage and exclusions are reviewed, including both NATS
      modes, R1/R3 and actual shipped runtime boundaries.
- [ ] A finite acceptance manifest is frozen, with equivalence rationales, campaign
      budgets and required-versus-follow-up gaps; exploratory time is recorded.
- [ ] Required security, malformed-input and fault cases run with finite budgets
      and assert state/authorization invariants.
- [ ] Findings affecting supported scope are fixed and verified or explicitly
      dispositioned; core security invariants remain mandatory.
- [ ] TD-002 restoration or an explicit enforceable scope decision is recorded;
      TD-001 stays deferred and TD-003 is assessed by its own criteria.
- [ ] Cold hosted sample and final native/bundle/image gates have retained evidence;
      failures and skipped coverage remain visible.
- [ ] Supported-scope matrix and semantic-change list are handed to milestone 36;
      threat model and operational limitations agree with the evidence.

Completion qualifies only the recorded scope and revision. Milestones 36–38 and
milestone 34's distribution gates still govern compatibility and release readiness.
