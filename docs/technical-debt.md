# Technical Debt Consolidation Report

This document consolidates all known technical debt items (TD-XXX) across the EpochGrid codebase, documentation, and CI workflows. All references to defer redactions, quarantine notices, skip notes, and evidence are centralized here as a single source of truth.

---

## Summary of Open Technical Debt Items

| ID | Status | Category | Impact |
|----|--------|----------|--------|
| TD-001 | Deferred | UI Reliability | Live typing indicators unreliable; disabled by default |
| TD-002 | Quarantined | CI/Authorization | Dynamic auth callout under short lease; excluded from default CI gates |
| TD-003 | Post-MVP | CI Reliability | Test execution budget variance; timing-sensitive failures |

**Last Updated**: 2026-10-20  
**Reference**: See [release notes](/docs/milestone-27-plan.md) for milestone-specific impacts.

---

## TD-001 — Live typing indicators (deferred until after alpha milestones)

### Description
Local TUI use does not reliably display another participant's typing activity. The typing smoke assertion also failed intermittently in CI. Adjusting the probe cadence did not establish that the user-facing feature works reliably. The exact runtime cause remains unresolved; synchronization delays and dropped transient activity are candidates, not a confirmed diagnosis.

### Current State
By explicit project decision, live typing start/stop assertions are **disabled by default** in all TUI smoke modes. Each run prints a skip notice:

```text
SKIP TD-001: live typing assertions disabled; see docs/technical-debt.md
```

Messaging, receipts, attachments, service participation and the other TUI assertions remain enabled. Encrypted ephemeral transport, tamper/replay protection, non-durability, expiry and probe unit tests remain enabled. Runtime behavior is unchanged; users should not rely on typing indicators. A green CI result does not certify this feature.

### Investigation Path
For investigation only, opt in with a bounded run:

```bash
python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py --check-typing
```

### Fix Criteria
After the alpha release milestones, either:
1. Fix and validate sustained real-user Alice/Bob typing under synchronization/reconnect load, then restore default live coverage; **or**
2. Remove the typing UI feature entirely.

Do **not** close this debt solely because a timing-sensitive smoke test passes once.

### Locations (References)
- `docs/ephemeral-events.md`: Live typing assertions disabled by default
- `docs/milestones.md`, `docs/development.md`: TD-001 status documented
- `README.md`, `SECURITY.md`: Typing UI unreliability noted in docs
- `scripts/dev/tui-smoke.py`: Check-typing flag with skip notice

---

## TD-002 — Dynamic authorization live checks (deferred during MVP work)

### Description
The default CI/local gate excludes the following:
1. `auth_callout::dynamic_enrollment_inbox_isolation_revocation_without_reload`
2. The full messaging mode of `dynamic-tui-smoke.py` (`dynamic-tui`)

This is a **coverage quarantine**, not a runtime fix. The focused `dynamic-join` reconnect regression remains required. All other 16 NATS integration cases, unit tests, static TUI modes, Compose, formatting, Clippy and build checks remain required. Both exclusions print a notice:

```text
SKIP TD-002: dynamic Auth Callout integration; run verify.sh nats-dynamic explicitly
SKIP TD-002: full dynamic TUI messaging smoke; run verify.sh dynamic-tui explicitly
```

A green gate does not certify dynamic enrollment, authorization expiry, revocation without reload, or dynamic TUI messaging end to end.

### Evidence Inspected (2026-10-18 to 2026-10-20)

#### Run #35457276144
- **Issue**: The dynamic Auth Callout case returned `timed out`
- **Context**: 16 other cases passed
- **Analysis**: Operation timeout, not the suite watchdog. The prior consumer INFO retry did not resolve all subsequent failures
- **Link**: <https://github.com/epochgrid/epochgrid/actions/runs/35457276144>

#### Run #35459239811
- **Issue**: Dynamic TUI failed waiting for `dynamic join`
- **Related**: Run #35459237965 also failed at `Bob to Alice` with `sync before send timed out; retry after reconnect: deadline has elapsed`
- **Link**: <https://github.com/epochgrid/epochgrid/actions/runs/35459239811>

#### Run #35946618543
- **Issue**: The later pending-join fix still failed at `Bob to Alice` with the same send/sync error
- **Status**: Formatting, Clippy, unit, build, NATS, Compose and static TUI steps passed
- **Link**: <https://github.com/epochgrid/epochgrid/actions/runs/35946618543>

#### Run #35946616747
- **Issue**: Exit 124 at the NATS suite's 360-second deadline while the final verified directory case was running
- **Analysis**: No preceding case failed; the dynamic case alone took roughly 90 seconds. Earlier successful suites spent about 329 seconds in tests plus 23 seconds compiling, leaving only about eight seconds of margin
- **Link**: <https://github.com/epochgrid/epochgrid/actions/runs/35946616747>

### Confirmed Failure Boundary
Dynamic join/send synchronization under short Auth Callout leases (three seconds in the integration case, six in the TUI). The precise remaining runtime race is unresolved; logs do not establish whether lease renewal, consumer recovery, or worker scheduling is responsible. Increasing the TUI assertion wait cannot send a draft already retained after an error.

### Investigation and Restoration
After building the workspace, run the quarantined checks explicitly (failures still return nonzero):

```bash
./scripts/dev/verify.sh nats-dynamic
./scripts/dev/verify.sh dynamic-tui
```

#### Work to Complete Before Closing This Debt
1. Instrument the exact failing admission/consumer/sync operation
2. Reproduce lease expiry during join and bidirectional send
3. Fix recovery without loosening authorization or revocation assertions
4. Demonstrate repeated cold CI runs covering short leases, reconnect, offline history and revocation
5. Separate compilation from the integration execution budget or isolate the dynamic case in its own bounded phase before restoring it
6. Remove the NATS skip filter, restore dynamic TUI in both CI and the default verifier, and update these docs

The later pending-join fix from remote commit `bce2482` has been merged with this quarantine. Its two unit tests and focused `dynamic-join` reconnect regression remain enabled; the broader dynamic messaging failure is still unresolved.

### Locations (References)
- `.github/workflows/ci.yaml`: Skips dynamic authorization checks in default CI
- `scripts/dev/verify.sh`: Skip notes for `nats-dynamic` and `dynamic-tui` subcommands
- `docs/operator/auth-callout.md.md`: Dynamic walkthrough; TD-002 status noted
- `docs/byo-nats`, `README.md`, `HANDOFF.md`: References to quarantine status

---

## TD-003 — Test and CI reliability (post-MVP delivery focus)

### Description
Schedule a dedicated reliability pass after MVP delivery. Cover execution budgets, fixture synchronization, disconnect/send behavior and failure diagnostics. This item adds no exclusions and does not change existing release gates or the separate TD-001/TD-002 restoration requirements.

### Evidence Inspected (2026-10-20)

#### Milestone 25 PR #15 Analysis
Head `d24e69b53b82a3cf11245982ed98f4a790d3ce38`, has seven CI attempts across its push and pull-request runs.

- **Push run #39315384951**: Attempts 1, 2 and 5 show exit 124 at the verifier's 360-second NATS deadline. The preceding cases pass; the suite is still executing the live revocation case when killed. This is neither an individual assertion failure nor the workflow's nine-minute step limit. Compilation consumes about 25–26 seconds of the same budget
- **Push run #39315384951 attempt 3**: Passes all 16 retained NATS cases in 241.73 seconds
- **PR run attempt 2**: Passes in 254.72 seconds after 18.05 seconds compiling (after first failure)
- **PR run attempt 4**: Cancelled; log returns `BlobNotFound`. Cause unclassified

> The fixed combined budget is demonstrably unreliable across these executions; a passing rerun does not repair it.

#### Offline Encrypted Queue Test Failure
Push attempt 3:
- Fails the main TUI assertion `offline encrypted queue` after its 25-second wait, before the 180-second phase watchdog
- Alice's screen retains the unsent draft and reports `sync before send timed out; retry after reconnect`
- The harness kills/waits for the broker and immediately sends, without waiting for client disconnect detection
- `Action::Send` checks connection state and attempts a three-second membership sync when still connected; failure deliberately retains the draft instead of encrypting/persisting it
- This exposes a **disconnect/send timing race** and a mismatch between the test's unconditional queue expectation and the application's failure behavior

> A longer assertion wait cannot submit the retained draft. This static TUI case is distinct from quarantined TD-002.

### Work and Completion Criteria
1. **Separate integration compilation from bounded test execution**: Measure per-case and whole-job durations on cold runners, budget for observed variance, and split long phases where useful. Keep finite watchdogs and descendant cleanup; do not use blanket retries or additional skips to manufacture a green gate
2. **Established-offline queue tests must wait for observable offline state**: Separately exercise sending during disconnect detection deterministically, with an explicit contract for retained drafts, user retry, persistence and exactly-once delivery. Preserve membership/revocation synchronization safety; do not bypass pre-send checks merely to satisfy the smoke assertion
3. **Audit fixed sleeps and timeouts**: Nested deadlines, readiness predicates and SQLCipher/Secret Service polling costs. Retain bounded, sanitized diagnostics identifying the case, operation, connection state and elapsed time at failure; distinguish assertion, operation timeout, phase watchdog and runner cancellation
4. **Validate repeated cold CI runs**: Inject disconnect/latency cases. Record first-attempt failure rates and duration distributions before/after changes, with an agreed sample size and reliability target. Close only with repeatable evidence and regression coverage for the identified race, not one green rerun

### Locations (References)
- `docs/milestones.md`: TD-003 mentioned in milestone planning
- `.github/workflows/ci.yaml`: Timing budget considerations

---

## Additional Technical Debt Notes

### General References Across the Codebase

| File | Section/Context | Note |
|------|-----------------|-------|
| `README.md` | Lines 10, 349, 378 | Live typing UI deferred (TD-001); dynamic authorization checks skipped (TD-002) |
| `SECURITY.md` | Line 174 | Typing UI unreliability noted; link to milestone status |
| `HANDOFF.md` | Lines 42, 78–80 | Technical debt boundaries and resource ownership preserved |
| `docs/milestones.md` | Multiple places | Status of TD-001/002/003 across releases |
| `docs/milestone-27-plan.md` | Lines 26, 185 | Post-MVP priorities; TD-003 work scheduled |
| `docs/development.md` | Multiple places | Development workflow impact of each TD item |
| `.github/workflows/ci.yaml` | Lines 46–47 | CI skip notices for deferred cases |
| `scripts/dev/verify.sh` | Lines 35, 54 | Verify script subcommands and skip logic |
| `scripts/dev/tui-smoke.py` | Multiple places | Typing check opt-in flag and skip behavior |

### Important Distinctions

**TD-002 vs TD-003**: These are distinct issues with different remediation paths:
- TD-002 specifically addresses the **dynamic Auth Callout lease timing race** (short leases causing failures)
- TD-003 more broadly covers **CI execution budget variance** including disconnect/send behavior, fixture synchronization, and failure diagnostics

The offline encrypted queue failure (TD-003 case #3 in PR #15) is **distinct from the dynamic messaging race** (TD-002). Do not merge these issues during resolution.

### Current Release State Summary (as of 2026-10-20)
- Default CI gate excludes TD-002 case (`dynamic-tui` and `nats-dynamic`)
- TUI smoke prints skip notices for TD-001 typing checks by default
- TD-003 adds no exclusions; it is a post-MVP reliability improvement item
- A passing green CI result does not certify complete feature coverage for any TD item

---

## See Also
- [Milestone Status](/docs/milestones.md) — Timeline of alpha/MVP releases and debt tracking
- [Operator Guide: Auth Callout](/docs/operator/auth-callout.md) — Dynamic walkthrough and usage notes
- [Milestone 27 Plan](/docs/milestone-27-plan.md) — Post-MVP priorities including TD-003 work
