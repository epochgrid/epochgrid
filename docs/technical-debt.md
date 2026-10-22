# Alpha technical debt

## TD-001 — Live typing indicators (deferred until after alpha milestones)

Local TUI use does not reliably display another participant's typing activity.
The typing smoke assertion also failed intermittently in CI. Adjusting the probe
cadence did not establish that the user-facing feature works reliably. The exact
runtime cause remains unresolved; synchronization delays and dropped transient
activity are candidates, not a confirmed diagnosis.

By explicit project decision, live typing start/stop assertions are disabled by
default in all TUI smoke modes. Each run prints a skip notice. Messaging, receipts,
attachments, service participation and the other TUI assertions remain enabled.
Encrypted ephemeral transport, tamper/replay protection, non-durability, expiry and
probe unit tests remain enabled. Runtime behavior is unchanged; users should not
rely on typing indicators. A green CI result does not certify this feature.

For investigation only, opt in with a bounded run:

```bash
python3 scripts/dev/run-bounded.py 180 python3 scripts/dev/tui-smoke.py --check-typing
```

After the alpha release milestones, either fix and validate sustained real-user
Alice/Bob typing under synchronization/reconnect load, then restore default live
coverage, or remove the typing UI feature. Do not close this debt solely because
a timing-sensitive smoke test passes once.

## TD-002 — Dynamic authorization live checks (deferred during MVP work)

The default CI/local gate temporarily excludes exactly
`auth_callout::dynamic_enrollment_inbox_isolation_revocation_without_reload`
and the full messaging mode of `dynamic-tui-smoke.py` (`dynamic-tui`). The focused
`dynamic-join` reconnect regression remains required. This is a coverage quarantine,
not a runtime fix.
All other 16 NATS integration cases, unit tests, static TUI modes, Compose,
formatting, Clippy and build checks remain required. Both exclusions print a
notice. A green gate does not certify dynamic enrollment, authorization expiry,
revocation without reload, or dynamic TUI messaging end to end.

### Evidence inspected on 2026-10-18

- [Run 35457276144](https://github.com/epochgrid/epochgrid/actions/runs/35457276144):
  the dynamic Auth Callout case returned `timed out`; 16 other cases passed.
  The same commit passed in PR run 35457319665. This was an operation timeout,
  not the suite watchdog. The prior consumer INFO retry did not resolve all
  subsequent failures.
- [Run 35459239811](https://github.com/epochgrid/epochgrid/actions/runs/35459239811):
  dynamic TUI failed waiting for `dynamic join`.
  [Run 35459237965](https://github.com/epochgrid/epochgrid/actions/runs/35459237965)
  failed waiting for `Bob to Alice`, with a retained draft and
  `sync before send timed out; retry after reconnect: deadline has elapsed`.
- [Run 35946618543](https://github.com/epochgrid/epochgrid/actions/runs/35946618543):
  the later pending-join fix still failed at `Bob to Alice` with the same
  send/sync error. Formatting, Clippy, unit, build, NATS, Compose and static
  TUI steps passed.
- [Run 35946616747](https://github.com/epochgrid/epochgrid/actions/runs/35946616747):
  exit 124 at the NATS suite's 360-second deadline while the final verified
  directory case was running. No preceding case failed; the dynamic case alone
  took roughly 90 seconds. Earlier successful suites spent about 329 seconds
  in tests plus 23 seconds compiling, leaving only about eight seconds of margin.
  The final directory test is not established as faulty and remains enabled.

The confirmed failure boundary is dynamic join/send synchronization under short
Auth Callout leases (three seconds in the integration case, six in the TUI).
The precise remaining runtime race is unresolved; logs do not establish whether
lease renewal, consumer recovery, or worker scheduling is responsible. Increasing
the TUI assertion wait cannot send a draft already retained after an error.
Serial compilation and tests sharing a tight deadline explain the separate suite
watchdog failure. Excluding the slow dynamic case restores budget headroom without
removing unrelated security checks or suppressing their failures.

### Investigation and restoration

After building the workspace, run the quarantined checks explicitly (failures
still return nonzero; both commands remain bounded):

```bash
./scripts/dev/verify.sh nats-dynamic
./scripts/dev/verify.sh dynamic-tui
```

Before closing this debt, instrument the exact failing admission/consumer/sync
operation; reproduce lease expiry during join and bidirectional send; fix recovery
without loosening authorization or revocation assertions. Demonstrate repeated
cold CI runs covering short leases, reconnect, offline history and revocation.
Separate compilation from the integration execution budget or isolate the dynamic
case in its own bounded phase before restoring it. Remove the NATS skip filter,
restore dynamic TUI in both CI and the default verifier, and update these docs.
The later pending-join fix from remote commit `bce2482` has been merged with this
quarantine. Its two unit tests and focused `dynamic-join` reconnect regression
remain enabled; the broader dynamic messaging failure is still unresolved.

## TD-003 — Test and CI reliability (post-MVP delivery focus)

Schedule a dedicated reliability pass after MVP delivery. Cover execution budgets,
fixture synchronization, disconnect/send behavior and failure diagnostics. This
item adds no exclusions and does not change existing release gates or the separate
TD-001/TD-002 restoration requirements.

### Evidence inspected on 2026-10-20

Milestone 25 [PR #15](https://github.com/epochgrid/epochgrid/pull/15), head
`d24e69b53b82a3cf11245982ed98f4a790d3ce38`, has seven CI attempts across its
push and pull-request runs: four NATS watchdog failures, one TUI assertion
failure, one cancellation, and one successful run.

- Push run [39315384951](https://github.com/epochgrid/epochgrid/actions/runs/39315384951)
  attempts 1, 2 and 5, and PR run
  [39315459339 attempt 1](https://github.com/epochgrid/epochgrid/actions/runs/39315459339/attempts/1),
  exit 124 at the verifier's 360-second NATS deadline. The preceding cases pass;
  the suite is still executing the live revocation case when killed. This is
  neither an individual assertion failure nor the workflow's nine-minute step
  limit. Compilation consumes about 25–26 seconds of the same budget.
- [PR attempt 2](https://github.com/epochgrid/epochgrid/actions/runs/39315459339/attempts/2)
  passes the complete default gate; NATS execution takes 254.72 seconds after
  18.05 seconds compiling. Push attempt 3 also passes all 16 retained NATS cases
  in 241.73 seconds. Slow attempts show broadly longer case durations, consistent
  with runner/resource or local dependency latency. The logs do not isolate CPU,
  disk, keyring or scheduling costs, and do not establish a GitHub outage or an
  SQLCipher correctness regression. The fixed combined budget is demonstrably
  unreliable across these executions; a passing rerun does not repair it.
- [Push attempt 3](https://github.com/epochgrid/epochgrid/actions/runs/39315384951/attempts/3)
  fails the main TUI assertion `offline encrypted queue` after its 25-second wait,
  before the 180-second phase watchdog. Alice's screen retains the unsent draft
  and reports `sync before send timed out; retry after reconnect`. The harness
  kills/waits for the broker and immediately sends, without waiting for client
  disconnect detection. `Action::Send` checks connection state and attempts a
  three-second membership sync when still connected; failure deliberately retains
  the draft instead of encrypting/persisting it. This exposes a disconnect/send
  timing race and a mismatch between the test's unconditional queue expectation
  and the application's failure behavior. A longer assertion wait cannot submit
  the retained draft. This static TUI case is distinct from quarantined TD-002.
- Push attempt 4 is cancelled; its job log returns `BlobNotFound`. Its cause is
  unclassified and is not counted as another proven timeout.

### Work and completion criteria

- Separate integration compilation from bounded test execution. Measure per-case
  and whole-job durations on cold runners, budget for observed variance, and split
  long phases where useful. Keep finite watchdogs and descendant cleanup; do not
  use blanket retries or additional skips to manufacture a green gate.
- Make established-offline queue tests wait for an observable offline state.
  Separately exercise sending during disconnect detection deterministically, with
  an explicit contract for retained drafts, user retry, persistence and exactly-once
  delivery. Preserve membership/revocation synchronization safety; do not bypass
  pre-send checks merely to satisfy the smoke assertion.
- Audit fixed sleeps, nested deadlines, readiness predicates and SQLCipher/Secret
  Service polling costs. Retain bounded, sanitized diagnostics identifying the
  case, operation, connection state and elapsed time at failure; distinguish
  assertion, operation timeout, phase watchdog and runner cancellation.
- Validate repeated cold CI runs and injected disconnect/latency cases. Record
  first-attempt failure rates and duration distributions before/after changes,
  with an agreed sample size and reliability target. Close only with repeatable
  evidence and regression coverage for the identified race, not one green rerun.
