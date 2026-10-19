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
and `dynamic-tui-smoke.py`. This is a coverage quarantine, not a runtime fix.
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
The latest inspected remote commit was `bce2482`; this checkout is `261bf68`.
The later pending-join change was inspected in CI logs, not imported here.
