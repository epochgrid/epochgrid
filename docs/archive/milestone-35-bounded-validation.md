# Milestone 35 bounded coverage implementation — 2026-11-12

Continuation of the [initial local record](milestone-35-local-validation.md), on
Ubuntu 26.04 x86-64, Rust 1.98.1. These are local diagnostics with uncommitted
changes, not the five-run hosted acceptance sample or final shipped-byte evidence.
No publication, settings change, quarantine removal or risk acceptance occurred.

## Changes and evidence boundaries

- Added AQ-PARSER-02: the real Unix IPC reader processes 4,096 deterministic
  JSON/length mutations, EOF/truncation fixtures and a maximum-size valid frame.
  Seed `0x3520261113`; corpus SHA-256
  `d8adc20795a4c326303680d3795adceda4046ec73b85f6ba928877d99eeac717`.
  The corpus uses ordered seeds prefixed by little-endian u64 byte lengths, as
  does AQ-PARSER-01. No new production parser or fault hook was introduced.
- Both campaigns now run once within the unit gate, each with a 180s watchdog,
  hard 512 MiB address-space limit and core dumps disabled. They need no keyring.
  Allocating beyond a separate 64 MiB regression budget returns failure, not pass.
  This bounds virtual memory per process, not aggregate machine RSS.
- Mapped seven existing application/attachment/import/config/report regressions;
  the mandatory enabled-unit inventory now has 26 IDs. Existing lost-publish and
  lost-ACK cases have focused AQ-DELIVERY-01/02 selectors and required discovery
  checks; they still execute once in the ordinary retained NATS gate.
- Added one R3 quorum-loss schedule to each existing BYO mode. After killing the
  leader and another broker, the fixture authenticates directly to the remaining
  broker, requires publish rejection/timeout within eight seconds, restores quorum,
  flushes durable work and asserts one recipient transcript entry. The direct
  connection prevents a merely disconnected producer from satisfying the test.
  Existing independent stream/consumer readiness predicates and deadlines remain.

## Retained failures and investigation

The first IPC campaign invocation hit sandbox `Operation not permitted` in its
socket fixture (5.050s wrapper, exit 101). The unchanged approved invocation passed
(0.164s wrapper). Wire passed at 0.032s under the new memory limit. This setup
failure is not counted as a passing first attempt.

The first ordinary unit gate failed in
`auth_callout::tests::isolated_worker_cannot_gain_authority_grants` with
`credential initialization already in progress`, caused by lock acquisition
returning would-block. Core result: 115 passed, one failed, three ignored and one
parser case partitioned separately; wrapper 19.977s. The gate correctly stopped
before the dedicated campaigns. The 512 MiB budget was not applied to that core
unit process. This is AQ-F04/TD-003, distinct from Secret Service locked/unavailable
errors. No bypass, retry, serialization or timeout increase was introduced.

One diagnostic gate ran under `strace -f -yy` restricted to `flock`, `clone`,
`clone3` and `close`, with a 300s outer watchdog and unchanged inner deadlines.
It passed in 107.582s. No credential-lock EAGAIN was observed in the trace. Tracing
changes scheduling, so this does not explain or fix the original failure. The
trace and raw logs remain local under `/tmp/epochgrid-m35-*`; retained evidence
excludes raw private paths and credential material. SQLCipher memlock warnings
were present, as in earlier local validation; no causal link was established.

The diagnostic gate ran 116 core, 20 service, 14 client and one registration test,
then the two dedicated campaigns: 153 top-level passes. Existing live-keyring and
broker ignored tests remain selected by their owning phases. Parser times under
tracing were 0.033s (wire) and 1.119s (IPC); do not compare these to untraced timings
as a performance estimate.

Initial quorum cases passed in configuration mode (97.691s) and operator-JWT mode
(104.575s). Review then tightened their assertions to require direct connectivity
to the surviving broker. Those earlier passes are retained diagnostics and are not
substituted for validation of the tightened cases. The final two R3 fixtures ran
in separate disposable containers concurrently; they are not cold hosted runs.

## Remaining acceptance

Final local results are bound to the source/executable/harness hashes in the
[machine record](milestone-35-bounded-evidence.json):

| Check | Final result |
| --- | --- |
| Tightened configuration R3 quorum schedule | Passed, 92.969s wrapper / 92.90s test |
| Tightened operator-JWT R3 quorum schedule | Passed, 105.431s wrapper / 105.34s test |
| AQ-DELIVERY-01 lost publish confirmation | Passed, 13.319s wrapper / 13.27s test |
| AQ-DELIVERY-02 lost ACK / staged replay | Passed, 40.865s wrapper / 40.79s test |
| Diagnostic unit gate under tracing | 153 top-level passes; original untraced failure remains AQ-F04 |
| Python harness | 77 tests passed, including campaign partition/failure and memory-limit enforcement |
| Build, formatting, Clippy and diff checks | Passed |

TD-002 and TD-003 remain open. Expired-certificate/discovered-endpoint cases,
completion of the fixed output-surface checks, shipped hostile-entry-point evidence,
final four-mode/artifact qualification, the reviewed cold sample and supported-scope
dispositions are still required. Optional broader fuzzing does not block alpha.
The acceptance manifest is not yet frozen. No new runtime wire/config/storage
semantics changed in this implementation pass.
