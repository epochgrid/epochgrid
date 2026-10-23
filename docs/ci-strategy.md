# CI strategy review — 2026-10-22

The full suite is **PR-only** and cancels superseded runs for the same PR.
**One build is shared by isolated execution jobs**, with compilation outside test
watchdogs. Increasing test-thread
counts or retrying failed suites is not the first remedy for the observed failures.

This review covers `.github/workflows/ci.yaml`, `scripts/dev/verify.sh`, the bounded
runner/keyring harnesses, the TUI disconnect/send path, and recent Actions results.
It is a CI cleanup between milestones 27 and 28, not a claim that TD-001, TD-002 or
TD-003 is resolved.

## Applied in this patch

- Trigger on PR `opened`, `synchronize` and `reopened`; remove `push`. Branch
  pushes without a PR and merges into `main` no longer schedule this full gate.
  Updating a branch with an open PR still runs the suite through `synchronize`.
- Group concurrency by workflow name and PR number, with `cancel-in-progress`.
  A newer revision supersedes the older run for that PR; separate PRs remain
  independent. Draft PRs retain the same coverage.
- Preserve required `validate` and four `byo-nats (case)` check names. `validate`
  now aggregates build, suite matrix and BYO outcomes with `always()`; failed,
  cancelled or skipped prerequisites cannot produce a passing gate. BYO jobs
  explicitly fail if their shared build failed.
- Retain read-only permissions, pinned actions, existing test coverage and named
  quarantines. No automatic retries or workflow path filters.

These changes take effect on revisions containing this workflow; they do not
retroactively cancel old runs launched without the concurrency group. There is no
scheduled or manual full-suite trigger in this patch. A future merge queue would
need an explicit `merge_group` decision before enabling it. The repository still
requires PR validation before merge; a direct push does not get a substitute gate.
See GitHub's [workflow event and concurrency semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## What the evidence says

The recent run listing contains both a push and a PR run for milestone 27 commit
`52b71b7`, and another push/PR pair for docs commit `4dfa38b`. Removing push removes
one full invocation for an otherwise equivalent push/PR pair; it does not imply
that total repository usage is always halved. The PR run checks the prospective
merge result, so it is not simply a byte-identical substitute for the push run.

The four BYO jobs in [PR run 39890750491](https://github.com/epochgrid/epochgrid/actions/runs/39890750491)
all passed on their first attempt. GitHub step timestamps give:

| BYO case | Compilation | Test step | Entire job |
| --- | ---: | ---: | ---: |
| Configuration standalone | 148 s | 55 s | 232 s |
| Configuration R3 | 216 s | 79 s | 319 s |
| Operator-JWT standalone | 210 s | 78 s | 318 s |
| Operator-JWT R3 | 201 s | 97 s | 323 s |
| **Sum of runner time** | **775 s / 12.9 min** | **309 s / 5.2 min** | **1,192 s / 19.9 min** |

These are elapsed step/job times, not a billing statement or a statistically
representative benchmark. The repository is public and uses standard hosted
Ubuntu runners; their execution minutes are currently free under
[GitHub's billing policy](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
Optimization here reduces consumed runner time and feedback delays, not necessarily
a paid bill. Artifact/cache storage has separate accounting; shared builds should
use short retention and measured sizes rather than trade free compute for large
persistent storage. The four jobs run on different VMs: concurrency reduces
elapsed feedback time but does not remove their repeated compilation cost.
The main `validate` job builds again. Its completed steps in the inspected snapshot
included 154 s of Clippy, 158 s in the combined unit-build/test step, and 58 s for
protected-state checks. On a later inspection, the main PR job had failed at
the same 360-second NATS watchdog, including 27.83 s of compilation. Both the
push and PR therefore fail this gate despite all four BYO cases passing.

The same commit's [push run 39890375996](https://github.com/epochgrid/epochgrid/actions/runs/39890375996/job/120208415430)
failed in the NATS phase with exit 124. The 360-second watchdog included 21.11 s
of compilation. Earlier cases had passed; the suite reached live revocation when
it was killed. It was not the nine-minute Actions step timeout or the 20-minute
job timeout. This reproduces the budget failure already recorded for milestone 25
in [TD-003](technical-debt.md#td-003--test-and-ci-reliability-post-mvp-delivery-focus).
Separating compilation recovers that portion of the budget but is not sufficient
proof that the remaining execution budget fits cold-runner variance.

The local milestone 27 gate passed its 16 retained NATS cases in 253.25 s. That
warm developer-machine result is useful regression evidence, not a cold-runner
budget. The previous cold run and local pass can both be accurate.

## Long duration and races are different problems

| Failure class | Evidence / diagnosis | Appropriate response |
| --- | --- | --- |
| Aggregate phase timeout | NATS tests plus compilation share 360 s; a passing prefix is killed | Separate build/execution and give independently bounded suites measured budgets |
| Operation timeout / state race | TUI kills the broker, immediately sends, and expects an offline queued message before the client necessarily detects disconnect | Wait for observable offline state for that test; separately test sending during detection and the retained-draft contract |
| Keyring availability failure | Milestone 27 local attempts lost disposable Secret Service access; later isolated and workspace runs passed | Keep isolated sessions; collect daemon/operation diagnostics and measure contention before changing concurrency |
| Actions job cancellation | Superseded revision or outer job ceiling | Record separately from test failures; do not label it a product race |

Before this change, in `scripts/dev/tui-smoke.py`, the established-offline queue assertion
followed `broker.kill()`/`wait()` with an immediate send. In
`crates/epochgrid-client/src/tui/worker.rs`, a client still marked connected first
performs a three-second membership/history sync. On failure, retaining the draft
is deliberate. Extending the subsequent assertion wait cannot send that draft.
This is distinct from the short-lease dynamic authorization problem in TD-002.
No evidence here establishes that overall suite length itself causes either race;
load and scheduling may expose timing assumptions, which require targeted tests.

## Implementation design

1. **Build once, preserve execution isolation.** Introduce one bounded build job
   for the pinned Ubuntu/Rust environment. Run cheap formatting/harness checks
   before expensive work. Build the workspace binaries/examples and test
   executables once, recording paths from Cargo's JSON output. Transfer only the
   required executables and a manifest tied to the workflow revision to execution
   jobs. Preserve the existing four BYO check names; they can remain separate jobs
   while consuming the same build. Do not upload the whole `target` directory or
   any `.dev`, database, keyring, credential or fixture state. Account for embedded
   `CARGO_BIN_EXE_*` paths, executable modes and native-library compatibility.
2. **Separate compilation from every execution budget.** The BYO runner already
   does this, but unit, Secret Service and retained NATS commands can still invoke
   Cargo compilation inside their watchdogs, including package-selection/feature
   differences. Use `cargo test --no-run` for the exact selections during build,
   then execute the recorded test binaries. Preserve doctest coverage explicitly.
   Split the 16 retained NATS cases into a small number of balanced execution
   groups or individually bounded invocations. Validate that every retained case
   appears exactly once and that no new case is silently omitted. Keep a bounded
   total job ceiling above the sum of its measured phase budgets plus setup and
   cleanup margin. Do not treat the sum of maximum step limits as typical runtime.
3. **Keep bounded parallelism.** Run independent suites on separate runners with
   their own brokers, ports, temporary homes and keyring sessions. Keep NATS cases
   serial within a runner initially (`--test-threads=1`). Keep tests that lock or
   remove credentials in their dedicated sessions. Ordinary unit tests currently
   use libtest's parallel default; benchmark a two-thread cap against that default
   before choosing one. `cargo -j` limits compiler jobs, not test threads. More
   simultaneous tests on a small runner can increase CPU, storage and Secret
   Service contention without reducing total runner consumption.
4. **Fix the known readiness assumption independently.** Make the established-
   offline TUI case observe disconnect before sending. Add a deterministic test
   for send-during-disconnect: draft retention, explicit retry, persistence and
   exactly-once delivery. Preserve membership/revocation safety checks. Keep
   TD-001/TD-002 quarantines visible until their own restoration criteria pass.
5. **Add measured caching and reporting.** Cache Cargo registry/Git dependencies
   first; benchmark a bounded compiled-dependency cache keyed by runner, toolchain,
   profile/features and lockfile. Caches are optional acceleration, not the source
   of the revision's test binaries; the build must work with a cold cache. Compare
   transfer/compression time and storage against the saved compilation time before
   retaining large artifacts or caches. Emit concise phase/case timing and failure
   categories, retaining sanitized diagnostics for failed cases, not private
   fixture material. Start with ten cold first attempts before and after a change,
   reporting median, maximum, failures and cancellations separately; collect more
   samples before making strong percentile or reliability claims.

[Cargo documents `--no-run` and separate test-harness arguments](https://doc.rust-lang.org/cargo/commands/cargo-test.html).
GitHub distinguishes [reusable dependency caches](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching)
from [artifacts passed between jobs](https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow).

Keeping one representative build at 148–216 s instead of the four measured builds
would remove roughly **9.3–10.5 runner-minutes per full run** from the BYO portion,
before artifact-transfer and setup overhead. This is an estimate, not a measured
saving. A lower-complexity alternative is one BYO job that builds once and runs all
four cases sequentially in separate keyring sessions. It saves repeated builds
but changes check names, lengthens that job's critical path, and may require
branch-protection updates. Sharing a build while retaining the matrix is the
preferred design when preserving current check names and fast feedback matters.

Do not upload an entire accumulated developer build tree: the local `target/debug`
was approximately 23 GB during this review. That is not the size of a clean CI
artifact, but it illustrates why selecting runtime files matters.

## What to retain and what remains open

Retain read-only workflow permissions, commit-pinned actions, `--locked` builds,
checksum-verified NATS downloads, bounded subprocess-group cleanup, fresh keyrings,
operator-owned BYO fixtures, visible quarantines and first-attempt failure evidence.
Keeping `fail-fast: false` for four short BYO execution jobs is reasonable while
qualifying distinct deployment modes; reconsider after compilation is shared.

The shared-build workflow and readiness fix are now implemented. Required check
names and branch rules remain unchanged. Cold hosted-runner qualification remains
necessary; this local implementation does not close TD-001, TD-002 or TD-003.

## Execution and artifact contract

`verify.sh build` runs locked workspace binary/example compilation and
`cargo test --workspace --no-run`, then records executable paths from Cargo JSON.
`target/ci/runtime.tar.gz` contains the runtime/test executables and the
manifest, preserving modes and original relative paths. The manifest checks the
Git revision, Rust source/Cargo input digest (including uncommitted local changes),
checkout path, OS version, architecture, libc, file hashes and executable modes.
The checkout path check protects embedded `CARGO_BIN_EXE_*` paths. All hosted jobs
use Ubuntu 24.04; a local Ubuntu 26.04 bundle cannot be substituted. Binaries may
also require system libraries supplied by that image and the keyring setup step.

Only the build job invokes Cargo. Doctests have an explicit source-based phase.
Local focused checks require `verify.sh build` first; stale or missing artifacts
fail with no fallback compilation. The default verifier orders these phases for
you. `byo-build` remains a compatibility alias.

The suite matrix isolates units, protected-state cases, four NATS groups and the
smoke suite. NATS ignored test names are discovered from the built harness;
removing exactly four BYO names and the TD-002 name leaves the retained suite.
Sorted round-robin partitioning includes every new retained case exactly once;
missing named qualification/quarantine cases and duplicate names are errors.
Cases run serially per runner with a fresh disposable keyring per invocation.
Current groups have four cases each. Rebalance based on case timing if durations
become uneven; increasing libtest concurrency is not the default remedy.

| Phase | Deadline / job ceiling |
| --- | --- |
| Formatting / harness | 60 s / individual harness 10–30 s |
| Clippy / executable compilation / doctests | 600 / 900 / 180 s; build job 35 min |
| Each unit executable | 180 s; suite job 20 min |
| Each protected-state case | 30–120 s; suite job 20 min |
| Each retained NATS case | 180 s, four per current group; suite job 20 min |
| Each BYO case | 260 s; job 12 min |
| Smoke phases | 90–180 s each; suite job 20 min |

Budgets include keyring setup for direct Rust harness invocations. NATS downloads
have a separate 120 s limit. Job ceilings leave room for artifact transfer,
dependency installation and cleanup. New cases are automatically covered, but
substantial suite growth requires revisiting group sizes and job ceilings.

The offline TUI smoke waits for rendered offline state before submitting. A
unit regression injects sync failure into the production send completion path,
checks draft retention/no persistence, explicitly retries, and checks one durable
message after reopening. The live smoke covers reconnect delivery and final
transcript counts. Membership/revocation sync remains mandatory while connected.

## Caching, diagnostics and measurements

The only enabled cache stores Cargo registry index/archive and Git source data,
keyed by runner OS/architecture, pinned Rust and lockfile. Runtime executables are
always rebuilt for the revision and transferred as artifacts, never sourced from
a persistent build cache. Runtime retention is one day. The artifact is gzip level
1 inside an uncompressed Actions artifact, preserving executable permissions
without redundant compression. CI uses debug level 1 to retain line information
with smaller debug data. Local bundle measurements were 542.8 MB at full debug
and 338.2 MB at debug level 1; hosted transfer time is not yet measured.

Bounded commands emit JSON timing records with label, duration, exit code and
`passed`, `command_failure`, `watchdog_timeout` or `cancelled` classification.
Operation-level timeouts remain command failures, with the assertion explaining
which operation failed; they are not misreported as outer watchdog expiry.
Keyring failures report the failed operation and status, without listing credentials.
Only timing JSON is uploaded (seven-day retention). Raw fixture files, keyring
homes, databases, private keys, environment dumps and application logs are excluded.
Abrupt runner termination can prevent a final record; use Actions' job conclusion
for those cancellations. Existing harness tests cover nonzero exit, timeout,
SIGTERM and descendant cleanup; new tests cover partitioning and invalid artifacts.

Experiments are explicit, outside the required gate, and retain first failures:

```bash
# Run after verify.sh build; alternate order, fresh keyrings for each execution.
python3 scripts/ci/benchmark.py unit-threads --samples 3
# Disposable cold/warm dependency build experiment, capped at 1 GiB before packing.
python3 scripts/ci/benchmark-cache.py
# Summarize saved Actions API records from two explicitly labelled cohorts.
python3 scripts/ci/benchmark.py runs /tmp/ci-samples/*.json
```

The cache experiment keys the runner/OS, rustc version, lockfile and profile/features,
removes workspace products, and measures compression/restoration before rebuilding.
It never enables or uploads a cache. The local trial found 1,807,797,040 bytes of
compiled dependencies, exceeding the 1 GiB limit, so it stopped before packing.
Keep compiled caching disabled pending a smaller, demonstrably beneficial candidate.
The cold local compilation took 32.685 s; this is not hosted-runner evidence.

Two local samples per unit-thread setting passed: default median 22.576 s / maximum
22.873 s; two threads median 38.706 s / maximum 41.149 s. Keep libtest's default.
These were warm local samples with other isolated checks running, not a controlled
hosted comparison; repeat on the target runner before drawing reliability conclusions.

For the run comparison, save each Actions run API response with its jobs API
`jobs` array, plus explicit `cohort` (`before`/`after`) and `cold` (boolean) fields.
Do not label unknown cache states cold. The reporter excludes reruns, separates
cancellations, and reports failure counts plus median/maximum summed runner time.
It flags fewer than ten completed cold first attempts per cohort as insufficient.
Collect these hosted samples after pushing the workflow; no percentile or reliable
savings claim is justified yet. Registry hits and cold compiled builds are distinct.

## Validation

Actionlint 1.7.12, formatting, warnings-denied workspace Clippy, explicit doctests,
108 unit tests, protected-state checks and all 16 retained NATS cases passed.
NATS direct execution totaled 242.932 s (longest case 39.678 s); the full TUI smoke
passed in 92.769 s. These warm local results do not establish hosted-runner savings.
All four BYO qualification cases and the Compose, dynamic-join, relationship and
participant smoke checks also passed. Aggregate-gate failure injection confirmed
that failed, skipped and cancelled prerequisites produce a nonzero gate result.
The harness checks cover artifact round-trip/modes, missing/stale/corrupt bundles,
partition coverage, failure exit codes, timeout/cancellation categories and cleanup.
The initial trigger-only review passed 107 units and 16 NATS cases; the new
send-during-disconnect regression adds one unit case. No hosted run of the redesigned
workflow has been performed yet.
