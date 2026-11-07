# CI execution and qualification

This describes the workflow on main through milestone 32 (`04652c7`). Milestone 33
image jobs and candidate publication are under separate review; see the
[roadmap](milestones.md). The [October 22 review](archive/ci-review-2026-10-22.md)
retains the historical design rationale, failed runs and measurements.

## Required jobs and triggers

The full suite runs on PR `opened`, `synchronize` and `reopened`. A superseding
revision cancels the same PR's older run. Branch pushes without a PR and merges
into main do not independently trigger this workflow. Draft PRs get the same checks.
The PR run validates the merge candidate, not a separate post-squash build.

| Job | Inputs and responsibility |
| --- | --- |
| `build` | Harness/format/Clippy/doctests and one native binary/example/test build |
| `tests` | Shared runtime artifact; unit, secrets, four retained NATS groups and smoke |
| `byo-nats` | Shared runtime artifact; four independent configuration/operator-JWT R1/R3 cases |
| `linux-build` | Locked release build and verified Linux candidate bundle |
| `linux-qualify` | Release bundle plus native test tools; smoke and four extracted-binary BYO cases |
| `validate` | Requires every prerequisite above to succeed, including matrix results |

Failed, skipped or cancelled prerequisites fail `validate`. Job dependencies do
not themselves configure branch-protection settings. Workflow permissions are
read-only; actions and the Rust toolchain are pinned. Main's workflow publishes
no packages or releases. There are no automatic retries or documentation-only
path exclusions. No new quarantine is introduced by CI restructuring.

TD-001 typing assertions and the two TD-002 live workflows remain excluded as
listed in [technical debt](technical-debt.md). TD-003 remains open despite the
shared-build and disconnect-observation improvements. A later passing rerun does
not erase its first failure or establish reliability.

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

The shared `build` job invokes Cargo for native tests and doctests. The separate
`linux-build` job compiles distributable release binaries; execution jobs do not compile.
Local focused checks require `verify.sh build` first; stale or missing artifacts
fail with no fallback compilation. The default verifier orders these phases for
you. `byo-build` remains a compatibility alias.

The suite matrix isolates units, protected-state cases, four NATS groups and the
smoke suite. NATS ignored test names are discovered from the built harness;
removing exactly four BYO names and the TD-002 name leaves the retained suite.
Sorted round-robin partitioning includes every new retained case exactly once;
missing named qualification/quarantine cases and duplicate names are errors.
Cases run serially per runner with a fresh disposable keyring per invocation.
At this baseline, groups have four cases each. Rebalance based on case timing if durations
become uneven; increasing libtest concurrency is not the default remedy.

| Phase | Deadline / job ceiling |
| --- | --- |
| Formatting / harness | 60 s / individual harness 10–30 s |
| Clippy / executable compilation / doctests | 600 / 900 / 180 s; build job 35 min |
| Each unit executable | 180 s; suite job 20 min |
| Each protected-state case | 30–120 s; suite job 20 min |
| Each retained NATS case | 180 s, four per current group; suite job 20 min |
| Each native BYO case | 300 s outer runner, 240 s workflow; job 12 min |
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
with smaller debug data. Historical size comparisons are in the
[October 22 review](archive/ci-review-2026-10-22.md); they are not current benchmarks.

Bounded commands emit JSON timing records with label, duration, exit code and
`passed`, `command_failure`, `watchdog_timeout` or `cancelled` classification.
Operation-level timeouts remain command failures, with the assertion explaining
which operation failed; they are not misreported as outer watchdog expiry.
Keyring failures report the failed operation and status, without listing credentials.
Execution jobs upload sanitized timing JSON (seven-day retention). The build jobs
also distribute the executable bundles described here, and Linux qualification
retains sanitized identity/result reports. Raw fixture files, keyring
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

Keep compiled caching disabled until a bounded cache shows a measured improvement
on the target runner. The historical cache-size and unit-thread experiments are
recorded in the archived review; they do not establish hosted-runner reliability
or justify changing the libtest concurrency default.

For the run comparison, save each Actions run API response with its jobs API
`jobs` array, plus explicit `cohort` (`before`/`after`) and `cold` (boolean) fields.
Do not label unknown cache states cold. The reporter excludes reruns, separates
cancellations, and reports failure counts plus median/maximum summed runner time.
It flags fewer than ten completed cold first attempts per cohort as insufficient.
Collect these hosted samples for the revisions being compared; no percentile or reliable
savings claim is justified yet. Registry hits and cold compiled builds are distinct.

## Linux distributable candidates — milestone 32

The internal runtime contract above remains unchanged. `linux-build` compiles
locked default-feature release binaries in the digest-pinned Ubuntu 24.04 builder
and packages only the two applications, manifest and notices. It verifies
checksums/layout and retains a candidate archive for seven days.

`linux-qualify` has smoke plus four BYO matrix entries. Each verifies the archive
and runs extracted binaries in a clean Ubuntu 24.04 container with no compiler
or debug application binaries. Only the revision-checked test harness and example
probes are mounted as test tools. Explicit binary selection applies to client,
authority and separate-UID control processes. See the
[artifact contract](operator/linux-artifacts.md) for coverage, metadata and limits.

The existing `validate` name is preserved and now also requires both Linux jobs.
A failed, skipped or cancelled prerequisite fails it. Existing regression suites,
quarantines and read-only workflow permissions remain. Build and runtime checks
have separate deadlines; no publishing credentials, tags, registry pushes or
GitHub Releases are introduced. Candidate availability alone does not establish
qualification; all same-revision prerequisites must pass.
