# PR #31 cluster recovery investigation — 2026-11-13

Local candidate on `fix/td-003-credential-lock`, based on `ceb6325`. The existing
credential-lock repair is retained. This investigation does not close TD-003.

## Hosted failure

[CI run 43257373465](https://github.com/epochgrid/epochgrid/actions/runs/43257373465)
tested PR head `9806d2c` through merge commit `a008075`. The only failing test job
was [Linux bundle configuration-cluster qualification](https://github.com/epochgrid/epochgrid/actions/runs/43257373465/job/131323864283).
The final aggregate job also failed. Native unit/NATS/BYO jobs, the other four
bundle suites and all five image suites passed.

The cluster case failed after 56.69 seconds with `alice: identity register` /
`registration rejected`, after broker quorum loss and restoration. This was an
operation rejection, not the phase watchdog or a credential-lock error. The
service logged only `dynamic identity operation rejected`; it did not identify
the failing backend operation. The original failure remains unexplained.

## Candidate changes

The fixture checked only Alice and Bob's CHAT/MAILBOX consumers after failover.
Earlier in the same case, quota recovery enrolls a third diagnostic device.
Registration reconciles all enrolled consumers, so the fixture's recovery
condition omitted a dependency. Also, successful INFO requests alone did not
check leader or live-majority state.

The recovery probe now derives its device list from the active registry and
requires an elected leader plus a current, online majority for every R3 stream
and enrolled consumer. R1 retains its successful-INFO condition. One R3 broker
remains stopped during recovery, so the predicate deliberately does not require
every replica. A unit regression covers absent/empty leaders, lagging and offline
peers, and recovery with one current peer. Probe failure reports the last stream
or consumer stage within the existing 40-second deadline.

Service rejection logs now include fixed operation-stage and failure-category
labels. They exclude request data, credentials, identity keys and raw backend
error strings. Response behavior, admission checks, repair behavior, watchdogs,
quarantines and client retries are unchanged.

This repairs a concrete readiness gap but is not proof that the gap caused the
hosted rejection. The unchanged local configuration-cluster baseline passed in
88.044 seconds. A future failure with the new stage labels may require a separate
runtime repair.

## Local validation

Builds and execution use the cached Ubuntu 24.04 qualification builder, Rust
1.98.1 and pinned NATS 2.14.5, with no container network, disposable keyrings,
separate-UID role fixtures and the normal execution deadlines. Compilation is
outside the test deadlines. These are warm local checks, not cold hosted evidence.

Local logs are in `target/m35/pr31-*.log`. The Ubuntu runtime manifest and build
outputs are in `target/m34-runtime24` (mounted as the checkout's `target` inside
the container). Each BYO case uses fresh fixture state. Unit and release builds
also ran during the BYO sample; this is not an isolated timing benchmark.

| Check | Result |
| --- | --- |
| Unchanged configuration-cluster baseline | Passed, 88.044s |
| Updated native build | Passed, 11.817s including packaging |
| Ordinary unit gate | Passed, including quorum regression and both resource-limited parser campaigns |
| Warnings-denied workspace/all-targets/all-features Clippy | Passed, 14.472s |
| Formatting and diff whitespace | Passed |
| BYO configuration R1 / R3 | Passed, 77.683 / 88.885s |
| BYO operator-JWT R1 / R3 | Passed, 85.840 / 98.843s |
| Local release build, archive packaging and checksum verification | Passed |
| Extracted bundle configuration-cluster qualification | Passed, 70.715s |

On a supported native Ubuntu 24.04 checkout, the corresponding focused checks
are:

```sh
./scripts/dev/verify.sh build
./scripts/dev/verify.sh unit
./scripts/dev/verify.sh clippy
./scripts/dev/verify.sh byo-nats
python3 scripts/release/build-linux.py --local --work target/pr31-release
python3 scripts/release/artifact.py package --work target/pr31-release --output target/pr31-dist
```

Verify/extract the emitted archive with `artifact.py verify`, then run
`scripts/release/qualify.py --bundle <extracted-directory> --suite configuration_cluster`
using the matching Ubuntu runtime manifest. This local session supplied
`--runtime-manifest target/m34-runtime24/ci/manifest.json`; the clean qualification
container exposes only the selected test executables, scripts, broker and bundle.
The bundle is marked local and is not a distributable candidate.

Recorded identities:

- Runtime Rust-source SHA-256: `fca48c867a4ca978618568a95dfc4d70d07d981667b59923e14f87d07b80cdf2`.
- Bundle build/test-source SHA-256: `811a36db07c19b18b9aa1d33d8f218e852e15c9d49806563a2d830dcbcbfe4ce`.
- Verified local archive SHA-256: `f732e85c6ce4e612930f376a1a8bb78a6b1514fbeceb55aae7f1e90e9b6c8395`.
- Qualification receipt: `target/m35/pr31-bundle-configuration-cluster.json`;
  bundle manifest SHA-256 `bdaf21101794d21097f45069f9ee70117471c56573f097a4f6ce309c535f0af4`.

No hosted rerun, publication, quarantine removal or TD closure is implied. The
remaining bundle/image suites and broader cold-run reliability sample were not
repeated for this candidate.
