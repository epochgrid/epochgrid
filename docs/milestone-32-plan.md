# Milestone 32 — official Linux binary artifacts

**Implemented and locally validated; hosted PR CI remains pending.** Milestone 31 merged into `main` in
PR #26 (`c73d51a`). This milestone defines and qualifies the distributable Linux
bundle. Milestone 33 owns the GHCR runtime image; milestone 34 owns release
publication, signing/attestations and the release supply chain. Packaging success
does not qualify `v0.1.0-alpha.1` or close TD-001/002/003.

The implemented contract and commands are in
[Linux binary qualification bundles](operator/linux-artifacts.md). The planning
requirements below remain the acceptance baseline.

## Outcome and scope

Produce a versioned, inspectable archive containing the client and backend that
can run on a documented Linux baseline without a Rust compiler, source checkout,
or developer build directory. Exercise the extracted binaries, including their
encrypted storage and separate authority/control roles, before accepting the
artifact. Keep production TLS, Secret Service, SQLCipher, resource limits and
audit failure semantics unchanged.

Start with one supported target: `x86_64-unknown-linux-gnu`, built and qualified
on Ubuntu 24.04 x86-64. This is a proposed support boundary to confirm during the
dependency inspection step, not a claim that existing binaries are portable.
Record actual ELF interpreter, required shared libraries and maximum required
GLIBC symbol version. Do not promise every glibc distribution or an older baseline
from the target triple alone. ARM64, musl/static binaries, other operating systems,
DEB/RPM packages, installers, automatic updates and systemd provisioning are
outside this milestone.

CI artifacts are qualification candidates until the later release workflow
publishes them. No tag, GitHub Release, registry push or release credentials are
needed for milestone 32. Do not label a candidate as a published official release.

## Existing integration points

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`: workspace version, locked
  dependencies and pinned compiler. Build both `epochgrid` and `epochgrid-service`.
- `crates/epochgrid-core`: bundled SQLCipher/vendored OpenSSL, TLS trust loading
  and Linux Secret Service. Inspect native linkage rather than assuming bundling
  eliminates runtime dependencies.
- `scripts/ci/runtime.py`: existing internal debug/test bundle, bound to checkout,
  source digest, OS and embedded test executable paths. Preserve its contract;
  it is not a user distribution format.
- `scripts/dev/verify.sh` and smoke/role fixtures: bounded build and execution
  phases, disposable keyrings, separate-UID checks and four BYO-NATS cases.
- `.github/workflows/ci.yaml`: read-only PR workflow, pinned actions and aggregate
  `validate` gate. Preserve existing required check names and test coverage.

## 1. Freeze the artifact and runtime contract

Add `docs/operator/linux-artifacts.md` with the exact supported environment,
runtime prerequisites, layout and installation/removal procedure. Distinguish
application dependencies from test-only packages. A configured D-Bus session and
unlocked Secret Service collection are still required; installing keyring packages
alone does not configure unattended service accounts. CA roots and a suitable
terminal remain runtime concerns. NATS is operator-provided and not bundled.

Use one archive so both roles and the client come from the same build:

```text
epochgrid-<version>-<target>/
  bin/epochgrid
  bin/epochgrid-service
  BUILD.json
  LICENSE
  THIRD_PARTY_NOTICES
  README.md
```

Candidate archives use
`epochgrid-<version>-candidate.<full-commit>-<target>.tar.gz`; the archive root
uses the layout above. Generate a sibling `SHA256SUMS` covering the archive and
any separately distributed metadata. Checksums detect corruption; they do not
authenticate a publisher. Keep final release naming/promotion in milestone 34.

Version `BUILD.json` independently. Record package version, full source commit,
target, `rustc -Vv`, Cargo version, lockfile digest, build profile/features,
build-environment identifier, runtime dependency inspection and SHA-256/size/mode
of every shipped payload except the manifest itself. The external archive checksum
covers the manifest. Reject dirty source inputs for distributable candidates;
local dirty builds must not carry candidate identity. Check both executable
`--version` outputs against the manifest, and preserve protocol/schema versions
independently of package version.

Ship dependency license notices derived from the locked resolved build graph,
including bundled native SQLCipher/OpenSSL components. Verify license information
and required texts; do not silently omit unknown licenses or assume the Rust crate
license covers all vendored sources. No fixture configuration, credentials,
keyrings, databases, examples/test executables or source checkout enters the bundle.

## 2. Implement bounded, repeatable packaging

Introduce release packaging under `scripts/release/` with explicit build, package
and verify entry points. Use `cargo build --locked --release --target
x86_64-unknown-linux-gnu` for the two production binaries with the pinned toolchain
and default production features. Use an isolated target/staging directory so stale
debug binaries cannot be selected accidentally. Fail on missing inputs, version
mismatch, unexpected target, missing licenses or failed dependency inspection.

Pin the build environment and record its identity. Retain existing dependency
verification and read-only workflow permissions. Any additional tool downloads
must be versioned and integrity checked; select exact tools during implementation.
Do not add `target-cpu=native` or require the builder's CPU extensions.

Package an explicit allowlist with regular files only, executable modes on the two
binaries and ordinary read-only payload modes elsewhere. Normalize member order,
ownership, timestamps (from the source commit) and gzip metadata. Reject unsafe
paths, links, unexpected members and accidental private files. Stage output and
finalize only on success; refuse overwriting an existing candidate. Verify hashes
after extraction in a fresh directory.

Repeat packaging from identical build inputs and compare archive hashes. This
tests deterministic packaging, not bit-for-bit compiler reproducibility. Record
binary/archive sizes and native dependencies before deciding whether stripping is
needed; any strip/debug-symbol policy must preserve useful crash diagnosis and
be exercised on the exact shipped executables. Avoid unrelated profile tuning.

## 3. Qualify the extracted release binaries

Run in a clean Ubuntu 24.04 runtime environment without Rust/Cargo, the repository
on PATH, or access to `target/debug`. Test drivers may remain outside that runtime;
they must select the extracted binaries explicitly. Never fall back to compilation
or developer paths. Verify ELF architecture/interpreter and all required shared
libraries before functional tests.

Required artifact checks:

- Archive layout, manifest/version consistency, executable modes, checksum
  verification and operation after relocating extraction to a path with spaces.
- Rejection of corrupt/truncated archives, modified/missing binaries, wrong target,
  manifest mismatch, unexpected files and unsafe archive members before execution.
- CLI help/version with no keyring; credential-using commands fail within existing
  bounds with missing/locked Secret Service and do not create plaintext fallback.
- Fresh client and authority/control initialization with disposable keyrings;
  encrypted database sentinel checks, restart and existing-state preservation.
- Separate-UID authority/control startup over verified TLS, deployment validation,
  enrollment, retained messaging/catch-up and revocation using the four existing
  BYO-NATS qualification cases against the extracted release binaries.
- CLI/TUI smoke against extracted binaries, plus authority audit info/export and
  worker denial. Preserve stopped-authority maintenance requirements and private
  audit-export permissions. Validate schema-2 explicit upgrade using the existing
  milestone 31 fixture rather than implying automatic upgrade or safe downgrade.

Adapt fixtures to accept explicit production-binary paths while retaining their
existing default internal-runtime manifest checks. Rust test executables may still
come from the test build, but evidence must identify which processes actually used
the release bundle. Unit tests alone, or a debug-binary BYO run, cannot qualify it.
Do not duplicate every unit test in the packaging harness.

## 4. Integrate CI and operator documentation

Add bounded candidate build/package and extracted-runtime qualification jobs to
the PR workflow. Include every new prerequisite in `validate`; failed, skipped
or cancelled packaging/qualification must fail that gate. Separate compilation
from execution budgets and measure first attempts before choosing final deadlines.
Retain pinned actions, isolated fixtures, bounded cleanup and visible quarantines.
Do not introduce retries to hide failures or broaden release-writing permissions.

Upload only the candidate archive, checksums and sanitized qualification metadata
with explicit short retention (initially seven days). Keep these separate from
the one-day internal test runtime. Record the source revision and artifact digest
in qualification results so later work can identify the tested bytes. Failed or
incomplete qualification must never be represented as release-ready.

Document checksum verification, extraction, choosing an installation directory,
PATH setup, dependency failures and separate service-account prerequisites.
Upgrades require stopping affected processes and preserving matching homes,
metadata and keyrings; binary replacement does not authorize schema migration.
Link milestone 31's explicit audit upgrade procedure. Do not promise downgrade
compatibility or describe copying only a home as a complete backup. Removing
binaries must not delete homes or keyring items.

Update README, CONTRIBUTING, CI strategy, milestone index and handoff to distinguish
source builds, CI candidates and future published downloads. Keep the README
concise and do not add a download link until that artifact actually exists.

## Delivery sequence and completion criteria

1. Inspect native linkage/licenses and freeze baseline, layout, manifest and
   runtime prerequisites; record any departure from the proposed target first.
2. Implement locked release builds, allowlisted packaging, checksums, notices and
   focused packaging rejection/determinism tests.
3. Add explicit release-binary fixture selection and clean-runtime qualification.
4. Wire CI gating and candidate retention; write installation/upgrade guidance.
5. Run formatting, warnings-denied Clippy, build/doctests, workspace units, harness,
   protected-state/Secret Service checks, retained NATS/smoke suites and all four
   BYO cases. Additionally run the extracted-artifact checks above; record local
   results and cold hosted PR CI separately.

Complete when a clean locked build produces the documented candidate, the exact
extracted binaries pass the declared runtime matrix without the build environment,
native dependencies and license contents are accounted for, unsafe/corrupt bundles
fail verification, and cold hosted CI passes the expanded aggregate gate. Leave
publication, signatures/attestations, GHCR and alpha qualification explicitly open.

## Implementation evidence — 2026-11-01

The supported target remains Ubuntu 24.04 x86-64. Locked release builds, reviewed
native/license contents, deterministic packaging and strict verification are
implemented. Both binaries require at most GLIBC 2.39. `--version` was added to
both CLIs to enforce manifest consistency. Local dirty builds are explicitly
labelled `local`; the clean-checkout candidate path is wired into PR CI.

Local formatting, warnings-denied Clippy, build/doctests, units, harness checks,
protected-state/Secret Service checks, all 16 retained NATS cases, normal smoke
workflows and all four regular BYO cases pass. The extracted Ubuntu 24.04 bundle
passes smoke and all four BYO cases with matching manifest/binary hashes. One
operator-JWT cluster attempt lost its disposable worker keyring; an isolated rerun
passed, with the original failure retained and its cause unresolved. No retries
or quarantines were added. See [HANDOFF](../HANDOFF.md) for logs and artifact identity.

Cold hosted PR CI has not run. The user subsequently authorized committing and
pushing the implementation branch and will prepare the PR. No tag or publication
is part of this request.
Milestones 33/34 and TD-001/002/003 remain open.
