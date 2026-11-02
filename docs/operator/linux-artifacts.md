# Linux binary qualification bundles — milestone 32

Milestone 32 builds and tests Linux candidate bundles. It does **not** publish
GitHub Releases, tags or GitHub Packages. Candidates are temporary GitHub Actions
artifacts, retained for seven days; they are not an alpha release. GHCR belongs
to milestone 33 and release publication/signatures/attestations to milestone 34.
TD-001/002/003 remain open. In particular, the quarantined full dynamic messaging
suite is not restored by packaging tests.

## Supported runtime

The qualification boundary is **Ubuntu 24.04, x86-64**, using the GNU target
`x86_64-unknown-linux-gnu`. The build/qualification Dockerfile pins the Ubuntu base
image digest; the compiler version comes from `rust-toolchain.toml` (currently
1.98.1). Apt package versions are recorded in `BUILD.json`. Package repositories
are not snapshotted; this is not a bit-for-bit reproducible compiler-build claim.
No other distribution, older glibc, ARM64, musl or operating system is qualified.

Runtime prerequisites:

- Ubuntu's glibc and libgcc runtime. `BUILD.json` records each ELF interpreter,
  direct `DT_NEEDED` libraries and highest required GLIBC symbol version; candidate
  builds reject a requirement above GLIBC 2.39 and unreviewed shared libraries.
- CA certificates for system trust (or the existing explicit custom-root setup),
  and a suitable terminal for the TUI.
- D-Bus plus a configured Secret Service provider with an unlocked default
  collection. GNOME Keyring is exercised. Installing `dbus-daemon`, `gnome-keyring`
  and `libsecret-tools` alone does not configure an unattended account's session.
- Operator-provided NATS following the [BYO contract](byo-nats.md).

SQLCipher and its OpenSSL dependency are bundled by the locked Rust dependency
build. Neither a system SQLCipher package nor a compiler is needed at runtime.
The test environment additionally has Python, binutils, sudo, the OpenSSL command,
and fixture tools; these are not application prerequisites.

Use distinct authority/control Linux accounts with independent keyring sessions.
Follow [secret storage](../secret-storage.md), [role setup](../backend-role-contract.md),
[TLS](tls.md) and [deployment validation](validation.md). No installer creates or
unlocks collections, provisions service users, installs systemd units or changes
operator-owned NATS configuration. There is no plaintext credential fallback.

## Bundle format and identity

Candidate name:
`epochgrid-<version>-candidate.<full-commit>-x86_64-unknown-linux-gnu.tar.gz`.
Local test builds replace `candidate` with `local`; they must not be promoted.
The archive contains only these regular files:

```text
epochgrid-<version>-x86_64-unknown-linux-gnu/
  bin/epochgrid
  bin/epochgrid-service
  BUILD.json
  LICENSE
  THIRD_PARTY_NOTICES
  README.md
```

Executable modes are 0755; other payloads are 0644. Archive ordering, ownership,
commit timestamps and gzip metadata are normalized. Packaging twice from the same
staging tree must yield the same archive checksum. Binaries are unstripped using
the default Cargo release profile; no CPU-native flags or profile tuning are added.

`BUILD.json` schema 1 records the package version, full commit, input digest,
local/dirty designation, lockfile hash, compiler/Cargo versions, target,
profile/features, OS/libc/system packages and build-definition digest. It records
size, mode and SHA-256 of every other payload, plus inspected native dependencies.
The input digest covers Rust/Cargo, scripts/notices, workflow and build configuration;
it excludes narrative docs. Candidate creation requires a completely clean checkout.
Protocol, storage and audit schema versions remain independent of package version.

`THIRD_PARTY_NOTICES` includes texts from the actual compiled dependency graph
(including build dependencies conservatively), nested native notices, and exact
crate source URLs. Missing texts are supplied only by version-bound reviewed
supplements with recorded source URLs and hashes. Unknown license identifiers or
missing texts fail the build. SQLCipher, OpenSSL and ring/BoringSSL notices are
mandatory. Dependency changes require reviewing these supplements.

The sibling `SHA256SUMS` covers the archive, including its manifest. Checksums
provide corruption detection, **not publisher authentication**. Qualification
reports identify the archive hash (verification report), manifest hash, binary
hashes, commit, suite and runtime image ID. Only completed suites produce a passing
report. A downloadable build artifact alone is not evidence of successful
qualification; check the same revision's entire `validate` gate.

## Verify, extract and install

Download a candidate archive and its `SHA256SUMS` from the same workflow revision.
Inspect the checksum file to ensure it names only the expected archive, then run
from their directory:

```bash
sha256sum --check SHA256SUMS
```

The repository's strict verifier additionally rejects missing/extra files,
links, unsafe paths, corrupt payloads, incompatible manifests and wrong revisions
before executing anything. It requires Python 3.11+ and binutils, not Rust:

```bash
python3 scripts/release/artifact.py verify \
  --archive /path/to/epochgrid-VERSION-candidate.COMMIT-x86_64-unknown-linux-gnu.tar.gz \
  --checksums /path/to/SHA256SUMS \
  --output '/path/to/new extracted bundle' \
  --require-candidate --commit FULL_COMMIT
```

Replace placeholders with the downloaded version/revision. The verifier creates a
new destination containing `bin/`, `BUILD.json` and the documentation (it strips
the archive's common top-level directory); it refuses an existing destination.
Use the verifier from the matching source revision. It validates content and
metadata, not authenticity. After successful verification, install both binaries
in a chosen directory, for example:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 '/path/to/new extracted bundle/bin/epochgrid' "$HOME/.local/bin/epochgrid"
install -m 0755 '/path/to/new extracted bundle/bin/epochgrid-service' "$HOME/.local/bin/epochgrid-service"
export PATH="$HOME/.local/bin:$PATH"
epochgrid --version
epochgrid-service --version
```

For service accounts choose an operator-managed binary directory accessible to
both accounts. The same service binary implements both roles; do not share homes
or keyring environments. A loader/GLIBC error indicates a runtime mismatch. A
Secret Service error requires fixing the account's session/collection, not copying
seed files into its home. A TLS root error requires the documented trust setup.

Stop affected processes before upgrading. Preserve homes, database metadata and
matching keyrings; copying only a home is not a complete backup. Binary replacement
does not authorize migration. Schema-2 authority state requires stopped-authority
[`audit upgrade`](audit.md); inspection refuses to migrate it. Do not assume an
older binary can read upgraded state. Removing the installed executables must not
delete homes, exports or keyring entries.

## Building and qualifying

On Linux with Docker, Python 3.11+, rustup and the pinned toolchain installed:

```bash
python3 scripts/release/build-linux.py
python3 scripts/release/artifact.py package \
  --work target/release-candidate/work --output target/linux-candidate
python3 scripts/release/artifact.py verify \
  --archive target/linux-candidate/*.tar.gz \
  --checksums target/linux-candidate/SHA256SUMS \
  --output 'target/extracted candidate' --require-candidate
```

Build uses a pinned Ubuntu container, the pinned toolchain mounted read-only and
an isolated Cargo target directory. Locked Cargo metadata is fetched before
compilation, including dependencies for other targets and development: the Linux
binary build alone does not populate that complete graph in a cold cache. Only
the registry cache is copied, never
Cargo credentials. Each new build needs a fresh work/staging path; output refuses
overwrite. For uncommitted local testing use `build-linux.py --local --work
 target/m32-local/work` and omit `--require-candidate` during verification.
Local outputs always carry `local` identity, even when built from a clean tree.

`artifact.py build --work PATH` is the direct in-environment entry point;
`--local` also permits host experimentation outside the supported baseline.
Such host outputs do not qualify Ubuntu 24.04. `package` rejects changed build
inputs; `verify` never compiles or repairs a bundle.

Run `scripts/release/test-artifact.py` for bounded archive/manifest rejection
coverage. The regular verifier includes it in `harness`. Full runtime qualification
requires the normal revision-bound test runtime built on Ubuntu 24.04, plus the
checksum-verified NATS fixture:

```bash
docker build --target runtime -f scripts/release/qualification.Dockerfile \
  -t epochgrid-artifact-tests:local .
python3 scripts/release/qualify.py --bundle 'target/extracted candidate' --suite smoke
python3 scripts/release/qualify.py --bundle 'target/extracted candidate' --suite configuration_standalone
```

Also run `configuration_cluster`, `operator_jwt_standalone` and
`operator_jwt_cluster`. `--runtime-manifest PATH` supports an isolated Ubuntu 24.04
test build. The runner validates source identity and test-tool hashes, then mounts
only the selected test harness, two example probes, scripts, NATS and the extracted
bundle into a network-isolated runtime. It refuses Rust/Cargo or debug application
binaries inside that environment. The bundle is relocated to a path containing
spaces. `EPOCHGRID_RELEASE_BIN_DIR` is the explicit fixture selector; an invalid
selection fails rather than falling back to a developer binary.

Smoke covers help/version, protected credentials and encrypted storage/recovery,
explicit audit upgrade, CLI/TUI operations, restart/offline behavior, relationships
and service participants. The four existing BYO cases cover verified TLS,
validation, separate-UID roles, enrollment, messaging/catch-up, revocation,
restarts, audit export/permissions and operator-owned resource preservation. Rust
harness logic and example probes remain test tools; every spawned production
client/authority/control executable comes from the extracted bundle.

CI keeps the existing regression jobs and adds `linux-build` plus five
`linux-qualify` matrix jobs. The aggregate `validate` gate rejects failed, skipped
or cancelled prerequisites. Build has a 20-minute watchdog; qualification has a
700-second outer ceiling and separate existing per-case deadlines (300 seconds
per BYO case). These are execution bounds, not performance guarantees. No retries
or new quarantine rules are added. Cold hosted PR evidence remains necessary.
