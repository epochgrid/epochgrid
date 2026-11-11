# Development and verification

Start with [contributing](../CONTRIBUTING.md) and the [README development walkthrough](../README.md#local-development).
Current scope is in the [roadmap](milestones.md); dated results and old upgrade
instructions are in the [archive](archive/README.md).

## Environment

Use Linux, the repository's pinned Rust toolchain, a C toolchain, make, Perl,
Docker Engine/Compose v2, Bash, Python 3, OpenSSL, curl, tar and sha256sum.
Client/backend commands need an unlocked Secret Service session. Tests use
isolated disposable keyrings; on Debian/Ubuntu install `dbus-daemon`,
`gnome-keyring`, `libsecret-tools` and `libglib2.0-bin`. Follow
[secret storage](secret-storage.md) for the session and protected-state contract.

For local separate-account tests, build the fixture image matching the build host:

```sh
# Ubuntu 26.04 (the Dockerfile default):
docker build -f scripts/dev/roles.Dockerfile -t epochgrid-role-tests:local .
# On Ubuntu 24.04 instead:
docker build --build-arg UBUNTU_VERSION=24.04 -f scripts/dev/roles.Dockerfile \
  -t epochgrid-role-tests:local .
```

The [role verification guide](backend-role-contract.md#verification-environment)
explains native hosted-runner and local Docker execution. This image is a
disposable test environment, not the runtime image being developed in milestone 33.
Do not substitute an incompatible host/libc build. Docker daemon access is needed
for local role fixtures. No production sudo permission is required.

## Default checks

From the repository root:

```sh
./scripts/dev/verify.sh
```

The verifier runs harness regressions, formatting, warnings-denied Clippy,
binary/example/test builds, doctests, unit and protected-state tests, retained
NATS integration, Compose/CLI, TUI, focused offline join/restart, relationship and
participant smoke, then all four BYO cases. The [CI guide](ci-strategy.md) describes
job isolation, manifests, deadlines and artifacts. Linux release-bundle qualification
is an additional hosted gate; use [the artifact guide](operator/linux-artifacts.md)
for its local commands.

Focused runs must use current compiled artifacts:

```sh
./scripts/dev/verify.sh build
./scripts/dev/verify.sh unit
./scripts/dev/verify.sh secrets
./scripts/dev/verify.sh nats
./scripts/dev/verify.sh byo-nats configuration_standalone
./scripts/dev/verify.sh byo-nats configuration_cluster
./scripts/dev/verify.sh byo-nats operator_jwt_standalone
./scripts/dev/verify.sh byo-nats operator_jwt_cluster
```

`byo-build` is an alias for `build`. A stale manifest is an error, not an invitation
to compile inside the test watchdog. Rebuild after changing Rust/Cargo inputs or
switching revisions. Native and release-bundle qualification select their own
revision-matched executables; invalid overrides must never fall back silently.

Tests allocate temporary homes, keyrings and brokers. Compose smoke uses its own
project and leaves the developer's `.dev` stack/state alone, but requires port 4222
free. Live Rust NATS cases use ephemeral loopback ports. Real terminal tests need
Unix PTYs. Never point fixtures at operator homes or retain private fixture state
as CI artifacts.

## Known coverage exclusions

[TD-001](technical-debt.md#td-001--live-typing-indicators-deferred-until-after-alpha-milestones)
disables live typing assertions. TD-002 excludes the full short-lease dynamic
Auth Callout and dynamic TUI messaging checks from the default gate. The focused
`dynamic-join` regression remains required. Explicit investigation runs still fail
on errors:

```sh
./scripts/dev/verify.sh build
./scripts/dev/verify.sh nats-dynamic
./scripts/dev/verify.sh dynamic-tui
```

Use `--check-typing` with the TUI runner only inside its disposable test-keyring
environment; see the debt register. Do not interpret a passing default suite or
isolated rerun as restoration of quarantined coverage. Preserve first failures;
classify assertion, operation timeout, watchdog and cancellation separately.

## Local application use and state

Production TLS is the default. Set `EPOCHGRID_PROFILE=development` in every
terminal using the README's plaintext static fixture. The bootstrap script builds
binaries, verifies the pinned NATS download and renders the development config.
Close clients before regenerating configuration and restart the service afterward.
Do not run a host broker and Compose on the same port.

Keep one client process per device home. Preserve homes, metadata, keyrings and
broker state across restart; `docker compose down` retains the named broker volume.
Deleting one side is not recovery. Current clients have [finite capacity limits](operator/capacity.md).
Offline history still needs the keyring. Use [restart/recovery](recovery.md) and
[encrypted administration recovery](encrypted-recovery.md) for their distinct scopes.

Pre-protected-storage development upgrade instructions are historical only.
Plaintext homes are refused; they are not automatically migrated or reset.
For production-shaped setup follow [Auth Callout](operator/auth-callout.md),
[backend roles](backend-role-contract.md), [capacity](operator/capacity.md) and
[validation](operator/validation.md), including any explicit [audit upgrade](operator/audit.md).
