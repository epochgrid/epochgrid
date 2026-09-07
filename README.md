# EpochGrid

EpochGrid is an open-source secure group communications project combining NATS
infrastructure with MLS end-to-end group encryption. Project: https://epochgrid.org
(secondary https://epochgrid.net). Organization: https://github.com/epochgrid.

**Current status: Milestones 0–4.** The working foundation creates independent
NATS and MLS device keys, persists them in SQLite, authenticates with NKeys and
registers verified public identities/KeyPackages over NATS request/reply.
Group creation, invitations and encrypted chat are **not implemented**.
No production security claim is made.

NATS supplies transport, authorization and JetStream/KV persistence. OpenMLS will
supply group confidentiality and cryptographic membership. The service receives
public registrations only; clients retain their own keys. See
[architecture](docs/architecture.md), [protocol](docs/protocol.md) and
[threat model](docs/threat-model.md).

## Run locally

Prerequisites: Rust/rustup (the repository pins 1.98.1), a C toolchain for bundled
SQLite, Docker Engine with Compose v2, Bash, curl, tar and sha256sum. The development
image supports Linux amd64/arm64 (including Linux Docker on macOS). Host integration
tests require a Linux environment or a native NATS server via `NATS_SERVER`.

```bash
./scripts/dev/bootstrap-nats.sh
```

This builds the workspace, initializes Alice, Bob and the service under ignored
`.dev/`, creates enrollment/configuration, downloads a checksum-pinned official
NATS 2.14.5 release from GitHub, and starts NATS/JetStream with Compose. No registry
pull or Docker Hub account is needed. The local image is tagged
`ghcr.io/epochgrid/nats-dev:2.14.5`; nothing is published.

Configuration must exist before NATS starts, so bootstrap precedes the first
`docker compose up -d`. Subsequent starts can use Compose directly.

Start the host service in its own terminal:

```bash
./target/debug/epochgrid-service
```

Alice's terminal:

```bash
./target/debug/epochgrid --home .dev/alice identity show
./scripts/dev/create-alice.sh
# After Bob registers:
./target/debug/epochgrid --home .dev/alice identity lookup bob
```

Bob's terminal:

```bash
./target/debug/epochgrid --home .dev/bob identity show
./scripts/dev/create-bob.sh
```

The registration commands print `EpochGrid device registered`. Repeating them or
restarting either client/service preserves the registration. `identity show`
prints public information only. The scripts register identities already created
by bootstrap. To create a separate local identity manually:

```bash
./target/debug/epochgrid --home .dev/another identity init alice --device desktop
```

Manual identities need explicit NATS permissions and enrollment before connecting;
only Alice/laptop and Bob/laptop are pre-enrolled. MVP multi-device operation is
not implemented. `--server` / `EPOCHGRID_NATS_URL` selects the NATS endpoint;
`--home` / `EPOCHGRID_HOME` selects local storage.

Stop infrastructure with `docker compose down`; the named JetStream volume and
local identities remain. Do not delete one side independently when resuming work.

## Verify

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration -- --ignored
./scripts/dev/smoke.sh
```

The explicit integration test starts isolated NATS/service processes, tests valid
and invalid registrations and authorization, then restarts NATS, service and
clients to verify disk persistence. The ordinary workspace tests do not require
NATS; CI runs both suites and a Compose/CLI smoke test. The smoke test stops the
Compose stack it starts, so run it when you are not using the development stack.

## Limitations

This is a loopback-only development environment without TLS. Private SQLite files
are unencrypted and protected by Unix directory/file permissions, not a secure
keystore. Registration is immutable (exact retries accepted), with no rotation,
revocation or KeyPackage replenishment yet. CHAT/MAILBOX and CHANNELS exist but are
unused. MLS groups, Welcome delivery, ciphertext-history assertions and group
restart/resume belong to later milestones; identity persistence alone does not
prove the full MVP. See [development](docs/development.md) and [SECURITY.md](SECURITY.md).
