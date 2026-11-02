# EpochGrid

[![CI](https://github.com/epochgrid/epochgrid/actions/workflows/ci.yaml/badge.svg?event=pull_request)](https://github.com/epochgrid/epochgrid/actions/workflows/ci.yaml)
[![Rust toolchain](https://img.shields.io/badge/Rust-1.98.1-orange?logo=rust)](rust-toolchain.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

EpochGrid is an end-to-end encrypted messaging system built with Rust, NATS, and
Messaging Layer Security (MLS). It provides command-line and terminal clients for
group conversations, with persistent history, offline delivery, and independent
devices per user.

NATS provides transport and persistence; OpenMLS provides group encryption and
cryptographic membership. Messages are encrypted on clients before reaching the
broker. The metadata backend manages public identity information without access
to message plaintext. Local message history and private state use SQLCipher,
with keys held in Linux Secret Service.

**EpochGrid is unaudited development software. Do not use it for sensitive or
production communications.** See the [security policy](SECURITY.md) and
[threat model](docs/threat-model.md).

[Website](https://epochgrid.org) · [Architecture](docs/architecture.md) ·
[Roadmap](docs/milestones.md) · [Contributing](CONTRIBUTING.md)

## Getting started

Host clients and services require Linux and an unlocked Secret Service keyring.
Install rustup, a C toolchain, make, Perl, Docker Engine with Compose v2, Bash,
Python 3, OpenSSL, curl, tar, and sha256sum. The Rust toolchain is pinned in
[rust-toolchain.toml](rust-toolchain.toml). See [keyring setup](docs/secret-storage.md)
before running the examples.

### Local development

This walkthrough uses a static, loopback-only development fixture. For an
operator-managed deployment, follow the [Auth Callout setup guide](docs/operator/auth-callout.md)
and [separate backend role setup](docs/backend-role-contract.md#setup-under-separate-linux-accounts).

Run commands from the repository root. In **each terminal**, use the same Linux
login and unlocked keyring session, and set:

```bash
export EPOCHGRID_PROFILE=development
export EPOCHGRID_NATS_URL=nats://127.0.0.1:4222
unset EPOCHGRID_TLS_CA_PATH EPOCHGRID_TLS_FIRST EPOCHGRID_TLS_MIN_VERSION
```

Build the binaries, create development identities, and start NATS:

```bash
./scripts/dev/bootstrap-nats.sh
```

Start the backend in a separate terminal and leave it running:

```bash
./target/debug/epochgrid-service --dev-static
```

Register the two development devices:

```bash
./scripts/dev/create-alice.sh
./scripts/dev/create-bob.sh
```

Create a channel, invite Bob, and accept the invitation:

```bash
./target/debug/epochgrid --home .dev/alice channel create engineering
./target/debug/epochgrid --home .dev/alice channel invite engineering bob
./target/debug/epochgrid --home .dev/bob channel join --from alice
```

Open each client in its own terminal:

```bash
# Alice
./target/debug/epochgrid --home .dev/alice tui

# Bob (in another terminal)
./target/debug/epochgrid --home .dev/bob tui
```

Use `/help` for commands and `/quit` to exit. Keep the device homes, keyring, and
NATS data across restarts; reopen the clients to resume an existing conversation.
Run only one client process per device home. See [terminal controls](docs/tui.md)
and [restart and recovery](docs/recovery.md) for details.

## Documentation

| Topic | Guides |
| --- | --- |
| Design | [Architecture](docs/architecture.md), [protocol](docs/protocol.md), [security boundaries](docs/threat-model.md) |
| Clients | [Terminal client](docs/tui.md), [multiple devices](docs/multi-device.md), [message relationships](docs/message-relations.md), [receipts](docs/receipts.md) |
| Identity and recovery | [Device verification](docs/device-verification.md), [revocation](docs/device-revocation.md), [encrypted recovery](docs/encrypted-recovery.md), [local storage](docs/secret-storage.md) |
| Integrations | [Attachments](docs/attachments.md), [service participants](docs/service-participants.md) |
| Deployment | [NATS requirements](docs/operator/byo-nats.md), [authentication](docs/operator/auth-callout.md), [backend roles](docs/backend-role-contract.md), [TLS](docs/operator/tls.md) |
| Operations | [Validation](docs/operator/validation.md), [diagnostics](docs/operator/diagnostics.md), [capacity](docs/operator/capacity.md) |
| Development | [Development guide](docs/development.md), [CI](docs/ci-strategy.md), [roadmap](docs/milestones.md), [known limitations](docs/technical-debt.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for environment setup and contribution
guidelines. Run the local verification suite with:

```bash
./scripts/dev/verify.sh
```

To run formatting, linting, build, unit, and NATS integration checks individually:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/dev/verify.sh build
./scripts/dev/verify.sh unit
./scripts/dev/verify.sh nats
```

Integration checks require the test infrastructure described in the
[development guide](docs/development.md) and
[role verification setup](docs/backend-role-contract.md#verification-environment).
CI runs on pull requests; the badge above reflects PR workflow runs.

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## License

EpochGrid is available under the [MIT License](LICENSE).

Security evidence: [authority audit operations](docs/operator/audit.md).
