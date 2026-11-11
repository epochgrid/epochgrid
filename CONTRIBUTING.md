# Contributing

Use the [roadmap](docs/milestones.md) for current scope and open work. Keep behavior,
operator contracts and examples synchronized. Wire-format changes need compatibility
review; authentication/storage changes need negative and restart coverage. Use safe
Rust, structured errors and tracing that excludes private data. Commit `Cargo.lock`;
never commit `.dev/`, credentials, private keys, databases or keyring fixtures.

## Setup and verification

Clone the repository and follow the [development guide](docs/development.md) for
the pinned Rust/Linux dependencies, disposable keyrings and separate-account test
image. Use the [README](README.md#local-development) to run the static development
demo; use the operator guides for the production-shaped path.

From the repository root:

```sh
./scripts/dev/verify.sh
```

For focused checks, run `verify.sh build` first, then the relevant execution phase.
Keep build time outside execution deadlines. The complete retained gate and
coverage exclusions are described in [CI](docs/ci-strategy.md) and
[technical debt](docs/technical-debt.md). Release-bundle changes also require the
[Linux qualification checks](docs/operator/linux-artifacts.md).

## Review and documentation

Report what changed, why, the exact checks run and any failures or unverified
paths. Preserve failed-run evidence even if a focused rerun passes. Hosted PR
checks remain required; a local pass is not cold-runner qualification.

[Git hooks](scripts/hooks/README.md) are optional local conveniences. A commit does
not install them, and hooks do not replace the verifier or hosted CI.

Keep current status in the [roadmap](docs/milestones.md), durable behavior in its
operator/protocol contract, and dated acceptance plans/results in the
[archive](docs/archive/README.md). Use the [documentation index](docs/README.md)
to find the owning document before creating another plan or guide. Do not mark a
milestone complete solely because code exists or a candidate archive was built.

Source is hosted at https://github.com/epochgrid/epochgrid. Main currently produces
temporary Linux qualification candidates; GHCR candidate transport is milestone 33
and release publication/signatures remain milestone 34. See the roadmap for their
actual delivery status. Report vulnerabilities through [SECURITY.md](SECURITY.md).
