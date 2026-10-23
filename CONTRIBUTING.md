# Contributing

Keep changes within the current executable milestone. Discuss broader scope in
an issue first. Follow the runnable README and keep it synchronized with behavior.
Use idiomatic safe Rust, structured errors and tracing without private data.

Before proposing a change, run the four README quality commands and the explicit
NATS integration test. Changes to wire types need compatibility review and tests;
changes to authentication or storage need negative and restart tests. Commit
Cargo.lock. Do not commit `.dev/`, credentials, private keys or databases.

Use https://github.com/epochgrid for source and `ghcr.io/epochgrid/*` for future
OCI artifacts. CI only validates; publishing is not configured.

## Setting up your development environment

1. Install prerequisites: rustup (Rust 1.98.1 pinned), C toolchain, make, Perl,
   Docker Engine with Compose v2, Bash, Python 3, OpenSSL, curl, tar, sha256sum.
   Linux clients also require Secret Service keyring; see [secret storage setup](docs/secret-storage.md).
2. Clone this repository and initialize:

   ```bash
   git init                  # Initialize local repo if not using GitHub clones
   pip install pre-commit    # Install pre-commit framework (run once on first setup)
   pre-commit install        # Install pre-commit git hooks (run once, ensures hooks are active)
   ```
3. Configure your workspace:

   ```bash
   export EPOCHGRID_PROFILE=development
   ./scripts/dev/bootstrap-nats.sh  # Bootstrap NATS and generate config
   ./target/debug/epochgrid-service --dev-static
   ```

4. Run all checks before submitting a PR:

   Build the disposable separate-user test image once on local Ubuntu hosts
   (`--build-arg UBUNTU_VERSION=24.04` for Ubuntu 24.04; default 26.04). Production
   TLS/BYO tests need this image to run the authority and worker under distinct
   UIDs and keyrings. See the [role verification environment](docs/backend-role-contract.md#verification-environment).

   ```bash
   docker build -f scripts/dev/roles.Dockerfile -t epochgrid-role-tests:local .
   ```

   ```bash
   ./scripts/dev/verify.sh    # Runs all quality gates (fmt, clippy, unit, etc.)
   ```

Before committing, the pre-commit hooks will run automatically on staged files.
The git commit message below has already ensured hooks are installed. Simply
stage your changes and commit:

```bash
git add <files>             # Stage your changes
git commit -m "feat: your change description"  # Hooks will auto-run if installed
```

## Understanding the project milestones

- Milestone 0–10: Initial alpha with NKey auth, MLS groups, encrypted chat, history
- Milestone 11: Persistent TUI, asynchronous messaging, unread indicators
- Milestone 22: Dynamic authorization, signed policies, MLS rekeying
- Milestone 23: Production TLS, system trust, certificate rotation
- See [architecture](docs/architecture.md), [protocol](docs/protocol.md), [CI strategy](docs/ci-strategy.md)
