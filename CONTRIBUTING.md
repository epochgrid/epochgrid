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


Start feature work on a clean branch based on current `main`. The `main` branch is
protected: submit a pull request and satisfy its required status checks before
merging. Do not push feature commits directly to `main` or bypass branch protection.
