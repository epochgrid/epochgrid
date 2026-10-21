# Milestone 25 handoff

## State

Milestone 25 is complete and locally validated. The follow-up repository cleanup
prepares this work for a PR on `feature/milestone-25-encrypted-state`, based on
current `origin/main` (`b21c25d`). Milestone 26 remains out of scope.

## Decisions and implementation

- SQLCipher through rusqlite's bundled SQLCipher/vendored OpenSSL feature.
- Independent random 256-bit Secret Service keys for client identity.sqlite,
  backend auth.sqlite and backend control/identity.sqlite; no plaintext fallback.
- Shared core database opener checks SQLCipher, applies a raw key through the C
  API before schema access, validates role/item binding and keeps SQL temp data
  in memory. Only opaque references/fingerprints are persisted outside encryption.
- Durable pending/ready database metadata and provisioning locks support retries
  without replacing committed keys or resetting missing/corrupt established state.
- Existing plaintext homes/registries are rejected unchanged. Milestone 24 v2
  administration archives remain supported into a new encrypted home/key, without
  adding history/MLS backup. Offline database reads now require the keyring.
- SQLite-managed read-only format probes preserve process-wide POSIX locks.
  A cross-process regression protects registry readers across external writes.
- TUI tests use a read-only Rust example inspector, keeping keys off command lines.
  Dynamic fixture failures now report bounded diagnostic tails.

## Changed files

Cargo manifests/lockfile; new core database.rs and database/tests.rs; core secrets,
identity and identity_model; affected schema-inspection tests; client recovery
allowlist; encrypted-query example; verification/CLI/TUI smoke scripts and CI label;
storage, recovery, security and feature documentation.

## Final validation — 2026-10-19

Passed: 84 unit tests, workspace binaries/examples build, warnings-denied Clippy,
formatting, ten Python harness tests, two live Secret Service tests, CLI/backend
lifecycle checks, focused dynamic join, relationship TUI and participant TUI.
Final reruns of all 16 retained NATS tests (253.24 seconds), Compose/CLI and main
three-device TUI also passed after the format-probe fix. The resolved feature graph
confirms bundled SQLCipher with vendored OpenSSL and one libsqlite3-sys dependency.

Logs are in /tmp/epochgrid-m25. Fixtures use disposable keyrings; none uses the
operator's login keyring. TD-001 typing and TD-002 full dynamic checks stay deferred.

An initial ordinary-file format probe broke SQLite's POSIX locks and caused a
reproducible dynamic enrollment failure. It was replaced with a SQLite-managed
probe; cross-process registry and focused dynamic-join tests pass. Temporary
admission logging was removed. No new validation exclusion was added.

## Next steps

Milestone 25 has no remaining local implementation/validation work. Review these
changes; protected-branch CI is still required before any merge. Start
a fresh thread for milestone 26 only when requested. Preserve the approved
fresh-state policy. The original milestone 24 merge `2e2fe9c` has the same tree as
`b21c25d`; the milestone 25 branch starts directly from `b21c25d` to keep the PR
history focused. Cleanup rechecked formatting and patch whitespace and inspected
the retained validation logs. Publication and required PR CI remain next steps;
no push or release was performed.
