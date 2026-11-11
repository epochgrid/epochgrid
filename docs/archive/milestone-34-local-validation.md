# Milestone 34 local validation — 2026-11-11

These are local development results, not hosted release acceptance. No GHCR
publication, Git tag, GitHub Release or repository-setting change was performed.

## Tested runtime payload

- Base revision: `85b04b245c0a3862d7c472284f2e072bc8439bde` with uncommitted milestone 34 implementation.
- Version: `0.1.0-engineering.1`; bundle/image are explicitly `local: true`.
- Ubuntu 24.04 x86-64 bundle and matching Ubuntu-built qualification tools.
- Tested source fingerprint: `4ca85c14e69707cff53b1fc00b26870276606e81fb05b563abda04a53e96a99c`.
- Archive SHA-256: `9dbfed639be84bf6c7ea71e9c3a414155c696fbb4592e658b2ba6983a769d2fb`.
- Image config ID: `sha256:10d5e9eb228132b025eab871f84501682807d74b1c87c8bf8b09e651ce80d67d`.
- Transport SHA-256: `27b6d6d32971cefed5b47cacd044e202cfa73246e876530e38a6554e153fbd9f`.

The final settings-credential isolation and attestation-read permissions were
reviewed after this runtime matrix. Those changes affect the publication boundary,
not application binaries; their rejection tests and Actionlint passed separately.
The final PR revision still requires hosted qualification. These local payloads
must never be relabeled or promoted as a clean main candidate.

## Checks

| Check | Result |
| --- | --- |
| Harness | 74 tests passed, including 23 release-pipeline policy/recovery cases |
| Workflow validation | Actionlint 1.7.12 passed |
| Rust | Formatting, warnings-denied Clippy, builds and doctests passed |
| Native unit phase | Isolated diagnostic passed after the initial failure below |
| Remaining native phases | Protected-state, all retained NATS, Compose/TUI, offline join, relationships, participants and all four BYO cases passed |
| Extracted bundle: smoke | Passed |
| Extracted bundle: configuration_standalone | Passed |
| Extracted bundle: configuration_cluster | Passed |
| Extracted bundle: operator_jwt_standalone | Passed |
| Extracted bundle: operator_jwt_cluster | Passed |
| Runtime image: smoke | Passed |
| Runtime image: configuration_standalone | Passed |
| Runtime image: configuration_cluster | Passed |
| Runtime image: operator_jwt_standalone | Passed |
| Runtime image: operator_jwt_cluster | Passed |
| Separate-role image boundary | Passed |
| Pinned tools | GitHub CLI 2.100.0 and Grype 0.121.3 checksum-verified |
| Validator environment | Hash-locked dependencies installed on Ubuntu 24.04/Python 3.12; policy tests passed |
| SPDX inventories | Actual 362-component Rust/native inventory and combined image inventory passed official SPDX 2.3 schema/subject checks |

## Retained failure and scan evidence

The initial full native run failed in core units (49 passed, 66 failed, three
ignored) with locked/unavailable disposable Secret Service errors. An unchanged,
isolated unit run passed later; that is not a root-cause fix. The diagnostic also
reported SQLCipher memlock warnings. TD-003 remains open; no quarantine, blanket
retry or deadline change was introduced. See the [debt record](../technical-debt.md).

Inventory hardening initially rejected rayon-core’s Cargo `links` singleton marker.
Its reviewed 1.13.0 build script links no native code; a version-specific exception
was added and the actual bundle was rebuilt successfully. Unknown native link
providers still fail closed.

The real scans found 11 Rust/native findings and 19 combined image findings. The
[sanitized local scan](milestone-34-local-scan.json) is explicitly unreviewed; these
counts are scanner findings, not exploitability conclusions or accepted risk. No
`docs/release-review.json` was fabricated.

## Hosted acceptance still required

The release workflow must first be reviewed and merged to protected main. The
`release` environment, immutable-release setting, short-lived administration-read
preflight credential, public GHCR ownership/access and milestone 33 candidate
transport must be ready. A reviewed vulnerability assessment must match fresh
scans and native components. Then an explicitly authorized engineering prerelease
must pass real signing, negative identity checks, public retrieval and durable
distribution-proof verification. Local mocks do not satisfy those gates.
