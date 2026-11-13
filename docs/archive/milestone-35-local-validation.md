# Milestone 35 local implementation evidence — 2026-11-12

Local diagnostics on Ubuntu 26.04 x86-64/glibc 2.43, Rust 1.98.1, based on
`5c81070c0561f0fee69834be51fac0cd4211a596` with uncommitted milestone 35 changes.
This is not supported-platform, hosted, cold-sample, bundle or image acceptance.
The [machine record](milestone-35-local-evidence.json) contains final Rust source,
executable and harness hashes, and the parser corpus identity. No release or
repository setting was changed. Existing user planning edits were preserved.

## Attempts, including setup failures

| Attempt | Command / phase | Result and classification |
| --- | --- | --- |
| 1 | `verify.sh build`, baseline | Passed, 14.620s; unchanged application sources |
| 2 | `verify.sh nats-dynamic`, sandbox | Setup failure, exit 6: pinned NATS download could not resolve GitHub; no application test ran |
| 3 | Same command, approved outside sandbox | Download/checksum passed (2.480s); exact dynamic integration case passed, 49.309s wrapper / 49.21s test |
| 4 | `verify.sh dynamic-tui`, sandbox | Setup failure, exit 127: D-Bus could not bind disposable socket; before bounded application runner, so no timing receipt |
| 5 | Same command, approved outside sandbox | Passed, 20.264s; join, bidirectional chat, offline history and ciphertext checks |
| 6 | `verify.sh build`, new Rust regressions | Passed, 19.977s |
| 7 | `verify.sh unit`, first inventory | Setup failure: service binary target was named `epochgrid-service`, not `epochgrid_service`; no tests executed |
| 8 | `verify.sh clippy` | Passed, 1.866s |
| 9 | Rebuild after parser deadline comment | Build/packing passed, 18.176s; shell then exited 2 because verifier was edited while its running shell was reading it. Current script passes `bash -n`; no runtime defect inferred |
| 10 | `verify.sh unit`, corrected binary name | Setup failure: capacity test lives under `integration_tests`, not `tests`; no tests executed |
| 11 | Inventory corrected and checked against real libtest lists | All 18 required cases present and enabled |
| 12 | `verify.sh unit`, corrected inventory | Passed: client 14 (0.915s), service 20 (5.087s), registration 1 (1.366s), core 117 (20.064s). Existing 21 ignored broker cases and 3 ignored live-keyring cases remain separately selected by their owning phases |
| 13 | `verify.sh harness` | All 75 Python harness tests passed, including missing/ignored security-case rejection; no new retries/skips |
| 14 | `verify.sh build`, add corpus digest output | Passed; only Rust change since unit pass is parser evidence logging |
| 15 | `verify.sh adversarial AQ-PARSER-01` | Passed, 0.064s wrapper / 0.01s test; validates focused selector against final build |
| 16 | Final formatting/Clippy/diff checks | Passed |

Attempts 2–5 exercised the baseline binaries before the new test-only Rust edits.
Their complete executable identity was not retained before subsequent rebuilds;
they are diagnostic observations, not final-candidate qualification evidence.
No failed attempt was discarded or counted as a passing first attempt. Full local
logs were inspected in `/tmp/epochgrid-m35-*`; this retained summary excludes
private homes, credentials, broker configuration and raw potentially sensitive logs.

## Parser reproducibility

Engine: Rust libtest plus in-tree xorshift64, seed `0x3520261112`, 4,096 mutations.
Corpus hash: `7d9fc5daec1136e247fb5ee4b1ae6ed88d9ad9dd4aca4241d89626bc69cd9165`.
Hash input is the ordered five wire seeds, each prefixed with its byte length as a
little-endian u64. The generator and mutation schedule live in
`wire::tests::bounded_seeded_wire_mutations`. Maximum input is 131,072 bytes;
the execution watchdog is 180s. No crashes or regression fixtures were produced.
The campaign does not establish absence of uncontrolled allocations in all parsers.

## Interpretation and next required evidence

The new token race has one durable winner, preserves exact retry and cannot activate
the losing device. Malformed or stalled worker sessions clear readiness and forward
no authority request. The seeded campaign and inventory enforcement pass. These are
required native regressions, not a declaration of completed adversarial coverage.

TD-002 was not reproduced by the two local runs and remains open under its original
restoration criteria. TD-003's earlier keyring/failover failures were not diagnosed
by a passing unit run; they remain unresolved findings. TD-001 remains deferred.
The [qualification register](../adversarial-qualification.md) lists remaining
fault/parser gaps, proposed scope and the reviewed cold hosted/artifact evidence
still needed. No risk was accepted and no scope exclusion was approved.
