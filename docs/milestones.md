# Current milestone and deployment status

This is the current status index. Individual milestone documents also retain
historical design and validation evidence; old test counts are not current totals.
No `v0.1.0-alpha.1` tag or production-ready release has been published.

| Milestone | Status | Implemented behavior / remaining work |
| --- | --- | --- |
| 0–10 | Complete | Alice/Bob MLS MVP, durable ciphertext history, offline catch-up, restart/resume and ciphertext-only acceptance coverage |
| 11 | Complete | Persistent TUI and scripting CLI |
| 12 | Complete in development model | Independent devices and MLS leaves, grouped user display; canonical identity enrollment added in 21 |
| 13 | Complete within documented limits | Manual verification and bounded authenticated registration history; no global transparency consensus |
| 14 | Legacy implementation retained only for development | Static NATS exclusion/reload and MLS rekeying; production replacement is 21–22 |
| 15 | Complete within documented recovery scope | Encrypted identity-administration recovery; excludes history and old MLS ratchets |
| 16 | Complete in development model | Encrypted Object Store attachments; dynamic permissions still need integration |
| 17 | Partial — UI deferred | Protected ephemeral transport implemented; unreliable live typing UI and its default live assertions deferred as TD-001 |
| 18 | Complete in development model | Protected device delivery/read receipts |
| 19 | Complete in development model | Append-only replies, edits and reactions |
| 20 | Complete in development model | Explicit MLS service participation and removal |
| 21 | Complete admission slice | Canonical users, local single-use enrollment tokens, encrypted Auth Callout and dynamic revocation denial |
| 22 | Implemented — live reliability deferred (TD-002) | Signed policies synchronized with the MLS outbox; exact grants, filtered durable consumers, signed Welcome relay, bounded lease expiry and revocation/rekey convergence; dynamic CLI/TUI chat and restart coverage quarantined after intermittent failures |
| 23 | Complete transport milestone | Shared production TLS profile, system/custom roots, name validation, configurable minimum version, TLS-first and certificate-rotation tests |
| 24 | Implemented; locally validated | Linux Secret Service credentials, no plaintext fallback, fresh installs only |
| 25 | Merged (#15) | SQLCipher client/backend state, independent Secret Service keys, fresh encrypted homes only |
| 26 | Implemented; locally validated | BYO-NATS contract, operator-JWT adapter, standalone/R3 cluster qualification; cold CI pending |
| 27 | Implemented; cold CI pending | Explicit initialization/export, offline/online validation, production startup admission gate and generated-artifact BYO fixtures |
| 28 | Merged (#21); hosted CI passed | [Backend privilege separation plan](milestone-28-plan.md) and [role contract](backend-role-contract.md): isolated authority/control roles, least-privilege runtime grants and restart-safe admission |
| 29 | Merged (#23); hosted CI passed | [Capacity contract](operator/capacity.md), transactional limits and finite broker budgets |
| 30 | Implemented; locally validated; hosted CI pending | [Operational diagnostics](operator/diagnostics.md): bounded authenticated runtime status, aggregate observations and troubleshooting |
| 31 | Not started | Structured security audit events, storage and export |
| 32–34 | Not started | Official Linux artifacts, GHCR runtime image and release supply chain |
| 35–38 | Not started | Broader adversarial suite, protocol/configuration freeze, first-run UX and operator documentation set |

## Which deployment path works today?

The original README walkthrough uses explicitly **development-only**
static NATS fixtures. Set `EPOCHGRID_PROFILE=development` in each terminal used for
those commands. The provided development smoke runners select it explicitly and
print a warning. This is not the alpha deployment model.

The production-shaped path supports dynamic enrollment/admission and normal
CLI/TUI encrypted chat, invitations, durable catch-up and revocation over verified
TLS. Dynamic join/send synchronization remains unreliable; its live checks are
temporarily quarantined under [TD-002](technical-debt.md). Use the [dynamic walkthrough](operator/auth-callout.md#dynamic-client-walkthrough).
Dynamic attachment access remains separate release work. The
[BYO-NATS contract](operator/byo-nats.md) defines the milestone 26 qualification
matrix; the complete development feature set is not yet release-qualified.
Completing TLS does not imply the alpha release gates are met. Standalone NATS credentials use [Linux Secret Service](secret-storage.md). MLS
private state, transcripts and backend registry data use SQLCipher with independent
Secret Service keys. Existing plaintext homes/registries require fresh enrollment;
offline database access also requires the keyring.

See [TLS](operator/tls.md), [Auth Callout](operator/auth-callout.md),
[dynamic authorization](architecture/dynamic-authorization.md), and
[deferred typing and dynamic authorization checks](technical-debt.md). Milestone 25 (protected SQLite state)
is merged. Milestone 26 (BYO-NATS qualification) is locally validated; milestone 27
initialization/export, offline/online validation and production startup enforcement
are implemented. See [deployment validation](operator/validation.md) for the
pre-provisioning requirement and coverage limits. Milestone 28 merged in PR #21;
hosted CI passed as recorded in HANDOFF. See the [role contract](backend-role-contract.md) and
[handoff](../HANDOFF.md) for the boundary and verification evidence.

Post-MVP delivery includes a dedicated test and CI reliability focus under
[TD-003](technical-debt.md#td-003--test-and-ci-reliability-post-mvp-delivery-focus),
covering execution budgets, fixture synchronization and disconnect/send races.


## Milestone 27 local validation — 2026-10-22

Initialization/export, non-initializing offline inspection, bounded online
validation and production startup enforcement are implemented. The shared resource
contract requires explicit R1/R3 replication. Production refuses missing or
incompatible resources and unhealthy replicas before device admission; operator
settings are never repaired automatically. Existing encrypted M26 homes use
explicit export/setup, without key or database migration.

All required local gates passed across the final verification phases: formatting,
warnings-denied Clippy, 107 workspace unit tests, binaries/examples, ten harness
regressions, three isolated live Secret Service tests, protected-state CLI checks,
16 retained NATS cases, Compose/CLI and main/relationship/participant TUI checks,
focused dynamic join/reconnect, and all four expanded BYO cases. The latter cover
both validation modes and startup refusal alongside retained messaging, restart,
revocation, failover and account isolation. Builds and integration runs remained
separate bounded phases. No automatic retry or quarantine rules were added.

Earlier disposable-keyring failures and corrected error-code assertions are
recorded in [HANDOFF.md](../HANDOFF.md), along with the final logs. The later
workspace unit and protected-state phases passed; the initial keyring-session
failure cause was not established. Cold CI for all four BYO cases remains required
before merge. These results do not qualify an alpha release. See
[deployment validation](operator/validation.md) for coverage and limitations.

## Milestone 26 local validation — 2026-10-20

Milestone 26 passes formatting, warnings-denied workspace Clippy, binaries/examples
build, 85 unit tests, ten harness regressions, both explicit live Secret Service
tests and protected credential/database lifecycle checks. All 16 retained NATS
cases pass in 252.26 seconds; Compose/CLI, main TUI, relationship TUI, participant
TUI and focused dynamic join/reconnect also pass.

The four BYO-NATS cases pass, including two consecutive final fresh-state matrix
runs (eight case executions). They cover configuration/operator-JWT authentication,
standalone/R3 cluster storage, verified client TLS and mutually authenticated routes,
enrollment and messaging, explicit admission/permission denials, account isolation,
broker leader loss, durable catch-up, backend restart, revocation, restored replica
convergence and unchanged operator configuration/resources. Each case takes roughly
26–43 seconds locally with prebuilt binaries and the default 30-second device lease.

The [deployment contract](operator/byo-nats.md) pins NATS 2.14.5 and documents the
operator-JWT default-sentinel/delegated-signing setup and unsupported configurations.
New CI matrix jobs separate compilation from execution. These are local fresh-state
results, not cold GitHub runner evidence; required CI/review remains before merge.
TD-001/TD-002 remain open, and post-MVP TD-003 reliability work is unchanged.
Validation logs are retained under `/tmp/epochgrid-m26-*.log`; see HANDOFF.md for
the specific files and implementation boundaries. No release has been published.

## Milestone 25 local validation — 2026-10-19

Milestone 25 passed formatting, warnings-denied workspace Clippy, all 84 unit
tests, workspace binaries/examples build, ten Python harness tests, all 16 retained
live NATS cases, Compose/CLI smoke, main/relationship/service-participant TUI
workflows, and focused dynamic join/reconnect. The final NATS suite completed in
253.24 seconds with the existing TD-002 case filtered out.

Two explicit live Secret Service tests and CLI/backend lifecycle checks also
passed, including encrypted administration recovery, restart, missing/locked/
duplicate/swapped keys, unavailable/stalled D-Bus sessions, and no-secret-file scans.
Database coverage includes unreadability without the key, encrypted WAL/journal
payloads, actual MLS signing-key/transcript/registry marker scans, process-crash
recovery, interrupted metadata commits, legacy plaintext rejection, and refusal to
reset established state. Cross-process registry readers/writers protect against
POSIX-lock loss; the format probe uses SQLite-managed connections.

Logs are retained locally under `/tmp/epochgrid-m25/`. Tests use disposable
password-protected keyrings and isolated Compose state; developer state is not
converted or reset. Existing plaintext homes remain unsupported. Recovery v2
archives retain administration-only scope, with a fresh database key on restore.

Live typing assertions and full dynamic authorization integration/messaging checks
remain deferred under TD-001/TD-002. A green default gate does not certify dynamic
authorization end to end. These are local results; protected-branch CI checks
remain required before merge. No alpha release or publication is implied.

Earlier milestone results are consolidated in
[historical local validation](development.md#historical-local-validation). See
[TD-002](technical-debt.md) for failed CI runs and restoration criteria.
