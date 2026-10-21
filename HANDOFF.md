# Milestone 26 handoff

## State

Milestone 25 PR #15 merged as `4be5cc4e62914ecdda72461a3ca1049722cdd93c`.
Milestone 26 implementation is on `feature/milestone-26-byo-nats`, based on that
merged `origin/main`. The user approved configuration-mode and operator-JWT,
standalone and three-node cluster qualification. Implementation and local validation
are complete; no commit, push, PR or release has been performed for milestone 26.

Preserve the existing TD-003 post-MVP test-reliability documentation changes. They
were carried from the milestone 25 review and are included in this working tree.
TD-001 typing and TD-002 short-lease dynamic messaging remain deferred; this work
adds no quarantine and does not resolve those debts.

## Implementation and boundaries

- Optional `auth.json.operator_jwt` contains authentication-account public NKey and
  signed, non-bearer auth-service user JWT. Configuration mode remains compatible.
- Validate JWT signature, type/version, connection-key/account binding, expiry and
  not-before. NATS checks the operator's delegated signing authority.
- Operator-mode requests bind the authentication account; user grants carry the
  application's `issuer_account`, signed by the existing generated issuer key
  delegated as an unscoped application-account signing key. All private EpochGrid
  keys stay in Secret Service; no operator/account root seed enters runtime config.
- The pinned NATS 2.14.5 `default_sentinel` routes device NKey connections into
  encrypted Auth Callout. No device-side JWT or static device allow-list is needed.
- Four isolated production-TLS qualification cases cover configuration/operator JWT
  on R1 standalone and R3 clusters. Routes use mutual TLS. Operator fixtures own
  configuration, account JWTs and pre-provisioned stream/KV replication settings.
- Exercise enrollment, messaging, negative TLS/admission/permission checks, account
  isolation, broker leader loss, offline history, backend restart, revocation,
  replica catch-up and preservation of operator config/resource settings.
- `byo-build` compiles separately. `byo-nats [CASE]` runs bounded cases; the default
  local verifier includes them and CI has four independent matrix jobs. Original
  16 NATS cases retain their existing phase/budget; the four new cases run separately.
- Deployment contract: `docs/operator/byo-nats.md`. Other versions/topologies,
  scoped JWT signers, dynamic attachments and backend HA are not qualified.
  Initialization/validation tooling is milestone 27; privilege separation is 28.
  Preserve milestone 25's fresh encrypted-state policy and SQLite-managed probes.

## Final local validation — 2026-10-20 (America/New_York)

Passed: formatting/patch whitespace, 85 workspace unit tests, warnings-denied Clippy, binaries/examples
build, ten harness regressions, protected credential/database lifecycle checks,
all 16 retained NATS cases (252.26 seconds), Compose/CLI, main/relationship/participant
TUI, focused dynamic join/reconnect and all four BYO-NATS configurations. Two
consecutive final fresh-state matrix passes succeeded (eight case executions,
roughly 26–43 seconds per case). Local documentation file links and verifier shell
syntax also pass. No new runtime synchronization fix was needed for this matrix.

Useful retained logs: `/tmp/epochgrid-m26-byo-final.log`,
`/tmp/epochgrid-m26-byo-repeat-{1,2}.log`, `/tmp/epochgrid-m26-clippy.log`, and
`/tmp/epochgrid-m26-{secrets,nats,compose,tui,dynamic-join,relations-tui,participants-tui}.log`.
The unit suite passed but emitted SQLCipher mlock warnings under concurrent local
load; no memory-lock guarantee is established by these tests.

Two test-design findings were corrected during implementation: async-nats can
return a connection on INFO before a later auth rejection (negative tests now
require explicit authorization errors); and each JetStream stream/consumer elects
its own leader (failover readiness now checks all relevant resources). No runtime
membership-sync bypass or assertion-suppressing retry was added.

## Next steps

Review the diff and run cold GitHub CI on the
feature branch before merge. Local fresh-state repetitions are not cold-runner CI
evidence. Ensure the new matrix jobs are included in merge review; adding jobs to
workflow YAML does not itself update protected-branch required-check settings.
Milestone 27 is not started. Do not claim the complete alpha release is qualified.
