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
| 24–25 | Not started | OS secret storage and protected SQLite state |
| 26–28 | Not started | Qualified BYO-NATS contract, initialization/validation and backend privilege separation |
| 29–31 | Not started | Resource bounds, operational diagnostics and structured audit events |
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
Dynamic attachment access and the broader BYO-NATS qualification remain separate
release work; the complete development feature set is not yet release-qualified.
Completing TLS does not imply the alpha release gates are met. Local secrets and
transcripts remain unencrypted pending Milestones 24–25.

See [TLS](operator/tls.md), [Auth Callout](operator/auth-callout.md),
[dynamic authorization](architecture/dynamic-authorization.md), and
[deferred typing and dynamic authorization checks](technical-debt.md). Milestone 24 (Linux secret storage)
is the next release-preparation milestone.


## Latest local validation — 2026-10-18

After merging the pending-join fix from `bce2482` with the TD-002 quarantine,
the complete default `./scripts/dev/verify.sh` gate passed: formatting,
warnings-denied workspace Clippy, all 67 unit tests, workspace build, ten Python
harness tests, all 16 retained live NATS cases, Compose/CLI smoke, the main,
relationship and service-participant TUI workflows, and the focused dynamic join
reconnect regression. The NATS suite completed in 192.67 seconds with exactly one
Auth Callout case filtered out. Verifier routing and failure propagation checks
also passed.

Live typing assertions and the full dynamic authorization integration/messaging
checks remain deferred under TD-001/TD-002 and were not rerun. A green default
gate does not certify dynamic authorization end to end. These are local results;
protected-branch CI checks remain required before merge.

Earlier milestone results are consolidated in
[historical local validation](development.md#historical-local-validation). See
[TD-002](technical-debt.md) for failed CI runs and restoration criteria.
