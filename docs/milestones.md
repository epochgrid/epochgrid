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
| 22 | Complete | Signed policies synchronized with the MLS outbox; exact grants, filtered durable consumers, signed Welcome relay, bounded lease expiry and revocation/rekey convergence; dynamic CLI/TUI chat and restart tested |
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
TLS. Use the [dynamic walkthrough](operator/auth-callout.md#dynamic-client-walkthrough).
Dynamic attachment access and the broader BYO-NATS qualification remain separate
release work; the complete development feature set is not yet release-qualified.
Completing TLS does not imply the alpha release gates are met. Local secrets and
transcripts remain unencrypted pending Milestones 24–25.

See [TLS](operator/tls.md), [Auth Callout](operator/auth-callout.md),
[dynamic authorization](architecture/dynamic-authorization.md), and
[deferred typing indicators](technical-debt.md). Milestone 24 (Linux secret storage)
is the next release-preparation milestone.


## Historical local validation — Milestone 23

Formatting, warnings-denied workspace Clippy, 60 unit tests, workspace build and
all 17 live NATS integration cases passed. The bounded harness, isolated Compose
CLI smoke and all three TUI smoke modes also passed. Typing assertions remain
explicitly skipped under TD-001. These are local results; branch CI is a separate
required check before merging. No release tag or artifact publication is implied.

## Latest local validation — Milestone 22 completion

Formatting, warnings-denied workspace Clippy, 62 unit tests and workspace build
passed. All 17 live NATS integration cases, the bounded harness, Compose CLI smoke
and all four TUI modes passed, including the new dynamic Auth Callout TUI flow.
The final lease/retry adjustment was also checked with the expanded dynamic
lifecycle case. It proves unchanged NATS configuration, no reload, per-group and
per-device isolation, active-connection expiry, revoked reconnect denial, MLS epoch
advancement and remaining-device messaging after restart. CI runs the new TUI mode
with an independent deadline. Protected-branch CI remains required before merge;
these local results are not a release tag or production security certification.
