# Roadmap and deployment status

Status reviewed against `main` at `5060a35` (documentation cleanup, PR #29) on
2026-11-11. This branch includes that merge and milestone 34 release automation.
This is the single current project-status and delivery-plan index. Merged means
present in main; it does not imply production readiness or a qualified release.
No alpha release or published runtime image is claimed.

## Current delivery

| Work | Status | Scope and next gate |
| --- | --- | --- |
| 24 — protected credentials | Merged, PR #14 | [Linux Secret Service](secret-storage.md); no plaintext fallback |
| 25 — encrypted local state | Merged, PR #15 | SQLCipher databases and independent keyring keys; fresh encrypted homes |
| 26 — operator-owned NATS | Merged, PR #16 | [Configuration/operator-JWT, R1/R3 qualification](operator/byo-nats.md) |
| 27 — initialization and validation | Merged, PR #17 | [Explicit setup/export and offline/online validation](operator/validation.md) |
| 28 — privilege separation | Merged, PR #21 | [Separate authority/control accounts and keyrings](backend-role-contract.md) |
| 29 — capacity | Merged, PR #23 | [Finite application and broker resource bounds](operator/capacity.md) |
| 30 — diagnostics | Merged, PR #24 | [Authenticated runtime status and troubleshooting](operator/diagnostics.md) |
| 31 — audit evidence | Merged, PR #26 | [Encrypted authority audit, export and explicit retention](operator/audit.md) |
| 32 — Linux bundles | Merged, PR #27 | [Verified candidates and extracted-binary qualification](operator/linux-artifacts.md); no release publication |
| 33 — runtime image | Merged, PR #28; hosted PR CI passed | Verified-bundle image, separate-role boundary and full image matrix; explicit GHCR candidate round trip still pending |
| 34 — release publication and supply chain | Release pipeline implemented and locally validated; hosted acceptance blocked | [Plan](milestone-34-plan.md), [release operations](operator/releases.md); rehearsal, provenance, SPDX/scanning, consumer policy, protected publication and recovery code present. Protected environment, immutable releases, candidate transport, vulnerability review and real hosted distribution proof remain outstanding |
| 35 — adversarial qualification | Implementation started; acceptance and scope review pending | [Plan](milestone-35-plan.md), [qualification register](adversarial-qualification.md): 26 required security regressions, concurrent redemption/hostile IPC tests and seeded wire campaign; broader fault coverage, TD-002 investigation and cold hosted/artifact evidence remain outstanding |
| 36 — protocol/configuration freeze | Acceptance plan written; not implemented or frozen | [Plan](milestone-36-plan.md): independent version contracts, fixed fixtures, explicit compatibility/upgrade matrix and hosted freeze evidence |
| 37 — first-run experience | Planned | Repeatable setup and actionable recovery without bypassing security prerequisites |
| 38 — operator documentation set | Planned release gate | Validate the supported install, operate, upgrade, backup/recovery and removal procedures end to end |

Milestone 33 merged in [PR #28](https://github.com/epochgrid/epochgrid/pull/28)
as `57d2739`. [Hosted CI run #90](https://github.com/epochgrid/epochgrid/actions/runs/42326075288)
passed for PR head `1a42ed7`, including image qualification. CI tested the PR
merge candidate; no separate squash-commit build is claimed. The
[archived plan](archive/plans/milestone-33.md) and
[implementation evidence](archive/handoff-m33.md) retain local image results,
the Python 3.12 harness correction and the unexplained native JWT-cluster timeout.
A passing unchanged focused rerun and hosted CI do not establish its root cause.

To close milestone 33, explicitly invoke candidate publication from protected main
and verify the registry digest round trip. Confirm package ownership, access and
visibility first. No publication is claimed here. No `latest`, semantic-version
or alpha release promotion belongs to milestone 33.

## Remaining delivery plan

Milestone 34 implementation follows its [acceptance plan](milestone-34-plan.md);
milestone 35's [adversarial acceptance plan](milestone-35-plan.md) supplies the
supported scope and security evidence for milestone 36's
[compatibility acceptance plan](milestone-36-plan.md). Execute those gates in that order.
Milestones 37 and 38 still need detailed acceptance plans. Review plans before implementation.
Their numbers organize ownership, not an assertion that
publishing an artifact finishes alpha qualification.

1. Finish milestone 33 qualification and candidate transport. Keep current
   Secret Service, SQLCipher, peer-UID isolation and operator-owned NATS boundaries.
2. Complete milestone 34's hosted promotion/verification acceptance using the qualified
   bundle and image, after implementation review. Bind artifacts to the selected release revision;
   do not relabel PR merge-candidate bytes as a different commit. Candidate transport
   is not a signed release.
3. Resolve or explicitly disposition release blockers through adversarial coverage
   and compatibility decisions (35–36). Dynamic Object Store permissions and
   short-lease dynamic messaging remain unqualified; a narrower release must say so.
4. Validate first-run and operator procedures against that supported scope (37–38).
   Existing guides are implementation contracts, not evidence that every release
   installation/upgrade/recovery workflow has been qualified.

Reliability work is tracked once in [technical debt](technical-debt.md): TD-001
live typing, TD-002 short-lease dynamic authorization/messaging, and TD-003 test/CI
reliability. Packaging or one green rerun closes none of them. TD-003 adds no
quarantines. Preserve failing evidence, bounded execution and authorization assertions.

Backend HA, remote authority/control placement, non-Linux credential providers,
ARM64/container-platform expansion and automatic plaintext-state migration are
outside the currently qualified scope; they need explicit future plans.

## What works today

The [README walkthrough](../README.md#local-development) is a static, loopback-only
**development fixture**. Set `EPOCHGRID_PROFILE=development` for its commands.
It is not the operator deployment model.

The production-shaped path uses [operator-owned NATS](operator/byo-nats.md),
[verified TLS](operator/tls.md), [explicit enrollment](operator/auth-callout.md),
[separate backend roles](backend-role-contract.md), and [deployment validation](operator/validation.md).
It supports dynamic admission and normal CLI/TUI messaging, but the short-lease
live workflows remain quarantined under TD-002. Dynamic attachment access is not
qualified. A green default gate does not certify the whole development feature set.

Runtime credentials require [Linux Secret Service](secret-storage.md). MLS private
state, transcripts and registry data use SQLCipher. Offline access also needs the
matching keyring. Existing plaintext homes require fresh enrollment; administration
recovery excludes message history and MLS ratchets. Use [audit upgrade](operator/audit.md)
for established schema-2 encrypted authority homes; never infer downgrade compatibility.

## Earlier delivered scope

| Milestones | Delivered behavior and limits |
| --- | --- |
| 0–10 | Two-device MLS MVP, durable ciphertext, offline catch-up and restart; [acceptance](mvp-acceptance.md) |
| 11–13 | TUI, independent devices, manual verification and bounded authenticated registration history; no global transparency consensus |
| 14 | Static revocation/reload retained for development; production admission/revocation is 21–22 |
| 15 | Encrypted identity-administration recovery; excludes transcripts and MLS ratchets |
| 16 | Encrypted Object Store attachments in the development model |
| 17 | Protected ephemeral transport; live typing UI deferred under TD-001 |
| 18–20 | Device receipts, append-only message relationships and explicit MLS service participants in the development model |
| 21–22 | Canonical enrollment, encrypted Auth Callout, signed policies, exact grants and revocation; live reliability remains TD-002 |
| 23 | Shared production TLS profile, custom/system trust, TLS-first and rotation coverage |

Completed acceptance plans and dated validation results live in the
[archive](archive/README.md). Test totals and local paths there describe old revisions;
use [development](development.md) and [CI](ci-strategy.md) for today's commands.
