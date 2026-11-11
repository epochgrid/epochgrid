# Roadmap and deployment status

Remote status verified against `main` at `57d2739` (milestone 33, PR #28) on 2026-11-10.
The `feature/milestone-34` branch includes the documentation cleanup and merged
runtime-image implementation at `57d2739`; main was fetched again on 2026-11-11.
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
| 35 — adversarial qualification | Planned, not implemented as a complete suite | Broader negative, fault and recovery coverage with explicit release evidence |
| 36 — protocol/configuration freeze | Planned, not frozen | Versioning, compatibility and migration commitments for the supported release scope |
| 37 — first-run experience | Planned | Repeatable setup and actionable recovery without bypassing security prerequisites |
| 38 — operator documentation set | Planned release gate | Validate the supported install, operate, upgrade, backup/recovery and removal procedures end to end |

Milestone 33's [PR #28](https://github.com/epochgrid/epochgrid/pull/28) merged on
2026-11-07 as `57d2739`. Its
[acceptance plan](https://github.com/epochgrid/epochgrid/blob/57d2739864c0cb3513d8bcb9859c4b25d30c0c8d/docs/milestone-33-plan.md)
and [handoff](https://github.com/epochgrid/epochgrid/blob/57d2739864c0cb3513d8bcb9859c4b25d30c0c8d/HANDOFF.md) preserve
the implementation and local evidence.
[Hosted CI run #90](https://github.com/epochgrid/epochgrid/actions/runs/42326075288)
passed all 25 jobs: native and extracted-bundle regressions, image construction,
all five image qualification jobs, and the aggregate gate. It tested the PR revision
`1a42ed7`/merge candidate; it does not qualify the squash commit's identity.
The earlier local native JWT-cluster failover timeout remains unexplained despite
its unchanged focused rerun and the later hosted pass. TD-003 remains open.

To close milestone 33: explicitly invoke candidate publication from protected main,
which rebuilds and qualifies the selected main SHA, and verify the registry digest
round trip. Confirm package ownership, access and visibility first. No manually
dispatched workflow runs were listed when checked on 2026-11-10; no successful
candidate publication is claimed.
No `latest`, semantic-version or alpha release promotion belongs to milestone 33.
The runtime guide and Compose example are preserved on the implementation branch.
Archive the plan after its candidate-transport gate is complete.

## Remaining delivery plan

Milestone 34 implementation follows its [acceptance plan](milestone-34-plan.md);
milestones 35–38 still need detailed acceptance plans. Review those plans before implementation.
Their numbers organize ownership, not an assertion that
publishing an artifact finishes alpha qualification.

1. Finish milestone 33 qualification and candidate transport. Keep current
   Secret Service, SQLCipher, peer-UID isolation and operator-owned NATS boundaries.
2. Implement milestone 34's planned promotion/verification contract using the qualified
   bundle and image, after plan review. Bind artifacts to the selected release revision;
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
