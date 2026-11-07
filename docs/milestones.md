# Roadmap and deployment status

Status reviewed against `main` at `04652c7` (milestone 32, PR #27) on 2026-11-06.
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
| 33 — runtime image | Implemented on a separate branch; hosted CI under review | Verified-bundle image, separate-role boundary, image matrix and controlled GHCR candidate transport; see below |
| 34 — release publication and supply chain | Planned, not implemented | Versioned promotion, GitHub Releases, signatures/attestations and provenance policy |
| 35 — adversarial qualification | Planned, not implemented as a complete suite | Broader negative, fault and recovery coverage with explicit release evidence |
| 36 — protocol/configuration freeze | Planned, not frozen | Versioning, compatibility and migration commitments for the supported release scope |
| 37 — first-run experience | Planned | Repeatable setup and actionable recovery without bypassing security prerequisites |
| 38 — operator documentation set | Planned release gate | Validate the supported install, operate, upgrade, backup/recovery and removal procedures end to end |

Milestone 33 is in [PR #28](https://github.com/epochgrid/epochgrid/pull/28), on
`feature/milestone-33-runtime-image` at `1a42ed7`, not in this main-based checkout.
Its [acceptance plan](https://github.com/epochgrid/epochgrid/blob/1a42ed7/docs/milestone-33-plan.md)
and [handoff](https://github.com/epochgrid/epochgrid/blob/1a42ed7/HANDOFF.md) are owned
by that branch. All six local image checks passed before the Python 3.12 harness
fix. That fix passed all 42 harness tests on Python 3.12 and triggered CI run #90;
it does not replace qualification of the new revision.
The full native verifier had a JWT-cluster failover-readiness timeout; an unchanged
focused rerun passed, without establishing a cause. The user is monitoring hosted
CI. This documentation snapshot does not report its eventual result.

To close milestone 33: obtain the required regression/hosted image evidence, merge,
then explicitly invoke candidate publication from protected main and verify the
registry digest round trip. Confirm package ownership, access and visibility first.
No `latest`, semantic-version or alpha release promotion belongs to milestone 33.
When it merges, reconcile this index with its final handoff and move the completed
plan into the [archive](archive/README.md).

## Remaining delivery plan

Milestones 34–38 retain the scopes above; detailed acceptance plans must be reviewed
before implementation. Their numbers organize ownership, not an assertion that
publishing an artifact finishes alpha qualification.

1. Finish milestone 33 qualification and candidate transport. Keep current
   Secret Service, SQLCipher, peer-UID isolation and operator-owned NATS boundaries.
2. Define milestone 34's promotion/verification contract using the qualified bundle
   and image. Bind artifacts to the selected release revision; do not relabel PR
   merge-candidate bytes as a different commit. Candidate transport is not a signed release.
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
