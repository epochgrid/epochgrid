# Historical plans and validation

These records preserve design decisions, failed attempts and validation evidence.
They are not installation instructions or the current backlog. “Pending,” “next,”
unit-test counts, local paths and branch names describe the recorded revision.
Git history retains earlier versions as well.

Use the [roadmap](../milestones.md) for current status, the
[documentation index](../README.md) for current contracts, and
[technical debt](../technical-debt.md) for open reliability work.

| Completed plan | Current contract |
| --- | --- |
| [27 — initialization and validation](plans/milestone-27.md) | [Validation](../operator/validation.md) |
| [28 — backend privilege separation](plans/milestone-28.md) | [Backend roles](../backend-role-contract.md) |
| [29 — resource bounds](plans/milestone-29.md) | [Capacity](../operator/capacity.md) |
| [30 — operational diagnostics](plans/milestone-30.md) | [Diagnostics](../operator/diagnostics.md) |
| [31 — security audit](plans/milestone-31.md) | [Audit operations](../operator/audit.md) |
| [32 — Linux artifacts](plans/milestone-32.md) | [Binary bundles](../operator/linux-artifacts.md) |
| [33 — runtime image implementation](plans/milestone-33.md) | [Containers](../operator/containers.md); candidate registry transport pending |

Implementation records:

- [Milestone 34 local validation](milestone-34-local-validation.md) and
  [unreviewed local scan](milestone-34-local-scan.json): implementation evidence,
  retained failures and outstanding hosted acceptance.

- [Milestone 33 handoff](handoff-m33.md): image qualification, harness correction,
  and unresolved native failover evidence; PR #28 and hosted CI subsequently passed.

- [Handoff through milestone 32](handoff-through-m32.md): local results, CI follow-ups
  and unresolved failures. Milestone 32 subsequently merged in PR #27.
- [Development history through protected storage](development-through-m25.md):
  early feature/upgrade notes; old plaintext-home procedures are obsolete.
- [CI design review, 2026-10-22](ci-review-2026-10-22.md): measurements and the
  transition to shared test builds. Current behavior is in [CI](../ci-strategy.md).
- [Historical milestone validation](milestone-validation-through-m32.md): previous
  status snapshot and local validation tables, not current merge/release status.

When a milestone merges, archive its acceptance plan and retain its failed as well
as passing evidence. Put operational behavior in its contract, and update the
roadmap once rather than copying current status into each historical record.
