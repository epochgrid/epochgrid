# Working handoff

Branch `feature/milestone-34` implements the engineering release pipeline on top
of milestone 33. Main advanced to `5060a35` (documentation cleanup, PR #29) during
implementation and has been merged into this branch before review.

Use [the roadmap](docs/milestones.md) for delivery status, the
[acceptance plan](docs/milestone-34-plan.md) for gates, and
[release operations](docs/operator/releases.md) for setup, consumer verification
and recovery. The implementation includes read-only rehearsal, qualification
receipts, compiled/native SPDX inventories, pinned scanning, signed consumer
policy, protected publication, collision/resume handling and durable distribution
attestations. Workspace version is `0.1.0-engineering.1`; nothing was published.

[Local validation](docs/archive/milestone-34-local-validation.md) records 74 passing
harness tests, Actionlint, native phase results, all five bundle suites, all five
image suites and the role-boundary proof. It also preserves the first core-unit
keyring failure and subsequent unchanged isolated pass. TD-001/002/003 remain open.
The real [local scan](docs/archive/milestone-34-local-scan.json) is unreviewed.

Milestone 34 is not marked complete. Hosted acceptance needs reviewed code on
protected main, release-environment/immutability setup, a short-lived settings-read
credential, milestone 33 candidate transport, reviewed vulnerability/native
coverage, and an explicitly authorized engineering prerelease with real signatures
and durable consumer proof. PR CI and hosted release evidence cannot be inferred
from local tests. No repository settings, public tags, releases or package
visibility were changed.
