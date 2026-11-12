# Working handoff

Current branch: `fix/td-003-credential-lock`, from checkpoint `274005e` of the
milestone 35 work below. The credential-lock failure now has a deterministic
fork/exec reproducer and an explicit owner-process unlock guard across all eight
production lock sites. AQ-LOCK-01/02 are required in the ordinary unit gate,
bringing its named inventory to 28. See the [repair evidence](docs/archive/td-003-lock-validation.md)
for validation and limits: five ordinary Ubuntu 24.04 unit gates (155 tests each),
live keyring checks, all 16 retained NATS cases and all four BYO modes passed.
TD-003 remains open: the first local sample exposed a
separate GNOME Keyring 50 daemon crash on Ubuntu 26.04, and cold hosted evidence
and the older failover investigation remain outstanding. No retries, concurrency
reduction, quarantine changes or plaintext credential fallback were added.

Milestone 35 implementation has started after reviewing its plan against the
milestone 34 tooling below. See the [qualification register](docs/adversarial-qualification.md)
and [local evidence](docs/archive/milestone-35-local-validation.md). The unit gate
initially required 26 named security cases, including new concurrent-redemption, hostile IPC
and seeded wire regressions. Broader fault/parser work, TD-002 reproduction,
hosted sampling, final artifact qualification and reviewed scope remain pending.
The [bounded follow-up](docs/archive/milestone-35-bounded-validation.md) adds IPC
mutations, mandatory 512 MiB parser limits, both R3 quorum-loss schedules and mapped
delivery recovery cases. Both R3 modes and delivery cases passed. An ordinary unit
run failed on credential lock contention; a traced diagnostic gate subsequently
passed without reproducing it. The separate AQ-F04 repair is recorded above;
broader TD-003 remains open. No quarantines were
removed and no runtime or distribution contract changed.

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
