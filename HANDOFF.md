# Working handoff

Documentation consolidation is reconciled with main `57d2739`, which merged
milestone 33 in [PR #28](https://github.com/epochgrid/epochgrid/pull/28).
[Hosted CI run #90](https://github.com/epochgrid/epochgrid/actions/runs/42326075288)
passed for PR head `1a42ed7`; this is PR merge-candidate evidence, not a separate
build of the squash commit.

Use [the roadmap](docs/milestones.md) for current status and next work,
[the documentation index](docs/README.md) for contracts, and
[technical debt](docs/technical-debt.md) for unresolved failures/restoration criteria.
The [container guide](docs/operator/containers.md), Compose example and image
qualification workflows are retained. Candidate publication remains explicitly
invoked; no registry publication or package-setting change is part of this fix.

[Milestone 33 evidence](docs/archive/handoff-m33.md) preserves the Python 3.12
harness correction, exact-image local results and unexplained native JWT-cluster
failover timeout followed by a passing unchanged focused rerun. Hosted CI success
does not establish its cause or close TD-003. TD-001/002/003 remain open.
Historical details through milestone 32 remain in
[the earlier handoff](docs/archive/handoff-through-m32.md).
