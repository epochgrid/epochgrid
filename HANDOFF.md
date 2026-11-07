# Working handoff

This checkout is the documentation-cleanup branch `docs/consolidate-project-plans`,
based on current main `04652c7` (milestone 32, PR #27). It does not contain the
milestone 33 implementation. No application, test or workflow behavior changes
are part of this cleanup.

Use [the roadmap](docs/milestones.md) as the single source of current milestone
status and next work, [the documentation index](docs/README.md) to find contracts,
and [technical debt](docs/technical-debt.md) for unresolved failures and restoration
criteria. Completed plans and dated validation are in [the archive](docs/archive/README.md).

Milestone 33 is in [PR #28](https://github.com/epochgrid/epochgrid/pull/28) on
`feature/milestone-33-runtime-image`. Initial implementation `6a9e622` was followed
by the Python 3.12 test-mock fix `1a42ed7`, which triggered CI run #90. The user is
monitoring hosted CI. Its [branch handoff](https://github.com/epochgrid/epochgrid/blob/1a42ed7/HANDOFF.md)
records the earlier exact-image qualification, passing corrected harness checks,
and unresolved native JWT-cluster failover timeout (unchanged focused rerun passed). Do not present those checks as
execution against this main-based checkout or as a passing full verifier result.

When reconciling the documentation branch with milestone 33, preserve its operator
container guide, Compose example, image plan and qualification evidence. Update the
roadmap to the actual merge/CI/publication results and archive the completed plan.
GHCR publication remains explicitly invoked; no publication or package-setting
change is authorized by this documentation cleanup. TD-001/002/003 remain open.

Historical handoff details through milestone 32 are retained in
[the implementation record](docs/archive/handoff-through-m32.md); pending-status
statements there are historical, not current blockers for already merged milestones.

The user authorized committing and pushing this documentation branch and will
prepare its PR. Local links/anchors, shell-example syntax and diff whitespace pass.
