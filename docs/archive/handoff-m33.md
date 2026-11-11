# Milestone 33 implementation and validation record

> Archived from main at `57d2739`. Pending and branch-status statements below
> describe their recorded revision. PR #28 subsequently merged and hosted CI
> run #90 passed; candidate publication is not established by that result.
> See the [roadmap](../milestones.md) for current status.

## Current status — PR #28 Python 3.12 harness fix

[CI run #89](https://github.com/epochgrid/epochgrid/actions/runs/42324513387)
failed in the native build's harness step. The image process test mocked `Path.stat`
with only `st_uid`; Python 3.12's `Path.is_symlink` calls `lstat` and needs `st_mode`.
Local Python 3.14 uses a different symlink path and did not expose the incomplete
mock. The fix returns an `os.stat_result` retaining file metadata and changing only
its simulated UID. Runtime ownership and symlink checks are unchanged.

Reproduced the exact failure in the Ubuntu 24.04/Python 3.12 fixture before editing.
After the fix, all four mount tests pass on Python 3.12 and 3.14; the full offline
harness (42 tests) passes on Ubuntu 24.04/Python 3.12. Diff whitespace also passes.
The user authorized committing and pushing this correction to trigger hosted CI.
The earlier image evidence below predates this test-source change; new hosted
qualification must bind to the new revision. The native failover timeout remains
unexplained. No qualification result, publication or release is inferred from
these harness checks.

## Previous status — milestone 33 implementation and final local qualification

Work remains on `feature/milestone-33-runtime-image`, based on `04652c7`.
The image adapter now runs the retained four BYO scenarios against the runtime
image's own binaries. The smoke suite covers protected credentials/encrypted state,
recovery and bounded key failures, schema-2 audit upgrade, and CLI/TUI offline
restart. Fixture processes retain signal, kill, RSS and cleanup semantics;
application containers receive only explicit state/bus/CA/IPC/export mounts.
No production Rust code or authorization semantics changed.

PR CI now builds the verified-bundle image once and transports it to five isolated
qualification jobs (smoke plus four BYO cases). Smoke also runs the distinct-UID
boundary proof. Every job participates in `validate`; reports survive failure and
artifacts expire after seven days. The separate `image-candidate.yaml` manual
workflow requires protected main and explicit package ownership/access/visibility
confirmation, reuses the full qualification workflow, refuses existing candidate
tags, pushes qualified bytes, and checks a digest pull on a fresh runner. Only
its push job gets package write permission. No publication has been invoked.

The [operator guide](../operator/containers.md) and
[Compose example](../operator/compose.runtime.yaml) now cover independent host
keyrings, role UIDs/homes, read-only IPC, TLS/broker provisioning, one-shot setup,
authenticated readiness, bounded stop/restart, audit exports/upgrades, optional
client use and digest-pinned candidate deployment. Milestone index, plan, CI and
binary-artifact documentation reflect the implemented paths.

Final image evidence (2026-11-06):

- `target/m33-completion2-image/image.json`: image contract passed; config ID
  `sha256:9602105da50b6d7997acfde00e49b67cb7adf86526820c729893b6a066bbdd4e`.
- Source fingerprint `9a34a810697391f28c9687d78b956dfa2e1096300dd2e0b2063c208650207afb`;
  transport 142,520,832 bytes, SHA-256
  `199caee9e5a87f34d4777c92c7c32194431b64f4a75181efb924ba759251e409`.
- All reports under `target/m33-completion-results/` passed against that exact
  image/source: smoke 18.877 s, configuration R1 66.635 s, configuration R3
  77.439 s, operator-JWT R1 76.700 s, operator-JWT R3 83.622 s, boundary 13.099 s.
  Reports separate setup/execution timing and retain failure/cleanup outcomes.
- The publication report gate accepts all six matching reports in an offline
  check. This dirty local image remains unpublishable; no registry test is claimed.
- Actionlint, Compose configuration, local documentation links and diff whitespace
  checks passed. The full repository verifier passed harness, formatting, Clippy,
  build/doctests, units, protected-state checks, retained NATS scenarios, Compose,
  all retained UI smoke and three native BYO cases. Its last native case,
  `operator_jwt_cluster`, failed at `stream/consumer failover readiness` after
  the existing 40-second readiness deadline. The full run is failed, not passed.
  Service logs show reconnection to surviving brokers, but the bounded log tails
  do not identify which stream/consumer remained unavailable. A focused diagnostic
  rerun of the unchanged case passed in 104.227 s; log
  `/tmp/epochgrid-m33-native-jwt-investigation.log`. The original failure remains
  unexplained and is not converted into a passing full verifier result. No
  timeout, assertion, automatic retry or quarantine policy changed. Preserve this
  observation in hosted CI review; it does not close TD-003.

The initial sandbox runs were blocked by Docker/D-Bus socket restrictions;
reruns used approved host access. Logs: `/tmp/epochgrid-m33-completion-build2.log`,
`/tmp/epochgrid-m33-completion-matrix.log` and
`/tmp/epochgrid-m33-completion-verify2.log`. Earlier failures are retained.

The user authorized staging, committing and pushing this branch and will create
the PR and monitor hosted CI. No hosted image run, registry publication or
package-setting change has been performed. A clean required regression gate, cold
hosted image CI and an explicitly invoked successful GHCR round trip remain
completion gates; milestone 34 and TD-001/002/003 stay open.

## Previous status — milestone 33 first local boundary slice implemented

The user requested beginning milestone 33 on 2026-11-05. Work is on
`feature/milestone-33-runtime-image`, based on `04652c7`. Existing planning edits
and `docs/architecture/roles-and-messaging.mmd` were preserved. No commit, push,
registry publication or package-setting change has been performed.

Implemented `scripts/release/runtime.Dockerfile` and `image.py`: verified archive
input, exact revision/source checks, Ubuntu 24.04 baseline, allowlisted context,
non-root service entrypoint, production profile, SIGINT stop contract, payload
re-extraction/hash comparison, native linkage/help/version checks, labels and
saved-layer inspection. Image reports distinguish config ID, bundle hashes and
transport checksum; package inventory/notices are retained. Local dirty-source
images are explicitly local and are not publishable candidates.

`prove-image-boundary.py` now passes the initial configuration/R1 boundary gate.
Separate application containers run as UIDs 21001/21002 (host runner UID 1000),
with private homes and independent external Secret Service helpers, authority-owned
IPC read-only in control, production TLS and operator-provisioned resources.
It checks authenticated status, authority-state/credential isolation, unrelated
UID rejection, socket replacement denial, Docker SIGINT stop/recreation, socket
cleanup, fresh worker sessions after authority restart, and bounded missing/locked
keyring refusal without changing worker metadata. Helpers and NATS stay outside
the application image; tests have no external egress. The M32 distinct-UID public
fixture regression is included. Cleanup removes only the run's disposable state.

Final local evidence:

- Image construction/contract: `target/m33-image-v3/image.json` and `image.tar`.
  Config ID `sha256:9e4a8a9df3c6a4303309ec6522ad46de299a302a184e68fa8a04f60159bc4904`;
  source fingerprint `c94d2c241f14b2cd4a1ca8955978b5b51259c94706ae6eb77f5d09d97069a5db`.
  Transport size 142,520,832 bytes; checksum
  `a110f97d2c26cde9d968f2f44f1e98849992cc5aac95f94ebe1c3b73b2a195b1`.
- Boundary proof: `target/m33-boundary-proof-v3.json`, passed in 12.467 seconds
  against that exact image and source fingerprint. Earlier failed reports remain
  under `target/m33-boundary-proof-*.json`; none were relabeled as successes.
- Full `./scripts/dev/verify.sh` passed, including all existing four BYO cases;
  log `/tmp/epochgrid-m33-verify.log`. Four offline image regression tests are
  included in the normal harness gate. No application Rust code changed.

Fixture findings were resolved without changing authorization: the D-Bus helper
needs passwd/group records for numeric service UIDs; the broker requires a signed
CA:FALSE leaf certificate; Docker lists tmpfs in `HostConfig.Tmpfs`, separately
from bind mounts. Live proof failures also corrected transient null status handling.

Next: complete the image adapter for the retained BYO assertions and client smoke,
protected-state/audit/schema-upgrade coverage, PR image jobs and cold hosted CI,
production Compose/operator examples, then controlled GHCR candidate transport.
No full image matrix or hosted image evidence is claimed. Confirm GHCR ownership,
Actions access and visibility before the first explicitly invoked publication.
See [container notes](../operator/containers.md) and the
[milestone 33 plan](plans/milestone-33.md). Milestone 34 and TD-001/002/003 remain open.
