# Milestone 33 — GHCR runtime image

> Archived implementation plan. PR #28 merged as `57d2739`; hosted CI run #90 passed.
> Candidate publication remains unverified. Statements below retain their original
> implementation-time context. See the [roadmap](../../milestones.md).


**Implementation in progress.** Runtime construction, separate-role isolation, image
qualification, CI and candidate publication tooling are implemented locally; see [container notes](../../operator/containers.md) and
[handoff](../handoff-m33.md) for evidence and remaining gates, including a native JWT
cluster failover timeout in the full verifier (unchanged focused rerun passed). Milestone 32 merged in
[PR #27](https://github.com/epochgrid/epochgrid/pull/27) as `04652c7`.
Its final [hosted CI run #88](https://github.com/epochgrid/epochgrid/actions/runs/41755686220)
passed, including the five extracted-binary qualification suites. The run tested
the PR revision/merge candidate, not a separate build of the squash commit.

## Outcome and scope

Produce and qualify a Linux amd64 runtime image built from the verified milestone
32 bundle, then provide a controlled path to publish a GHCR **candidate** and
verify it by registry digest. Proposed package: `ghcr.io/epochgrid/epochgrid`.
Include both binaries so client administration and the two backend roles use the
same bytes. The backend is the primary container deployment; interactive client
use remains optional and requires an explicit terminal and its own credentials.

Milestone 33 owns image construction, container runtime qualification, operator
instructions and candidate registry transport. Milestone 34 retains versioned
release promotion, GitHub Releases, signatures/attestations, supply-chain policy
and alpha release qualification. No `latest`, semantic-version or alpha release
tags belong in this milestone. Implementing this plan does not close TD-001/002/003.
Planning creates no images, package settings, tags or registry publications.

Initial support: Ubuntu 24.04 amd64 image on a Linux Docker host with native UID
mapping and local Unix sockets. Qualify hosted Ubuntu 24.04 explicitly. Rootless
Docker, user-namespace remapping, Docker Desktop, Kubernetes, ARM64 and remote
authority/control placement are outside the initial support claim. Do not weaken
peer-UID checks to expand compatibility.

## 1. Prove the runtime boundary first

The existing `scripts/release/qualification.Dockerfile` is a test environment,
not a production image. It includes sudo, Python and disposable keyring tools.
The existing BYO fixture also starts both roles in that environment; it does not
prove isolation across separate runtime containers.

Before completing image/publishing tooling, demonstrate one configuration-mode
standalone deployment with these constraints:

- Authority and control run in separate containers with explicitly configured,
  distinct, non-root numeric UIDs/GIDs. Bindings created by `role-bind` retain the
  existing kernel peer-credential checks. A default image UID is only a default;
  examples must override it separately for each role.
- Each role has its own private persistent home and independently provisioned
  Secret Service session under the matching host UID. Mount only that role's bus
  socket (or a dedicated minimal bus directory) and set its explicit D-Bus
  address. No authority bus, keyring directory or database enters the control
  container. Keyring persistence and unlock policy remain operator-managed.
- Share only an authority-owned, non-worker-writable IPC directory, at the same
  short absolute path in both containers. Authority mounts it writable; control
  mounts it read-only and must still be able to connect to the sockets. Prove
  status access, peer UIDs and inability to replace sockets under this layout.
- Use operator-owned NATS over the production TLS profile. Mount custom roots
  read-only when needed. No broker, account root seeds or development credentials
  are baked into the image.

Disposable host-side D-Bus/keyring fixtures may bootstrap with elevated privileges
in tests, then drop to the actual service UIDs. No privileged helper or passwordless
sudo belongs in the shipped image. Test host and container UID differences, not
just the developer's UID 1000. Include the milestone 32 public-fixture permission
regression in the path used by the new runner.

Missing or locked keyrings must fail within existing bounds without provisioning
replacement keys. Recreating a container must preserve its home/keyring binding.
Document remount/recreation requirements if a host bus socket is replaced. Do not
introduce an automatic keyring-unlock entrypoint or pass seed/unlock values in
image layers, build args, CLI arguments or environment variables.

If this proof fails, record the specific UID, socket, D-Bus or mount incompatibility
before building out the matrix. Fix fixture/runtime integration rather than
changing application authorization semantics.

## 2. Build the exact verified bundle into a minimal image

Proposed files: `scripts/release/runtime.Dockerfile`,
`scripts/release/image.py`, and `scripts/release/test-image.py`.

Reuse the same revision's verified Linux candidate and its `BUILD.json`; do not
compile Rust again inside the runtime image or select binaries from `target/debug`.
Validate candidate/source identity before creating a small allowlisted build
context. Copy both executables and the bundle manifest/licenses/notices. A dirty
local build may be tested with explicit local identity but cannot be published.

Pin the Ubuntu 24.04 base by digest. Install only demonstrated runtime dependencies
(including CA roots and required shared libraries); record base digest and final
OS-package inventory, and retain OS package copyright notices. Application notices
from milestone 32 remain required. Installing a Secret Service provider in the
application image is unnecessary for the proposed externally managed bus model.
Neither Rust/Cargo, test harnesses, NATS, sudo nor fixture state may enter any image
layer. Inspect saved layers as well as the final filesystem for accidental inputs.

Set a non-root numeric default user, production profile, and exec-form service
entrypoint with a harmless default such as `--help`; never initialize homes or
start combined development `serve` implicitly. Document the explicit client
entrypoint override. Provision volume ownership outside application startup;
do not recursively chown mounted homes or run a root startup wrapper.

Run with a read-only root filesystem, dropped capabilities and no-new-privileges.
Provide bounded writable temporary storage and only the required persistent home
and IPC mounts. Qualify writable SQLCipher WAL/SHM and explicit audit exports under
that policy. No Docker socket, privileged mode or host network is required by the
operator example. Test networking uses isolated fixture networks without external
egress; production reaches only the configured operator broker as appropriate.

Record OCI source/revision/version/license labels and a versioned image report:
bundle archive/manifest/binary hashes, source commit, base digest, platform, image
config ID, transport archive checksum and, after publication, registry manifest
digest. These identifiers are distinct; do not equate a Docker image ID or tar
checksum with a registry manifest digest. Re-extract image binaries and compare
them with the input manifest. Do not claim reproducible compilation or identical
image digests from unsnapshotted apt repositories.

Review stop behavior explicitly: the service currently uses `ctrl_c()` in its
shutdown paths. Prefer a tested `STOPSIGNAL SIGINT` to match those handlers;
verify bounded stop, lock/socket cleanup and restart with Docker's actual stop
operation. Add SIGTERM support only if the chosen runtime contract requires it,
with focused tests. Do not assume shell wrapping or PID 1 handles signals correctly.

## 3. Qualify the shipped image, not an augmented test image

Add `scripts/release/qualify-image.py` and a container process adapter for the
existing fixtures. Keep orchestration, certificates, NATS and keyring helpers
outside application containers. Production executables must be the image's own
files, selected by image ID/digest without binary mounts or fallback. Preserve
existing extracted-bundle and native regression suites.

Required checks:

| Area | Acceptance evidence |
| --- | --- |
| Image contract | Architecture, labels, exact payload hashes, notices, native linkage, non-root defaults, no build/test/private inputs |
| Basic execution | Both help/version paths; explicit client override; read-only filesystem and intended writable mounts |
| Protected state | Initialization with separate keyrings, encrypted database sentinel checks, missing/locked/wrong keys, container recreation and matching-state preservation |
| Role boundary | Distinct container UIDs, expected peer credentials, worker cannot read authority files or retrieve authority credentials, unrelated UID rejected, socket ownership enforcement |
| Production matrix | Configuration and operator-JWT modes, each standalone and R3 cluster, with existing TLS/admission/permission/revocation/failover/resource-preservation assertions |
| Lifecycle | Readiness through authenticated status, worker loss closes admission within the existing lease, authority restart requires a fresh worker, bounded Docker stop and restart |
| Operations | Offline/online validation, status/diagnose, authority audit export and worker denial, explicit stopped-authority schema-2 upgrade |
| Client | Protected client commands and representative CLI/TUI/offline-restart smoke using image binaries with explicit terminal setup |

Container startup ordering is not readiness. Use existing bounded status/diagnostic
interfaces and distinguish transient unavailable IPC from credential/schema/TLS
failure. Define supervisor restart expectations; do not add an unbounded retry loop
that hides a failed startup or silently repeats administration operations.

Extend existing fixture process selection narrowly rather than rewriting the BYO
scenarios or copying assertions. Preserve signal/exit status, timeout and cleanup
semantics across `docker exec`/container operations. Always retain sanitized per-case
results and timing on failure. Raw keyring dumps, private homes and audit records
are not upload artifacts. Add focused tests for corrupt/mismatched image inputs,
wrong source/UIDs, failed phases and report identity.

## 4. CI and controlled GHCR candidate publication

PR CI remains read-only and publishes nothing. Add one image-build job dependent
on `linux-build`, then isolated image-contract/smoke and four BYO qualification
jobs. Reuse the Linux archive and existing test tools without rebuilding application
binaries. Export/load the exact built image across jobs, verify its transport hash
and config ID, and bind all reports to that image. Keep candidates and sanitized
reports for seven days, measure image archive size, and avoid distributing build
caches. Include all new prerequisites in the existing `validate` aggregate.

Measure the first container matrix before fixing per-case/job watchdogs; keep
compilation, container setup and execution budgets separate. Failed, skipped or
cancelled image qualification fails the aggregate. No automatic retries or new
quarantines. Run the normal repository verifier as well as image-specific checks;
do not replace milestone 32 coverage with image checks.

Proposed publication is a separate manually dispatched workflow from protected
`main`, restricted to that ref. It must build and qualify the actual selected main
SHA in that run before promotion. PR merge-candidate artifacts cannot simply be
relabeled as a squash commit, and expired seven-day artifacts are not a release
source. Reuse qualification workflow logic to avoid divergent gates.

Only the final publishing job receives `packages: write`; use `GITHUB_TOKEN`,
pinned actions and repository linkage labels. The proposed candidate tag is
`candidate-<full-sha>-<run-id>-<attempt>`; refuse an existing tag and record the
registry digest. Tags are references, not an immutability guarantee. Push the
already-qualified image without rebuilding it, then pull by digest on a fresh
runner and verify payload/manifest identity and basic execution. A failed pull
check leaves an unqualified candidate, never a passing publication report.

Confirm package ownership, Actions access and intended visibility before the first
publication; do not change organization/package visibility implicitly. Document
authenticated pulls where needed and digest-pinned deployment. No long-lived PAT,
release signing or `id-token: write` is needed for the candidate transport path.
GitHub documents [GHCR authentication, repository linkage and digest pulls](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
and [workflow publication](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images).

## 5. Operator documentation and delivery order

Add `docs/operator/containers.md` and a separate production-shaped Compose example,
leaving the existing development-only `compose.yaml` unchanged. Document explicit
role UIDs, private home ownership, IPC path/mounts, independent host keyring setup,
production TLS, broker prerequisites, bounded stop/restart, diagnostics, resource
limits, pull-by-digest and removal. Include one-shot init/bind/validate/audit command
examples under the correct account and image; never auto-run migrations.

Upgrades stop affected processes and retain matching homes, metadata and keyrings.
Reverting an image does not imply database downgrade compatibility. Removing an
image/container must not delete persistent state or credentials. No host installer,
systemd provisioning, unattended unlock service or Kubernetes deployment is added.
Update README, milestone index, CI strategy, binary-artifact guide and handoff with
actual supported paths and evidence; do not advertise a nonexistent public image.

Delivery slices:

1. Prove two-container UID/IPC/Secret Service operation with one standalone case;
   settle mount, entrypoint, signal and support contracts.
2. Implement verified-bundle image construction, identity reports and rejection
   tests; inspect runtime dependencies, filesystem/layers and notices.
3. Complete image lifecycle/role/protected-state checks and all four BYO cases,
   plus client smoke; record exact tested IDs and failures.
4. Integrate PR gates and operator examples; obtain cold hosted CI evidence.
5. Implement controlled candidate publication, qualify the selected main revision,
   and record successful GHCR pull-by-digest evidence when publication is invoked.

Milestone 33 is complete only when the documented image is qualified locally and
in cold hosted CI, the role/keyring boundary holds across separate containers,
and an explicitly invoked candidate publication has verified registry round-trip
evidence. Until then distinguish implementation, qualification and publication
status. Milestone 34 and the existing release/reliability limitations remain open.
