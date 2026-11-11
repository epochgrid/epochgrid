# Runtime containers — milestone 33 implementation notes

Milestone 33 implements verified-bundle image construction, separate-container
role/keyring isolation, the four-case BYO matrix, protected-state/client smoke,
PR image gates and a manually dispatched GHCR candidate workflow. Local reports
are recorded in [handoff](../../HANDOFF.md). Cold hosted CI and an explicitly
invoked registry round trip remain completion gates; no published runtime image
is advertised. See the [plan](../archive/plans/milestone-33.md).

## Local construction and proof

Use a Linux amd64 Docker host with native UID mapping. The application image uses
the pinned Ubuntu 24.04 base and the exact executables from a verified Linux
bundle. Rootless Docker, user-namespace remapping, Docker Desktop, ARM64 and remote
role placement are outside this initial proof. Run from the repository root.

Build a fresh local bundle as described in the [binary guide](linux-artifacts.md).
The source fingerprint includes test/build scripts, so regenerate the bundle after
changing them. Existing output directories are refused, not replaced.

```sh
python3 scripts/release/build-linux.py --local --work target/m33-linux
python3 scripts/release/artifact.py package \
  --work target/m33-linux --output target/m33-bundle
python3 scripts/release/image.py \
  --archive target/m33-bundle/epochgrid-*.tar.gz \
  --checksums target/m33-bundle/SHA256SUMS \
  --work target/m33-image --local
```

`image.py` verifies the archive before assembling an allowlisted build context.
It checks the bundle revision/source/baseline, re-extracts and compares all image
payload files, verifies labels/defaults/native linkage, and inspects every saved
layer for build tools and private inputs, including files hidden by later layers.
Application notices, the OS package inventory and OS copyright notices are
retained. No Rust compilation happens in the runtime image.

The output includes `image.id`, `image.tar` and `image.json`. The JSON report records
the source, bundle/manifest/binary hashes, base digest, package inventory, Docker
config ID and transport archive checksum/size. It reports image construction and
contract checks, **not** completion of runtime or release qualification. A config
ID and tar checksum are not registry manifest digests. Unsnapshotted apt packages
mean identical image digests are not promised. `--local` images cannot become
publishable candidates by removing a label or changing their tag.

Prepare the disposable test environment and run the boundary proof:

```sh
docker build --target runtime -f scripts/release/qualification.Dockerfile \
  -t epochgrid-artifact-tests:local .
./scripts/dev/download-nats.sh
image_id=$(cat target/m33-image/image.id)
python3 scripts/release/prove-image-boundary.py \
  --image "$image_id" --result target/m33-boundary.json
```

This runner creates and deletes its own private fixtures. It never uses the
operator's keyring. Two disposable helper containers model independently managed
host Secret Service sessions; they bootstrap account records and permissions as
root, then run D-Bus/keyrings as UIDs 21001 and 21002. D-Bus requires a passwd record
for its service UID. The helper image and its tools never enter the application
containers. The test broker and certificate/resource provisioning are also separate.
The Docker daemon is used by the host orchestrator, never mounted into an
application container. The fixture network has no external egress.

The application containers use the image's own binaries, distinct non-root UIDs,
private persistent homes, and only their respective bus directories. They share
`/eg-ipc`, owned by the authority and mounted read-only by the control. Both use a
read-only root filesystem, dropped capabilities, no-new-privileges and a bounded
16 MiB temporary filesystem. The runner exercises authenticated status, production
TLS/R1 resources, keyring/state isolation, socket replacement denial, unrelated
UID rejection, Docker stop/recreation and missing/locked keyring refusal. It also
runs the milestone 32 public-fixture permission regression under a distinct UID.

Reports contain sanitized check names, source/image identities, failure phase and
elapsed time. Private fixture homes/keyring files are deleted, not retained as
artifacts. Failed attempts remain failed; the runner does not retry cases or
restart a failed service. Readiness polling is bounded and stops when the service
exits. The focused proof does not replace the native or extracted-bundle suites.

## Runtime contract established by the proof

The default image user is `65532:65532`; deployment must explicitly override it
with different numeric UIDs/GIDs for authority and control. Provision private
home ownership outside application startup. Each matching host account needs its
own persistent, unlocked Secret Service session. Mount only that role's bus socket
or dedicated bus directory and set `DBUS_SESSION_BUS_ADDRESS` explicitly. Mounting
a private desktop runtime directory wholesale is not the intended deployment.
Never expose authority keyring/database state to control.

Use the same short absolute IPC path in both containers. Its directory must be
authority-owned and not writable by the worker. Kernel peer-credential checks
remain enabled. The control can connect to sockets through the read-only mount
but cannot replace them. If mounting a single bus socket and that socket is
replaced, recreate/remount the container; a bind mount can retain the old inode.
With a dedicated directory mount, replacement is visible, but a failed application
still requires an explicit restart after the session is ready.

The service is the exec-form entrypoint, and the default command is harmless
`--help`. Explicitly select `serve-authority` or `serve-control`; initialization,
binding and schema upgrades are separate one-shot operations. No entrypoint
unlocks a keyring, changes volume ownership, or runs development `serve`.

Docker stop uses `SIGINT` to match the existing service shutdown handlers. The
proof checks clean exit and socket cleanup before restart. Restart the authority,
wait for reconciliation, then start a fresh control process; a previous worker
session does not carry over. Missing/locked keyrings are errors, not instructions
to initialize replacement credentials.

The optional client entrypoint is `/usr/local/bin/epochgrid`; interactive use
requires an explicit terminal and the client's own home and Secret Service bus.
The image smoke suite exercises protected client commands, CLI/TUI use and an
offline/restart scenario, plus explicit schema-2 audit upgrade. Test helpers stay
outside the application image.

## Provision and run with Compose

[compose.runtime.yaml](compose.runtime.yaml) is a separate production-shaped
example. Use Docker Compose on a Linux amd64 host with native UID mapping. Set:

- `EPOCHGRID_IMAGE` to a locally qualified config ID or a qualified registry digest.
- `AUTHORITY_UID`/`AUTHORITY_GID` and `CONTROL_UID`/`CONTROL_GID` to separate
  non-root host accounts. Do not reuse the same UID.
- `AUTHORITY_HOME` and `CONTROL_HOME` to existing private directories owned by
  their respective accounts (mode 0700).
- `AUTHORITY_BUS_SOCKET` and `CONTROL_BUS_SOCKET` to those accounts' independently
  provisioned, unlocked Secret Service bus sockets. Follow [secret storage](../secret-storage.md).
  Keep keyring storage persistent on the host and provide an operator-managed unlock policy.
- `EPOCHGRID_IPC_DIR` to an authority-owned directory, mode 0755, outside both
  private homes. It mounts at `/eg-ipc` in both containers; control has read-only access.
- `EPOCHGRID_NATS_URL` to the production TLS endpoint and `EPOCHGRID_CA_FILE` to
  the operator trust bundle. The broker must be reachable from the Compose bridge;
  `localhost` addresses the container itself.

Compose refuses absent bind sources. Provision their ownership as the host
administrator before starting containers. The example provides a read-only root,
16 MiB temporary filesystem, 512 MiB memory limit, 128-process limit, dropped
capabilities and no-new-privileges. Size application capacity using the
[capacity guide](capacity.md); these container limits do not resize broker resources.

These examples use configuration mode/R1. For operator-JWT or R3, use the
[BYO setup](byo-nats.md) and corresponding `auth-init` arguments. Define a shell
helper in the repository root:

```sh
egcompose() { docker compose -f docs/operator/compose.runtime.yaml "$@"; }
egcompose config --quiet
egcompose run --rm --no-deps authority --home /state auth-init \
  --auth-mode configuration --target-account EPOCHGRID --replicas 1
egcompose run --rm --no-deps control --home /state worker-init
```

Record the worker's printed public NKey as `WORKER_PUBLIC_NKEY`. With both
services stopped, bind it under the authority and transfer the public JSON to
the worker account as `$CONTROL_HOME/bindings.json`. The transfer is an explicit
host administration operation; do not mount either private home into the other role.

```sh
egcompose run --rm --no-deps authority --home /state role-bind \
  --worker-uid "$CONTROL_UID" --worker-nkey "$WORKER_PUBLIC_NKEY" \
  --socket /eg-ipc/control.sock > public-bindings.json
# Transfer public-bindings.json to CONTROL_HOME/bindings.json with control ownership.
egcompose run --rm --no-deps control --home /state worker-configure \
  --bindings /state/bindings.json
```

Apply the authority's generated deployment artifacts to the operator broker using
its administrator context. Initialization does not provision NATS. Complete JWT
signing when applicable. Then validate and start the services:

```sh
egcompose run --rm --no-deps authority --home /state validate \
  --auth-config /state/auth.json --offline --format json
egcompose run --rm --no-deps control --home /state validate-control --offline --format json
egcompose up -d authority
# Check authenticated authority status; start control after reconciliation is ready.
egcompose exec authority epochgrid-service --home /state status --role authority --format json
egcompose up -d control
egcompose exec authority epochgrid-service --home /state \
  --server "$EPOCHGRID_NATS_URL" validate --auth-config /state/auth.json --online --format json
egcompose exec control epochgrid-service --home /state validate-control --online --format json
```

Health checks use authenticated status, but startup ordering alone is not
readiness. Before control starts, authority status normally exits 1 because
`worker_live` is false; require `observations.reconciled: true`, then start control
and require the combined admission gate to become ready. Inspect the reported readiness/reconciliation and diagnostic codes;
missing credentials, schema failures and TLS errors require operator repair.
The example deliberately leaves restart policy to the supervisor (`restart: "no"`).
Use bounded startup checks and alert on failures. After authority loss, admission
closes within the worker lease; stop the old control, restore authority reconciliation,
then start a fresh control process. Do not repeatedly run initialization as recovery.

```sh
egcompose exec authority epochgrid-service --home /state status --role authority --format json
egcompose stop control authority
# Restart after repairing the cause, preserving both homes and keyrings.
egcompose up -d authority
# Check authority observations.reconciled before starting a fresh control.
egcompose up -d control
```

## Audit, upgrades and optional client

Stop control and authority before stopped-authority audit commands. Upgrade only
an established schema-2 home, with its matching credentials and a retained backup:

```sh
egcompose stop control authority
egcompose run --rm --no-deps authority --home /state audit upgrade
egcompose run --rm --no-deps authority --home /state audit info
```

For exports, provision `AUDIT_DIR` as a private authority-owned host directory.
Read `STORE_ID` and `UPPER_SEQUENCE` from `audit info`, then explicitly mount it:

```sh
egcompose run --rm --no-deps -v "$AUDIT_DIR:/audit-output" authority \
  --home /state audit export --output /audit-output/events.jsonl \
  --store "$STORE_ID" --after 0 --upper "$UPPER_SEQUENCE" --max-records 1000
```

Follow [audit cursor and partial-file rules](audit.md). Exports are sensitive
plaintext; do not upload them as CI reports. Control cannot export authority records.
Writable homes support SQLCipher WAL/SHM while the root remains read-only.
Reverting an image does not establish database downgrade compatibility.

Client use requires a separate client UID, private home and unlocked bus socket.
For an already initialized and enrolled client, after setting `CLIENT_UID`,
`CLIENT_GID`, `CLIENT_HOME` and `CLIENT_BUS_SOCKET`:

```sh
docker run --rm -it --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user "$CLIENT_UID:$CLIENT_GID" --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --mount "type=bind,src=$CLIENT_HOME,dst=/state" \
  --mount "type=bind,src=$CLIENT_BUS_SOCKET,dst=/run/epochgrid-bus,readonly" \
  --mount "type=bind,src=$EPOCHGRID_CA_FILE,dst=/trust/ca.pem,readonly" \
  -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/epochgrid-bus \
  -e EPOCHGRID_TLS_CA_PATH=/trust/ca.pem \
  --entrypoint /usr/local/bin/epochgrid "$EPOCHGRID_IMAGE" \
  --home /state --server "$EPOCHGRID_NATS_URL" tui
```

## Qualification and GHCR candidates

`qualify-image.py` accepts `smoke`, the four BYO case names, and a focused
`audit-upgrade` suite. It verifies transport checksum, config ID, bundle manifest,
source identity and Ubuntu 24.04 test-tool hashes before loading/running the image.
Use the same-revision Ubuntu 24.04 runtime manifest; a native manifest from a
different distribution is refused. Example:

```sh
python3 scripts/release/qualify-image.py --image-report target/m33-image/image.json \
  --runtime-manifest target/ci/manifest.json --suite smoke \
  --result target/image-results/qualification-smoke.json
```

PR CI builds one image and runs smoke plus four independent BYO jobs, including
the boundary proof. All are required by `validate`; no PR job publishes.
Sanitized reports and the exact transport image are retained for seven days.

After merge, an operator may explicitly dispatch **GHCR candidate** from protected
`main`. Confirm package ownership (`epochgrid`), repository linkage/Actions access
and intended visibility first. The workflow never changes visibility. First-time
creation requires the separate private-package input; public visibility must
already be configured by the package owner. The workflow qualifies the selected
main SHA anew, pushes only those image bytes under
`candidate-<full-sha>-<run-id>-<attempt>`, refuses an existing tag, then pulls by
digest on a fresh runner and verifies payload and execution. Only the final
`registry-verification.json` result `qualified` establishes a successful round trip;
a `pushed` report alone does not.

For a private package, authenticate using your organization's approved GHCR pull
credentials through `docker login ghcr.io --password-stdin`. Use the qualified
report's registry digest, not the Docker config ID or transport checksum:

```sh
docker pull ghcr.io/epochgrid/epochgrid@sha256:REGISTRY_MANIFEST_DIGEST
export EPOCHGRID_IMAGE=ghcr.io/epochgrid/epochgrid@sha256:REGISTRY_MANIFEST_DIGEST
```

The digest placeholder must be replaced with actual qualified evidence. No
`latest`, version, or alpha release tags are produced. Removing containers with
`egcompose down` preserves bind-mounted state; never delete homes/keyrings as part
of image cleanup. Milestone 34 and TD-001/002/003 remain open.

For engineering prerelease promotion, signed verification and failure recovery,
see [release operations](releases.md). Consult the [roadmap](../milestones.md) for
actual hosted publication status.
