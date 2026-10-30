# Backend role contract — milestone 28

Implementation is complete; hosted CI qualification remains pending. Production requires the two
isolated roles. The combined `serve` command is restricted to explicit development
homes without role bindings.

## Authority and worker

The authority owns Auth Callout, registry decisions, signed records, consumer
reconciliation and opaque Welcome delivery. The worker owns only NATS control
subscriptions and forwarding over a local Unix socket. This refines the original
plan: keeping reconciliation in the authority avoids trusting worker-supplied
consumer configurations or completion acknowledgments. No private key, database
handle, SQL, grant template or arbitrary signing operation crosses IPC.

| Identity | Publish | Subscribe |
| --- | --- | --- |
| Auth Callout connection | Existing encrypted Auth Callout response subjects | Existing Auth Callout request subject |
| Authority application identity | Account INFO; INFO for CHAT, MAILBOX and three KV streams; consumer INFO/CREATE/DELETE on CHAT and MAILBOX; IDENTITIES/TRANSPARENCY KV reads and writes; opaque device inbox delivery; explicit audit/revocation administration requests | Its own request inbox prefix |
| Worker | `_INBOX.>` replies | `epochgrid.v1.identity.*`, `epochgrid.v1.channel.*`, its own request inbox prefix |

Neither application identity gets stream creation, updates, purge, deletion,
raw CHAT/MAILBOX retrieval, system-account administration or unrelated KV access.
The exact grants live in `epochgrid_core::backend_roles`. Consumer names contain
the device NKey within one NATS subject token; subject wildcards cannot constrain
that token's prefix or the consumer configuration payload. Consumer management
therefore stays in the trusted authority. The worker has no consumer capability.

The worker can disrupt/control replies and observe public metadata, enrollment
tokens in requests and opaque protocol bytes. Original signature/token validation
remains in the authority. Compromise of the worker can cause denial of service;
it cannot directly sign claims, change registry rows or reconfigure consumers.
Compromise of the authority is still compromise of authorization. Neither process
has MLS group secrets. Root and a compromised OS remain outside this boundary.

## Local protocol and admission

IPC uses a versioned JSON envelope with a four-byte big-endian size prefix,
maximum 512 KiB encoded frame, and maximum 65536-byte wire payload. Only the
enumerated control subjects are forwarded. There is one active worker session,
one queued operation and one request in flight. Read, write and operation phases
have five-second deadlines. A connection starts with sequence-zero readiness;
subsequent sequences increase strictly. Unknown operations, versions, repeated
sequences, oversized frames and unexpected peer UIDs close the session.

The authority checks worker UID with kernel peer credentials, and the worker
checks authority UID. Both accounts must be distinct and non-root. The socket
parent is authority-owned and not writable by other accounts; the socket permits
connection attempts from other accounts so peer authentication can reject them.
An exclusive lock prevents duplicate authorities from replacing the socket.
A second, read-only `.status` socket accepts inspection from either bound UID.
It reports reconciliation and worker-lease state without replacing the active
worker connection. A per-home runtime lock also prevents rebinding a running home.

New device admission requires both successful authority reconciliation and a live
worker session whose last valid frame is less than five seconds old. The worker
sends a heartbeat each second while idle. A dead or stalled worker cannot keep
admission open beyond that lease, even if a response is pending. Existing device
claims retain their documented expiry; delivered ciphertext cannot be recalled.
Worker readiness never proves resource compatibility: the authority performs
resource validation and reconciliation itself before opening admission.
The worker exits on authority/IPC failure. The operator's process supervisor must
restart it after the authority is available; the service does not replay an
unacknowledged control operation on its own. Existing client idempotency and
durable registry repair remain responsible for ambiguous requests. Restarting
only the authority cannot reuse the old worker lease to open admission.

## Setup under separate Linux accounts

Each account needs its own unlocked Secret Service session and private home.
Never pass the authority's session bus or keyring environment into the worker.
The socket directory is separate from the authority's private state directory.
The operator creates that directory with authority ownership and traversal access
for the worker, and manages both process lifetimes.

1. Under the worker account: `epochgrid-service --home WORKER_HOME worker-init`.
   Record the printed public NKey. Repeating this preserves the same credential.
2. With the existing backend stopped, under the authority account:
   `epochgrid-service --home AUTHORITY_HOME role-bind --worker-uid UID
   --worker-nkey PUBLIC_NKEY --socket /absolute/runtime/control.sock`.
   Save its public JSON output and transfer it to the worker account.
   Use `--auth-config FILE` if the existing configuration has a different filename
   within the authority home. Setup also writes the version-one public
   `runtime-permissions.json` capability artifact before committing role bindings.
3. Under the worker account: `epochgrid-service --home WORKER_HOME
   worker-configure --bindings PUBLIC_BINDINGS_FILE`.
4. Start `serve-authority --auth-config AUTHORITY_HOME/auth.json` under the
   authority account, then `serve-control` under the worker account, using the
   same verified TLS endpoint and independently supplied trust settings.

Run worker `validate-control --offline --format json` after configuration, and
`validate-control --online --format json` after startup. Online worker validation
checks the peer-authenticated authority readiness report; it does not connect to
NATS or claim resource/TLS qualification. Run authority `validate --auth-config
AUTHORITY_HOME/auth.json --online` for those checks. Authority reports include
role checks when bindings are present. Offline validation does not create state.

These setup operations preserve the existing authority signing identity and
encrypted database. Binding/configuration writes are atomic and no-clobber;
identical retries succeed, including an interruption between permission-artifact
publication and binding completion. Edited artifacts are refused. Different choices
require an explicit operator review. Stop all old backend processes before the
transition; the runtime lock coordinates new binaries, not older versions.
Runtime does not create a missing worker credential. Broker resource provisioning
remains operator-owned. Local transition/restart checks pass; see
[HANDOFF](../HANDOFF.md) for verification evidence and the remaining hosted CI gate.

## Verification environment

The four BYO cases and the production TLS regression run the worker as Linux UID
65534 and the authority as the normal test user, each with a disposable keyring.
They probe access to authority files and credential IDs through both the worker's
own session and the authority's D-Bus address. The public exchange contains no
secret values. It stages only the worker helper/keyring scripts, service binary
and permission-probe executable in an authority-owned directory accessible to
the worker. The worker runs from that directory and never needs checkout access.
CI uses hosted-runner `sudo`; local runs use a disposable Docker
image with read-only binary/script mounts and no external network:

```bash
docker build -f scripts/dev/roles.Dockerfile -t epochgrid-role-tests:local .
./scripts/dev/verify.sh build
python3 scripts/dev/test-role-isolation.py
python3 scripts/dev/test-role-isolation.py tls
```

The local container bootstrap makes the checkout directory private to UID 1000
and verifies that `nobody` cannot traverse it before dropping privileges. Tests
then run as UID 1000 and workers as `nobody`, covering hosted-runner path isolation
without changing host checkout permissions or exposing authority state.

Build the image with `--build-arg UBUNTU_VERSION=24.04` when binaries were built on
Ubuntu 24.04. The default image matches Ubuntu 26.04 local binaries. On an isolated
runner with passwordless sudo to `nobody`, `EPOCHGRID_ROLE_NATIVE=1` runs the same
fixtures natively. Do not grant that sudo permission to production service users.

## Capacity ownership

The [capacity contract](operator/capacity.md) assigns registry, admission-rate and
broker checks to the authority. The worker retains fixed bounded NATS/IPC queues,
prioritizes heartbeat selection, and receives no quota-administration permission.
Client-local database/outbox budgets remain separate. Capacity configuration is
public; authority keyrings and registry handles never cross the IPC boundary.
