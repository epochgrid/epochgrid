# Development notes

Follow README for setup. Bootstrap preserves keys and groups, regenerates public
configuration/enrollment, verifies a pinned GitHub NATS binary, and builds a
scratch image with its license. Close device clients before bootstrap and restart
the service afterward. No base image is pulled and no image/package is published.

For host NATS on Linux instead of Compose:

```bash
cargo build --workspace
./target/debug/epochgrid dev-config
./scripts/dev/download-nats.sh
.dev/nats-image/nats-server -c .dev/nats.conf
```

Start service/clients as in README. Do not run host NATS and Compose on the same
port. The downloaded 2.14.5 release is the tested server; select it with NATS_SERVER
for integration tests. The existing host-installed 2.10.11 is not the development
pin. Client IDs are 1–32 lowercase ASCII letters, digits or hyphens.

The service provisions CHAT, MAILBOX, IDENTITIES, CHANNELS and durable per-device
MAILBOX and CHAT consumers at startup. Static group permissions span the shared Alice/Bob
lab; they are not membership-aware. Consumers are filtered server-side and clients
cannot create/modify them. Service replies are restricted to `_INBOX.*` to avoid
turning requests into service-authorized writes to KV or group subjects.

The client holds a device-directory file lock even for diagnostic commands.
Use one CLI per device at a time. `channel flush` retries pending ciphertext.
Repeating `channel invite` for the same peer flushes its original invitation;
it does not generate another Commit. A failed or unexpected Welcome is not
acknowledged; it may require operator cleanup. Package reservations do not expire
or replenish yet. These constraints remain in the multi-device alpha.

There is no automatic destructive reset. Deleting local state independently of
server data is not a recovery method. `docker compose down` retains data. Review
what must be kept before manually removing both sides of a disposable setup.

CI pins checkout by SHA and Rust by release, with read-only repository permission
and no publishing credentials. Ordinary tests do not need NATS. The explicit
integration suite spawns isolated NATS/service processes on an ephemeral loopback
port, tests both directions of MLS traffic and scans CHAT payloads for plaintext.
A port allocation race is possible on a busy shared host. The Compose smoke test
uses `.dev/` and Python 3 to drive two real interactive CLI processes, restarts
both and repeats the exchange, then tests offline history and pagination. It stops the Compose stack afterward.

Milestone 8 implements durable application history. Re-run bootstrap and restart
the service when upgrading so clients receive their new CHAT permissions and
consumers. Bootstrap force-recreates the NATS container to reload changed config,
retaining its named data volume. SQLite schema changes are additive; keys/groups
and old deduplication records remain intact.

Use `channel sync NAME` to fetch/decrypt the current backlog, or
`message history NAME --offline` to inspect/process locally staged data without
NATS. `message receive` consumes one undisplayed entry; `chat` automatically drains
the local display queue and fetches new deliveries. If catch-up fails due to a
network/database problem, reopening retries. Unavailable legacy entries and
quarantined messages are reported. Quarantine retains raw ciphertext and has no
repair/delete command yet; a failed packet does not advance the ratchet.

Both local transcripts and staged unknown-group ciphertext currently grow without
quotas. CHAT uses the existing stream retention configuration; history cannot
restore deleted server messages, reset devices or discarded MLS state. Keep server
and device state together. Plaintext already displayed by old Milestone 7 clients
cannot be reconstructed. Do not delete deduplication records to force decryption.

Milestone 9 adds process-kill and interrupted-transaction recovery tests to ordinary
`cargo test --workspace`. The NATS suite additionally tests a lost Welcome ACK and
an ambiguous publish retried after a shortened test-only deduplication window.
The Compose smoke test kills both chat clients, verifies their device locks are
released, and exchanges messages through fresh processes using the existing groups.

Online `channel sync` and `message history` now flush pending device-wide ciphertext
before catch-up, as chat startup does. Offline history remains local only. No schema,
wire, consumer or dependency migration is needed for Milestone 9. See
[recovery.md](recovery.md) for the failure matrix and restart instructions.

Milestone 10 completes the narrow MVP acceptance gate. `scripts/dev/verify.sh`
runs the required Cargo checks, downloads the pinned NATS binary, explicitly runs
all live integration cases, and executes the Compose CLI smoke test. CI calls
the same script. It uses development identities for Compose; close existing clients
and the host service first. The Rust integration tests use fresh temporary roots
and ephemeral ports, and never reset `.dev/` or its NATS volume.

The CLI acceptance test requires `cargo build --workspace` before its explicit run
because it launches the sibling `epochgrid` binary beside `epochgrid-service`.
It initializes both devices through CLI commands, then performs registration,
discovery, invitation, offline traffic, infrastructure restart and history checks.
See [MVP acceptance](mvp-acceptance.md) for the requirement-to-test mapping.

Milestones 0–10 are complete for the two-device slice. This does not establish
production readiness, hardware power-loss tolerance, member-removal security or
future-epoch catch-up. No additional product scope is enabled by this milestone.

Milestone 11 adds `epochgrid tui`; the original `chat` remains useful for scripting.
The unchanged MVP baseline passed before implementation. `verify.sh` includes the
isolated `scripts/dev/tui-smoke.py` pseudo-terminal test in addition to the existing
checks. It needs Unix PTYs (Linux CI) and the built binaries; it does not touch the
Compose development volume. See [TUI operation](tui.md) for keyboard controls,
reconnect semantics and the Ratatui feature constraint.

Milestone 12 supports additional independent devices and creator-serialized MLS
additions. Follow [multi-device enrollment and migration](multi-device.md) before
upgrading existing clients. Its fifth live integration case exercises Alice/laptop,
Alice/desktop and Bob/laptop, including consumer progress migration and restart.
Run `cargo build --workspace` first, then:

```bash
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration -- --ignored --test-threads=1
NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/tui-smoke.py
```

These isolated tests leave active development clients and the Compose volume alone.
The full `verify.sh` also runs the shared Compose smoke test and requires stopping
your development sessions first.


Milestone 13 requires regenerating permissions and restarting the service before
launching upgraded clients. Existing directory records are imported into
TRANSPARENCY KV; SQLite migration 2 retains identities/groups/history and adds local
trust state. Follow [verification setup](device-verification.md), including optional
independent directory-key pinning before first discovery. The NATS suite now has
seven cases, including adversarial history/key substitution and competing atomic
appends. New feature work starts on a clean branch and reaches protected `main`
through a PR with required status checks; do not push feature commits to `main`.


Milestone 14 requires another coordinated bootstrap/service/client restart. Preserve
existing state: migration 3 is additive and the regenerated configuration retains
previous revoked-key exclusions. Compose mounts `auth/` as a directory so atomic
include-file replacement is visible to the broker. The host service needs the
restricted `.dev/system` identity and write access to `.dev/auth/`; only one actuator
may own a development root. No NATS process restart is required for an individual
revocation. See [revocation commands and failure recovery](device-revocation.md).

The shared verification command now runs nine isolated NATS cases and a three-client
PTY scenario including live revocation. The new cases exercise forced disconnect,
rekeyed messaging, bootstrap/restart persistence and durable intent surviving actuator
failure. They use temporary roots and ports. `device list` reports authorization and
local trust separately; remote connection presence is not inferred from directory state.

## Verification deadlines

CI runs the same `scripts/dev/verify.sh` phases separately: `harness`, `fmt`,
`clippy`, `unit`, `build`, `nats`, `compose` and `tui`. Each phase uses an external
wall-clock watchdog with a ten-second heartbeat, exit code 124 on timeout, and
TERM/KILL cleanup of its process group. Deadlines are 60s for formatting, 600s for
clippy, 180s for unit tests, 300s for build, 120s for NATS download, 360s for the
nine serial NATS cases, and 180s each for Compose and TUI. The job retains its
20-minute outer limit; GitHub step limits also apply. A timed-out phase fails CI.

The Compose smoke service must exit within five seconds of SIGINT; otherwise the
test reports failure and forces termination. Signal handling is registered before
service readiness. Python child cleanup and Rust test-child cleanup have explicit
limits; the deliberate crash-test pause has a 30-second failsafe. Test CLI output
uses temporary files to avoid pipe-buffer deadlocks while awaiting process exit.
The timeout harness tests normal failure exit codes, hung descendants and cancellation.

TUI smoke inspections open read-only SQLite connections and close them explicitly.
Only SQLITE_BUSY/SQLITE_LOCKED is retried, for at most five seconds per read; persistent
locks and all other SQL errors fail. The harness regression tests exercise a real
exclusive writer lock, successful retry, deadline expiry, and read-only enforcement.
