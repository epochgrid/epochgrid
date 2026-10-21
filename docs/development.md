# Development notes

See the [current milestone status](milestones.md). Production transport is the
default. For all local plaintext commands in this document, set
`export EPOCHGRID_PROFILE=development` in each terminal. Development smoke runners
select this explicitly; production TLS tests override it per subprocess and require
OpenSSL for temporary test certificates. See [TLS configuration](operator/tls.md).

## Current verification

Run `./scripts/dev/verify.sh` for the default CI gate. It includes workspace unit tests,
16 live NATS cases, Compose/CLI smoke, static TUI workflows and the focused
`dynamic-join` reconnect regression, dedicated protected-credential checks, plus formatting,
Clippy, build and harness checks. Live typing assertions (TD-001) and the dynamic
Auth Callout integration/TUI checks (TD-002) are deferred; see
[technical debt](technical-debt.md) for evidence and restoration criteria.
The dynamic checks remain available through `verify.sh nats-dynamic` and
`verify.sh dynamic-tui`; explicit runs still fail on errors.

See [current validation results](milestones.md#latest-local-validation--2026-10-19).
Milestone-specific notes below describe upgrades and coverage; previous passing
runs are consolidated under [historical validation](#historical-local-validation).

Credential-using phases now run in isolated disposable Secret Service sessions;
install `dbus-daemon gnome-keyring libsecret-tools` on Debian/Ubuntu. See
[protected storage](secret-storage.md) for setup, fresh encrypted-state requirements,
and the Milestone 25 database-encryption boundary. `verify.sh compose`
uses temporary homes and its own Compose project; it leaves the developer's `.dev`
state and stack alone, but needs port 4222 free.

## Historical local setup and milestone upgrade notes

The upgrade notes below describe pre-Milestone-24 development. They do not provide
an upgrade path into Milestone 25: plaintext homes/registries are unsupported.
Milestone 24 v2 administration archives can be restored into fresh encrypted homes.

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
the default live integration cases, and executes the Compose CLI smoke test. CI calls
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
upgrading existing clients. Its live integration case exercises Alice/laptop,
Alice/desktop and Bob/laptop, including consumer progress migration and restart.
Run `cargo build --workspace` first, then:

```bash
./scripts/dev/verify.sh nats
EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/tui-smoke.py
```

These isolated tests leave active development clients and the Compose volume alone.
The full `verify.sh` also runs the shared Compose smoke test and requires stopping
your development sessions first.


Milestone 13 requires regenerating permissions and restarting the service before
launching upgraded clients. Existing directory records are imported into
TRANSPARENCY KV; SQLite migration 2 retains identities/groups/history and adds local
trust state. Follow [verification setup](device-verification.md), including optional
independent directory-key pinning before first discovery. The NATS suite covers adversarial history/key substitution and competing atomic
appends. New feature work starts on a clean branch and reaches protected `main`
through a PR with required status checks; do not push feature commits to `main`.


Milestone 14 requires another coordinated bootstrap/service/client restart. Preserve
existing state: migration 3 is additive and the regenerated configuration retains
previous revoked-key exclusions. Compose mounts `auth/` as a directory so atomic
include-file replacement is visible to the broker. The host service needs the
restricted `.dev/system` identity and write access to `.dev/auth/`; only one actuator
may own a development root. No NATS process restart is required for an individual
revocation. See [revocation commands and failure recovery](device-revocation.md).

The shared verification command includes isolated NATS cases and a three-client
PTY scenario including live revocation. The new cases exercise forced disconnect,
rekeyed messaging, bootstrap/restart persistence and durable intent surviving actuator
failure. They use temporary roots and ports. `device list` reports authorization and
local trust separately; remote connection presence is not inferred from directory state.

## Verification deadlines

CI runs the same `scripts/dev/verify.sh` phases separately: `harness`, `fmt`,
`clippy`, `unit`, `build`, `nats`, `compose`, `tui`, `relations-tui` and
`participants-tui`, plus `dynamic-join` and `secrets`. Each phase uses an external
wall-clock watchdog with a ten-second heartbeat, exit code 124 on timeout, and
TERM/KILL cleanup of its process group. Deadlines are 60s for formatting, 600s for
clippy, 180s for unit tests, 300s for build, 120s for NATS download, 360s for the
16 default serial NATS cases (dynamic Auth Callout is deferred as TD-002), and
180s each for Compose and TUI. The job retains its
20-minute outer limit; GitHub step limits also apply. A timed-out phase fails CI.

The Compose smoke service must exit within five seconds of SIGINT; otherwise the
test reports failure and forces termination. Signal handling is registered before
service readiness. Python child cleanup and Rust test-child cleanup have explicit
limits; the deliberate crash-test pause has a 30-second failsafe. Test CLI output
uses temporary files to avoid pipe-buffer deadlocks while awaiting process exit.
The timeout harness tests normal failure exit codes, hung descendants and cancellation.

TUI smoke inspections use the read-only `encrypted-query` Rust example (built by
`verify.sh build`), which loads the database key from the isolated keyring. Keys
are never passed on the command line. The plaintext Python inspector is used only
for standalone harness fixtures. Connections close after each inspection.
Only SQLITE_BUSY/SQLITE_LOCKED is retried, for at most five seconds per read; persistent
locks and all other SQL errors fail. The harness regression tests exercise a real
exclusive writer lock, successful retry, deadline expiry, and read-only enforcement.

Encrypted-storage regression tests include separate-process registry writers while
existing readers remain open. Never inspect an active database with ordinary file
opens/closes inside the application process: that can release SQLite's POSIX locks.
The format probe uses SQLite-managed read-only connections and marker scans run in
a separate process. See [SQLite's locking explanation](https://www.sqlite.org/howtocorrupt.html#posix_advisory_locks_canceled_by_a_separate_thread_doing_close_).


## Milestone 15 recovery validation

Migration 4 is additive and automatic; stop each client before upgrading. No service
protocol or NATS permission upgrade is required. Keep existing state. Do not downgrade
a database with a recovery-only marker to an older client.

`recovery export`, `recovery restore` and `recovery status` are local CLI operations.
Follow [the recovery guide](encrypted-recovery.md) for the complete replacement-device
workflow. Files ending in `.egrecovery` and `.egsecret` are ignored by Git; do not commit
recovery material using another extension. The exporter never prints the secret or
accepts one through command-line arguments/environment variables. Both output paths
must be new files in existing directories; Unix permissions are 0600.

The shared verification script and CI include the recovery case:

```bash
cargo build --workspace
EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 150 \
  cargo test --locked -p epochgrid-service --test registration encrypted_recovery \
  -- --ignored --test-threads=1
```

The recovery test has its own 120-second deadline, uses the existing bounded CLI/process
helpers, and runs in an isolated temporary fabric. It exports through the CLI, deletes
the original home, restores verified identity evidence, performs a signed revocation,
enrolls a new device, retires the lost device, and exchanges new encrypted messages.
An old archive cannot bypass revocation. Stream payloads and stopped broker/service
files are scanned for message markers, the original NKey seed and recovery secret.
The package is also checked for recognizable plaintext. Core/CLI tests cover wrong
secrets, damaged/oversized inputs, expiry, sticky identity changes, checkpoint rollback,
file permissions, overwrite refusal and atomic restore/migration behavior.


## Milestone 16 attachments

Stop clients/service, rebuild, run bootstrap, then restart the service and all clients.
Retain existing local and NATS data. Migration 5 is additive; service startup creates
or updates ATTACHMENTS retention/capacity. Device permissions add publication of
`$O.ATTACHMENTS.C.*` and `$O.ATTACHMENTS.M.*`, plus exact stream INFO and MSG.GET
APIs for OBJ_ATTACHMENTS. No client stream purge/delete/update or consumer management
permissions are granted. Do not send manifests to pre-M16 clients.

The shared verification command includes the attachment case. It has a 120-second outer bound and exercises CLI multi-chunk round trip,
corruption, Object Store links, expiry, restart and continued NKey revocation. TUI
smoke also sends/saves an attachment with a path containing spaces, then scans stopped
NATS storage for the plaintext marker. Run just the new NATS case after building:

```bash
EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/run-bounded.py 150 \
  cargo test --locked -p epochgrid-service --test registration attachments \
  -- --ignored --test-threads=1
```

See [attachment commands, limits and retention](attachments.md). CLI/TUI read
EPOCHGRID_ATTACHMENT_MAX_BYTES and EPOCHGRID_ATTACHMENT_TTL_SECONDS; the service
exposes attachment-retention-seconds and attachment-store-max-bytes flags. Reducing
retention can expire existing objects. The client stores no automatic file cache.


## Milestone 17 validation

Rerun bootstrap when upgrading to regenerate ephemeral subject permissions. Typing
requires no new flags. Run `./scripts/dev/verify.sh nats` for the bounded live Core
NATS non-durability test and `./scripts/dev/verify.sh tui` for existing messaging
workflows. Live typing assertions are disabled by default in every TUI smoke mode
(see [TD-001](technical-debt.md)); a passing smoke run does not validate typing UI. `cargo test --workspace` also tests dropped-event
ratchet independence, ordering, expiry, tamper, impersonation and revoked leaves.
See [ephemeral events](ephemeral-events.md) for precise protection and replay limits.


## Milestone 18 validation

Schema 6 adds compact receipt metadata and automatically indexes existing retained
ciphertext. Keep clients updated together. `message receipts CHANNEL --offline`
shows retained device claims; omit `--offline` for a bounded online exchange.
The NATS suite exercises Alice laptop/desktop and Bob with different delivered/read
states, restart, encrypted references and unchanged stream sequences. The TUI suite
checks background delivery, visible-message reads and separate device receipts.
No additional infrastructure or service configuration is needed.


## Milestone 19 validation

Upgrade all participant binaries together; schema 7 and the new protected application
envelope require updated clients. No NATS configuration changes are needed. The
NATS integration suite exercises CLI reply/edit/reaction add/remove, offline catch-up,
restart, unchanged original ciphertext and absence of plaintext. The real TUI suite
exercises the same commands by short ID in a separate bounded phase:
`./scripts/dev/verify.sh relations-tui` (90 seconds). The existing
`./scripts/dev/verify.sh tui` retains its 180-second deadline. Unit tests cover late targets, reversed
transport ordering, author checks, duplicate IDs, migration rollback and projection
replay from retained events. Use `message events CHANNEL --offline` for original
content/full IDs and `message history CHANNEL --offline` for the current projection.

## Milestone 20 validation and upgrade

Existing databases migrate to schema 8 without reset. Regenerate operator enrollment
and restart the backend only when adding the service's public device binding; no new
NATS bucket, stream, subject or backend flag is needed. See [setup and commands](service-participants.md).
The NATS suite includes a bounded participant CLI/daemon test. Use
`./scripts/dev/verify.sh participants-tui` for the separate 120-second terminal test.
The original TUI and relationship tests keep their existing deadlines.

The service terminal test waits for its specific acknowledged Welcome rather than a stale UI
notice. Compose smoke now waits at most ten seconds for a complete NATS INFO greeting
before launching the backend; an open Docker port alone did not establish readiness.

## Dynamic authentication migration

Legacy fixture service invocations require `--dev-static`; the scripts and existing
acceptance helpers pass it explicitly. No production path falls back to this mode.
The opt-in `verify.sh nats-dynamic` phase runs the Auth Callout case using only one
static auth-service identity, dynamic Alice/Bob enrollment, inbox denial, claim expiry,
revocation and backend restart without NATS file mutation/reload. Dynamic test transport
is explicitly development plaintext; the callout exchange is still XKey-encrypted.
See [operator/auth-callout.md](operator/auth-callout.md) for the current boundary.

## Milestone 23 validation

The existing `./scripts/dev/verify.sh nats` phase includes the production TLS case.
It uses temporary CAs and real NATS/Auth Callout/client/service binaries: valid
custom trust, native-root loading through a subprocess-local Linux trust override,
wrong CA, hostname mismatch, plaintext refusal, TLS version negotiation, retained
connection certificate rotation, and TLS-first restart. It changes no host trust
store and uses finite process/outer deadlines. The remaining NATS fixtures explicitly
use the development profile. No live typing checks have been re-enabled.

## Milestone 22 dynamic messaging validation

The Auth Callout NATS case now exercises real MLS chat across independent enrolled
devices, group removal, generation changes, unauthorized inbox/group/consumer access,
revoked active-connection expiry, reconnect denial, coordinator rekeying and messages
after restart. It checks actual CHAT payloads for a recognizable plaintext marker
and proves the NATS configuration is unchanged with no reload. Three-second claims
intentionally exercise expiry; catch-up retries are bounded and idempotent.

Run `./scripts/dev/verify.sh dynamic-tui` for actual Alice/Bob pseudo-terminals using
only dynamically enrolled device keys. It creates/invites/joins through the TUI,
exchanges messages asynchronously and reopens Bob to catch up offline history.
Every subprocess and phase has a deadline. Dynamic TUI and the dynamic Auth
Callout integration case are temporarily excluded from the default CI/local gate
under [TD-002](technical-debt.md). Run `./scripts/dev/verify.sh nats-dynamic`
for the latter. Explicit runs still fail on errors; static development tests remain
required. Live typing assertions remain deferred as TD-001.

### PR #13 lease-expiry CI regression

Push run `35457276144` failed in the dynamic admission test with a bare `timed out`
after approximately 24 seconds; the PR run on the same commit passed. The harness
watchdog did not fire. Three local repetitions also passed. The error text and
absence of later negative-test logs point to the initial MAILBOX consumer INFO
lookup, but the original run had no backtrace to establish the exact call site.

Consumer INFO reads previously had no retry when an authorization lease expired
while awaiting a response. CHAT and MAILBOX lookup now renew admission and retry
once on the typed timeout error only, within an overall 15-second deadline.
Authorization/configuration errors fail immediately; neither this change nor the
tests relax permissions, lease-expiry assertions or CI deadlines. Fault-injection
unit tests cover a lost response, persistent timeouts, other errors and failed
readmission. CI enables Rust backtraces, and lookup errors identify the stream.

The retry change passed locally, but subsequent CI failures persisted. See
[TD-002](technical-debt.md) for the later evidence and current quarantine.

## Historical local validation

These results were recorded during milestone implementation. Counts describe those
revisions, not the current gate, and individual passes did not establish reliability.

| Revision / milestone | Unit tests | Live NATS cases | Other recorded checks |
| --- | --- | --- | --- |
| 19 | 48 | 14 | Cargo gates, Compose/CLI, main and relationship TUI, harness |
| 20 | 51 | 15 | Cargo gates, Compose/CLI, three TUI workflows, eight helper tests |
| 21 | 55 | 16 | Cargo gates, harness, Compose/CLI, three static TUI workflows |
| 23 | 60 | 17 | Cargo gates, harness, Compose/CLI, three static TUI workflows |
| 22 completion | 62 | 17 | Cargo gates, harness, Compose/CLI, four TUI workflows including dynamic Auth Callout |
| Consumer INFO retry (`261bf68`) | 65 | 17 | Cargo gates and dynamic TUI chat/restart smoke |

Milestone 23 preceded the final Milestone 22 completion work. Later CI failures
supersede any implication that the dynamic workflows are reliable; current coverage
and validation are recorded in the [status index](milestones.md) and
[technical debt](technical-debt.md).
