# EpochGrid

EpochGrid combines NATS infrastructure with MLS end-to-end group encryption.
Project: https://epochgrid.org.
Organization: https://github.com/epochgrid.

**Current status: Milestones 0–12 are complete.** EpochGrid has a working secure
messaging alpha with a persistent terminal client and independent devices per user.
JetStream stores MLS protocol bytes; readable transcripts stay on each device.
This is unaudited development software, not a production-ready security product.

| Milestone | Status | Scope |
| --- | --- | --- |
| 0–10 | Complete | NKey authentication, signed device registration and discovery, MLS groups and invitations, encrypted chat, durable history, offline catch-up, restart/resume and ciphertext-only acceptance tests |
| 11 | Complete | Persistent TUI with history, asynchronous messaging, unread indicators and reconnect |
| 12 | Complete | Independent devices per user, operator enrollment, device discovery, ordered MLS membership catch-up and logical user membership |
| 13 | Next | Device verification and key transparency |
| 14–20 | Planned | Revocation/rekeying, encrypted recovery, attachments, ephemeral events, receipts, message relationships and secure service participants |

See [multi-device setup and upgrade](docs/multi-device.md) for the current enrollment
workflow, migration requirements and three-device validation scenario.

NATS supplies transport, authentication, authorization and persistence. OpenMLS
supplies group encryption and cryptographic membership. The service handles public
identity metadata over NATS request/reply and never receives application plaintext.
See [architecture](docs/architecture.md), [protocol](docs/protocol.md), and
[security boundaries](docs/threat-model.md).

## Start development infrastructure

Prerequisites: rustup (Rust 1.98.1 is pinned), a C toolchain for bundled SQLite,
Docker Engine with Compose v2, Bash, Python 3, curl, tar and sha256sum.
The development image supports Linux amd64/arm64, including Linux Docker on macOS.
Host integration tests require Linux or a native NATS server via `NATS_SERVER`.

```bash
./scripts/dev/bootstrap-nats.sh
```

Bootstrap builds the host binaries, creates Alice/Bob/service identities under
ignored `.dev/`, generates public enrollment/configuration, and starts NATS with
JetStream. It verifies a pinned official NATS 2.14.5 GitHub release checksum and
builds a local scratch image tagged `ghcr.io/epochgrid/nats-dev:2.14.5`. No Docker
Hub dependency or publishing is involved. Configuration must exist before the
first Compose start; subsequent starts can use `docker compose up -d`.

When upgrading from earlier milestones, close clients, re-run bootstrap and
restart the service to apply the updated NATS permissions and durable consumers. Bootstrap recreates the NATS
container so regenerated permissions take effect; persistent volumes are retained.
Existing identities and group state are retained.

Start the host service in a separate terminal:

```bash
./target/debug/epochgrid-service
```

Register both pre-created devices:

```bash
./scripts/dev/create-alice.sh
./scripts/dev/create-bob.sh
```

## Discover, create and invite

In Alice's terminal:

```bash
./target/debug/epochgrid --home .dev/alice identity lookup bob
./target/debug/epochgrid --home .dev/alice channel create engineering
./target/debug/epochgrid --home .dev/alice channel invite engineering bob
```

In Bob's terminal:

```bash
./target/debug/epochgrid --home .dev/bob channel join --from alice
./target/debug/epochgrid --home .dev/bob channel members engineering
```

Bob may be offline when Alice invites him. His durable mailbox retains the Welcome.
The join checks its authenticated MLS signer against the expected inviter's
verified directory identity. If Bob has already joined, skip `channel join`.
`channel create` rejects an existing name; skip it when resuming a group.

## Persistent terminal client

After bootstrap and device registration, run one per terminal:

```bash
./target/debug/epochgrid --home .dev/alice tui
./target/debug/epochgrid --home .dev/bob tui
```

Milestone 11 adds channels, persisted history, composition, unread counts, member
lists and automatic reconnect. Tab switches channels; Enter sends; Up/Down scroll;
PgUp loads older history and PgDn returns to latest. Use `/create NAME`,
`/invite USER [DEVICE]`, `/join INVITER [DEVICE]`, `/members`, `/devices`, `/help`, `/quit` or
Ctrl-C. Use `//` for a message beginning with `/`. Offline sends are encrypted and
queued locally; `[pending]` means no server acknowledgment yet. A failed local
send retains the composition. Uncommitted drafts are not saved on exit.
`/members` groups device leaves by user; `/devices` shows each cryptographic device.
See [TUI architecture and controls](docs/tui.md).

## Chat

Alice's terminal:

```bash
./target/debug/epochgrid --home .dev/alice chat engineering
```

Bob's terminal:

```bash
./target/debug/epochgrid --home .dev/bob chat engineering
```

Messages sent while a peer is offline are retained and fetched when it returns.
Received messages display their authenticated MLS sender,
for example `alice/laptop> deployment complete`. `/quit`, EOF or Ctrl-C exits.
Restart either command to continue with the persisted group and ratchet state.
One process may use a device directory at a time; the client holds an OS file lock.

For scripting, receive the next undisplayed message (including offline backlog):

```bash
./target/debug/epochgrid --home .dev/bob message receive engineering --timeout 30
```

```bash
printf 'deployment complete' | ./target/debug/epochgrid --home .dev/alice message send engineering
```

Messages are limited to 16 KiB. Sending reads stdin to avoid placing message text
in the client's command-line arguments. After a network failure, retry stored
ciphertext without creating another message:

```bash
./target/debug/epochgrid --home .dev/alice channel flush
```

`identity show` prints only public data. `channel list` and `channel members NAME`
inspect local MLS groups. `--home`/`EPOCHGRID_HOME` selects the device directory;
`--server`/`EPOCHGRID_NATS_URL` selects NATS. To initialize a different device:

```bash
./target/debug/epochgrid --home .dev/example identity init alice --device laptop
```

A manually initialized device needs explicit NATS enrollment/configuration. The
bootstrap initially enrolls Alice/laptop and Bob/laptop. Milestone 12 supports
additional independent devices through public operator enrollment; see
[multi-device setup and upgrade](docs/multi-device.md).
Stop infrastructure with `docker compose down`; local keys and server data remain.

## History and offline catch-up

Retry queued ciphertext, fetch the current backlog and persist its authenticated
plaintext locally:

```bash
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob message history engineering --limit 50
```

`chat`, `channel sync`, and online `message history` flush the device-wide outbox
before catching up. This retries pending invitations and sends using their original
ciphertext. `chat` then polls the same durable path for new messages. `message receive` returns one undisplayed incoming message per call;
remaining messages stay queued locally. Browsing history does not consume that
queue. A network error can exit the client; reopen it to resume.

History shows JetStream sequence numbers in brackets, in ascending order. Request
an earlier page with `--before <sequence>` (exclusive). Read locally retained
history without connecting to NATS with `--offline`:

```bash
./target/debug/epochgrid --home .dev/bob message history engineering --offline --limit 50
```

Limits are 1–1000 entries per page. Locally queued sends without a publish
acknowledgment appear as `[pending]` after published history. Duplicate deliveries
do not create duplicate transcript entries. Invalid/undecryptable packets are
quarantined locally and counted rather than blocking later messages.

The first sync after upgrading can only recover ciphertext still retained by
JetStream and decryptable with local MLS state. Messages already processed by
Milestone 7 clients have no saved plaintext; history marks those entries
unavailable. Restoring old keys or replaying ciphertext cannot recover erased keys.

**Local transcripts are unencrypted development storage**, alongside private MLS
state. Retaining plaintext means endpoint compromise can expose historical content
even after MLS ratchet keys have been erased. NATS still receives no application
plaintext. Deleting server or local data independently is not a recovery method.

## Resume after an exit or failure

Keep the same device directory and NATS data volume. Start infrastructure/service
as above if they are stopped, then reopen `chat engineering` for either device.
Do not reinitialize identities, create another group or reinvite an existing member.
For a noninteractive recovery pass:

```bash
./target/debug/epochgrid --home .dev/alice channel sync engineering
./target/debug/epochgrid --home .dev/bob channel sync engineering
```

Use `channel flush` to retry only the outbox. A send failure can occur after NATS
has stored the message: retry the outbox before submitting that text again.
If joining was interrupted, repeat `channel join --from alice` to acknowledge a
redelivered Welcome; `channel list` shows whether the local join already committed.
If no invitation is available and the group exists, continue with sync/chat.
`message history --offline` never connects or publishes pending messages.

See [restart and recovery](docs/recovery.md) for tested failure boundaries and limits.

## Verify

Run the same complete MVP and alpha gate as CI (includes the pinned NATS download and Compose):

```bash
./scripts/dev/verify.sh
```

Or run its Cargo and live checks individually after downloading NATS:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration -- --ignored --test-threads=1
./scripts/dev/smoke.sh
NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/tui-smoke.py
```

The isolated NATS integration suite covers registration, discovery, authorization,
offline Welcome delivery, two-way encryption, ordered backlog replay, lost
acknowledgment recovery and NATS/client state reload. It checks that
`EPOCHGRID_TEST_SECRET_91F3` never appears in stored CHAT payloads. Unit tests cover
wrong inviters, tampering, wrong groups, replay and persistence. The Compose smoke
test launches two independent interactive clients, exchanges messages both ways,
kills both clients without graceful shutdown, then repeats with fresh processes.
It also verifies device locking, offline history,
pagination, repeated receives and automatic catch-up. The fresh MVP acceptance
case drives identity initialization, registration, discovery, invitation and chat
through separate CLI processes, restarts infrastructure, then scans every stream
payload/header/subject and broker/service files for test plaintext and client NKey
seeds. CHAT framing must be MLS PrivateMessage; MAILBOX must contain MLS Welcome.
See [MVP acceptance coverage](docs/mvp-acceptance.md) for assertions and limits.
Process tests also kill
workers with uncommitted SQLite writes; NATS tests cover a lost Welcome ACK and
a publish retry beyond the server deduplication window. CI runs all of these.

The smoke test uses the development identities and stops the Compose stack it
starts; run it while your interactive clients/service are stopped.

The multi-device integration case exercises Alice/laptop, Alice/desktop and
Bob/laptop: enrollment, device discovery, consumer migration, MLS epoch advancement,
offline catch-up, restart, mailbox isolation and ciphertext-only storage. The isolated
real-terminal test runs all three clients, checks logical membership, exchanges
messages with both Alice devices and verifies that the new device receives no
pre-join history. It also covers offline queuing, reconnect and terminal restoration.

## Current limits

- Multiple device leaves per user; additions are serialized by the creator device.
  One initial KeyPackage per device is reserved for one group.
  No replenishment, rotation, removal or revocation yet. Initial package expiry
  currently also limits signing-key lookup; long-lived identity lifecycle is pending.
- History processes encrypted Commits and applications in order across additions.
  New devices receive future messages, not earlier history. Offline ciphertext
  queued before an epoch change may become unreadable; avoid membership changes
  while participants have queued sends. Verification and revocation remain pending.
  Retention quotas/cleanup and hardware power-loss testing remain pending.
  Process termination and interrupted SQLite transaction recovery are tested.
  A crash around terminal output can repeat display; history remains available.
- Static development group permissions span the Alice/Bob lab namespace. Exact
  per-group NATS authorization is pending; inbox reads remain device-specific.
- Loopback development without TLS; SQLite and journals contain unencrypted local
  private state. Use trusted private directories, not production secrets.
- CHANNELS KV is provisioned but unused. No HTTP, attachments or other non-goals.

See [development](docs/development.md) and [SECURITY.md](SECURITY.md).
