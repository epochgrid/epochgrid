# EpochGrid

EpochGrid combines NATS infrastructure with MLS end-to-end group encryption.
Project: https://epochgrid.org (secondary https://epochgrid.net).
Organization: https://github.com/epochgrid.

**Milestones 0–8 work:** independent NATS/MLS device identities, verified discovery,
persistent groups, durable invitations, authenticated Welcome joining and live
encrypted Alice/Bob chat with durable history and offline catch-up. JetStream
stores MLS protocol bytes; readable transcripts stay on each device. This is an unaudited development prototype.

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
bootstrap only enrolls Alice/laptop and Bob/laptop; multi-device users are deferred.
Stop infrastructure with `docker compose down`; local keys and server data remain.

## History and offline catch-up

Fetch the current backlog and persist its authenticated plaintext locally:

```bash
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob message history engineering --limit 50
```

`chat` catches up automatically on startup and polls the same durable path for
new messages. `message receive` returns one undisplayed incoming message per call;
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

## Verify

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace
NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration -- --ignored
./scripts/dev/smoke.sh
```

The isolated NATS integration test covers registration, discovery, authorization,
offline Welcome delivery, two-way encryption, ordered backlog replay, lost
acknowledgment recovery and NATS/client state reload. It checks that
`EPOCHGRID_TEST_SECRET_91F3` never appears in stored CHAT payloads. Unit tests cover
wrong inviters, tampering, wrong groups, replay and persistence. The Compose smoke
test launches two independent interactive clients, exchanges messages both ways,
then repeats after restarting both processes. It also verifies offline history,
pagination, repeated receives and automatic catch-up. CI runs all of these.

The smoke test uses the development identities and stops the Compose stack it
starts; run it while your interactive clients/service are stopped.

## Current limits

- Two devices per group; one initial KeyPackage per device, reserved for one group.
  No replenishment, rotation, removal or revocation yet. Initial package expiry
  currently also limits signing-key lookup; long-lived identity lifecycle is pending.
- History currently covers application messages in the existing two-device epoch.
  Later membership changes and multi-epoch handshake catch-up are not implemented.
  Retention quotas/cleanup and complete crash/power-loss testing remain pending.
  A crash around terminal output can repeat display; history remains available.
- Static development group permissions span the Alice/Bob lab namespace. Exact
  per-group NATS authorization is pending; inbox reads remain device-specific.
- Loopback development without TLS; SQLite and journals contain unencrypted local
  private state. Use trusted private directories, not production secrets.
- CHANNELS KV is provisioned but unused. No HTTP, attachments or other non-goals.

See [development](docs/development.md) and [SECURITY.md](SECURITY.md).
