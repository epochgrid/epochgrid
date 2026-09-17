# EpochGrid

EpochGrid combines NATS infrastructure with MLS end-to-end group encryption.
Project: https://epochgrid.org.
Organization: https://github.com/epochgrid.

**Current status: MVP and initial alpha features implemented; production-shaped alpha
preparation is in progress.** Milestone 21 admission works, Milestone 22 dynamic
authorization is in progress, Milestone 23 provides verified production TLS, and live
typing UI is deferred (TD-001). See the [current milestone status](docs/milestones.md).
EpochGrid has a persistent terminal client and independent devices per user.
JetStream stores MLS protocol bytes; readable transcripts stay on each device.
This is unaudited development software, not a production-ready security product.

| Milestone | Status | Scope |
| --- | --- | --- |
| 0–10 | Complete | NKey authentication, signed device registration and discovery, MLS groups and invitations, encrypted chat, durable history, offline catch-up, restart/resume and ciphertext-only acceptance tests |
| 11 | Complete | Persistent TUI with history, asynchronous messaging, unread indicators and reconnect |
| 12 | Complete | Independent devices per user, operator enrollment, device discovery, ordered MLS membership catch-up and logical user membership |
| 13 | Complete | Manual device verification, persistent key-change warnings and a signed Merkle registration log |
| 14 | Legacy/dev-only | Signed device revocation, native NATS credential exclusion, MLS removal/rekeying and offline reconciliation |
| 15 | Complete | Client-encrypted control-credential/trust recovery; fresh device enrollment and re-invitation for messaging |
| 16 | Complete | Client-encrypted attachments via NATS Object Store, protected metadata, explicit save, retention and tamper tests |
| 17 | Partial — UI deferred | Encrypted ephemeral transport implemented; live typing indicators are unreliable and their TUI checks are disabled pending [post-alpha review](docs/technical-debt.md) |
| 18 | Complete | Encrypted device delivery/read receipts, distinct server acceptance and visible-message read tracking |
| 19 | Complete | Stable application IDs, append-only replies/edits/reactions, authenticated ordering and replay |
| 20 | Complete | Explicit MLS service participants, encrypted status replies, restart-safe processing and coordinator removal |
| 21 | Complete admission slice | Canonical identity enrollment and encrypted NATS Auth Callout |
| 22 | In progress | Signed group policies and scoped grants; client/consumer/Welcome integration remains |
| 23 | Complete transport milestone | Production TLS, system/custom trust, hostname verification, minimum version and certificate rotation |
| 24–38 | Not started | Secret storage, deployment qualification, operations and release preparation |

Invite the reference `@status [service]` participant and send `/status` in the TUI.
See [service setup, trust and removal](docs/service-participants.md). The metadata
backend remains separate and has no group plaintext access.

Use `/reply ID TEXT`, `/edit ID TEXT`, `/react ID VALUE` and `/unreact ID VALUE`
in the TUI. See [message relationships](docs/message-relations.md) for CLI commands,
stable IDs, upgrade requirements and edit history. Upgrade all clients together.

See [delivery and read receipts](docs/receipts.md) for device status, offline limits
and `message receipts CHANNEL [--offline]`.

Typing indicators are automatic in the TUI; drafts are never transmitted. See
[ephemeral events](docs/ephemeral-events.md) for protection, expiry and upgrade details.

See [multi-device setup and upgrade](docs/multi-device.md) for the current enrollment
workflow, migration requirements and three-device validation scenario.
See [device verification and transparency](docs/device-verification.md) for independent
fingerprint comparison, directory key pinning and the limits of the log.
See [device revocation](docs/device-revocation.md) for upgrade instructions,
`device revoke USER DEVICE`, network enforcement and offline rekeying semantics.

NATS supplies transport, authentication, authorization and persistence. OpenMLS
supplies group encryption and cryptographic membership. The metadata backend handles public
identity metadata over NATS request/reply and never receives application plaintext.
See [architecture](docs/architecture.md), [protocol](docs/protocol.md), and
[security boundaries](docs/threat-model.md).

## Authentication migration toward alpha

Dynamic NATS Auth Callout admission uses a provider-neutral identity registry.
Milestone 22 now has signed coordinator policies, exact group subject grants and
transactional membership revocation. Normal dynamic CLI/TUI messaging still needs
policy/outbox synchronization, filtered durable consumers and Welcome relay. See [the migration inventory](docs/architecture/auth-migration.md) and
[Auth Callout setup and current limits](docs/operator/auth-callout.md). The existing
walkthrough below is an explicitly static development fixture, not the supported
alpha deployment model. No alpha release has been tagged; dynamic group permissions,
secure local storage and the remaining release gates are still required.

## Start development infrastructure

Prerequisites: rustup (Rust 1.98.1 is pinned), a C toolchain for bundled SQLite,
Docker Engine with Compose v2, Bash, Python 3, OpenSSL (for TLS integration tests),
curl, tar and sha256sum.
The development image supports Linux amd64/arm64, including Linux Docker on macOS.
Host integration tests require Linux or a native NATS server via `NATS_SERVER`.

Production is the default transport profile. In **every terminal** used for the
local plaintext walkthrough below, explicitly select development:

```bash
export EPOCHGRID_PROFILE=development
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
export EPOCHGRID_PROFILE=development
./target/debug/epochgrid-service --dev-static
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

## Verify device identity

Bob displays his own fingerprint with `epochgrid --home .dev/bob device fingerprint`.
Alice compares it through an independent channel, then supplies the complete value:

```bash
./target/debug/epochgrid --home .dev/alice device fingerprint bob laptop
./target/debug/epochgrid --home .dev/alice device verify bob laptop --fingerprint 'FULL FINGERPRINT FROM BOB'
./target/debug/epochgrid --home .dev/alice transparency audit
./target/debug/epochgrid --home .dev/alice transparency status
```

An observed key change is persistently flagged and blocks audited discovery and new
invitations. The TUI surfaces trust failures. Inspect retained evidence using
`device fingerprint bob laptop --offline`. The first directory signer is trusted
on first use unless pinned independently beforehand with `transparency pin U...`.
The [verification guide](docs/device-verification.md) explains upgrade steps and why
this does not detect every malicious-server or split-view attack.

## Encrypted identity recovery

Stop the client using this home before exporting. Use two new files; keep the
secret separately from the encrypted package (for example in a password manager):

```bash
./target/debug/epochgrid --home .dev/alice recovery export \
  --output alice.egrecovery --secret-file alice.egsecret

# After loss, restore into a new, empty home.
./target/debug/epochgrid --home .dev/alice-recovered recovery restore \
  --input alice.egrecovery --secret-file alice.egsecret
./target/debug/epochgrid --home .dev/alice-recovered recovery status
./target/debug/epochgrid --home .dev/alice-recovered transparency audit
```

The restored home recovers identity administration and retained verification evidence.
**It cannot chat and contains no MLS private keys or message history.** Resume messaging
with an independently initialized device, ordinary operator enrollment, revocation of
the lost device, and a fresh invitation from a remaining group coordinator. Recovery
does not reactivate revoked credentials. See the [complete recovery workflow and
security semantics](docs/encrypted-recovery.md). The service never receives the secret
or decrypted package; encrypted recovery files can be kept in untrusted storage.

## Encrypted attachments

Upgrade every group member and rerun bootstrap before sending attachments; see the
[attachment guide](docs/attachments.md) for permissions, limits and retention.

```bash
./target/debug/epochgrid --home .dev/alice attachment send engineering ./report.pdf --mime application/pdf
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob attachment list engineering
./target/debug/epochgrid --home .dev/bob attachment save engineering ATTACHMENT_ID ./saved-report.pdf
```

The TUI supports `/attach PATH` and `/save ID OUTPUT_PATH`, including paths with
spaces. Files are encrypted before Object Store upload; filenames, MIME types and
keys travel inside MLS. Downloads authenticate before writing and refuse overwrite.
Default maximum size is 8 MiB, with seven-day object retention. No automatic downloads
or file execution occur. Local manifests contain plaintext DEKs; explicitly saved
files are plaintext and are excluded from recovery exports.

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
EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" cargo test -p epochgrid-service --test registration -- --ignored --test-threads=1
./scripts/dev/smoke.sh
EPOCHGRID_PROFILE=development NATS_SERVER="$PWD/.dev/nats-image/nats-server" python3 scripts/dev/tui-smoke.py
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
pre-join history. It also covers offline queuing, reconnect and terminal restoration. Two additional
NATS cases cover directory migration, explicit fingerprint verification, malicious
history/key substitution, competing log appends and restart persistence. Two revocation
cases cover forced disconnect, refused reconnect, MLS exclusion, durable intent retries
and service/broker restart. The terminal workflow also exercises live device revocation. The encrypted-recovery
case destroys Alice’s original home, restores control authority and trust, verifies
revocation remains effective, and resumes two-way messaging with a fresh leaf.

## Current limits

- Multiple device leaves per user; membership changes are serialized by the group coordinator.
  One initial KeyPackage per device is reserved for one group.
  Removal/revocation is implemented; package replenishment and key rotation remain pending. Initial package expiry
  currently also limits signing-key lookup; long-lived identity lifecycle is pending.
- History processes encrypted Commits and applications in order across additions.
  New devices receive future messages, not earlier history. Offline ciphertext
  queued before an epoch change may become unreadable; avoid membership changes
  while participants have queued sends. Known revoked-epoch queued sends are blocked
  and must be resent explicitly after rekeying. Offline groups wait for their coordinator.
  Retention quotas/cleanup and hardware power-loss testing remain pending.
  Process termination and interrupted SQLite transaction recovery are tested.
  A crash around terminal output can repeat display; history remains available.
- The transparency log is bounded to 65,536 encoded bytes and 256 registrations.
  First-contact trust, isolated split views, freshness and account ownership remain
  explicit limits; there is no automatic identity-replacement workflow.
- The legacy development revocation fixture manages one broker and needs a restricted
  reload key. Dynamic Auth Callout revocation does not edit NATS configuration;
  remaining MLS/consumer convergence work is tracked under Milestone 22.
- Static development group permissions span the Alice/Bob lab namespace. Exact
  grants exist in the dynamic policy path, but normal-client/durable-consumer
  integration is pending; inbox reads remain device-specific.
- The explicit loopback development profile permits plaintext. Production connections
  require [verified TLS](docs/operator/tls.md). SQLite and journals contain unencrypted local
  private state. Use trusted private directories, not production secrets.
- Recovery restores identity administration only; no old MLS state or transcript is
  backed up. Messaging needs operator enrollment and a surviving group coordinator.
  Lost recovery secrets and already revoked credentials require operator assistance.
- Attachments require connectivity and are buffered within a configurable size limit.
  Bucket authorization spans the shared lab; malicious members can deny availability.
  Expiration cannot erase downloaded copies or DEKs already known to recipients.
- CHANNELS KV is provisioned but unused. No HTTP or external storage service.

See [development](docs/development.md) and [SECURITY.md](SECURITY.md).
