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
or replenish yet. These constraints deliberately limit the first two-device slice.

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

Next is Milestone 10: final MVP integration and security assertions. Process-crash
coverage does not claim exhaustive filesystem or hardware power-loss recovery.
