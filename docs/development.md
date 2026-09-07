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
mailbox consumers at startup. Static group permissions span the shared Alice/Bob
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
both and repeats the exchange. It stops the Compose stack afterward.

Milestone 8 is next: durable chat history retrieval and ordered offline catch-up.
Current chat is live-only; missed ciphertext remains in CHAT but is not replayed.
