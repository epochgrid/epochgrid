# Development notes

Follow README for first setup. `bootstrap-nats.sh` preserves existing local
identities; repeating it regenerates public config/enrollment and restarts NATS
as needed. It never prints seeds. The binary download verifies fixed upstream
SHA-256 hashes. No base image is pulled: Compose builds a scratch image using the
official GitHub release binary and its license. No image/package is published.

To run infrastructure directly on a Linux host instead of Compose:

```bash
cargo build --workspace
./target/debug/epochgrid dev-config
./scripts/dev/download-nats.sh
.dev/nats-image/nats-server -c .dev/nats.conf
```

Then start the service and clients as in README. Do not run host NATS and Compose
on the same port. The host installed NATS 2.10.11 is not the pinned development
server; tests use downloaded 2.14.5 via NATS_SERVER.

The service provisions CHAT, MAILBOX, IDENTITIES and CHANNELS at startup. Devices
can only publish registration requests and subscribe to their own random reply
subjects. They cannot access another inbox or JetStream APIs. The service has
JetStream API administration plus public KV write permissions and temporary
one-response authorization. This is development provisioning authority; separate
it from runtime permissions before expansion. Clients have no group permissions
yet because group operations are not implemented.

A future destructive reset must remove local identities and server data together;
there is deliberately no automatic deletion script. `docker compose down` retains
data. Review what you need to keep before manually removing data.

CI pins checkout by commit and the Rust toolchain by release, with read-only
repository permissions and no publishing secrets. Ordinary tests are offline
after dependency download. The NATS integration test explicitly opted into by CI
spawns its own processes on an ephemeral loopback port and uses a temporary
directory; a port allocation race is possible on a busy shared host.
