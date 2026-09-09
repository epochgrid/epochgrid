# Multi-device identity — Milestone 12

A user groups independently enrolled devices. Every installation has its own NKey,
MLS signing/HPKE keys, MLS leaf, inbox, consumer, SQLite file and ratchets. Operator
managed enrollment remains authoritative. Adding a device initializes only that
installation; it does not grant account authority or copy another device's secrets.

## Enroll Alice's desktop

Close development clients and stop the identity service before regenerating
configuration. Preserve `.dev/` and the Compose volume. Build the updated workspace.
On the new installation:

```bash
./target/debug/epochgrid --home .dev/alice-desktop device add alice --device desktop
```

This prints a **public** `alice/desktop=U...` binding. On the development operator's
machine, substitute that complete printed binding below:

```bash
./target/debug/epochgrid dev-config --enroll 'alice/desktop=U...'
./scripts/dev/bootstrap-nats.sh
./target/debug/epochgrid-service
```

The service stays running in its terminal. Bootstrap retains additional public
bindings in `.dev/additional-enrollment.json`; repeated runs preserve them.
Existing bindings cannot be replaced through `--enroll`. Both NATS configuration
and the service enrollment file must be updated. No seeds are transferred.
For installations on separate hosts, distribute only the public binding and use
`--server` for the fabric address; the default lab listener is loopback without TLS.

In another terminal, register the new device and discover Alice's registered devices:

```bash
./target/debug/epochgrid --home .dev/alice-desktop identity register
./target/debug/epochgrid --home .dev/bob device list alice
./target/debug/epochgrid --home .dev/alice channel invite engineering alice --device desktop
./target/debug/epochgrid --home .dev/alice-desktop channel join --from alice
```

The invite runs on the device that created the channel. Close its TUI before using
CLI commands on the same home, or use `/invite alice desktop` in the TUI. The desktop
can use `/join alice` instead of the CLI join. Run a TUI for each independent home:

```bash
./target/debug/epochgrid --home .dev/alice-desktop tui
```

`device list` defaults to the local user. TUI `/members` shows `alice, bob`;
`/devices` shows all three leaves. CLI `channel members engineering --users`
collapses users; the existing command without `--users` preserves device diagnostics.
Invitations are explicit per device, not automatic fan-out to every registered device.

## Membership and persistence

The creator device serializes additions. Other members authenticate and merge its
MLS Commits. Non-creator invitations fail before claiming a KeyPackage. Every add
advances the epoch; existing devices consume encrypted Commits and application
messages together in CHAT sequence order, including after an offline interval.
A new device joins using its own Welcome and receives future messages, not another
installation's historical plaintext or old epoch keys. Exact invitation retries
flush existing ciphertext instead of adding duplicate leaves.

SQLite migration 1 adds `epochgrid_migrations` and `group_join_epochs`. Existing
groups checkpoint their current epoch; new joins record the Welcome epoch. No
keys, transcript or ratchets are deleted. Retained traffic below that floor is
skipped after checking its MLS framing/group ID, without authenticating or decrypting
it: a new member cannot authenticate epochs for which it has no keys. This is not
proof of historical integrity. Current/future epoch data goes through OpenMLS.
Commit processing, deduplication and delivery progress commit atomically.

The service updates each existing CHAT consumer filter from `.group.*.message` to
`.group.*.*`, preserving its acknowledgment progress. CHAT itself still contains
only message and handshake subjects. Stop old clients during upgrade, regenerate
NATS permissions, restart the updated service, then launch updated clients. Mixed
Milestone 11/12 clients are unsupported; do not downgrade databases or binaries
after advancing membership. Backup stopped local state and server data before an
upgrade; do not reset either as a migration strategy.

## Limits and trust

One initial KeyPackage per device is still reserved for one group, without
replenishment. Initial KeyPackage expiry also limits signing-key lookup. Legacy directory listing is bounded to 32 devices and the protocol's 65,536-byte
envelope limit. Milestone 13 audited listing follows the full-log capacity bound.
The operator, directory and NATS administrator remain trusted for identity binding;
Milestone 13 adds [manual verification and transparency](device-verification.md);
revocation remains future work.

Online sends catch up before encryption. Offline TUI sends remain queued as exact
ciphertext; if membership changes before publication, that old-epoch ciphertext
may be undecryptable after receivers advance. New members cannot read it. The client
does not retain old epochs or silently re-encrypt/retry plaintext in a newer epoch.
Avoid changing membership while participants have queued sends. Concurrent
membership writers, lost/invalid Commit repair and fork reconciliation are deferred.
MLS integrity does not prevent a malicious transport from withholding/reordering
traffic or disrupting availability.

Compromising one Alice device exposes its local secrets and plaintext and permits
sending as that device. Collapsing user labels is presentation, not shared keys or
proof of the human's identity. NATS group permissions still span the development
lab; inbox consumption remains per device. No historical erasure or removal security
is claimed. Revocation requires the later credential/MLS lifecycle milestone.

## Validation

The unchanged MVP Cargo, isolated NATS and real-terminal suites passed before this
change. The three-device integration test covers public enrollment rejection and
acceptance, device discovery, consumer-filter migration retaining progress, old
messages then Commit catch-up, new-device history boundaries, independent keys,
three-way messaging, restart, mailbox isolation and ciphertext scans. Unit tests
cover Commit transaction rollback, database migration, logical membership, signed
listing validation and public enrollment conflicts. The real-terminal test additionally runs three clients, checks collapsed membership,
exchanges messages with both Alice devices and checks the new-device history boundary.
It retains asynchronous messaging and offline queue/reconnect coverage. These tests
use isolated roots; the active developer Compose stack is not reset or interrupted.
