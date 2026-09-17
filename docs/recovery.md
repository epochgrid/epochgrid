# Restart and recovery — Milestone 9

Current deployment and milestone status: [status index](milestones.md). Local
plaintext examples require `EPOCHGRID_PROFILE=development`; the complete messaging
walkthrough still uses development fixtures. See [production TLS](operator/tls.md)
for secure transport and the remaining dynamic-deployment limits.

This records the original MVP milestone. For current alpha capabilities and limits,
see [the README](../README.md), [multi-device membership](multi-device.md) and
[device verification/transparency](device-verification.md).

Reopen the same device directory to continue an existing two-device MLS group.
Identity, membership, epochs, sending/receiving ratchets, outbox, staging and local
transcript are persisted in one SQLite database. OpenMLS and application writes
share transactions. An OS file lock permits one client per device; the operating
system releases it when the process dies. Do not delete a lock file to bypass a
running client.

## Resume commands

With NATS running against its existing volume, run either:

```bash
./target/debug/epochgrid --home .dev/alice chat engineering
./target/debug/epochgrid --home .dev/alice channel sync engineering
```

Both flush the entire device's pending outbox in insertion order before catching
up this channel. Online `message history` also resumes outgoing work. The selected
channel must exist before any outbox publish is attempted. `channel flush` retries
only outgoing work; `message history engineering --offline` processes already
staged ciphertext and reads the transcript without network activity. `message
receive` can display a locally committed unread entry without connecting; when
it needs NATS, it flushes the outbox before fetching.

If NATS or local storage fails, the command can exit with an error. Restore access
and rerun sync/chat. A send error does not prove the server rejected the message:
retry the ciphertext outbox before submitting the same text as another message.
An interrupted invite is retried with the original `channel invite` command or by
flushing the outbox. An interrupted join can be retried with `channel join --from
alice`; byte-identical Welcome redelivery uses the persisted join marker rather
than consuming the private KeyPackage again. If no Welcome is available but
`channel list` shows the group, the join committed and sync/chat can continue.

Do not re-run identity initialization, recreate the group, delete databases or
restore an older database to solve connectivity problems. Keep `.dev/<device>/`
and the NATS data volume. Stop clients before moving their complete directories;
full-state backup and rollback-safe MLS restore are not implemented. Milestone 15
adds separate [encrypted identity-administration recovery](encrypted-recovery.md),
which excludes every MLS private key and transcript.

## Tested boundaries

| Failure boundary | Persisted state and recovery | Automated coverage |
| --- | --- | --- |
| Invitation committed before publish | Epoch, Commit and Welcome reopen together; outbox publishes original bytes | Core process-kill test and NATS resume test |
| Join committed before mailbox ACK | Membership survives; duplicate Welcome does not consume private keys again | Core process-kill test and live lost-ACK test |
| Send committed before publish | Sending ratchet, ciphertext and local transcript survive together | Core process-kill test |
| Server stores send before local sent marker | Retry original ciphertext; local transcript remains unique even beyond server dedup window | Live ambiguous-publish test |
| Ciphertext staged before decryption | Reopen and process staged data; lost ACK permits matching redelivery | Core process-kill test and durable-history NATS test |
| Receive transaction interrupted before commit | SQLite rolls back ratchet, plaintext, dedup and progress; same ciphertext decrypts after reopening | Core process-kill test |
| Decryption committed before display | Unread plaintext survives; ciphertext is not decrypted twice | Core process-kill test |
| Active chat processes killed | OS locks release; new Alice/Bob processes continue two-way traffic in existing groups | Compose CLI smoke test |

The core test signals that a boundary has been reached, then its parent forcibly
kills it while the store remains open (SIGKILL on Unix). It also checks SQLite
integrity and subsequent two-way ratchet progression. The interrupted-transaction
case kills the worker after real OpenMLS decryption and transcript writes, before
COMMIT. It does not rely on graceful shutdown, unwinding or Rust destructors.

The NATS ambiguous-publish test shortens only its isolated CHAT stream's dedup
window to one second, confirms the original publish, leaves its local outbox
pending, and retries after expiry. It requires a second stored ciphertext copy
and a single transcript entry at the earliest observed sequence on each device.
No server deduplication setting changes in normal development configuration.

Welcome and CHAT ACKs use async-nats's
[confirmed acknowledgment](https://docs.rs/async-nats/0.50.0/async_nats/jetstream/message/struct.Message.html#method.double_ack)
after local durable commit. A lost confirmation remains recoverable through
idempotent redelivery. This is not an atomic transaction across SQLite and NATS.

## Limits

Tests cover process failure on the development filesystem, not power loss, disk
corruption, full disks, restored stale device snapshots or deleted server streams.
History cannot restore missing ratchet state or ciphertext removed by retention.
The initial KeyPackage's expiry still limits signing-key lookup in this prototype;
long-lived identity lifecycle and package replenishment remain future work.

The original Milestone 9 tests cover the two-device epoch. Milestones 12–14 add
ordered membership-Commit replay and revocation; see their architecture notes. Terminal output is not
transactional: a crash after printing but before marking displayed can repeat a
line. No exactly-once display or hardware durability guarantee is claimed.
Local plaintext transcripts and private state remain unencrypted development
storage. Recovery testing is not a security audit.
