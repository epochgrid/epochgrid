# Delivery and read receipts — Milestone 18

Submitted means ciphertext and sending state committed locally. Server accepted
means JetStream acknowledged the original ciphertext. Delivered means a peer device
has authenticated and persisted the message. Read means that device marked the
message presented locally. These are separate facts, not interchangeable labels.
Read is a client assertion, not proof of human attention. A dishonest member can lie.

Receipt requests and responses are new typed events in the existing signed,
MLS-exporter-encrypted Core NATS envelope. They inherit its current-epoch membership,
freshness checks and lack of per-event forward secrecy. Subjects, timing and size
remain visible. No receipt enters JetStream, the durable outbox or the transcript.
The service backend has no plaintext role. Existing typing enum indices remain
unchanged; older clients ignore unsupported event variants.

Requests identify the SHA-256 of the immutable MLS ciphertext, scoped to a group.
This is a delivery reference, separate from the application-level message ID introduced in
Milestone 19. A device answers only from its local authenticated incoming transcript
and only when the requester is that message's authenticated sender. The response
identity comes from the current MLS leaf signature. Senders persist only receipts
for their own known outgoing messages; unknown references are discarded. Read
supersedes delivered; duplicates and reordered delivered responses cannot regress
state. Device records remain separate even when UI labels collapse users.

Migration 6 adds a ciphertext reference index and a compact receipt table; existing
transcripts are backfilled without changing ciphertext or ratchets. Local receipt
state is unencrypted metadata like the existing transcript. It is excluded from
recovery. No schema reset is required. Read markers predate this migration; old
markers mean the older client presented the message according to its then-current
behavior.

The interactive client requests receipts for recent outgoing history periodically.
Offline peers answer after both clients overlap online again; receipt absence means
unknown, not failed delivery. This deliberately does not guarantee receipt recovery
when peers never overlap, or after removal from the group. Existing read/delivery
claims persist locally across restart. No unbounded receipt event history is stored.

## Usage and boundaries

The TUI shows `submitted`, `server accepted`, then individual device claims such as
`alice/laptop: delivered; alice/desktop: read` below outgoing messages. It requests
the selected channel's latest 100 accepted outgoing messages in rotating batches
of at most eight every five seconds. It answers requests for any local channel,
including background channels. Only visible message text is marked read; merely
loading a history page or receiving a message in a background channel is not read.
Partial visibility counts as presentation. Historical claims remain after revocation
and do not imply a device is still authorized.

For scripting or diagnostics:

```bash
epochgrid message receipts engineering --offline
epochgrid message receipts engineering --wait 5
```

The online command first audits/synchronizes, then exchanges requests and responses
for 1–60 seconds (default five). Preflight has a separate ten-second deadline. Run
it on both peers, or keep the peer TUI running. It requests the latest 100 outgoing
messages every two seconds and answers incoming requests during that interval.
The command does not mark messages read. `message receive` and interactive `chat`
retain their existing presentation markers; a subsequent receipt exchange reports
them. `message history` remains inspection-only and does not mark rows read.
Older receipts outside the automatic 100-message window are retained if already
observed; obtaining missing older receipts is not implemented in this alpha.

Upgrade clients together before using receipt exchange. Existing text/attachment
and durable MLS formats are unchanged, but older clients cannot reopen a database
migrated to schema 6. No NATS stream, consumer, bucket, permission, backend flag or
environment-variable change is needed beyond Milestone 17 ephemeral permissions.
A device that was not a historical recipient must not infer message delivery from
its mere current membership. Receipt claims reflect client assertions and cannot
prove that an honest decryption occurred on a malicious member's endpoint.

## Validation notes

The baseline quality gates, 39 unit tests, 12 NATS tests and TUI flow passed before
implementation. Milestone 18 adds migration/receipt and viewport coverage: 42 unit
tests and 13 live NATS tests pass, together with formatting, warnings-denied clippy,
workspace build, bounded harness and isolated Compose checks. The old unversioned
schema fixture was updated to remove migration-6 tables when simulating an old home.

One repeated parallel unit run reported a transient device-lock acquisition failure
in the existing encrypted-recovery restart test. The full suite passed on rerun
without a recovery or lock-behavior change; the cause was not established. This is
recorded as a test reliability observation, not claimed fixed by receipt work.


Milestone 19 keeps receipt references bound to each immutable MLS ciphertext. Its
conversation projection does not overwrite receipt history; read remains a client
presentation claim, not proof of reading every superseded revision. Copies with an
identical authenticated application ID share their logical presentation marker.
