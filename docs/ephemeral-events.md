# Ephemeral encrypted events — Milestone 17

Current deployment and milestone status: [status index](milestones.md). Local
plaintext examples require `EPOCHGRID_PROFILE=development`; the complete messaging
walkthrough still uses development fixtures. See [production TLS](operator/tls.md)
for secure transport and the remaining dynamic-deployment limits.

Known limitation: live TUI typing indicators are unreliable. Their end-to-end
assertions are disabled by default pending post-alpha review; see
[TD-001](technical-debt.md). The transport security tests remain enabled.

Core NATS carries generic versioned `EphemeralEvent` values on
`epochgrid.v1.group.<gid>.ephemeral`. Initial events are TypingStarted and
TypingStopped. The event type, timestamp and signature are encrypted. No event
is queued in the durable outbox, transcript, attachment index, SQLite or JetStream.
Typing state and replay evidence exist only in bounded process memory.

## MLS protection without advancing the chat ratchet

OpenMLS 0.9 uses the same application sender ratchet for PrivateMessages in a group,
regardless of NATS subject. Thousands of dropped typing messages could exceed the
receiver's maximum forward distance and break later durable chat; receiving newer
live events could also erase keys needed by older durable messages. Increasing the
ratchet window cannot bound an arbitrarily long offline interval.

Instead use RFC 9420 section 8.5 MLS-Exporter with an EpochGrid-specific label and
context bound to group ID, epoch, sender leaf and a random event ID. Each event gets
an AES-256-GCM key from the current MLS epoch, with a fresh random nonce. The sender
also signs the protected event with its independent MLS credential signing key.
Verify this signature against the current group's sender leaf: sharing an exporter
secret does not let another member impersonate that leaf. This is an application
use of standard MLS export, AEAD and signatures, not another group key agreement or
membership protocol. No exporter keys or events are written to local storage.

This deliberately uses an exporter-protected application envelope, not MLS
PrivateMessage framing. Durable chat and attachments keep their existing MLS
PrivateMessage protection. Exported ephemeral keys lack per-event forward secrecy:
compromise of an epoch exporter secret can expose recorded ephemeral events from
that epoch. MLS epoch changes replace the exporter secret; receivers accept only
the current epoch and active, non-revoked leaves. Revocation/rekey checks also guard
sending. Loss, reordering and ephemeral traffic volume never advance chat ratchets.
No draft MLS extensions or new cryptographic dependencies are enabled.

References inspected: [RFC 9420 §8.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-8.5),
OpenMLS 0.9.0 `src/group/mls_group/exporting.rs`, `src/tree/sender_ratchet.rs`, and
OpenMLS traits 0.6 signature/AEAD APIs. Exporter confidentiality is explicitly weaker
than per-message ratchet secrecy; this scope is appropriate to short-lived activity
indicators, not message-content replacement.

## Activity, ordering and limits

The TUI announces ordinary message composition, refreshes after two seconds of
continued edits, and stops after three idle seconds, clearing, submission or a
channel switch. Commands do not announce typing. Each receiver expires activity
within eight seconds even if the stop is lost or its worker is busy. Device activity
is tracked separately and displayed with logical usernames. Reconnect clears local
activity; there is no offline event queue or replay subscription.

Canonical signed Unix-millisecond timestamps order each device's events. Older or
duplicate timestamps cannot extend activity; a stop wins ties. Stopped entries stay
as tombstones until expiry. At most 256 device/group records are retained, rejecting
new records at capacity until expiry. Receivers allow at most one second of future
clock skew; keep host clocks synchronized. Restart forgets ordering evidence, so a
recorded event may be replayed within its remaining eight-second freshness window.
Current-epoch-only processing can drop events during membership catch-up. These
losses are intentional. Activity is advisory, never a delivery receipt.

The worker handles at most 32 received events per sync iteration and discards invalid
envelopes without writing them to quarantine or logs. NATS connection queues remain
subject to SDK limits; flood resistance and traffic-analysis protection are not
claimed. Missing or stale queued UI activity is discarded, not retried durably.

## Upgrade and validation

Close clients and rerun `./scripts/dev/bootstrap-nats.sh` to regenerate development
NKey permissions, then restart clients. Custom deployments must grant device publish
and subscribe access to authorized `epochgrid.v1.group.<gid>.ephemeral` subjects.
The development template uses the existing group wildcard authorization model.
Do not add these subjects to CHAT or any other stream. No backend flag, environment
variable, stream, consumer, KV bucket or SQLite migration is added. Old clients simply
lack indicators; durable protocol compatibility is unchanged.

Unit coverage checks encryption, tamper, sender impersonation, freshness, ordering,
capacity, revocation and restart after 1,100 lost events. The bounded NATS test checks
live delivery with unchanged CHAT/MAILBOX sequence numbers and no late-subscriber
replay. The optional `--check-typing` terminal test exercises typing without inserting a
transcript row; it is disabled by default under TD-001.

Historical Milestone 17 validation (not current test totals or typing UI qualification): formatting, warnings-denied workspace clippy, 39 unit
tests, workspace build, all 12 live NATS tests, the three-device PTY workflow and
isolated Compose chat/restart/history smoke test passed. The Compose check used a
free host port because an existing local fabric owned 4222; no existing fabric was
stopped or reset. All subprocess workflows retain the existing watchdog deadlines.

The diagnostic TUI probe uses separated typing bursts with varied pauses under a
fixed 25-second deadline. Its simulated timing/loss tests remain enabled, but this
does not establish that the real typing UI is reliable. Default CI explicitly skips
the live typing assertions; see [TD-001](technical-debt.md). All messaging and
cryptographic ephemeral-event assertions remain enabled.


Milestone 18 reuses this protected transport for receipt queries and responses.
Those events also remain non-durable, but their derived device claims are compacted
in SQLite. Typing state remains memory-only. See [receipts](receipts.md).
