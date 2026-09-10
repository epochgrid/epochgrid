# Interactive client — Milestone 11 design

Baseline: the unchanged `scripts/dev/verify.sh` passed before implementation,
including four live NATS cases and the two-client Compose workflow.

Use `epochgrid tui` alongside the unchanged scripting commands and line-oriented
`chat`. Ratatui 0.30.2 and Crossterm 0.29 are the maintained compatible pair checked
against https://ratatui.rs/installation/ and https://docs.rs/ratatui/0.30.2/.

A terminal event loop owns rendering/composition. One dedicated worker thread owns
IdentityStore and a Tokio runtime: SQLite's shared Rc provider never crosses thread
boundaries. Bounded commands and a latest-value snapshot channel connect them.
The worker reuses existing group/invitation operations, ciphertext outbox and CHAT
consumer; network work has bounded timeouts. Offline composition is encrypted and
committed locally before it is shown as pending. Reconnect retries the original
ciphertext. Storage/crypto errors are surfaced without pretending a send succeeded.

The TUI reads existing transcripts and local displayed flags. Active history clears
local unread flags after rendering; these are not network read receipts. Pages use
existing stream sequence cursors. No timestamps are invented for old messages.
No schema or wire changes are needed. Two-device groups and one initial package
per device remain the MVP limits until Milestone 12.

Implemented controls: Tab/BackTab select channels, Enter submits, PgUp/PgDn page history,
Ctrl-C quits. Slash commands create channels, invite/join with an explicit inviter,
and show members. Terminal state must be restored on normal exit, error and panic.
Tests cover model/keyboard/rendering and real Alice/Bob pseudo-terminals,
including offline queuing, reconnect and restart.

## Operation and limits

Run `epochgrid --home .dev/alice tui` and `epochgrid --home .dev/bob tui` after
bootstrap/registration. The existing line-oriented `chat` and every scripting
command remain available. Commands are `/create NAME`, `/invite USER [DEVICE]`,
`/join INVITER [DEVICE]`, `/members`, `/help` and `/quit`. Prefix `//` to send a
literal leading slash. Esc clears composition; backspace deletes one Unicode
scalar. Up/Down scroll wrapped history; PgUp fetches an older 100-message page,
PgDn returns to latest. Sequences label history; pending sends are explicitly
labelled. Input scrolls horizontally and bracketed paste cannot submit itself.

The worker's command queue holds at most 32 operations; congestion leaves input
intact. A send's composition clears only after local encryption/outbox commit,
not when it enters the command queue. Failed encryption retains the draft. The
outbox automatically retries during network polling, with reconnect delays from
one to eight seconds and bounded network attempts. Sending while offline still
requires an existing group with a peer. Invite/join failures require explicit retry.
The UI remains responsive while those network operations wait. Errors are displayed
without normal-level tracing output corrupting the alternate screen.

Local plaintext history appears before connecting. All known channels process
staged deliveries, so background channels gain unread counts. Rendering an active
100-message page marks its entries locally displayed, including entries below/above
the viewport; this is a navigation indicator, not proof of human reading and not
a network receipt. Terminal restoration covers Ctrl-C, /quit, errors and unwinding;
SIGKILL cannot restore terminal modes. Drafts not yet committed remain volatile.

Ratatui's `unstable-rendered-line-info` feature is enabled to measure wrapped
paragraph height accurately; the lockfile and rendering tests constrain this API.
No OpenMLS, NATS wire, consumer, authorization or SQLite schema changes were needed.
The only core addition is a read-only unread count using existing transcript flags.
`verify.sh` now also runs `tui-smoke.py`, an isolated real-PTY test that creates and
joins a group, exchanges messages, checks background unread state, stops NATS,
queues a send, restarts a TUI offline, reconnects and checks terminal restoration
and absence of the TUI plaintext markers in NATS files.

During repeated full validation, the existing parallel NATS recovery suite once
failed with a transient device-lock contention while process-spawning tests were
running together. The shared gate now serializes those process-based integration
cases (`--test-threads=1`); all assertions and production device locking remain
unchanged. Each case still starts isolated NATS/service processes.


Milestone 12: `/members` lists unique logical users; `/devices` lists their MLS
leaves. Invite an additional installation with `/invite USER DEVICE`; it joins with
`/join INVITER DEVICE` (inviter device defaults to laptop). Enrollment must happen
first using the [operator workflow](multi-device.md). Online sends catch up before
encryption; offline queued ciphertext can become unreadable if membership changes
before publication. Adding devices does not transfer earlier message history.


Milestone 13 audits the signed registration log during network polling. Persistent
trust warnings take precedence over ordinary notices; a changed identity remains
blocked across restarts. Offline history still renders. Run fingerprint comparison
and manual verification commands with the TUI closed for that home; see
[device verification](device-verification.md). A failed audit stops that polling
cycle, so an unavailable identity service can delay interactive delivery even while
NATS is reachable. Established scripting chat remains an MLS group operation.

Milestone 14 network polling also audits revocations, processes removal Commits and
rekeys when this device is coordinator. New encryption waits for known revoked leaves
to be removed. Queued old-epoch messages are retained but blocked, with a visible warning;
resend needed text explicitly after rekeying. Revocation can be issued by the operator
or another active installation using `device revoke USER DEVICE`. A broker-disconnected
device shows connection loss; without updated evidence it cannot infer the cause.

Membership views render from the latest worker snapshot, including additions/removals
while the view is open. Security warnings take precedence over local command notices.
