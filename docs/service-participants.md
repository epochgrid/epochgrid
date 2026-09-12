# Secure service participants — Milestone 20

The reference `status/service` installation is an ordinary enrolled device with its
own NKey, independent MLS signing material, mailbox, SQLite database and group leaf.
It is separate from `epochgrid-service`, the metadata backend. It receives no backend
credentials. Operators enroll its public binding through the existing development
configuration workflow; channel coordinators explicitly invite it and its operator
explicitly joins the Welcome from a named inviter.

For this narrow alpha, device ID `service` is the authenticated service-label
convention. Membership displays render these leaves as `@USER [service]`; raw device
lists retain `USER/service`. The label is bound by the existing signed registration
and MLS credential, not by a mutable directory display name. It is not an attestation
of code or trustworthiness. Other automation can use this convention; there is no bot
framework or new registration wire version.

`epochgrid participant run CHANNEL [--once]` operates one
explicitly joined channel. It handles original `/status` events only, never edits,
reactions, replies, its own messages or other service messages. Replies use the MLS
application envelope and a ReplyTo relation. A local schema-8 processing record and
the encrypted response/outbox commit atomically, preventing duplicate responses on
restart or application-event replay. Processing does not assert a human read receipt.
Each online pass has a deadline; the persistent runner retries transient failures
with bounded polling and responds to Ctrl-C. `--once` is finite for automation.

Channel removal is an MLS Remove Commit issued only by the existing active group
coordinator. It removes one explicitly named leaf, advances the epoch and preserves
historical transcripts. This is separate from account-wide device revocation: NATS
credentials remain valid and the current broad CHAT consumer may still receive
ciphertext. The removed leaf cannot derive future epoch secrets. Existing NATS group
ACL limitations remain; use device revocation to disable its fabric credential.

A participant is an intentional plaintext recipient and retains unencrypted local
history under the same endpoint boundary as clients. Removal cannot erase previously
received plaintext or prevent a remaining member from forwarding content. Service
responses describe only its local connection and MLS operation, not fabric-wide
health or security certification. No messages or secrets are logged by the runner.


## Run the reference participant

Build the workspace. Stop the backend and client processes before regenerating
operator configuration; retain existing state and volumes.

```bash
./target/debug/epochgrid --home .dev/status device add status --device service
```

Copy the **public** `Operator enrollment: status/service=U...` binding printed by
that command into the next command (replace `U...` with the complete public NKey):

```bash
./target/debug/epochgrid dev-config --enroll 'status/service=U...'
./scripts/dev/bootstrap-nats.sh
```

Restart `./target/debug/epochgrid-service --dev-static` in its existing terminal. The additional
public enrollment is retained by bootstrap. Then:

```bash
./target/debug/epochgrid --home .dev/status identity register
./target/debug/epochgrid --home .dev/alice channel invite engineering status --device service
./target/debug/epochgrid --home .dev/status channel join --from alice
./target/debug/epochgrid --home .dev/status participant run engineering
```

The last command runs persistently until Ctrl-C, removal or revocation. Use a separate
terminal for Alice/Bob. In a TUI use `/invite status service`, `/members`, `/devices`
and `/status`; every member can see the encrypted request and reply. Do not run a CLI
operation against an installation already locked by its TUI/runner. To send from a
script without adding a newline:

```bash
printf /status | ./target/debug/epochgrid --home .dev/alice message send engineering
```

Stop Alice's TUI before this coordinator CLI command:

```bash
./target/debug/epochgrid --home .dev/alice channel remove engineering status --device service
```

The runner stops after processing the removal. Bob and Alice can continue messaging
in the new epoch. Existing history remains readable locally. Removal cannot recall
old-epoch ciphertext already published or delayed by the transport. Rejoining a
removed local group is not implemented; use a fresh service installation/identity
and a new invitation. Coordinator self-removal is also outside this milestone.

## Persistence and compatibility

Migration 8 adds `participant_events`, keyed by group/application ID. It stores no
additional message content. Every examined event (including ignored commands) is
recorded so subsequent passes progress in bounded batches. The record, response
ratchet, transcript and outbox share one transaction. A failure rolls them all back;
an ambiguous publish retries the original ciphertext. No exactly-once transport
claim is made: application IDs and the processing table suppress duplicate work.
This state must be retained with MLS state and is excluded from recovery packages.
Existing local databases migrate automatically, without reset; old binaries cannot
open schema 8. On-wire compatibility remains Milestone 19: existing clients can
process the response and standard MLS Remove Commit, though old UIs lack the service
label and `/status` shortcut (`//status` sends the literal request there).

One runner handles one channel in one installation. It does not auto-join mailboxes,
fetch attachments, execute shell commands, interpret arbitrary message relationships,
or send human read receipts. At most 100 retained events are considered per pass;
the runner polls once per second with a 15-second deadline on each network pass.
Only a successful catch-up permits responses. Persistent failures are logged without
message bodies; `--once` returns an error to automation. Status text describes the
local state at processing time and can arrive later after retry. The signed service
device convention is disclosure, not enforcement that every automated client uses
this label. Members can run other software under ordinary identities.

## Validation

Unit tests cover transaction rollback, restart, canonical-event replay, ignored
relationship/own-service events, coordinator authorization, epoch advancement,
blocked old outbox entries and inability to decrypt after removal. A bounded live
NATS test exercises the shipped CLI, persistent runner, pre-join secrecy, removal,
remaining-client continuity and absence of request/response plaintext in CHAT.
`./scripts/dev/verify.sh participants-tui` exercises real terminals and ciphertext-only
storage with its own 120-second watchdog; it does not extend the existing TUI test.
