# Device revocation — Milestone 14

Revocation is an irreversible signed request by an active installation of the same
user, or by the directory operator. It names the exact registered user, device and
NKey. It cannot replace keys, restore authorization or erase historical plaintext.
Authorization (`active`/`revoked`), local trust (`unverified`/`verified`/`changed`),
connection status and MLS membership are separate states. Active does not imply
online. Remote presence is not implemented; a disconnected revoked installation
cannot distinguish network failure from revocation until it obtains evidence.

## Upgrade and commands

Stop the service and clients, run `./scripts/dev/bootstrap-nats.sh`, and restart the
service and clients. Keep `.dev/` and the JetStream volume. Bootstrap creates the
restricted system identity, public authorization include and directory mount needed
for native NATS reload. SQLite migration 3 preserves keys, groups, history and trust,
adds the revocation checkpoint/cache and blocked-outbox tables, and pins each
existing group's coordinator signing key. Do not downgrade upgraded databases or
mix old clients with revocation-aware clients.

With Alice/laptop, Alice/desktop and Bob/laptop enrolled and joined:

```bash
# Close the TUI using this home before invoking the scripting command.
./target/debug/epochgrid --home .dev/alice device revoke alice desktop
./target/debug/epochgrid --home .dev/alice device list alice
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob channel members engineering
```

The operator can revoke a device without owning a group leaf:

```bash
./target/debug/epochgrid --home .dev/service device revoke alice laptop
```

Use another active device or the operator, especially when revoking the last device
of a user. Self-revocation disconnects the caller before it can receive confirmation;
use an active authorized device/operator to inspect and retry the same target. A
retry does not append a duplicate or perform another removal. There is no un-revoke:
replacement enrollment must use a new device ID and independent keys.

TUI and line-chat polling audit revocations and process removals automatically.
Scripting send/sync/history does the same. `device list` shows directory authorization
beside local trust. Revoking through another home does not require stopping the
other running clients. `transparency status` shows the retained revocation checkpoint and locally pending
MLS groups. `transparency audit` verifies both journals; audit failures
are persistent local warnings. A rejected/timed-out revoke may have recorded intent:
repair the actuator and retry, rather than assuming the device remains authorized.

## Durable intent and NATS enforcement

A separate signed append-only Merkle journal lives at `revocations` in TRANSPARENCY
KV. Registration snapshot bytes and Milestone 13 roots are unchanged. Clients retain
both prefix checkpoints and reject rollback, rewriting, signer mismatch, duplicate
targets and unauthorized revocation signatures. Old Audit requests fail closed once
any revocation exists. Revoked devices disappear from active lookup/KeyPackage APIs;
immutable public registration evidence remains available to current audit clients.

The service records intent before network enforcement. It atomically rewrites
`revoked-nkeys.json` and `auth/users.conf`, requests native NATS RELOAD, then deletes
the device's CHAT and MAILBOX consumers. Removing the NKey terminates existing
connections and prevents reconnect, including inbox access. Success acknowledges
these steps; it does not assert that offline MLS groups have advanced. The service
retries pending intent every two seconds and reapplies it at startup. Bootstrap
preserves the revoked-key exclusions. Keep the journal and public exclusion file:
deleting development state is not an authorization-preserving upgrade.

NATS 2.14.5 supports `$SYS.REQ.SERVER.<server-id>.RELOAD`. A dedicated system-account
NKey has only that publish permission and its own reply subscriptions. It has no
group data access. The host service needs this identity and write access to the public
authorization directory. Reload clears dynamic response grants, so service publishing
also permits reply prefixes for active enrolled devices. Ordinary clients receive no
system privileges. The original global account and its JetStream storage are retained.

This is a single managed broker/service actuator with a local process lock. The
service is trusted for network authorization and metadata, not message confidentiality.
Multiple brokers, externally managed credentials and clustered actuators are not
implemented. An unavailable actuator leaves durable intent pending and does not
produce a successful acknowledgment. Native reload cannot prevent a malicious NATS
administrator from restoring credentials; MLS removal provides the content boundary.

## MLS removal and offline groups

The current coordinator serializes membership changes. Initially this is the creator.
When revoked, the lowest-index non-revoked leaf succeeds it. Its first Commit must
remove exactly the locally known revoked leaves, with no other proposals. The coordinator's
MLS signing key is persisted, so a newly invited device cannot inherit authority by
reusing a vacated leaf index. Unsupported signing-key/credential replacement and
proposal types other than Add/Remove are rejected, preserving the directory binding. Historical coordinator authority remains pinned until
its removal Commit is merged. A Welcome authenticates the explicitly selected
inviter and initializes the joining device's coordinator pin; it is not a proof of
all historical coordinator decisions.

Each revocation records the broker's last CHAT sequence. Historical authenticated
Commits from that revoked signer may be merged up to this cutoff; later Commits are
rejected. All remaining clients process stream history before electing/removing.
Removal, epoch state and exact Commit outbox bytes share a SQLite/OpenMLS transaction.
Crashes retry the same ciphertext. New encryption is blocked while a known revoked
leaf remains; offline groups wait for their coordinator to resume. The service does
not know private group membership and cannot manufacture an MLS removal Commit.

Queued application ciphertext under a known revoked epoch is blocked before
publication or merging removal, and retained locally with a warning. It is not silently
re-encrypted; manually resend needed text after the new epoch is established. Old
plaintext already delivered or published cannot be recalled. The existing single-use
KeyPackage and offline membership-change limitations still apply.

## Security limits and validation

After removal, EpochGrid aims to inherit MLS future-epoch exclusion when correctly
implemented. Revocation does not erase old plaintext, copies of keys or backups.
Before a device learns revocation it can queue old-epoch messages offline; before
rekeying there is no new-epoch secrecy claim. A malicious directory can suppress a
revocation or replay an unchanged old checkpoint to a client that has not observed
it. There is no freshness proof, witness network or global split-view detection.
A compromised authorized same-user device can revoke siblings; the operator can
revoke any enrolled device. Manual fingerprints do not eliminate these authorities.

Automated tests cover unauthorized/tampered requests, signed-log rollback, schema and
MLS transaction rollback, creator succession, reused leaf slots, late creator Commits,
blocked old outboxes, future ciphertext exclusion and restart. Two live NATS cases
cover existing-connection termination, failed reconnect, consumer deletion, surviving
three-device messaging, ciphertext-only storage, idempotent retry, broker/bootstrap
restart, failed enforcement and service restart with durable intent. The real-terminal
three-client workflow also revokes a connected device and verifies automatic rekeying
and continued messaging between the survivors.
