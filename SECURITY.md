# Security policy

EpochGrid is an unaudited development prototype. Do not use it for sensitive or
production communications. Supported development work targets the current main
branch; no stable security-supported release exists yet.

Report vulnerabilities privately using GitHub's “Report a vulnerability” facility
on the affected repository in https://github.com/epochgrid when enabled. If it is
unavailable, contact an organization maintainer privately to arrange disclosure;
do not post exploit details or secrets in public issues. No dedicated security
email or response-time commitment has been established.

Never attach NATS seeds, credentials, recovery secrets/packages, SQLite databases
or real private messages.
Local SQLite now retains unencrypted message history as well as private keys.
See [the threat model](docs/threat-model.md) for implemented boundaries and gaps.

The Milestones 0–10 MVP has automated acceptance coverage for the two-device flow,
ciphertext storage and restart recovery. Passing it does not constitute a security
audit or change the prototype's deployment status. See the
[acceptance evidence and limits](docs/mvp-acceptance.md).

The Milestone 11 terminal client does not change production readiness or key
storage. Its offline queue and visible history retain the same local plaintext
storage exposure. Unread indicators are local UI state, not secure read receipts.


Milestone 12 supports independent device leaves for the same logical user. A
compromised device exposes its own local state and can impersonate that device;
collapsing user labels does not make devices share keys. Enrollment is still trusted
to the operator/directory for initial authorization. Milestone 13 adds manual
verification, key-change detection and a bounded authenticated log. Milestone 14 adds signed revocation and MLS removal. A new device receives a Welcome for its join
epoch, not prior history. Earlier framed traffic is skipped without authentication
because the new device has no historical keys. Creator Commits are authenticated and
merged atomically with local progress. Offline ciphertext from before a membership
change may be undecryptable afterward. Transport suppression/reordering and group
permission wildcards remain availability/metadata limitations. Revocation does not provide historical erasure. See [multi-device boundaries](docs/multi-device.md).


Milestone 13 retains device fingerprints and a signed Merkle prefix checkpoint.
Manual verification requires an independently obtained complete fingerprint;
changed observed keys are sticky and block audited discovery/invitation/join.
Checkpoint rollback, prefix rewriting and signer changes are rejected. First contact
uses TOFU unless the operator key is pinned independently. No gossip/witness network,
freshness proof or global split-view detection is provided. A compromised signer can
append dishonest new identities; local database loss discards observed evidence.
The log and fingerprints do not prove human identity or retroactively verify every
existing MLS leaf. TUI audit failures are prominent; local transcripts remain
readable. The service still cannot read application plaintext. See [verification security boundaries](docs/device-verification.md).


Milestone 14 records signed revocation intent before native NATS credential removal
and durable-consumer deletion. A successful response confirms network enforcement;
offline MLS groups advance when their coordinator returns. Updated clients block new
encryption with known revoked leaves and block queued old-epoch application ciphertext.
A revoked coordinator is replaced deterministically, with signing-key authority pinned
across leaf-slot reuse. Remaining members process MLS removal Commits and advance epochs.
Neither removal nor network exclusion erases historical plaintext or endpoint backups.

The service now holds a restricted system-account reload NKey and controls one broker's
public authorization include. It remains unable to derive group secrets. An administrator
can defeat NATS exclusion; post-removal confidentiality relies on MLS. An active same-user
device or directory operator can authorize revocation. Signed revocation checkpoints
retain rollback evidence but do not prove freshness or prevent withheld revocations and
isolated split views. See [revocation design, upgrade and limitations](docs/device-revocation.md).


Milestone 15 adds encrypted identity-administration recovery. Possession of both
archive and secret exposes the original NKey and its still-authorized network/control
privileges, including same-user revocation. It exposes no MLS private keys, epoch
secrets or transcript. Restored homes cannot chat; replacement devices need normal
operator enrollment and fresh invitations. Revoked credentials stay revoked.

Recovery preserves trust evidence only as of export time. A valid older archive
cannot be detected as stale offline. The service cannot decrypt the package, but
endpoint compromise, co-located secret/package storage, swap and crash dumps remain
risks. Keep recovery secrets outside the device and apart from archives. Local
restored state is unencrypted development SQLite; no hardware-keystore or guaranteed
secure-erasure claim is made. See [recovery boundaries](docs/encrypted-recovery.md).
