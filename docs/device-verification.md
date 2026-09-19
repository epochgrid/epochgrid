# Device verification and transparency — Milestone 13

Current deployment and milestone status: [status index](milestones.md). Local
plaintext examples require `EPOCHGRID_PROFILE=development`; the complete messaging
walkthrough still uses development fixtures. See [production TLS](operator/tls.md)
for secure transport and the remaining dynamic-deployment limits.

Each installation retains observed device fingerprints, manual verification state,
and a signed Merkle checkpoint for the registration directory. These controls detect
changes within that installation's observed history. They do not prove ownership of
a human identity or make the directory globally trustworthy.

## Upgrade and use

Close clients and stop the identity service before upgrading. Preserve local SQLite
files and the NATS volume. Re-run `scripts/dev/bootstrap-nats.sh` to build binaries
and update permissions, then restart `epochgrid-service`. The service imports existing
immutable registrations into TRANSPARENCY KV; SQLite migration 2 adds trust/checkpoint
state without deleting identities, groups, ratchets or transcripts. New clients require
the updated service and fail closed on audited discovery if it is unavailable or old.
Older clients still understand existing wire operations but lack these protections;
upgrade all clients and do not reopen migrated databases with old binaries.

For stronger first-contact trust, obtain the service's **public** NKey independently
from the operator. The operator can read it with `epochgrid --home .dev/service
identity show` while the service is stopped. Before first discovery on each device:

```bash
./target/debug/epochgrid --home .dev/alice transparency pin 'U...'
```

Substitute the full service public key. Without this step, the first successfully
validated checkpoint pins its signer by trust-on-first-use. Replacing an existing
pin is refused. `transparency status` shows the retained signer, root and size, or
an independently pinned signer awaiting its first checkpoint.

Bob displays his own fingerprint locally; this command does not need NATS:

```bash
./target/debug/epochgrid --home .dev/bob device fingerprint
```

Alice discovers Bob's fingerprint, compares all 64 hexadecimal digits through an
independent channel, then explicitly supplies the independently obtained value:

```bash
./target/debug/epochgrid --home .dev/alice device fingerprint bob laptop
./target/debug/epochgrid --home .dev/alice device verify bob laptop --fingerprint 'FULL FINGERPRINT FROM BOB'
./target/debug/epochgrid --home .dev/alice device list bob
./target/debug/epochgrid --home .dev/alice transparency audit
./target/debug/epochgrid --home .dev/alice transparency status
```

`identity verify bob --device laptop --fingerprint '...'` is an equivalent command.
Whitespace and hexadecimal letter case are ignored during comparison; shortened
fingerprints are rejected. Reading a value from the same directory and echoing it
back is not independent verification. Each device must be verified separately.
Close a device's TUI before running CLI commands on its home; the file lock remains.

Observed devices start `unverified`; successful manual comparison marks `verified`.
A changed observed identity becomes `changed`, even if it was never manually verified.
The old fingerprint is retained, the new fingerprint is recorded, and audited
lookup/invitation/join fails. The warning survives restart and is prominent in the
TUI. Inspect both values without contacting the directory:

```bash
./target/debug/epochgrid --home .dev/alice device fingerprint bob laptop --offline
```

Changed identities remain blocked even if the old identity reappears. There is no
silent replacement, reset command or replacement-authorization workflow in this
milestone. Keep the evidence and investigate with the operator; do not delete the
local database to suppress a warning. Milestone 14 adds [revocation](device-revocation.md) as a separate authorization
state; identity replacement remains unimplemented.

## Fingerprint construction

Fingerprint v1 is SHA-256 of ASCII `EpochGrid device fingerprint v1` plus NUL,
followed by postcard serialization of this tuple in order:

1. registration protocol version (`u16`);
2. user ID and device ID (`String` each);
3. NATS public key (`String`);
4. TLS-serialized MLS credential (`Vec<u8>`);
5. MLS signing public key (length-prefixed byte sequence).

The NKey signature binds these values in the registration. MLS keys remain independent
of NATS keys. The display uses all 32 digest bytes, uppercase hexadecimal grouped in
fours. Timestamp, generation and HPKE KeyPackage bytes are excluded so eventual
package refresh alone does not change the identity fingerprint. Full OpenMLS package
validation still gates admission and actual invitation/discovery. Historical audit
checks the NKey-signed immutable record rather than requiring a historic package to
remain unexpired; fingerprint extraction uses OpenMLS's `unverified_credential`
only after validating the enclosing NKey signature and credential-byte match.
Package replenishment itself is not implemented by this milestone.

## Authenticated append-only history

Log order assigns a registration sequence number starting at 1. Leaf hashes are
SHA-256(0x00 || canonical v1 Register envelope). Internal nodes hash 0x01 || left ||
right; the split is the largest power of two below the leaf count. The empty tree
hashes the empty byte string. This is the [RFC 6962 Merkle construction](https://www.rfc-editor.org/rfc/rfc6962#section-2.1),
not a claim of Certificate Transparency protocol compatibility.

The service signs a domain-separated checkpoint containing version, leaf count,
root and service public NKey using its existing NKey. It has no MLS group secrets.
Clients validate checkpoint/device signatures, entry count, unique endpoints/NKeys,
and Merkle root. Every later checkpoint must use the pinned signer, have at least
as many leaves, and reproduce the retained root over its first previous-size leaves.
A full public snapshot therefore supplies inclusion and prefix evidence. Audited
CLI lookup/listing and invitations use this log, so a mutable IDENTITIES projection
cannot silently substitute their public identity. KeyPackage claim responses must
match the audited registration before group addition. Legacy raw directory APIs
remain for protocol compatibility; their responses alone are not transparency proofs.

One compare-and-swap update to `TRANSPARENCY/snapshot` atomically publishes the full
log and checkpoint. Conflicting writers re-read and retry; exact registration retries
are idempotent. IDENTITIES is updated afterward. Startup imports pre-log registrations
and repairs a missing directory projection from the log. A conflicting projection
or signer fails rather than being overwritten. Historical registrations remain
immutable. First startup establishes a baseline; it cannot reconstruct a pre-upgrade
history that was never recorded. Importing a previously unlogged registration
requires a currently valid KeyPackage; already-logged historical records can be
audited and projected after expiry without making that package usable again.

This first-generation log is bounded to **65,536 encoded bytes and 256 entries**,
whichever is reached first; transport overhead can impose a slightly lower practical
limit. Admission fails without discarding old entries when it cannot append. There
is no pruning, pagination, compact proof API, witness service, signer rotation or
scalable deployment claim. Full snapshots are a deliberate small-alpha tradeoff for
atomic persistence and independently verifiable prefixes. NATS KV stores public
registrations and commitments only. Clients cannot directly read/write this bucket;
its request/reply audit API exposes only the public snapshot.

## Security boundaries

An unchanged old checkpoint can be replayed: no freshness or availability guarantee
is provided. A malicious first view or isolated split views across installations
cannot be detected without independent comparison/gossip. A compromised log signer
can append dishonest new identities, though it cannot change a retained prefix
without detection by a client retaining that checkpoint. Manual fingerprints and
independent service-key pinning address different first-contact trust decisions.
No global transparency network, account ownership proof or erasure of historical
plaintext is implemented. Revocation is covered by Milestone 14. Removing local trust state loses evidence.

The TUI audits during network polling; failures are persistent, visible and block
that polling cycle until corrected. A successful audit clears a transient audit
warning, but never clears changed-device state. Existing local history stays visible
and offline composition remains possible. Milestone 14 also audits revocations in the online scripting chat/message path
and reconciles revoked MLS leaves before new encryption. Creator membership
policy and MLS authentication remain the group boundary. NATS metadata and local
unencrypted private state/transcripts have the same exposure as before.

## Validation

The unchanged Cargo gates, five NATS cases and three-device terminal workflow passed
before edits. New unit tests exercise stable fingerprints across package refresh,
manual comparison, MLS-key substitution, sticky verification persistence, Merkle
prefixes/signatures, rollback and transactional schema migration. Live tests cover
legacy import, projection repair, signed truncation/reordering/signer replacement,
malicious projection and log substitution, explicit CLI verification, competing CAS
appends and idempotent registration. Existing ciphertext, restart and terminal tests
remain in CI. Public transparency snapshot payloads join the plaintext/seed scans.
