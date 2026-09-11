# Encrypted recovery — Milestone 15

Recovery exports a device's NATS control credential and public identity/trust
metadata to a client-encrypted file. It deliberately excludes every MLS private
key, KeyPackage private bundle, group epoch, ratchet, pending delivery and message
transcript. A restored installation is marked **recovery-only**: it can inspect
identity evidence, audit the directory and authorize same-user revocations while
its recovered NKey remains authorized. It cannot chat, create groups or consume
Welcomes. This is identity-administration recovery, not an MLS database backup.

## Why this boundary

The alpha's immutable registration log binds each device to one single-use
KeyPackage. Restoring a stale database could reuse sending ratchets or an already
consumed KeyPackage. Replacing the package silently would conflict with pinned
identity history. Instead, resuming messaging requires a new device ID, independently
generated NATS and MLS keys, ordinary operator enrollment, and a fresh MLS invitation.
Existing active members/coordinators perform removal and re-invitation. Revocation
is irreversible; a recovery file cannot resurrect a revoked credential. If all
credentials are revoked, the operator must authorize the replacement. If no group
members survive, the group cannot be recovered; create a new group.

## Package and secret

The file format is independently versioned: an authenticated fixed header identifies
EpochGrid recovery v1 and AES-256-GCM, followed by a random 96-bit nonce and AEAD
ciphertext with its 128-bit tag. All account metadata, timestamps, group hints and
trust evidence are encrypted. Each export generates an independent uniform 256-bit
secret using the existing OpenMLS RustCrypto random provider. The secret is encoded
as `EG1-` followed by 64 hexadecimal digits. This is not a password or mnemonic;
there is no password input and no password KDF. The random secret is used directly
as the AEAD key, exclusively for this package. Header bytes are associated data.
Encryption uses the existing OpenMLS RustCrypto AES-GCM implementation.

The CLI writes the secret to a separate, new private file and never prints it or
accepts it as an argument/environment value. Store the secret separately from the
package, preferably in a password manager or offline medium. Export refuses to
overwrite either path. Package inputs are bounded before decoding. Decryption and
validation must succeed before any identity state is restored, and restoration is
transactional into an uninitialized store. Migration 4 adds recovery metadata while
preserving existing identities, groups and transcripts.

## Security semantics

Possessing both files grants the original NKey's network/control authority, including
same-user revocation while still active. It grants no MLS decryption or signing
keys. Recovery does not erase an old endpoint or prove it was destroyed. Retire the
lost device through the existing revocation workflow after enrolling a replacement;
retain another active device/operator to confirm self-revocation. Never deploy two
normal messaging clients by copying a live SQLite database.

Trust fingerprints, sticky changed-key evidence, directory/revocation checkpoints
and cached revocations survive as of export time. Changes observed after that export
are not recovered. A valid older encrypted file cannot be detected as stale offline;
retained checkpoints detect only history older than those checkpoints. Audit online
before relying on identity information. Recovery does not add freshness proofs,
rollback-resistant hardware or global transparency witnesses.

The service has neither recovery secrets nor a recovery API. Users may keep the
opaque encrypted file in untrusted storage; this milestone does not provision an
Object Store bucket. Package size is observable. Local restored NKeys remain in
unencrypted development SQLite. In-memory secret buffers are zeroized where owned;
this is not a guarantee against swap, crash dumps or library/runtime copies.

## Commands and replacement workflow

Stop the process using Alice's home before export. These commands write no secret
to stdout or argv. Use new output paths; move the secret to separate protected
storage before relying on the archive. Keep the encrypted package outside the
installation that might be lost.

```bash
./target/debug/epochgrid --home .dev/alice recovery export \
  --output alice.egrecovery --secret-file alice.egsecret
```

After the original installation has actually been lost, restore to an empty home.
Do not delete a working home to test recovery; use a temporary directory instead.
For the built-in Compose lab, restoring to the lost `.dev/alice` path also preserves
the public Alice/laptop binding expected by bootstrap. Do not let bootstrap generate
a different Alice/laptop identity before restoring.

```bash
./target/debug/epochgrid --home .dev/alice recovery restore \
  --input alice.egrecovery --secret-file alice.egsecret
./target/debug/epochgrid --home .dev/alice recovery status
./target/debug/epochgrid --home .dev/alice transparency audit
./target/debug/epochgrid --home .dev/alice transparency status
./target/debug/epochgrid --home .dev/alice device fingerprint bob laptop --offline
```

Restore authenticates before opening the home. It refuses a nonempty directory;
core restoration also rejects existing identity/trust/message state. After an I/O
failure inspect the destination; use another empty home if no restore committed.
A crash while writing two output files can leave incomplete files. Keep the previous
backup, verify a new package with a restore into a separate temporary home, and use
new output filenames on retry. File sync is used, but no filesystem power-loss
atomicity across the pair is claimed. Windows users must secure directories with
appropriate ACLs; automated 0600 enforcement is Unix-specific.

For messaging, initialize an independent replacement and record its public NKey:

```bash
./target/debug/epochgrid --home .dev/alice-replacement device add alice --device replacement
```

The operator then stops clients/service, adds the printed PUBLIC binding, bootstraps
the existing fabric without deleting state, and restarts the service:

```bash
./target/debug/epochgrid dev-config --root .dev \
  --enroll 'alice/replacement=PUBLIC_NKEY_PRINTED_ABOVE'
./scripts/dev/bootstrap-nats.sh
./target/debug/epochgrid-service
```

The replacement is a new trust domain. Pin its directory signer using the retained
signer shown by the recovered home's `transparency status`, then register it. Compare
Bob's fingerprint to the independently retained value from the recovered home (or
compare with Bob directly). Do not take the comparison value from a fresh, unverified
lookup on the replacement itself.

```bash
./target/debug/epochgrid --home .dev/alice-replacement transparency pin PUBLIC_DIRECTORY_NKEY
./target/debug/epochgrid --home .dev/alice-replacement identity register
./target/debug/epochgrid --home .dev/alice-replacement device verify bob laptop \
  --fingerprint 'FULL_RETAINED_BOB_FINGERPRINT'
./target/debug/epochgrid --home .dev/alice-replacement device revoke alice laptop
```

If no directory pin/fingerprint was retained, ordinary first-contact trust and manual
verification rules apply. A changed-key warning in the recovered home requires
investigation; creating a fresh home must not be used to dismiss that evidence.
If the archived NKey is already revoked, local restore/status still works but NATS
will refuse it. The operator can enroll a replacement without that credential.

In the original Alice/Bob group, Bob becomes coordinator when the lost Alice leaf
is removed. With Bob's original home intact:

```bash
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob channel invite engineering alice --device replacement
./target/debug/epochgrid --home .dev/alice-replacement channel join --from bob
./target/debug/epochgrid --home .dev/alice-replacement tui
```

Bob should independently verify the new Alice device fingerprint before inviting it.
The new leaf receives future messages, not the old transcript. The single-use
KeyPackage limit remains: a device currently accepts one group invitation. Recovery
does not promise automatic rejoining of every hint in an archive. The surviving
coordinator may be a different device in larger groups; use `channel members` and
the existing coordinator rules. Group hints in `recovery status` are informational.

## Acceptance evidence

The automated CLI/NATS test exports an Alice home with history and verified Bob
identity, deletes it, restores its NKey and evidence, and uses that credential for a
real signed same-user revocation. It then enrolls a fresh device, revokes the lost
leaf, processes MLS rekeying, re-invites Alice and exchanges two-way ciphertext after
reopening both homes. A second restore of the old archive still fails NATS reconnect
after revocation. Stream payloads and stopped broker/service files contain neither
recognizable message plaintext nor recovery secret/client seed. The archive scan
also excludes known plaintext. These are regression tests, not a cryptographic audit.

Unit tests cover AEAD tampering, wrong secrets, format/version/size limits, atomic
restore rollback, schema migration, overwrite refusal, private file modes, absence
of restored MLS signer/group state, expired public KeyPackages, retained sticky
key-change warnings, and registration/revocation prefix rollback checks.
