# Linux credentials and encrypted SQLite — Milestones 24–25

EpochGrid stores standalone device and backend credentials in Linux Secret Service.
Homes contain opaque references and independently checked public-key bindings.
There is no plaintext fallback, including in the development transport profile.
Pre-Milestone-25 plaintext homes and registries are unsupported; use fresh state
and enrollment. No migration or automatic reset is provided. Milestone 24 v2
recovery archives remain usable for administration recovery into a fresh encrypted
home; older archive formats remain unsupported.

## Day-one setup

Install/configure a Secret Service provider (GNOME Keyring is exercised by CI) and
configure a password-protected **default collection**, available and unlocked in the session that runs
EpochGrid. Linux desktop logins commonly manage this session. EpochGrid does not
create collections or automatically unlock them: unlock through the OS keyring
manager before retrying a locked-keyring error. A provider may request approval
when creating an item; cancellation/failure is reported and the same five-second
deadline applies. Provision unattended service credentials in advance.

On Debian/Ubuntu, the development/test tooling uses:

```bash
sudo apt-get install dbus-daemon gnome-keyring libsecret-tools
```

These packages alone do not configure an unattended account's session or unlock
policy. A running D-Bus session, Secret Service provider and unlocked default
collection are all required for initialization/enrollment and loading credentials.

Run the ordinary identity initialization/enrollment, CLI, TUI and backend commands
in that session. No credentials need to be copied into seed files or environment
variables. Existing supported homes keep the same identity across process restarts.
`identity show`, offline history and recovery status require the database key
from Secret Service, even when they do not load the NKey. TUI loads its NKey on its dedicated worker before network
retries, so credential failures are shown as startup errors instead of connectivity
failures. Each keyring operation has a five-second deadline.

For headless operation, the operator must provision a persistent Secret Service
session and default collection under the service account, arrange unlocking, and
provide that account's session-bus environment to the process. Run `auth-init` and
`serve-authority` against the same authority keyring. Provision `worker-init` and
run `serve-control` under a distinct Linux account and independent Secret Service
session. Never forward the authority's bus/keyring environment into the worker.
See the [role setup](backend-role-contract.md). An unattended process cannot answer desktop unlock
prompts; missing/locked credentials prevent startup before admission. Containers do
not automatically inherit a host keyring. There is no seed-file alternative or
non-Linux adapter in this milestone.

## Protected material and remaining exposure

| Material | Storage |
| --- | --- |
| Client/device NKey, including restored administration identity | Secret Service; public reference in `identity.sqlite` |
| Backend directory/control NKey | Secret Service; public reference under `control/` |
| Auth Callout account issuer, XKey and connection NKey | Secret Service; typed references in version-2 `auth.json` |
| MLS signing keys, private KeyPackages, group and ratchet secrets, attachment keys | SQLCipher-encrypted SQLite; independent database key in Secret Service |
| Transcripts, membership/trust records, receipt and relationship metadata | SQLCipher-encrypted SQLite; independent database key in Secret Service |
| Explicit encrypted recovery archive and its separate secret file | User-controlled portable recovery material, never an automatic runtime fallback |

`credentials.json` records role-to-item references and initialization progress; it
contains no secret values. Labels/lookup attributes contain an opaque random item
ID and application namespace, not usernames, paths or private keys. Reads validate
key type and public binding; duplicate matches, missing keys and wrong bindings
fail without replacement or fallback. The backend does not silently choose another
collection when the default is unavailable.

Secret Service uses an encrypted D-Bus session. Its provider controls at-rest
protection and unlock/access policy; the API does not attest encrypted persistence.
This is not a claim of hardware backing,
non-exportable keys or isolation from other applications running as the same user.
The unlocked application necessarily holds credentials in memory. Owned secret
buffers are zeroized where practical; libraries may retain copies. A running
process may cache a loaded NKey and SQLCipher key until exit, so locking the keyring is not device
revocation or a guarantee that already-loaded keys have been erased.

Copying only a home does not copy its standalone credentials. A lost keyring cannot
be repaired from public references: restore the appropriate keyring or use the
supported encrypted identity-administration recovery flow, then enroll a fresh
messaging device. A copied database without its key cannot expose MLS private material or history
through ordinary SQLite access. Database backup/recovery is not supplied by the
identity-administration archive: preserve matching database files, metadata and
the keyring through an operator-managed consistent backup if those must survive.

## Encrypted database lifecycle

SQLCipher protects client `identity.sqlite`, backend `auth.sqlite`, and backend
`control/identity.sqlite`, each with an independent random 256-bit key. Keys are
stored only in Secret Service; their public fingerprint and opaque item reference
are recorded in `credentials.json` and `<role>.database.json`. This fingerprint is
not an asymmetric public key. Database metadata is versioned, contains no key,
and is bound to an encrypted record carrying the role and item ID.

Application connections apply their key before schema queries or migrations and
check that SQLCipher is present. A separate unkeyed, read-only format probe rejects
legacy plaintext databases. Database pages and journal/WAL page payloads are encrypted;
temporary SQL tables remain in memory. File names, sizes, timing, public metadata,
and sidecar structure remain observable. Directories/files use 0700/0600. Explicit
attachment saves remain plaintext. This does not protect an unlocked process from
same-user compromise, or cover swap/core dumps, exports or unrelated logs.

A short per-database lock serializes opening/provisioning, separately from the
identity lifetime lock. The key and pending metadata reach durable storage before
SQLite creation. An encrypted binding transaction precedes marking the metadata
ready. Retries reuse that key. Missing metadata for an existing database, missing
keys, wrong bindings, corruption, or a missing/empty established database fail
without reset or replacement. Plaintext databases are rejected unchanged. No key
rotation, automatic key deletion, plaintext conversion or database export is offered.

Keep the entire home/registry metadata with its database. If startup reports a
missing key, restore the original keyring; if it reports missing metadata or a
mismatched database, restore the matching set. Do not delete metadata to force
initialization. Locked/unavailable keyrings must be corrected before retrying.
An open process can retain decrypted state until exit; keyring locking does not
immediately revoke it.

## Interrupted initialization and recovery

Backend `auth-init` validates authentication mode, accounts and R1/R3 before
provisioning, serializes setup/export with `auth-init.lock`, and records the
choices in public `auth-init.json`. Retry interrupted setup with the same options.
Public artifact bundles are staged and atomically published without overwriting
operator edits; `auth.json` is committed last. Completed setup refuses reruns even
when an operator-issued JWT is still pending. Use `deployment-export` to regenerate
artifacts: it resolves existing credential references and control-key binding but
never creates keys, opens databases, or changes `auth.json`. Use [offline validation](operator/validation.md) for non-initializing encrypted-state
inspection, credential bindings and permissions. It uses SQLite read-only snapshots;
SQLite-managed WAL/SHM bookkeeping may change, but application data is not repaired
or migrated.

A per-home lock serializes provisioning. EpochGrid durably records an opaque pending
item reference before writing to Secret Service, verifies the stored value, and
then commits its public binding. A lost create response is resolved by reading the
same item on retry. Once the binding is committed, a missing item is an error; it
is never regenerated. SQLite identity/trust changes remain transactional.

Retry initialization or restore against the same home after correcting a transient
backend error. Restore authenticates the archive before opening the destination and
accepts only a fresh or interrupted-restore home; existing identities/trust are never
overwritten. Interrupted operations may retain a pending keyring item and public
metadata for retry. No automatic keyring deletion/garbage collection is performed,
so cleanup cannot accidentally remove a key used by another supported home. If
abandoning an installation, keep its metadata until any manual keyring cleanup is
complete. Deleting a home alone does not delete its keyring entries.

## Verification

```bash
./scripts/dev/verify.sh unit
./scripts/dev/verify.sh build
./scripts/dev/verify.sh secrets
./scripts/dev/verify.sh nats
```

`verify.sh` wraps credential-using tests in a fresh D-Bus session and disposable
GNOME keyring with a random password supplied over stdin. The test wrapper isolates
XDG data/config/runtime directories and never uses the caller's login keyring.
The standalone failure-state tests use an in-memory backend; existing identity
and process-restart tests use the real isolated provider. The `secrets` phase also
checks lock/duplicate errors and real CLI/backend initialization and recovery, and
scans owned files for known NKey/XKey and raw/encoded database-key values.
Database tests cover unkeyed/wrong-key access, encrypted WAL/journals, crash
recovery, provisioning failure and preservation of existing state. Missing fixture dependencies fail the
phase rather than silently skipping coverage.

Compose smoke copies its fixture into a temporary root and uses a distinct Compose
project; it no longer uses or stops the developer's `.dev` stack. It still needs
host port 4222 to be available. Normal development bootstrap keeps using `.dev`
and the operator's real keyring. Never use the disposable test wrapper to create
identities you intend to keep: its keyring is deleted when the wrapped command exits.

TD-001/TD-002 remain deferred; passing storage checks does not certify the full
quarantined dynamic messaging lifecycle.

## Design references

The [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)
provides the interoperability contract. [Lookup attributes](https://specifications.freedesktop.org/secret-service/latest/lookup-attributes.html)
are not secrets, [locking may change at any time](https://specifications.freedesktop.org/secret-service/latest/unlocking.html),
and the API [does not mandate application access control](https://specifications.freedesktop.org/secret-service/latest/ch10.html).
The Rust adapter uses [`secret-service` 5.2](https://docs.rs/secret-service/5.2.0/secret_service/)
with Tokio and Rust cryptography; the exact dependency resolution is in Cargo.lock.

Online validation uses the same non-initializing local inspection before resolving
existing auth-service and control credentials for bounded broker inspection. It
never opens another Auth Callout listener or creates credentials. Production
startup also requires successful local validation before bootstrap; resource
compatibility and health then gate device admission. See
[deployment validation](operator/validation.md).
