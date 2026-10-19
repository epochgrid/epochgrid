# Linux credential storage — Milestone 24

EpochGrid stores standalone device and backend credentials in Linux Secret Service.
Homes contain opaque references and independently checked public-key bindings.
There is no plaintext fallback, including in the development transport profile.
Pre-Milestone-24 homes, backend configurations and recovery archives are unsupported;
use fresh state and enrollment. No migration or automatic reset is provided.

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
`identity show`, offline history and recovery status can inspect public/local state
without loading the NKey. TUI loads its NKey on its dedicated worker before network
retries, so credential failures are shown as startup errors instead of connectivity
failures. Each keyring operation has a five-second deadline.

For headless operation, the operator must provision a persistent Secret Service
session and default collection under the service account, arrange unlocking, and
provide that account's session-bus environment to the process. Run `auth-init` and
`serve` against the same keyring. An unattended process cannot answer desktop unlock
prompts; missing/locked credentials prevent startup before admission. Containers do
not automatically inherit a host keyring. There is no seed-file alternative or
non-Linux adapter in this milestone.

## Protected material and remaining exposure

| Material | Storage |
| --- | --- |
| Client/device NKey, including restored administration identity | Secret Service; public reference in `identity.sqlite` |
| Backend directory/control NKey | Secret Service; public reference under `control/` |
| Auth Callout account issuer, XKey and connection NKey | Secret Service; typed references in version-2 `auth.json` |
| MLS signing keys, private KeyPackages, group and ratchet secrets, attachment keys | Still in unencrypted SQLite; Milestone 25 |
| Transcripts, membership/trust records, receipt and relationship metadata | Still in unencrypted SQLite; Milestone 25 |
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
process may cache a loaded NKey until exit, so locking the keyring is not device
revocation or a guarantee that already-loaded keys have been erased.

Copying only a home does not copy its standalone credentials. A lost keyring cannot
be repaired from public references: restore the appropriate keyring or use the
supported encrypted identity-administration recovery flow, then enroll a fresh
messaging device. A copied SQLite database still exposes MLS private material and
history until Milestone 25; this milestone is not complete local-state encryption.

## Interrupted initialization and recovery

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
scans owned files for known NKey/XKey values. Missing fixture dependencies fail the
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
