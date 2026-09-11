# Threat model

EpochGrid is designed to protect application message content from network
observers, NATS servers, JetStream compromise and infrastructure administrators.
The implemented two-device flow uses OpenMLS encryption. The fresh CLI acceptance
test verifies MLS PrivateMessage framing in CHAT and checks four known plaintext
markers and both client NKey seeds are absent from every stream payload, subject
and header, stopped broker/service files, and the captured service log. This is evidence for that tested
path, not a production security audit or proof for every possible execution.

The project aims to inherit MLS forward secrecy and post-compromise security when
correctly implemented, including exclusion of removed members from future epochs.
Milestone 14 implements removal and tests future-epoch exclusion. Explicit key
updates and comprehensive post-compromise lifecycle security testing remain pending.

Implemented boundaries include independent NATS/MLS keys, NKey network
authentication, signed registration and operator enrollment, verified discovery,
one-use KeyPackage reservation, authenticated Welcome senders, encrypted MLS
application/Commit traffic, device-specific mailbox consumption, transactional
local state and replay suppression. The identity service is trusted for enrollment
and metadata, but not message confidentiality. A signature proves key possession,
not human identity. Milestone 13 adds the bounded directory protections described
below; first contact and cross-client split views remain significant limitations.

Not hidden: subjects, timing, sizes, connection metadata, usernames, group names
inside MLS group IDs, public credentials/KeyPackages, or traffic analysis.
The local Compose setup has no TLS and binds loopback. NKeys do not encrypt
transport. Configure TLS and trust roots before any remote deployment.

Development group permissions use namespace wildcards, so enrolled devices can
observe unrelated lab ciphertext or inject invalid traffic. MLS rejects invalid
content; transport authorization does not yet enforce exact membership. Clients
can publish to peer inboxes but cannot read them. A malicious enrolled client can
reserve a peer's initial KeyPackage or block its mailbox with unwanted traffic.
Availability and request flooding are not protected in this slice.

Endpoint compromise can expose private keys and the retained plaintext transcript.
MLS key erasure does not erase the separately retained local plaintext history.
SQLite and journals are unencrypted; Unix directories/files use 0700/0600 and an OS file lock.
Use a dedicated private directory on a trusted filesystem. Windows ACL integration
is not implemented. Future adapters should support Linux Secret Service, macOS
Keychain/Secure Enclave, Windows CNG/TPM and mobile secure keystores.

Local transactions couple OpenMLS changes to the ciphertext outbox and deduplication
markers. These are not distributed transactions. Outbox retries can duplicate a
publish beyond NATS's deduplication window; recipients suppress exact copies.
Milestone 8 stages ciphertext before a confirmed ACK and atomically commits the
receive ratchet, transcript and local delivery marker. Lost ACKs, storage failures,
ordered replay, duplicate packets and restart are covered by targeted tests.
Invalid/undecryptable packets are retained in local quarantine so they cannot
block valid history. Other groups' ciphertext remains staged until explicitly
processed; it inherits the existing shared lab visibility and storage/DoS risks.

Transcripts and a local undisplayed queue survive restart. A crash between output
and its local display marker may repeat terminal output, but history is retained.
There is no distributed exactly-once display guarantee. Milestone 7 clients did not
retain plaintext, and their already-consumed messages are shown as unavailable.
Broker retention/deletion, complete power-loss fault injection and retention quotas
remain limitations; Milestone 12 adds ordered catch-up across membership additions. Backups
restoring old ratchet state are not safe recovery. No exactly-once delivery or comprehensive crash-safety claim is
made. Key rotation and package replenishment/expiry remain open. Milestone 15
recovers control credentials and trust metadata without restoring old ratchets.

Milestone 10's [acceptance matrix](mvp-acceptance.md) records the completed MVP
checks. A plaintext-marker scan is a regression detector, not proof of semantic
security or absence of every possible key leak. It does not detect arbitrary
transformed/encoded leaks or audit memory, side channels, dependency vulnerabilities
or remote deployments. Tests do not claim to hide public identity metadata, prove
forward secrecy/post-compromise recovery, or protect an already compromised device.

Milestone 11's TUI retains the same cryptographic and authorization boundaries.
Offline sends persist ciphertext and the existing unencrypted local transcript;
uncommitted composition is volatile. Incoming terminal control bytes are escaped,
and bracketed paste does not execute commands automatically. Normal tracing output
is disabled in TUI mode to avoid leaking content or corrupting terminal rendering;
operation errors and quarantined-delivery counts are shown in the UI. Local unread
indicators describe channel navigation, not remotely authenticated reading.


Milestone 12 supports independent device leaves for the same logical user. A
compromised device exposes its own local state and can impersonate that device;
collapsing user labels does not make devices share keys. Enrollment is still trusted
to the operator/directory for initial authorization. Milestone 13 adds manual
verification, key-change detection and a bounded authenticated log. Milestone 14 adds signed revocation and MLS removal. A new device receives a Welcome for its join
epoch, not prior history. Earlier framed traffic is skipped without authentication
because the new device has no historical keys. Creator Commits are authenticated and
merged atomically with local progress. Offline ciphertext from before a membership
change may be undecryptable afterward. Transport suppression/reordering and group
permission wildcards remain availability/metadata limitations. Revocation does not provide historical erasure. See [multi-device boundaries](multi-device.md).


Milestone 13 retains device fingerprints and a signed Merkle prefix checkpoint.
Manual verification requires an independently obtained complete fingerprint;
changed observed keys are sticky and block audited discovery/invitation/join.
Checkpoint rollback, prefix rewriting and signer changes are rejected. First contact
uses TOFU unless the operator key is pinned independently. No gossip/witness network,
freshness proof or global split-view detection is provided. A compromised signer can
append dishonest new identities; local database loss discards observed evidence.
The log and fingerprints do not prove human identity or retroactively verify every
existing MLS leaf. TUI audit failures are prominent; local transcripts remain
readable. The service still cannot read application plaintext. See [verification security boundaries](device-verification.md).


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
isolated split views. See [revocation design, upgrade and limitations](device-revocation.md).


## Encrypted recovery compromise

An encrypted recovery package contains the original device NKey and public
identity/trust metadata. Anyone obtaining the package and its separate random secret
can exercise that credential’s remaining fabric/control privileges, including
same-user revocation. The package omits all private MLS keys, group epochs, ratchets,
message history and private KeyPackages; it does not itself decrypt past or future
chat. The service and storage operators receive neither recovery secret nor plaintext.
Package size, file existence and any external storage metadata remain observable.

Recovered homes are explicitly administration-only. Fresh messaging devices need
independent keys, operator enrollment and re-invitation. Old-device revocation must
still be performed and cannot be undone by restoring an earlier export. If every
member’s MLS state is lost, the old group and its history cannot be recovered. No
claim is made that restoring a control credential proves the original endpoint was
destroyed, erases its plaintext, or establishes human account ownership.

The encrypted snapshot preserves directory pins, verified/changed fingerprints,
revocation evidence and warnings at export time. Later observations are lost; a
valid old package cannot prove freshness. Prefix checks retain their existing limited
rollback detection. A replacement messaging home starts with independent trust state;
use the recovered fingerprints and directory pin to verify it before invitations.
Secret files must be stored separately and protected by the user. Filesystem permissions,
zeroization of owned secret buffers and AEAD authentication do not protect a compromised
endpoint, swap or library/runtime copies. Tests cover wrong secrets, corruption,
transaction rollback, no MLS-state restoration, fresh-device messaging and continued
NATS revocation. They do not establish production readiness.


Milestone 16 protects attachments with client-side AES-256-GCM and puts the key,
filename, MIME and plaintext hash inside MLS. Object Store sees random names,
ciphertext, sizes, timing and ciphertext digests. A holder of an MLS-protected
manifest is an intentional attachment recipient. Revocation prevents future fabric
access but cannot erase already saved files, ciphertext copies or known DEKs.
Client expiration is an availability policy, not cryptographic timed erasure.

Local SQLite retains manifest DEKs unencrypted; explicitly saved files are plaintext.
Recovery excludes both attachment keys and files. No automatic download, path derived
from a received filename, execution or preview is performed. Authenticating a file
proves byte integrity, not that a member-supplied file is safe to open. Shared lab
Object Store permissions allow active devices to observe ciphertext and corrupt or
fill the bucket; availability, per-object authorization and malware scanning are not
implemented. Native bucket retention/capacity and bounded transfers limit ordinary
resource use. All clients must be upgraded to render binary manifests safely.
See [attachment boundaries and validation](attachments.md).


Milestone 17 typing events use signed MLS-exporter encryption over Core NATS.
NATS sees routing, epoch, sender leaf index, timing and size, but not event contents.
No ephemeral event is stored in JetStream or SQLite. Unlike durable MLS messages,
these events have no per-event forward secrecy: compromise of an epoch exporter
secret exposes recorded events from that epoch. Signatures authenticate individual
current leaves. Revocation checks and epoch changes reject removed senders; offline
clients must first learn revocation. Activity expires within eight seconds, and is
advisory; bounded replay within that freshness window after restart remains possible.


Milestone 18 receipts are signed MLS-exporter-encrypted device claims over Core
NATS, inheriting the ephemeral transport's epoch-scoped secrecy and metadata
leakage. A read claim means client presentation, not proof of human attention;
a malicious group member can lie about delivery or reading. Unknown receipts
cannot create messages. Local compact receipt metadata is unencrypted and excluded
from recovery. Loss or non-overlapping online sessions can leave state unknown.
Previously observed receipts survive revocation as historical claims, not evidence
of current authorization. See [receipt semantics](receipts.md).
