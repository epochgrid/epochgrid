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
Removal, explicit key updates and those lifecycle security tests are not implemented.

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
made. Rotation/revocation, package replenishment/expiry and recovery remain open.

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
verification, key-change detection and a bounded authenticated log; revocation
remains unimplemented. A new device receives a Welcome for its join
epoch, not prior history. Earlier framed traffic is skipped without authentication
because the new device has no historical keys. Creator Commits are authenticated and
merged atomically with local progress. Offline ciphertext from before a membership
change may be undecryptable afterward. Transport suppression/reordering and group
permission wildcards remain availability/metadata limitations. No revocation or
historical erasure guarantee is added. See [multi-device boundaries](multi-device.md).


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
