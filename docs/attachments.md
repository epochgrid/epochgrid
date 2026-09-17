# Encrypted attachments — Milestone 16

Current deployment and milestone status: [status index](milestones.md). Local
plaintext examples require `EPOCHGRID_PROFILE=development`; the complete messaging
walkthrough still uses development fixtures. See [production TLS](operator/tls.md)
for secure transport and the remaining dynamic-deployment limits.

Clients encrypt each file with a fresh random AES-256-GCM key and nonce before
uploading to NATS Object Store `ATTACHMENTS` (`OBJ_ATTACHMENTS`). Object names are
random 128-bit IDs; descriptions, filenames, MIME types and keys never enter public
Object Store metadata. An MLS application payload carries a versioned manifest:
object ID, filename, MIME type, sizes, expiration, SHA-256 plaintext hash, key and
nonce. The AEAD associated data binds the object ID and MLS group routing ID.

Existing unframed chat text stays compatible. Attachment manifests reserve a binary
prefix beginning with 0xff, which cannot collide with normal UTF-8 CLI text. New
clients render a safe attachment summary instead of binary payload/key material.
Older clients cannot render attachments and must be upgraded before receiving them.
Migration 5 adds a local attachment manifest index, written in the same transaction
as outgoing/received MLS state and transcript. The index permits explicit downloads
after restart without re-decrypting old MLS messages. Manifests/DEKs are plaintext
local SQLite state and are excluded from encrypted recovery exports.

The sender catches up membership before upload, encrypts/uploads bounded file bytes,
then catches up again and queues the manifest through the existing transactional MLS
outbox. Failed upload sends no manifest. A failure after upload may leave orphan
ciphertext; bucket retention bounds its lifetime. A committed manifest retries with
its original MLS ciphertext. Transfers require a connection; attachment upload is
not an offline file queue. No plaintext attachment cache or automatic downloads exist.

Downloads require a manifest from the selected group's authenticated local history.
Object metadata is untrusted: reject links, wrong bucket/name, invalid chunk IDs,
size/count mismatches and expired manifests. Read a bounded number of chunks with
bounded total bytes and a wall-clock deadline, then verify AEAD and the protected
content hash before opening an output file. The user supplies an explicit output
path; received filenames never select filesystem paths. Saving refuses overwrite.

The installed async-nats 0.50 Object::poll_read unwraps consumer errors and get()
follows object links. Download instead uses standard Object Store metadata and
JetStream get_first_raw_message_by_subject to read its chunks. This retains the NATS
Object Store format while returning errors on missing chunks or denied access.
No per-download consumers or broad consumer-management permissions are required.
Upload chunks are 32 KiB to fit the existing 64 KiB NATS max_payload.

The development authorization scope remains a shared lab: active devices may publish
ciphertext chunks/opaque metadata and read ciphertext in ATTACHMENTS, but cannot
create/delete/purge streams or change retention. A malicious enrolled client can
corrupt objects, consume capacity and deny availability. MLS-protected keys and AEAD
provide confidentiality/integrity, not availability or protection from malicious
members intentionally distributing files. Revocation removes the old NKey's access;
previous recipients retain downloaded plaintext and DEKs. Expiration is not erasure
of copies and cannot revoke a recipient's prior attachment knowledge.


## Upgrade and commands

Stop all clients and the service, rebuild, run `./scripts/dev/bootstrap-nats.sh`,
and restart the service/clients. Preserve `.dev/` and the NATS volume. Bootstrap
adds exact ATTACHMENTS publish/read API permissions to every active device; old
revoked NKeys remain excluded. Migration 5 preserves existing identities, groups,
transcripts, recovery markers and trust. The new service creates the bucket. There
is no new service request/reply subject, HTTP endpoint or consumer type.

Upgrade every member before sending files: pre-M16 clients interpret application
bytes as text and do not safely summarize a manifest containing a DEK. Existing
UTF-8 text messages and the v1 registration/recovery protocols remain unchanged.

```bash
cargo build --workspace
./scripts/dev/bootstrap-nats.sh
./target/debug/epochgrid-service
```

After both devices have joined a channel, Alice sends a file:

```bash
./target/debug/epochgrid --home .dev/alice attachment send engineering ./report.pdf \
  --mime application/pdf
```

Bob fetches the protected manifest through normal chat catch-up, lists local
attachments, and chooses a new destination path:

```bash
./target/debug/epochgrid --home .dev/bob channel sync engineering
./target/debug/epochgrid --home .dev/bob attachment list engineering
./target/debug/epochgrid --home .dev/bob attachment save engineering ATTACHMENT_ID ./saved-report.pdf
```

`attachment list` is local/offline and returns at most 1000 indexed attachments.
The ID is printed by send/list/history. Saved files are not executed or opened
automatically; MIME/filename values are sender claims, not a content safety verdict.
Unix output files are created with mode 0600. Use private directories/appropriate
Windows ACLs. A write error removes the incomplete file where possible; a process
or power failure during the final plaintext write may leave a partial local file.
Authentication/corruption failures occur before opening the output path.

In the TUI, use `/attach PATH` and `/save ID OUTPUT_PATH`. The remainder of each
command is a path and may contain spaces; do not add shell quotes. The selected
channel determines manifest lookup. Attachment summaries arrive asynchronously
through normal MLS history. The renderer remains responsive during transfers; the
worker catches up after the bounded transfer completes. No automatic download or
thumbnail generation occurs. Transfers require connectivity. If sending fails
ambiguously, sync/flush pending messages before submitting the file again to avoid
duplicate attachment posts. Orphan uploads expire with bucket retention.

## Limits and retention

| Setting | Default | Scope |
| --- | --- | --- |
| `EPOCHGRID_ATTACHMENT_MAX_BYTES` | 8388608 (8 MiB) | Client upload/download; allowed 1 byte–64 MiB |
| `EPOCHGRID_ATTACHMENT_TTL_SECONDS` | 604800 (7 days) | Client manifest expiration, 1 second–1 year |
| Service `--attachment-retention-seconds` | 604800 | Object Store max_age; 60 seconds–1 year |
| Service `--attachment-store-max-bytes` | 536870912 (512 MiB) | Total bucket capacity; minimum 1 MiB |
| Network transfer deadline | 30 seconds | Entire send/download, not per chunk |

The sender caps manifest TTL at the bucket retention observed before upload. The
receiver rejects expiration using its local clock. Size policy is client-side and
does not prevent a malicious authorized client from uploading other data; bucket
capacity/max_age provide server-side resource bounds. Empty files are supported.
Files are encrypted/authenticated wholly in bounded memory before chunking/writing.

The service updates retention/capacity on an existing compatible bucket without
recreating it. Reducing retention may promptly remove old objects; expiration and
capacity are not guarantees of availability. NATS expires chunk and metadata
messages using native stream retention, also covering interrupted/orphan uploads.
The manifest and conversation event remain in history after object expiration.
Changing a manifest's local expiration cannot recover expired chunks. Recipients
that already possess ciphertext and its key can bypass client expiration; it is
not cryptographic timed deletion.

## Validation

Unit tests cover ciphertext round trip, wrong group binding, tampering, truncation,
expiration, size/name/MIME limits, empty files, safe rendering, manifest framing,
transaction rollback and schema migration. The live NATS case covers multi-chunk
CLI send/save, offline manifest delivery, restart, retention reconfiguration,
overwrite refusal, real stored-chunk corruption, malformed object links, expiration
and revoked NKey reconnect. It scans CHAT, MAILBOX and OBJ_ATTACHMENTS payloads for
known plaintext/file-name markers. The real-terminal smoke test sends/saves a file
with spaces in its name and scans stopped NATS files for its plaintext marker.
All loops/requests have finite bounds; the attachment NATS case has a 120-second
outer deadline in addition to per-transfer limits.
