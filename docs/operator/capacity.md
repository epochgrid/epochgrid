# Capacity and overload

Milestone 29 uses a public `capacity.json` beside the backend `auth.json`.
Fresh `auth-init` installs it. Production startup and offline validation require
it; an M28 installation must explicitly upgrade before starting M29. The original
replica-only `deployment.json` remains unchanged. Exported bundles contain a
version-two deployment manifest embedding the capacity policy and all five finite
broker configurations. Version-one rendering retains its historical semantics.

The policy contains no credentials. Authority database limits belong to the
backend operator. Each client can supply its own `capacity.json` in its device
home; otherwise bounded client defaults apply. Worker ingress uses fixed transport
ceilings and does not need access to the authority's home or keyring.

## Defaults and ceilings

| Boundary | Default | Hard ceiling / behavior |
| --- | --- | --- |
| Retained users / devices | 32 / 32 | 32 / 32, including revoked devices |
| Active devices per user | 8 | 32, no more than declared retained devices |
| Retained enrollment tokens | 256 | 4096; expired/used evidence is retained |
| Retained authority groups / local groups | 32 | 128 |
| Membership edges | 512 | 4096 |
| Groups per device | 16 | 16; bounds signed grants |
| Retained local trust bindings | 256 | Fixed; authenticated observations may use database recovery space |
| Stored registration | 1536 bytes | Fixed ceiling checked before transaction commit |
| Normal pending outbox | 256 messages, 4 MiB payload | Configurable up to 4096 messages / 64 MiB |
| Revocation repair outbox reserve | 32 messages, 2 MiB | Only authenticated local revocation reconciliation may use it |
| Database logical pages | 256 MiB | Configurable up to 16 GiB |
| Database recovery reserve | 16 MiB | Up to 1 GiB; strictly less than total |
| Auth Callout / control operations | 32 per second, burst 64 | Configurable up to 1024 each; separate constant-sized buckets |
| Authenticated device admission / policy updates | 4 per second, burst 8 / 16 | At most 32 retained principal buckets per handler |
| Revocation requests | 4 per second, burst 8 | Separate bucket; original signature checks still apply |
| NATS subscription / outgoing command queue | 64 entries each | Fixed; slow-consumer overflow is bounded loss, not acceptance |
| NATS payload | 65536 bytes | Production server must declare exactly this value |
| Local IPC | 512 KiB frame, one queued + one in flight | Existing five-second deadlines and worker lease preserved |
| Outbox read batch | 16 rows | Fixed upper ID per flush; no collection of the entire queue |
| CHAT / MAILBOX storage | 64 MiB / 16 MiB | Finite, reject new; no eviction of accepted history |
| IDENTITIES / CHANNELS / TRANSPARENCY | 1 MiB each | Finite native history-one KV, reject new at capacity |
| CHAT / MAILBOX consumers | Declared retained devices each | Includes revoked-device headroom |
| KV consumers | 8 each | Fixed; no runtime stream administration |

Broker byte settings range from 256 KiB to 1 TiB per stream. These are logical
stream budgets, not physical disk allocations. R3 requires three replicas plus
index/WAL/compaction and recovery headroom. R3 history-one KV replacement also
needs room for the incoming record before releasing the old value; at a tightly
filled quota it rejects the replacement while retaining the old revision. An
operator capacity increase permits the same replacement without deleting history. The operator must supply matching
account/server quotas and filesystem capacity; runtime cannot inspect or change
all of those settings with its narrow grants.

The 32-device maximum fixture uses maximum-length identity/device names and
measures 607 bytes per registration, 19,519 bytes for the complete signed audit
snapshot, and 8,319 bytes for revoking every retained device with maximum cutoffs.
The 1536-byte registration ceiling supplies more than twice the measured record
size while 32 records plus 1024 framing bytes fit below 65536. Revocation retains
independent wire headroom. This intentionally constrains v1 growth; no snapshot is
truncated and no pagination/version reinterpretation is introduced. Capacity
beyond these representation ceilings requires a future protocol change.

## Exhaustion and recovery

Registry checks run inside the same immediate transaction as enrollment, token
creation and group-policy changes. A rejection rolls back token consumption,
membership changes and associated generations. Exact accepted retries do not
consume another slot. Revocation does not free historical identity capacity.

Outbox insertion shares the MLS transaction. Full queues reject new work and roll
back ratchets, transcript and delivery intent. Broker rejection leaves the pending
outbox row durable. Flush resumes in ID order in bounded batches. Ambiguous publish
acknowledgments retain the existing message ID and deduplication behavior; a timeout
does not prove the publish or control mutation failed.

Incoming chat ciphertext is durably staged before acknowledgment. Storage failure
leaves it unacknowledged or pending; processing does not advance the durable state
on a failed transaction. Normal writes cannot consume the database recovery
reserve; revocation ingestion and removal/rekey may use it. Physical disk failure
can still prevent recovery and requires operator intervention. No automatic deletion,
pruning, vacuum or replacement identity is used to regain capacity.

SQLite page accounting is a logical high-water check. It does not bound WAL bytes,
temporary files, allocator overhead or physical disk consumption. Apply filesystem
quotas and retain headroom separately. Subscription payload storage is at most
64 × 65536 bytes per subscription on the qualified honest broker, excluding metadata,
parser buffers and in-flight work. This is not an RSS ceiling or a DoS guarantee.

Control overload returns the existing v1 `Rejected` response; invalid or overloaded
Auth Callout requests fail closed. No new wire discriminant was added. Token buckets
refill with monotonic time and restart full. The replay cache remains independently
bounded and does not evict live entries to admit more requests. Worker heartbeat
selection has priority over incoming control traffic; recovery retains its separate
local path. A sustained authentication flood can deny new connections, including
backend reconnections, until load subsides. Never treat that state as readiness.

## Client policy changes

Stop the device's TUI/chat and install a complete policy against its existing home:

```sh
epochgrid --home DEVICE_HOME capacity-install --policy capacity.json
```

This takes the normal exclusive device lock and reads established SQLCipher state
without provisioning keys. It refuses a policy smaller than retained groups,
pending outbox rows/bytes or normal database usage. Only after validation does it
atomically replace the local policy. Pending repair work may need to drain first.
No client history or identity is recreated. An interrupted temporary policy file
can be replaced by rerunning the same command under the device lock.

## Stopped upgrade and capacity changes

1. Stop both authority and worker. Retain the encrypted homes, original keyrings,
   public bindings and deployment artifacts. Do not run `auth-init` again.
2. Prepare a complete version-one capacity policy. Use a fresh installation's
   exported `capacity.json` or the checked-in [default policy](capacity-default.json).
3. Check retained state and publish a new immutable artifact directory:

   ```sh
   epochgrid-service --home BACKEND capacity-export \
     --auth-config BACKEND/auth.json --policy capacity.json \
     --output capacity-artifacts-v1
   ```

   The command takes runtime/setup locks, inspects existing encrypted state without
   migrating or provisioning keys, refuses limits below retained usage, publishes
   the full bundle without clobbering edits, then atomically installs the policy.
   A crash before installation leaves the old policy active; rerun the identical
   command. Installing the policy does not claim broker readiness.
4. With application-account administrative credentials, inspect and apply each
   exported stream configuration using the operator's NATS tooling. Existing
   CHAT/MAILBOX must switch from discard-old to discard-new. Check existing bytes
   before reducing any broker quota. Keep native KV history-one semantics.
5. Run authority offline validation, start authority and worker, then run authority
   online validation and worker validation. Startup refuses incompatible broker
   budgets; runtime never edits them. Check every R3 endpoint and replica health.

For a later capacity increase, supply the new policy, a new output directory and
`--replace`. This explicitly replaces the local policy atomically after retained
usage validation; previous artifact directories remain intact. Changed files in an
existing output bundle are refused. Never lower limits below existing usage or
bypass a failed validation by removing encrypted state.

Worker validation reports its own credential/binding and authenticated authority
status. Authority validation owns registry and broker capacity checks. Root account,
server and filesystem provisioning remain explicit operator checks.
