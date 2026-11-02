# Operational diagnostics

Milestone 30 adds a bounded local snapshot of the running authority. Run as the
account that owns the selected home:

```bash
# Authority account:
epochgrid-service --home /path/to/authority status --role authority --format json
# Control worker account:
epochgrid-service --home /path/to/worker status --role control --format human
```

Select `--role` explicitly. Status reads existing private binding configuration
and makes one peer-authenticated Unix-socket request. It opens no database, makes
no NATS or Secret Service connection, creates no state and performs no repair.
A locked keyring therefore does not prevent inspecting an already-running process.
The worker account receives no registry usage or capacity policy details.

Exit 0 means the authority's sampled admission gate is open; exit 1 means a live
response reports it closed; exit 2 means configuration, argument or observation
failure. `unknown` does not prove a process is stopped. JSON owns stdout and uses
no tracing initialization. Human output presents the same fields. CLI syntax
errors use ordinary stderr. The total socket deadline is five seconds, with no
retry, a 256-byte request limit and 16 KiB response limit. A busy status listener
can make observations unavailable while the control path remains healthy.

## Report version 1

The envelope has `version`, `role`, `readiness`, `reasons`, `instance`, `uptime_ms`,
`observations` and `coverage`. Readiness is `ready`, `not_ready` or `unknown`.
`instance` is an independent random 128-bit hexadecimal identifier created each
process start. It is unrelated to credentials or device identity. Unknown reports
have null instance, uptime and observations. Unsupported versions fail explicitly.
The separate deployment validation report remains version 1 unchanged.

All ages and uptime use monotonic time in milliseconds. Runtime observations are
sampled while forming the response; independent counters/connections are not a
transactionally atomic system snapshot. The readiness predicate is the same one
used for device Auth Callout: reconciliation complete and a live worker session
whose last frame is less than five seconds old. Inspection never renews that lease.
The special bound backend bootstrap identities retain their existing exemptions.

| Observation | Owner and meaning |
| --- | --- |
| `reconciled`, `worker_live` | Authority gate predicates; a socket response alone is not readiness |
| `worker_lease_age_ms`, `worker_lease_limit_ms` | Current session frame age and 5000 ms lease; age is null with no live session or an unavailable clock sample |
| `auth_requests`, `control_requests` | Fixed process-lifetime aggregate counters described below |
| `ipc_disconnects` | Worker sessions ending with an error, including malformed/expired sessions; no client identity labels |
| `reconciliation_success`, `reconciliation_failure` | Completed startup/mutation/repair reconciliations and failed repair attempts |
| `reconciliation_age_ms` | Age of last successful reconciliation; null until success; it is historical, not a continuously refreshed dependency certificate |
| `control_queue_used`, `control_queue_limit` | Current local forwarding channel occupancy and fixed one-entry limit; excludes the in-flight operation and OS socket backlog |
| `auth_connection`, `control_connection` | Current authority-side NATS client-library state (`connected`, `disconnected`, `pending`); null before handles are available |
| `permission_denied_observed` | Sticky permission-error observation from the authority application connection since process start; false is not proof of complete permissions |
| `capacity` | Authority view only; cached registry aggregate counts and logical SQLCipher bytes, policy limits and recovery reserve |

Capacity contains `availability`, `age_ms`, `usage` and `collection_ms`. A single
read transaction on the existing authority registry handle collects users, devices,
tokens, groups, membership edges and logical pages. It runs at startup and on a
10-second maintenance interval, with no new database handle or background database
task. Collection does not hold the snapshot mutex while querying. Slow main-loop
operations may delay refresh. After 30 seconds the value is `stale` and usage is
null; collection failure makes it `unavailable`, never zero. `collection_ms` records
elapsed query time, including lock delay, for local cost assessment. Capacity does
not include the control identity database, client homes or broker usage; use their
existing validation/inspection procedures. These are logical budgets, not physical
filesystem/WAL or peak-memory guarantees.
The four local BYO fixture samples on 2026-10-30 each recorded `collection_ms: 0`
(less than one millisecond at this resolution). This supports the 10-second
refresh interval for these small fixtures; it does not certify larger deployment
sizes or a worst-case lock/latency bound. Existing database waits remain bounded
by their one-second busy timeout.

Counters saturate at `u64::MAX`, reset at process restart and are not a durable
audit trail. Both operation classes have `received`, `accepted`, `denied`,
`rate_limited`, `malformed` and `timeout`:

- Auth received counts calls to the encrypted callout processor; messages without
  a usable reply/header can be discarded before that point. Accepted counts a
  generated user grant; denied counts a denied decision or processing error.
  Rate-limited counts global or verified-principal bucket rejection. Malformed
  counts oversized encrypted inputs; other cryptographic/validation errors are
  included in denied. Timeout is zero: this processor has no separate timed scope.
- Control received counts operations taken by the authority main loop. Accepted
  counts a non-rejected response body after processing; denied includes explicit
  rejection, processing error or operation deadline. Rate-limited and malformed
  count known bucket and size/wire-decode rejections. Timeout counts the five-second
  operation deadline, including ambiguous mutations; it does not prove rollback.

Counters describe processing stages, not disjoint billing totals or delivery ACKs.
Signing/publish failures can follow a decision. Unreceived messages, broker drops,
worker-discarded requests and OS queues are not inferred from missing replies.

All coverage fields are false: `broker_resources`, `worker_network`, `keyring`,
`physical_capacity`, `audit_trail`. The worker view is an authority observation of
its session, not independent worker NATS health. A ready response does not certify
replica health, configuration drift, quota adequacy or future admission. Known
connection/permission observations are advisory and do not add new admission
predicates. Fixed reason codes describe only causes established by the gate.

## Troubleshooting

| Result | Action |
| --- | --- |
| `configuration_invalid` | Check selected role/account, existing bindings, ownership and private modes using [role setup](../backend-role-contract.md); status does not provision missing state |
| `authority_unavailable` | Inspect the supervisor and sanitized startup failure; run offline validation under the authority account; an absent socket does not identify the root cause |
| `observation_timeout`, `unsupported_response` | Check load and matching binaries; the old minimal status exchange remains supported but an old authority cannot supply the new diagnostic report |
| `reconciliation_pending` | Use authority online validation and pending-work/startup diagnostics; observe repair counters and retain durable work; the snapshot alone cannot identify a broker quota rejection |
| `worker_absent`, `worker_lease_expired`, `lease_unavailable` | Check both supervisors, matching bindings and worker startup; start the worker after the authority is available; do not replay an ambiguous request automatically |
| Connection disconnected/pending | Run explicit authority online validation to distinguish TLS, endpoint and authentication failures |
| Permission-denial observation | Review existing exported grants and run online validation; this sticky observation clears only on restart and never grants extra permissions |
| Capacity usage near/exceeding a limit, or stale/unavailable | Inspect with offline/online validation and follow the [stopped capacity upgrade](capacity.md); no evidence is deleted to recover space |

Dependency failures such as locked/missing keyring, unreadable/busy database,
incompatible resources and broker quota rejection require
[deployment validation](validation.md) or operator-owned broker inspection. Run:

```bash
# Authority's own account and keyring session:
epochgrid-service --home /path/to/authority validate \
  --auth-config /path/to/authority/auth.json --offline --format json
EPOCHGRID_TLS_CA_PATH=/path/to/operator-ca.pem \
  epochgrid-service --home /path/to/authority --server tls://nats.example:4222 \
  validate --auth-config /path/to/authority/auth.json --online --format json
# Worker account:
epochgrid-service --home /path/to/worker validate-control --offline --format json
```

Online validation is an explicit dependency probe, with its own bounded waits and
coverage. Neither command administers streams. Route TLS, account limits and
operator configuration remain outside runtime credentials; see [BYO NATS](byo-nats.md)
and [TLS](tls.md). Preserve established homes, keys, SQLite sidecars and pending
work. Never reinitialize, purge history or disable security to make status green.

Reports omit keys, tokens, JWTs, names, NKeys, message content, rows, subjects,
URLs, local paths and raw error chains. Fixed aggregate counts can still reveal
activity. Saving or sharing a report is an explicit operator action; no support
archive is collected. This contract does not sanitize unrelated legacy debug logs;
do not collect unrestricted trace output as a support bundle. Structured durable
security audit events remain milestone 31, and TD-001/002/003 remain open.

Milestone 31 adds encrypted authority audit schema 3. Existing homes require a
stopped-authority `audit upgrade` before production validation. See the
[security audit contract](audit.md) for storage bounds, coverage gaps, retention,
export permissions and failure behavior. Status exposes aggregate audit health;
only the authority account can export evidence.
