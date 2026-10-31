# Deployment validation

Milestone 27 provides non-initializing local inspection of an established backend:

```bash
epochgrid-service --home ./epochgrid-state validate \
  --auth-config ./epochgrid-state/auth.json --offline

# Explicitly check local transport inputs too, without contacting the endpoint:
EPOCHGRID_TLS_CA_PATH=./operator-ca.pem \
  epochgrid-service --home ./epochgrid-state --server tls://nats.example:4222 \
  validate --auth-config ./epochgrid-state/auth.json --offline --format json
```

Run as the backend's Linux account in its provisioned, unlocked Secret Service
session. Select exactly one of `--offline` or `--online`. Exit status
is zero only when every required check passes. Failed checks return nonzero;
malformed command arguments also return nonzero. Human output is the default.
JSON occupies stdout exclusively; sanitized failure diagnostics use stderr.

In offline mode, no NATS connection or Auth Callout listener is started. A supplied `--server`
(or `EPOCHGRID_NATS_URL`) is parsed and checked against the shared TLS policy,
including rejection of embedded credentials. Without a supplied endpoint, that
check is marked `not_checked`; the service's development default URL is not
silently treated as a deployment choice. TLS environment settings and trust
roots are inspected locally in either case. Local certificate parsing does not
prove server identity, TLS reachability or operator route security.

## Checks and coverage

| Check IDs | What is checked |
| --- | --- |
| `local.home`, `local.control_home` | Existing backend-owned directories, no symlink, no group/other access |
| `local.auth_config` | Existing private version-2 configuration in the backend home; existing semantic/JWT checks, including rejection of an incomplete operator setup |
| `local.deployment_manifest` | Private replica manifest plus explicit capacity policy; R1/R3; never created during validation |
| `local.permissions.auth.*`, `local.permissions.control.*` | Existing metadata/database files and present SQLite sidecars; backend ownership, regular file type and owner-only permissions |
| `local.credentials.*` | Six existing Secret Service roles, matching metadata/configuration/control bindings, and independent IDs/public bindings |
| `local.capacity` | Valid explicit policy and existing registry counts, record sizes and logical database pages within budget |
| `local.database.auth` | Existing SQLCipher state, ready metadata, matching database role/key binding, integrity and foreign-key checks, complete auth schema version 2 |
| `local.database.control` | Existing SQLCipher state/bindings/integrity, local schema version 8 and OpenMLS migration version 6, required tables/columns, signed service/laptop identity matching configuration and credentials |
| `local.transport.inputs`, `local.transport.endpoint` | Shared TLS profile, usable trust roots, optional endpoint policy; no connection |
| `coverage.network`, `coverage.operator` | Explicitly not checked: broker authentication, resources/replicas, server version/payload, route TLS, account isolation, signer authority, resolver lifecycle and physical capacity adequacy |

The control registration's signature and identity binding are inspected without
rejecting historical KeyPackages solely because they have expired. Schema checks
verify supported migration histories and required tables/columns. This is not a
semantic audit of every private application record or a full MLS state recovery
test. A local pass is **not** deployment readiness or alpha qualification.

## No initialization, repair or migration

Validation never calls `AuthRegistry::open` or `IdentityStore::open`. It creates
no home, provisioning metadata, lock files, credentials, database or schema. It
does not change configuration, permissions, application data or migration state.
Missing metadata, incomplete setup, old/new schemas, plaintext databases, wrong
bindings and corrupt encrypted state fail instead of triggering repair.

All database access, including the plaintext format probe, uses SQLite-managed
connections. Inspection uses `SQLITE_OPEN_READ_ONLY`, `query_only` and a read
transaction, with no immutable mode and no ordinary file-descriptor content reads.
This avoids releasing another SQLite handle's POSIX locks or ignoring committed
WAL data. Each database is inspected in its own consistent read snapshot; there
is no coordinated snapshot across configuration, keyring and both databases.
Avoid concurrent initialization or credential rotation during validation.

SQLite may create or update WAL/SHM bookkeeping while servicing a read-only
connection. Sidecar existence, timestamps or shared-memory contents are therefore
not guaranteed unchanged. Do not delete live sidecars to prevent this. Application
pages and schema are not modified by validation, and an active writer can continue.
A busy database produces a retryable inspection failure; validation does not
stop the running backend. Existing Secret Service operation deadlines still apply.

## Versioned report

The JSON envelope has `version: 1`, `mode: "offline"` or `"online"`, `success` and `checks`.
Each check has:

- `id`: stable identifier from the table above.
- `status`: `passed`, `failed` or `not_checked`.
- `required`: whether this check must pass for command success.
- `expected` and `observed`: public, sanitized values. Failed observations use
  stable diagnostic codes; successful manifest checks include version/replicas.
- `remediation`: a safe operator action for failures or blocked prerequisites,
  otherwise null.

A required check blocked by a failed prerequisite is `not_checked`, not passed.
Network and operator coverage checks are never counted as local passes. Reports
exclude seeds, database keys, enrollment tokens, credential/JWT payloads, URLs,
private records and raw database/parser error chains. This report is separate
from milestone 31's audit-event system.

Common observations include `state_missing`, `permissions_too_open`,
`permissions_insufficient`, `unsafe_file_type`, `operator_setup_incomplete`, `credential_missing`,
`credential_duplicate`, `credential_binding_mismatch`, `keyring_locked`,
`keyring_unavailable`, `keyring_timeout`, `plaintext_database`,
`initialization_incomplete`, `database_metadata_invalid`, `database_unreadable`,
`database_binding_mismatch`, `database_integrity_failed`, `schema_unsupported`,
`database_busy`, `control_identity_mismatch`, `tls_inputs_invalid` and
`endpoint_invalid`. Use the associated check ID and remediation to distinguish
which state needs attention.

For an established milestone 26 home lacking `deployment.json`, use
[deployment-export](auth-callout.md#commands-and-configuration) with an explicit
replica declaration, then rerun validation. Restore missing state/keyring items
from the same installation; do not rerun initialization over an established home.
For an interrupted fresh setup, review its state and retry the original setup
command separately. Operator mode requires the externally signed non-bearer
service JWT before validation can pass.

## Online inspection

Start the backend after provisioning the generated resources, then run:

```bash
EPOCHGRID_TLS_CA_PATH=./operator-ca.pem \
  epochgrid-service --home ./epochgrid-state --server tls://nats1.example:4222 \
  validate --auth-config ./epochgrid-state/auth.json --online --format json \
  --endpoint tls://nats2.example:4222 --endpoint tls://nats3.example:4222
```

Online validation first runs the local checks. With valid local state it connects
using the existing auth-service and control credentials. It does not start an Auth
Callout listener, create devices or tokens, or modify broker resources or application
records. The backend must already be running to admit the control connection.

Supply one to eight endpoints through `--server`/`EPOCHGRID_NATS_URL` and repeated
`--endpoint`. Each is checked individually with discovery and reconnect disabled;
a healthy cluster member cannot hide a failed supplied endpoint. Reports identify
endpoints by zero-based input index, omitting URLs. Each network operation has a
five-second deadline and the complete network phase has a 60-second deadline.
Local keyring/database checks retain their individual bounded waits.

| Check IDs | What is checked |
| --- | --- |
| `online.endpoints` | Explicit endpoint count |
| `online.endpoints.N.auth` | Auth-service credential connection and flushed authenticated session |
| `online.endpoints.N.jetstream` | Successful authenticated application-account JetStream API response |
| `online.endpoints.N.server` | Qualified NATS version 2.14.5, max payload exactly 65536; discovered endpoint count |
| `online.endpoints.N.resources.NAME` | Existing CHAT, MAILBOX and all three KV backing streams against the shared manifest/contract, including KV history and replication |
| `online.endpoints.N.resources.NAME.replicas` | Leader present for clustered resources, expected peer count, current/non-offline peers with no reported lag |
| `coverage.discovery`, `coverage.operator` | Not certified: discovered endpoints, mutual route TLS, account isolation, signer scope, resolver lifecycle or physical capacity adequacy |

Failure codes distinguish `permission_denied`, `authentication_denied`, `timeout`,
`endpoint_unavailable`, `service_unavailable`, `tls_failed`, `resource_missing`,
`resource_incompatible`, `server_incompatible`, and `replicas_unhealthy`.
Transport-library errors that do not expose a TLS-specific category may appear as
endpoint unavailability. Incompatible resources include the names of differing
contract fields, without dumping server configuration. Resource and replica checks
are observations at inspection time, not continuous monitoring or a deployment-wide
atomic snapshot. A failed validation command does not stop the backend.

## Production startup admission gate

Under the production profile, `serve-authority` requires successful local inspection before
opening its temporary Auth Callout bootstrap path. Device admission remains closed;
only the bound authority and worker identities can bootstrap. The same authenticated server,
resource-contract and replica checks must pass before reconciliation and readiness.
Failures abort the temporary auth task and exit with admission closed. Startup
never creates missing streams/KV buckets or changes operator settings. Once checks
pass, existing lifecycle reconciliation may update application records and consumers.
The explicit development profile retains its legacy fixture provisioning behavior.

Milestone 28 adds [separate-account role bindings](../backend-role-contract.md).
The authority's report includes `local.backend_role` and, online,
`runtime.backend_role`. New device admission additionally requires a current worker
lease. The worker runs `validate-control --offline|--online [--format json]` in its
own account/keyring. Its online mode checks the local authority's authenticated
status socket; it does not inspect NATS resources or connect to a supplied endpoint.
`coverage.role_network` states this limit. No authority credential is shared with
the worker validator. The combined `serve` command is development-only.

Existing encrypted milestone 26 homes must run `deployment-export --replicas 1|3`,
apply/review all five generated resource specifications using operator credentials,
and run offline validation before production startup. Do not reinitialize established
keys or databases. Wait for replica recovery before restarting into a degraded
cluster: the gate requires all declared replicas healthy. This is a startup gate,
not a continuous configuration monitor; use online validation after changes.

## Capacity validation

Milestone 29 requires a valid `capacity.json`. Offline `local.capacity` inspects
existing encrypted registry counts, registration sizes and logical database usage
without provisioning or migration. Online checks compare finite byte/consumer
budgets and discard-new policy exactly and require server `max_payload: 65536`.
An M28 home must follow the [stopped capacity upgrade](capacity.md). Worker
validation covers its own state and authenticated authority readiness; it does not
read authority policy or claim to inspect server/account/filesystem quotas.
