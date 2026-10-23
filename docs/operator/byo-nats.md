# Bring your own NATS — milestone 26 contract

This contract defines the NATS integration being qualified for EpochGrid. It does
not certify the whole application for production: TD-001/TD-002 remain open,
dynamic attachments are not supported, and deployment tooling, backend privilege
separation and operational limits remain later milestones.

## Qualification matrix

The pinned target is **NATS Server 2.14.5**, with Linux EpochGrid clients/backend,
verified TLS 1.3, encrypted Auth Callout, persistent JetStream storage, and the
default 30-second device authorization lease. Short-lease dynamic messaging remains
unqualified under TD-002; this matrix does not certify every accepted TTL setting.

| Authentication | Topology | Resource replication | Qualification case |
| --- | --- | --- | --- |
| Server configuration | Standalone | R1 | `configuration_standalone` |
| Server configuration | Three-node cluster | R3 | `configuration_cluster` |
| Operator JWT with default sentinel | Standalone | R1 | `operator_jwt_standalone` |
| Operator JWT with default sentinel | Three-node cluster | R3 | `operator_jwt_cluster` |

Results are recorded in [current milestone status](../milestones.md). Other server
versions, scoped signing keys, leaf nodes, gateways, JetStream domains/API remapping,
mixed-version clusters and managed services that cannot expose this contract are
unqualified. Broker clustering does not make the single local backend registry
highly available. Never run backend replicas with independent registry copies.

## Ownership and trust

The operator owns server configuration, account JWTs/resolvers, TLS certificates,
cluster routes, storage directories, backups and resource budgets. EpochGrid never
rewrites/reloads that configuration or needs a system-account administration key.
Run the auth listener in an isolated authentication account and delegate exactly
one dedicated application account. Other accounts must not import/export EpochGrid
subjects or Auth Callout traffic. Do not share the application account with
untrusted services. No per-device static NATS users or fallback allow-list is used.

Use `auth-init` under the backend's Linux account and unlocked Secret Service
session. Preserve its SQLCipher databases, metadata and keyring; existing plaintext
homes remain unsupported. Only public key references and signed non-bearer service
JWTs belong in `auth.json`; private credential values stay in Secret Service.
Configure verified `tls://` endpoints and an appropriate CA as described in
[TLS](tls.md). Each advertised cluster hostname must be reachable and covered by
its certificate. Protect inter-server routes with mutual TLS. The local
qualification fixture uses mutually authenticated TLS 1.3 on loopback routes;
its disposable certificates and local topology are not a deployable cluster config.

## Configuration mode

Integrate the generated `nats-reference.conf` with operator-owned TLS and JetStream
configuration. Set `auth.json.target_account` to the application's account name.
Leave `operator_jwt` absent. Configure the generated issuer and XKey, the isolated
authentication account, the fixed auth service connection key in `auth_users`, and
only the application account in `allowed_accounts`.

The auth service subscribes to `$SYS.REQ.USER.AUTH` and `_INBOX.>` and publishes
responses on `$SYS._INBOX.>`. Do not grant clients access to those subjects. Keep
NATS authentication deadlines large enough for the configured service, and clock
synchronization healthy: EpochGrid rejects stale callout requests and requires an
expiry no more than 60 seconds ahead.

## Operator-JWT mode

Operator mode uses account JWT external-authorization settings instead of a server
`authorization.auth_callout` block. The qualified entry path is the pinned server's
`default_sentinel`: an authentication-account bearer user JWT with publish and
subscribe deny-all, which routes unauthenticated connections to Auth Callout.
It grants no EpochGrid identity. EpochGrid still verifies each device's own NKey
nonce signature and enrollment token/registry authorization. Operators must accept
this entry mechanism; an arbitrary existing SSO/JWT arrangement is not equivalent.

1. Create separate authentication and application accounts under the operator.
   Keep operator/account root private keys outside EpochGrid.
2. In the authentication account JWT, configure external authorization with the
   generated connection public key in `auth_users`, the application account public
   key in `allowed_accounts`, and the generated encryption public key as `xkey`.
3. Issue a **non-bearer** user JWT for the generated connection public key, in the
   authentication account, with the auth service permissions listed above. Its
   possession key remains the existing Secret Service item. EpochGrid validates
   signature, subject, account binding, type and validity window on configuration
   load; NATS validates issuer delegation against its account resolver.
4. Register the generated `issuer.public_key` as an **unscoped signing key** of the
   application account. This key signs the dynamically generated user grants; it
   is not the operator root key. Scoped templates are not qualified because they
   can replace/conflict with EpochGrid's per-device permission sets.
5. Set `target_account` to the application account public NKey and add:

   ```json
   "operator_jwt": {
     "auth_account": "<authentication account public NKey>",
     "connection_jwt": "<operator-issued signed auth service user JWT>"
   }
   ```

6. Configure `default_sentinel`, the operator/system account and the account
   resolver on every server. The sentinel belongs to the authentication account,
   denies all publish/subscribe operations, and is not an `auth_users` bypass user.
   Distribute updated JWTs through the operator's normal resolver process. Update
   the backend configuration and restart it before its service JWT expires.

For example, the authentication account's **operator-signed JWT payload** includes
the following `nats.authorization` fragment (these are public keys, not seeds):

```json
{
  "auth_users": ["<auth.json.connection.public_key>"],
  "allowed_accounts": ["<application account public NKey>"],
  "xkey": "<auth.json.encryption.public_key>"
}
```

The application account's JWT includes
`"signing_keys": ["<auth.json.issuer.public_key>"]` under `nats`. Its JetStream
limits must permit the resources below. Merely editing decoded JSON is insufficient:
the operator must sign and distribute each account JWT. The corresponding server
configuration has this shape:

```text
operator: "<operator-signed operator JWT>"
system_account: "<system account public NKey>"
resolver: <operator-managed account resolver>
default_sentinel: "<deny-all bearer user JWT in the authentication account>"
```

The qualification fixtures use `resolver: MEM` with `resolver_preload` for the
signed authentication, application, system and unrelated test accounts. Production
resolver lifecycle, credential issuance and operator trust remain operator-owned.

Callout requests must name the configured authentication account. Responses bind
the requesting server and temporary connection key. Admitted user JWTs specify
the application `issuer_account`, signed by the delegated key; account-name
audience placement is used only in configuration mode. Requests and responses
remain XKey-encrypted in both modes. No device-side JWT files are required.

## JetStream resource contract

Use the default `$JS.API` prefix and file storage. Provision resources in the
application account before production startup. Missing or incompatible resources
stop startup; existing resources are never automatically converted to R3. Milestone 27 now generates all five resources with explicit
R1/R3 via [auth-init/deployment-export](auth-callout.md#commands-and-configuration).
The four qualification fixtures consume these artifacts and run
[offline validation](validation.md) before startup, during backend operation and
after restart. Production startup requires the manifest and compatible, healthy
pre-provisioned resources before admission. Run online validation against the
running backend, supplying each endpoint explicitly; discovery does not certify
uninspected brokers. Failure does not repair operator resources or stop an
already-running backend.

| Resource | Subjects / purpose | Required behavior |
| --- | --- | --- |
| `CHAT` | `epochgrid.v1.group.*.message`, `epochgrid.v1.group.*.handshake` | Limits retention; preserve offline ciphertext/history; maximum message size 65536 |
| `MAILBOX` | `epochgrid.v1.user.*.*.inbox` | Limits retention; durable Welcome delivery; maximum message size 65536 |
| KV `IDENTITIES` | `$KV.IDENTITIES.>` | File storage, history 1; signed directory projection |
| KV `CHANNELS` | `$KV.CHANNELS.>` | File storage, history 1 |
| KV `TRANSPARENCY` | `$KV.TRANSPARENCY.>` | File storage, history 1, maximum value size 65536; append-only signed records use distinct keys |

Set replicas to 1 for standalone or 3 for **all five** streams/KV backing streams
in the qualified cluster. Server `max_payload` must accommodate 65536-byte wire
messages. Do not add subject transforms, TTL/age eviction, interest/workqueue
retention, or external publishers that alter protocol history. Storage quotas must
cover the intended retention period; unlimited test defaults are not capacity
planning. Milestone 29 will address broader resource bounds.

The backend creates `device_<public NKey>` pull durables on CHAT and MAILBOX.
CHAT filters are exact authorized group message/handshake subjects (an empty
membership uses a reserved nonmatching subject); MAILBOX filters match only that
device's inbox. Both use explicit ACKs and batch/pending limits of one. MAILBOX uses
a five-second ACK wait; CHAT uses a two-second ACK wait. Preserve the backend's
filter lifecycle and consumer replica inheritance. Clients may use INFO/NEXT/ACK
for their own consumers, but cannot create consumers or read raw streams.

The current control connection has application-account JetStream management
authority and directory/transparency access. Full backend privilege separation is
milestone 28; the dedicated account is the present containment boundary. Dynamic
Object Store attachment access is outside this contract.

## Failure and recovery contract

New admission fails closed without Auth Callout, on revocation, or on invalid TLS
trust. Existing device grants expire within `authorization_ttl_seconds` (default
30, range 2–60); the control connection uses a 60-second lease. There is no promise
of instantaneous revocation. Preserve current membership synchronization before
encrypting; TD-002 still tracks short-lease join/send failures.

R3 qualification kills the CHAT leader, continues acknowledged publishing with
two nodes, restores the node and checks resource settings. Standalone qualification
restarts the broker using its persisted store. Both restart the backend and client
processes and verify retained history, bidirectional messaging, authorization
denials and unchanged operator configuration. This is process/node-failure
qualification, not a guarantee against simultaneous disk loss or loss of quorum.

## Reproducing qualification

Install the existing Rust, OpenSSL and isolated keyring test dependencies, then:

```bash
./scripts/dev/verify.sh byo-build
python3 scripts/dev/run-bounded.py 120 ./scripts/dev/download-nats.sh
./scripts/dev/verify.sh byo-nats
# Or one isolated case:
./scripts/dev/verify.sh byo-nats operator_jwt_cluster
```

Compilation has a separate bounded phase. Each case has a fresh keyring and state,
a 240-second workflow deadline and a 260-second outer watchdog. CI runs the four
cases in independent jobs without rerun-on-failure. Readiness checks and explicit
server permission errors distinguish test setup from authorization failures.

Upstream contracts: [Auth Callout](https://docs.nats.io/learn/security/auth-callout),
[pinned request/response validation](https://github.com/nats-io/nats-server/blob/v2.14.5/server/auth_callout.go),
and [pinned operator/default-sentinel fixtures](https://github.com/nats-io/nats-server/blob/v2.14.5/server/auth_callout_test.go).
