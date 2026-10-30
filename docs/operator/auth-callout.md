# Auth Callout contract — Milestones 21–22

Dynamic enrollment, authorization, CLI/TUI chat and revocation are implemented.
Local secrets and state are protected by Secret Service and SQLCipher. Operational
hardening and release gates remain. Do not deploy the static development bootstrap
as production authentication. See the [BYO-NATS contract](byo-nats.md) for milestone
26 configuration-mode and operator-JWT qualification.

NATS Auth Callout is the production admission model. Operators integrate the callout
in an isolated authentication account and delegate only the EpochGrid application
account. They retain ownership of server/operator/cluster configuration. Static keys
are needed for the callout/backend service identities only, never per client device.

The callout needs an account signing NKey matching the configured issuer, an XKey
private seed matching `auth_callout.xkey`, and a service connection credential listed
in `auth_users`. Protect the private seeds outside public config. The backend directory
signing identity remains separate from the callout issuer and client MLS identities.
Use `allowed_accounts` to constrain configuration-mode delegation in shared fabrics.
No EpochGrid client may subscribe to or publish on `$SYS.REQ.USER.AUTH`.

Encryption is required for callout requests/responses. Decrypt with the configured
XKey, validate the signed request and bind the response to its temporary user key and
server ID. Verify the device NKey nonce signature independently; it is the possession
credential, not the temporary connection key. Enrollment tokens can authorize only
an enrollment endpoint, and are never logged. Unregistered normal connections fail.

Fail closed on invalid signatures, expired requests, identity mismatch, registry
failure, disabled users, revoked devices or unavailable auth service. Bounded claim
expiry limits stale admission after lifecycle changes. No implicit static-user fallback
and no server reload are allowed. The application backend must not hold a system-account
reload credential in dynamic mode. MLS owns cryptographic membership independently.

Upstream references inspected for this implementation:
* [NATS Auth Callout documentation](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout)
* [NATS ADR-26](https://github.com/nats-io/nats-architecture-and-design/blob/main/adr/ADR-26.md)
* [Pinned NATS 2.14.5 implementation](https://github.com/nats-io/nats-server/blob/v2.14.5/server/auth_callout.go)

Rust compatibility: async-nats 0.50 exposes NKey+token CONNECT and request/reply but no
high-level Auth Callout service. `nats-jwt` 0.3 lacks Auth Callout types; `nats-jwt-rs`
0.1.1 provides signed JWT encoding/decoding. Its signature decoder does not enforce
claim freshness or semantic policy; EpochGrid must do those checks explicitly. Use
minimal request types tolerant of omitted optional server fields. Existing nkeys 0.4.5
provides compatible XKey encryption with the `xkeys` feature.


## Commands and configuration

The qualification target is NATS Server 2.14.5. The [BYO-NATS contract](byo-nats.md)
defines the standalone/clustered and configuration/operator-JWT test matrix and
the additional operator-owned setup required for JWT mode.
Only the fixed auth-service NKey is a static NATS user; the fixed backend integration
NKey is admitted by the configured auth component, never by a device allow-list.
Both are service credentials, separate from arbitrary enrolled devices.

```bash
epochgrid-service --home ./epochgrid-state auth-init \
  --auth-mode configuration --target-account EPOCHGRID --replicas 1
```

Run initialization and the service under the same Linux account and provisioned
Secret Service session. [Secret storage setup](../secret-storage.md) describes the
unlocked-keyring prerequisite and headless service contract.

Initialization writes a version-2 `auth.json`, public credential references,
`deployment.json` (version 1, explicit R1/R3), and `deployment-artifacts/` containing
five native stream configurations and integration instructions. Configuration mode
also writes `nats-reference.conf` beside `auth.json` for existing callers.
Credential values live in Secret Service, not seed files.
It does not contact, write to or restart NATS. Integrate the snippet's dedicated
auth account, application account and callout block with operator-owned config,
including TLS. `--target-account` sets the account name in both generated files.
`issuer`, `encryption` and `connection` are typed keyring references with public-key
bindings; `control_nkey` admits only the backend's fixed possession credential.
The directory-signing credential is also in Secret Service; `HOME/control` keeps
its public identity and reference. Missing/locked credentials fail startup before
admission. Version-1 configs and plaintext seed files are unsupported; use fresh
backend state and enrollment rather than migrating them.

For operator-JWT mode, create the operator-owned authentication and application
accounts first, then supply only their **public** account NKeys:

```bash
epochgrid-service --home ./epochgrid-state auth-init \
  --auth-mode operator-jwt --auth-account "$AUTH_ACCOUNT_PUBLIC_NKEY" \
  --target-account "$APP_ACCOUNT_PUBLIC_NKEY" --replicas 3
```

This writes `operator_jwt` with an empty `connection_jwt`, prints **INCOMPLETE**,
and emits `operator-delegation.json` instead of a configuration-mode snippet.
`serve-authority` rejects the placeholder. Use the [operator-JWT signing steps](byo-nats.md#operator-jwt-mode)
to sign/distribute the account delegations and issue the non-bearer service JWT,
then put that JWT in `auth.json.operator_jwt.connection_jwt`. Do not remove
`operator_jwt` to bypass the incomplete state. Root seeds and system-account keys
never enter EpochGrid. Completion of local initialization is not deployment readiness.

Apply the five generated resource files using your application's administrator
context, after reviewing capacity budgets. From `deployment-artifacts/`:

```bash
for resource in CHAT MAILBOX KV_IDENTITIES KV_CHANNELS KV_TRANSPARENCY; do
  nats --context APPLICATION_ADMIN stream add --config "$resource.json"
done
```

These are native stream configurations, including KV backing streams. Every
resource uses the chosen replica count. Supply server TLS, verified `tls://`
endpoints, custom CA roots when required, `max_payload` exactly 65536, and mutual
route TLS for clusters. Existing resources need explicit operator review rather
than blind recreation. EpochGrid does not provision administrator credentials.

`auth-init` without options preserves configuration-mode/EPOCHGRID/R1 defaults.
Completed initialization refuses reruns, including an operator setup awaiting its
JWT. After an interrupted initialization, retry the same command and options:
`auth-init.json` records the choices before provisioning, and credential metadata
retains key identities. `auth.json` is published last as the local completion marker.

Regenerate artifacts from established state without modifying `auth.json`, keys
or databases:

```bash
epochgrid-service --home ./epochgrid-state deployment-export \
  --auth-config ./epochgrid-state/auth.json
# Existing milestone 26 homes need an explicit initial replica declaration:
epochgrid-service --home ./epochgrid-state deployment-export \
  --auth-config ./epochgrid-state/auth.json --replicas 3
```

Export checks existing keyring references and control-key binding without opening
or initializing databases. It also supports pending operator configurations.
It is not full encrypted-state validation. The auth file must reside in `--home`;
the manifest belongs beside it. An existing manifest cannot be silently changed
with `--replicas`. Identical bundles may be exported repeatedly; changed/incomplete
bundles are refused. To preserve edited artifacts, use `--output ./new-artifacts`
with a new directory whose parent already exists. Files are atomically published
with mode 0600 and bundle directories with mode 0700. Export never overwrites the
legacy root `nats-reference.conf`.

[Offline `validate`](validation.md) now inspects established credentials, encrypted
state, permissions and local TLS inputs without initialization or NATS access.
Production startup now requires compatible pre-provisioned resources and healthy
declared replicas before opening device admission. It never creates missing
streams/buckets or changes their settings. After startup, run `validate --online`
against each supplied endpoint; see [validation](validation.md) for deadlines,
report codes and operator coverage limits. Existing M26 homes must export a
manifest with explicit replicas and apply/review the generated resources first.

`authorization_ttl_seconds` defaults to 30 and accepts 2–60 seconds. NATS expires
connections on this deadline; reconnect requires a new signed, current-state grant.
The operator-managed backend integration connection uses a fixed 60-second lease,
independent of device TTL. It is outside device revocation and its configured key
must be rotated deliberately by the operator. `development_plaintext` defaults
to false. Setting it true is an explicit, logged development-only exception; it is
never a supported alpha transport profile and also requires
`EPOCHGRID_PROFILE=development`. Production rejects this setting. The shared
[Milestone 23 TLS profile](tls.md) configures trust roots, minimum TLS version and
TLS-first for both service connections and clients. With `development_plaintext`
disabled, the service also requires callout evidence that the requesting client
used TLS. See the [current milestone status](../milestones.md) for deployment limits.

Complete the [separate-account role setup](../backend-role-contract.md#setup-under-separate-linux-accounts)
before production startup. Under the authority account and its own keyring:

```bash
epochgrid-service --home ./epochgrid-state --server tls://nats.example.org:4222 \
  serve-authority --auth-config ./epochgrid-state/auth.json
```

Then, under the distinct worker account and its independent keyring:

```bash
epochgrid-service --home ./epochgrid-worker --server tls://nats.example.org:4222 \
  serve-control
```

Both processes need the verified TLS trust settings. Device admission remains
closed until authority reconciliation and the worker readiness handshake succeed.
The old combined `serve` command is development-only.

Issue and deliver a token through a secure channel; avoid shell arguments/logs:

```bash
umask 077
epochgrid-service --home ./epochgrid-state user-invite --handle alice > alice.enrollment
epochgrid --home ./alice-device --server tls://nats.example.org:4222 \
  identity enroll --device laptop < alice.enrollment
```

Remove the enrollment file after successful delivery/use according to your secret
handling policy. Invite lifetimes default to ten minutes and accept `--ttl` 1–3600
seconds. A token binds one canonical user to one device key; exact same-key retries
repair interrupted enrollment without allowing another key to reuse the token. Token
hashes, not bearer credentials, persist in `auth.sqlite`. No password database is used.
Enrollment tokens are redacted in debug formatting and zeroized where held by the
application. Normal reconnects send NKey possession proof, not the enrollment token.

The client prints its canonical UserId. Use canonical IDs for directory lookup and
revocation in this initial slice. Handles remain local-provider aliases; handle-based
UI resolution is not yet implemented. The service can issue another token for an
existing local handle without changing its UserId. Each new device generates separate
NATS and MLS keys. Existing legacy MLS credentials must not be renamed: use a fresh
canonical device installation and re-invitation when migrating an old fabric.

## State and current boundaries

A dedicated, migrated `auth.sqlite` stores users, bindings, token hashes, public device
registrations, readiness/revocation state and authorization generations. Its directory
is 0700, DB 0600, with WAL, foreign keys and a bounded busy timeout. It is currently a
single service-host registry; do not run replicas with independent copies. Broader
backend storage and cluster operation are not yet release-qualified.

Admission begins only after signed revocation history is reconciled. Revocation first
commits to the signed directory log and then denies registry admission. A crash between
these steps is repaired before devices can reconnect. Historical revoked bindings
remain available for log verification but never count as active admission records.
No dynamic code constructs BrokerControl, reads a static device user list, or writes
NATS configuration. Existing connections may remain usable until their claim expires;
this is bounded revocation latency, not immediate disconnection. Devices and backend
fail closed when fresh authorization cannot be obtained.

Device grants cover registration/audit/lookup/revocation/KeyPackage discovery, the
restricted enrollment endpoint, their own request/reply prefix and inbox, exact
authorized group subjects, and INFO/NEXT/ACK on their own CHAT/MAILBOX consumers.
They grant no cross-device inbox publication, raw CHAT reads, consumer management,
or general group wildcard. Attachment Object Store grants remain separate release
work; use the explicit static fixture to exercise the historical attachment demo.
Do not claim the alpha release gates are satisfied.

Auth Callout replay tracking uses the signed server ID and per-connection temporary
user key, the binding NATS itself enforces, rather than assuming a JWT ID is the
connection identity. Denials reveal no enrollment tokens. The protected auth account
and server-enforced request-subject publication deny are required trust boundaries;
a self-signed server JWT alone does not establish membership of a trusted fabric.

Milestone 22 synchronizes signed coordinator updates on
`epochgrid.v1.channel.policy` before publishing the associated MLS Commit and
Welcome. The control service owns membership-filtered CHAT consumers and relays
signed, opaque Welcomes on `epochgrid.v1.channel.welcome`. Clients never publish
directly to another inbox. Changing filters rebuilds the durable consumer and
replays matching history; local sequence deduplication preserves previously staged
messages. An empty group list uses a reserved filter that matches no valid group.
On startup or interrupted mutations, admission stays closed until durable lifecycle
state and filters are repaired. Unsafe existing MAILBOX filters fail closed.
See [the implementation design](../architecture/dynamic-authorization.md).

## Dynamic client walkthrough

First integrate the configuration above with your operator-owned NATS fabric and
start the service over verified TLS. Enroll Alice and Bob in separate client homes
using separately issued tokens. Keep each printed canonical `egusr-...` UserId;
commands currently use that ID rather than the local provider handle. A custom CA
requires `EPOCHGRID_TLS_CA_PATH` on each client and service process.

On Alice's installation, set `BOB_USER` to Bob's printed canonical UserId:

```bash
epochgrid --home ./alice-device --server tls://nats.example.org:4222 channel create engineering
epochgrid --home ./alice-device --server tls://nats.example.org:4222   channel invite engineering "$BOB_USER" --device laptop
```

On Bob's installation, set `ALICE_USER` to Alice's printed canonical UserId:

```bash
epochgrid --home ./bob-device --server tls://nats.example.org:4222   channel join --from "$ALICE_USER" --device laptop
epochgrid --home ./bob-device --server tls://nats.example.org:4222 tui
```

Run `tui` with Alice's home and the same server too. Inside the TUI, `/create NAME`,
`/invite USER DEVICE` and `/join USER DEVICE` use the same durable implementation.
Send messages, close either client and reopen it: local MLS state and filtered
JetStream history resume. The service receives only MLS ciphertext/protocol data.
Channel creation is local first; its authorization intent is synchronized on the
next invite/send/sync or TUI network tick. Interrupted network operations retain
queued work for retry.

For another device of Alice, issue a new token with the same `--handle alice`, enroll
with a distinct `--device workstation`, and invite that canonical user/device leaf.
An active Alice device can run `device revoke "$ALICE_USER" workstation`.
The device is denied on reconnect without editing NATS configuration. Existing
claims expire within the configured TTL; active coordinators remove its MLS leaves
on sync before sending future-epoch messages. Offline coordinators delay MLS
rekeying, and revocation never erases previously delivered plaintext.

`./scripts/dev/verify.sh dynamic-tui` is an isolated plaintext **development test**
of this dynamic path, including real terminal clients and offline catch-up. It
creates temporary operator configuration solely for the test; none of its device
NKeys are static NATS users. The TLS integration test separately exercises the
shared verified transport used by these commands.
