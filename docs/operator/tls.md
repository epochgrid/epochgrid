# Production TLS profile — Milestone 23

The shared TLS profile and live validation are implemented. This transport
milestone does not complete Milestone 22's dynamic messaging integration. See the
[current status and validation summary](../milestones.md).

## Design

All EpochGrid-owned NATS connection paths must share one TLS policy, including
normal client reconnects, enrollment-token connections, the backend control
connection and the Auth Callout listener. The default profile is production.
Production requires an explicit `tls://` endpoint and `require_tls(true)` on the
NATS connection options, so discovered/reconnected endpoints cannot downgrade it.
Certificate verification uses rustls and the endpoint hostname/IP SAN; there is
no insecure verifier, hostname override or plaintext fallback.

Configuration is shared by `epochgrid` and `epochgrid-service`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `EPOCHGRID_PROFILE` | `production` | `production` or explicitly `development` |
| `EPOCHGRID_TLS_CA_PATH` | unset | PEM trust bundle; replaces system roots for this process |
| `EPOCHGRID_TLS_MIN_VERSION` | `1.3` | `1.3`, or `1.2` to allow both TLS 1.2 and 1.3 |
| `EPOCHGRID_TLS_FIRST` | `false` | Set `true` only when the NATS listener uses TLS-first |
| `EPOCHGRID_NATS_URL` / `--server` | local development address | Use `tls://nats.example.org:4222` for production |

Unknown values, invalid/empty bundles and unsupported schemes fail closed. An
explicit development profile permits `nats://` fixtures and emits a warning;
TLS endpoints still verify certificates in development. The static backend fixture
also requires `--dev-static`. Dynamic plaintext fixtures additionally require
`auth.json.development_plaintext=true`; that setting is rejected in production.
No private client key is reused as a TLS identity. mTLS is not required here.

## Operator-owned configuration

Add TLS to the appropriate existing client listener; do not replace the fabric's
accounts, authorization or cluster configuration:

```text
tls {
  cert_file: "/etc/nats/tls/server-chain.pem"
  key_file: "/etc/nats/tls/server-key.pem"
  min_version: "1.3"
}
```

The certificate SAN must match the endpoint DNS name, including any server names
advertised for reconnect/discovery. Connecting to an IP requires
that IP in the certificate's IP SAN. A custom CA does not bypass hostname checking.
NATS's standard handshake begins with public INFO metadata, then TLS protects
CONNECT credentials and subsequent traffic. TLS-first additionally encrypts that
initial metadata; configure `handshake_first: true` on the NATS TLS block and
`EPOCHGRID_TLS_FIRST=true` on every relevant EpochGrid process.

```bash
export EPOCHGRID_PROFILE=production
export EPOCHGRID_NATS_URL=tls://nats.example.org:4222
# Omit for certificates issued by an OS-trusted CA:
export EPOCHGRID_TLS_CA_PATH=/etc/epochgrid/fabric-ca.pem
epochgrid-service --home /var/lib/epochgrid serve --auth-config /etc/epochgrid/auth.json
```

Set the same transport variables for client enrollment and subsequent client use.
Do not put enrollment tokens, NKey seeds or TLS private keys in endpoint URLs.

## Rotation and compatibility

Leaf certificate rotation under an already trusted CA is accepted on subsequent
TLS handshakes; automatic reconnect retains certificate/name verification and the
minimum TLS version. EpochGrid does not reload or restart an adopter's NATS server.
An operator reload to install rotated certificates is a TLS maintenance operation,
not a requirement of device admission or revocation.

For CA rotation, distribute a bundle containing both old and new CAs, restart the
EpochGrid processes to load that trust configuration, rotate the NATS certificate,
then remove the old CA and restart the EpochGrid processes again. Existing
connections do not hot-reload trust files. Restart does not recreate MLS groups.
TLS session settings do not enable early application data (0-RTT).

async-nats 0.50.0 re-exports rustls and accepts a custom ClientConfig. Its connector
uses the endpoint host for verification and honors required TLS on reconnect.
The pinned version also attempts native root loading even with a custom config;
errors from that platform loader fail the connection rather than bypassing trust.
Keep a working platform certificate-store installation on the host.

References: [NATS TLS configuration](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/tls)
and [async-nats connection options](https://docs.rs/async-nats/0.50.0/async_nats/struct.ConnectOptions.html).


For handshake failures, check the certificate chain, SAN and trust-bundle path
first. An EOF or timeout can also indicate a TLS-first mismatch; both ends must
use the same handshake mode. Never resolve these errors by disabling verification.
The tests generate short-lived fixtures with OpenSSL and do not install their CAs
into the host trust store. The NATS integration suite exercises the actual client
and service binaries in production mode even though older fixtures use development.


Live regression coverage verifies custom-CA enrollment and registration, native
trust loading, wrong CA and wrong hostname rejection on both binaries, production
plaintext/development-setting rejection, preserved trust checks in development,
TLS-1.2-only peer rejection by the default TLS 1.3 minimum, explicit TLS 1.2
negotiation, retained-connection leaf rotation, and TLS-first client/service restart.
