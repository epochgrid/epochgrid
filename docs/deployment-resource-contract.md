# Milestone 27 resource comparison rules

The pure `epochgrid_core::deployment` module now supplies `auth-init` and
`deployment-export`. Atomic artifact publication and explicit mode/account/R1–R3
initialization are implemented. [Offline validation](operator/validation.md) checks
the manifest and existing local state. Online inspection and production startup
use the same comparison rules for existing application-account resources. Production
startup refuses missing/incompatible resources before device admission and never
creates or changes them. See the [implementation plan](milestone-27-plan.md).

`DeploymentManifest` serializes as `{"version":1,"replicas":3}` (R1 is also
supported). Unknown versions, unknown/duplicate fields and other replica counts
are rejected. Setup/export persists it beside `auth.json` as `deployment.json`;
existing homes without a manifest must explicitly declare replicas during export.
The existing authentication schema is unchanged.

The renderer returns this manifest and five native JetStream stream CREATE JSON
documents: `CHAT.json`, `MAILBOX.json`, `KV_IDENTITIES.json`, `KV_CHANNELS.json`,
and `KV_TRANSPARENCY.json`. KV backing streams use the native history-one KV
configuration (rollup, deny-delete, direct reads and discard-new). They can be
applied as stream configurations by an application-account administrator. All four
BYO fixtures now consume generated resources and mode-specific integration artifacts.
See [setup/export commands](operator/auth-callout.md#commands-and-configuration).

Comparison takes the requested resource name independently of the observed INFO
configuration. It returns all differences with resource, field, expected and
observed values. It does not mutate configurations or contact NATS.

| Fields | Compatibility rule |
| --- | --- |
| Name and subjects | Exact resource name and exact subjects from the BYO contract; subject order ignored, duplicates rejected |
| Storage, retention, replicas | File, limits, explicit manifest R1/R3 on all five resources; zero is not implicit R1 |
| CHAT/MAILBOX and TRANSPARENCY message size | Exactly 65536 bytes |
| IDENTITIES/CHANNELS message size | Unlimited (`0`/`-1`) or at least 65536 bytes |
| Per-subject messages | KV exactly 1; CHAT/MAILBOX unlimited (`0`/`-1`) |
| Discard policy | CHAT/MAILBOX old; KV new; discard-new-per-subject disabled |
| Age, message TTL, delete-marker TTL, schedules, counters, pause | Disabled/absent; history cannot expire or be transformed by these features |
| Mirrors, sources, subject transforms, republish | Absent; empty sources list is equivalent to absent |
| Acknowledgments and persistence | Acknowledgments enabled; persistence absent/default, never asynchronous |
| Sealed, template owner, mirror-direct | Disabled/empty |
| Rollup | Enabled for KV only |
| KV deny-delete, deny-purge, direct reads | True, false, true respectively |
| Consumer limits | No inactivity eviction; max pending must be at least -1 (finite positive limits are capacity choices) |
| Total bytes/messages and consumer count | Operator-selected finite budgets preserved; `0`/`-1` accepted as unlimited; values below -1 rejected |
| Description, metadata, placement, compression, duplicate window, first sequence | Preserved; do not determine resource compatibility |
| CHAT/MAILBOX delete/purge restrictions and direct reads; atomic/batch publishing | Preserved; do not alter the required publishing/consumer path |

Finite budgets with discard-old may evict history at capacity. A compatibility
pass does **not** establish capacity adequacy or a retention-duration guarantee.
The validator must report this limitation. Replica health, server version/payload,
KV bucket status, account configuration and inspection coverage require online
checks; none are inferred from configuration equality.

The async-nats 2.11, 2.12 and 2.14 field features are enabled so INFO decoding
retains TTL, scheduling and counter settings instead of silently discarding them.
This does not broaden the qualified server target beyond NATS 2.14.5.

Tests use independent INFO configuration fixtures, check generated artifacts
against those fixtures, exercise field-by-field rejection on all resources, and
verify compatible operator settings remain untouched. These unit results do not
replace the four production-TLS qualification cases or cold CI evidence.
