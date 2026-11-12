# Milestone 36 — protocol and configuration compatibility freeze

**Planned; implementation and freeze acceptance have not started.** The
[roadmap](milestones.md) owns delivery status. This plan defines the compatibility
commitments needed for the supported release scope; it does not declare the
current pre-release formats stable or close milestones 34–35.

## Outcome and prerequisites

Produce a reviewed compatibility contract, fixed reference fixtures, an explicit
upgrade matrix and executable regression gates. An operator must be able to tell
whether a binary can read a home, communicate with its peers and use the broker
configuration before starting a state-changing operation.

Planning and inventory work can proceed now. Freeze acceptance requires milestone
35's [supported-scope decision and adversarial evidence](milestone-35-plan.md)
and disposition of compatibility-relevant findings. Milestone 35 acceptance does
not depend on a completed compatibility freeze; there is no circular gate.
Distribution of the frozen baseline also requires milestone 34's actual hosted
release acceptance. Record exact revisions and evidence; a milestone number, package
version or passing development test is not a qualified compatibility baseline.

Retain Ubuntu 24.04 x86-64, Linux Secret Service, SQLCipher, separate authority and
worker accounts, local peer-authenticated IPC, verified TLS and operator-owned
NATS. Keep configuration/operator-JWT and R1/R3 qualification. Dynamic attachments and
short-lease messaging gain no support promise from this plan: milestone 35 must
qualify the claimed scope or obtain an explicit, enforceable narrower scope decision.
Live typing stays deferred under TD-001 until after alpha milestones. TD-001/002/003
remain open until their own completion criteria are met.

### Division of work with milestone 35

Milestone 35 owns hostile-input behavior, authorization/state invariants,
same-version crash/reconnect recovery, bounded fuzzing and the cold-run reliability
sample. This milestone owns canonical historical fixtures, version policy,
old/new binary combinations, migrations and downgrade refusal. Reuse milestone
35's corpus, fault hooks and assertions; add version-specific expectations rather
than duplicating the adversarial suite. Its handoff supplies supported/excluded
scope, findings, candidate identities and security-driven semantic changes.

A security fix takes precedence over preserving unsafe historical behavior. If
compatibility work changes a tested security boundary, rerun affected milestone
35 cases on the new candidate and update its evidence before freeze acceptance.
Unchanged tests may be reused by the shared gate; evidence from an older revision
must not be relabeled as qualification of changed code. Neither milestone closes
the other's acceptance checklist automatically.

## 1. Inventory independently versioned contracts

Add `docs/compatibility.md` during implementation as the normative compatibility
index. For every surface, record producer/consumer, version discriminator, accepted
versions, limits, canonical encoding, unknown-field behavior, side effects on
rejection, upgrade owner and supporting fixture/test. Link owning documentation
instead of duplicating it. The following are inventory starting points, not a
completed audit:

| Surface | Current source and behavior to reconcile |
| --- | --- |
| Public request/reply | `wire.rs`, [protocol](protocol.md): postcard envelope v1, Body tags 0–23, subjects, identifiers, bounds and rejection semantics |
| Signed records | Registration, transparency/revocation checkpoints, group policies and Welcome relay: exact field order, domain separators, key roles and replay rules |
| MLS and application traffic | MLS ciphersuite/TLS framing, group IDs, application envelopes, attachments, receipts, relationships and ephemeral messages; distinguish supported operations from development-only formats |
| Broker resources and authorization | [Resource contract](deployment-resource-contract.md), exact grants, consumer names/filters/ACK behavior, deployment manifests and qualified NATS version |
| Backend IPC | [Role contract](backend-role-contract.md): framing/version, readiness, sequence rules, peer UIDs, deadlines and lease behavior; status socket is a separate surface |
| Operator configuration | Auth configuration, role bindings, runtime permissions, capacity, deployment export, TLS/profile settings, paths and environment/CLI precedence |
| Protected state | Database/keyring binding metadata, authority schema 3, local schema 8 and OpenMLS migration version 6; validate these observations against code before freezing |
| Recovery and exports | Recovery archive v2, administration-only recovery limits, audit event/export schemas and retention semantics |
| Machine interfaces | Validation/diagnostic JSON, audit output, stable error codes, script-facing CLI flags and exit status; inventory release manifest/consumer formats from milestone 34 separately |

Do not assume all JSON has the same extensibility rules. Identify strict and
extensible documents individually, including duplicate keys, missing fields,
unknown fields and invalid numeric values. A version-one on-disk deployment
manifest plus explicit capacity policy currently loads as an effective version-two
contract; document that distinction without silently rewriting operator files.
Resolve contradictions between code and documentation before approving the freeze.

## 2. Define the compatibility policy

- Keep package SemVer, wire/IPC versions, schema migrations, configuration versions
  and export versions independent. A package patch must not silently reinterpret
  signed bytes, change grants or make supported persistent state unreadable.
- Establish one named initial baseline at an exact reviewed revision. No blanket
  promise covers all earlier engineering builds or future versions. Every release
  declares its supported predecessor revisions and upgrade edges; an omitted edge
  is unsupported.
- Preserve existing postcard enum indices, field order, signing domains and
  canonical bytes within a frozen format. Appending a variant can still break an
  older peer's behavior; require an explicit mixed-version decision and tests.
- Treat changed defaults, limits, resource semantics, authorization and error
  handling as compatibility changes even when serialization is unchanged. No
  fallback may broaden grants, weaken TLS, omit audit or open admission early.
- Reject unsupported versions and malformed inputs with bounded, sanitized errors.
  Authenticate security-sensitive decisions; version metadata alone grants no
  authority. Do not add unauthenticated capability negotiation to bypass rejection.
- Default backend upgrades to a coordinated stop/start of authority and worker.
  Mixed backend versions and rolling upgrades are unsupported unless specifically
  implemented and proven. Define client/service combinations per operation; never
  infer compatibility merely because both advertise wire v1.
- Document deprecation and removal per surface in release notes. A breaking change
  requires an explicit format/version or migration decision and reviewed support
  matrix update, including during prereleases. No silent schema rollback.

## 3. Preserve reference bytes and semantics

Create a versioned fixture corpus with a manifest of source revision, format,
expected result and SHA-256. Use synthetic identities and test-only credentials;
never production keyrings or private user state. Keep expected bytes checked in
and reviewed independently of the serializer being tested. Routine tests must not
regenerate expected outputs from current code.

Cover every wire variant, signed record/domain, supported application envelope,
IPC operation and public configuration/report schema. Decode known bytes and
compare expected fields; encode known values and compare exact bytes where
canonical encoding is part of the contract. For signatures and MLS, retain valid
reference material plus controlled clocks for expiry tests; do not disable lifetime
checks to make old fixtures pass. JSON comparisons should test defined semantics
unless ordering itself is signed or otherwise contractual.

Negative cases include unknown versions/tags, reordered or altered signed fields,
cross-domain signature reuse, trailing/truncated data, duplicate/unknown JSON keys,
out-of-range bounds, wrong roles/UIDs and unsupported configuration combinations.
Assert rejection has no unintended credential creation, migration, broker mutation,
ACK, ratchet advancement or admission success, as applicable to each entry point.
Security fixes to unsafe historical behavior take priority over byte compatibility
and require a documented breaking-change decision.

## 4. Qualify upgrades and refusal paths

Select at least one real predecessor revision with encrypted state and separate
backend roles. Record its source and build identity. Synthetic migration fixtures
supplement that executable baseline; they do not establish binary interoperability.
If no predecessor is supportable, explicitly choose fresh enrollment as the initial
release policy and demonstrate safe rejection of old homes instead of promising
an untested upgrade. Older binaries may already lack future-schema guards: do not
claim that a new guard retroactively makes every old executable safe.

| Case | Required result |
| --- | --- |
| Fresh frozen-baseline deployment | Offline/online validation and supported end-to-end workflows pass for both NATS modes at R1/R3 |
| Selected predecessor to candidate | Each declared supported configuration/state migration succeeds; unsupported combinations refuse before mutation |
| Old client/new service and new client/old service | Per-operation supported results or documented bounded rejection; no accidental enrollment or privilege expansion |
| Authority/worker mismatch | Supported pairing is tested or incompatible pairing refuses without opening admission |
| Future/unknown state or configuration | No reset, repair, overwrite or partial migration; existing identity and state remain inspectable with appropriate tooling |
| Interrupted upgrade | Inject failures at transaction and cross-file/keyring boundaries; restart either completes an explicit idempotent step or reports actionable recovery |
| Downgrade/restore | Document refusal and supported recovery boundaries; prove the stated path without reusing stale MLS ratchets or replaying already-consumed state |

Inventory existing explicit capacity and audit upgrades and automatic client
migrations before changing behavior. Preserve identity keys, trust checkpoints,
revocation cutoffs, audit sequence/coverage, deduplication markers, pending outbox
bytes, MLS state and transcript contents across each supported upgrade. Exercise
offline backlog and pending operations, not only empty freshly initialized homes.
Read-only validation must remain free of migration/initialization side effects.

An encrypted database copy alone is not a recovery promise: account/keyring
bindings and consistent local state are required. Administration recovery excludes
history and MLS ratchets. Do not propose generic snapshot rollback of active MLS
state. Plaintext homes, recovery v1, remote IPC, backend HA and platform expansion
remain outside this milestone.

## 5. Implementation sequence and evidence

1. Inventory code, docs and test coverage; resolve milestone 35 scope and record
   the initial baseline and proposed support matrix in `docs/compatibility.md`.
2. Add the fixed corpus and focused compatibility tests. Correct parser/version
   guards and documentation gaps without adding unrelated runtime features.
3. Implement only the migrations or refusal paths required by approved upgrade
   edges. Add realistic predecessor, interrupted-upgrade and mixed-version cases.
4. Integrate bounded compatibility checks into the existing verification harness
   and aggregate CI gate. Reuse native/bundle/image qualification, with exact old
   and new binary identities retained; do not substitute current binaries for old.
5. Update protocol, configuration and operator upgrade documentation. Record dated
   hosted results, commands, artifact identities, failures and unsupported cases.
   Supply milestone 37 with setup/version diagnostics and milestone 38 with tested
   upgrade/recovery procedures.

Use focused unit/fixture checks for parser changes, then the relevant protected
storage, role-isolation and BYO suites. Run retained native regressions and all five
extracted-bundle and image suites plus the image role-boundary proof for the final
candidate. Add the compatibility matrix to hosted qualification; local successes
alone do not close acceptance. Preserve existing deadlines, quarantines and failing
evidence; do not add blanket retries or silently skip unavailable baseline tests.

## Completion checklist

- [ ] Supported scope and milestone 35 findings are explicitly dispositioned.
- [ ] Contract inventory has no unresolved version/encoding/security ambiguities.
- [ ] Named baseline, independent version policy and supported upgrade edges are reviewed.
- [ ] Fixed positive/negative fixtures cover the frozen surfaces and run in required CI.
- [ ] Real predecessor, mixed-version, state-preservation and interruption evidence
      supports every claimed upgrade edge; exclusions have tested safe refusal paths.
- [ ] Final hosted native, bundle, image and compatibility gates pass on recorded identities.
- [ ] Protocol/configuration/upgrade docs agree with tested behavior; milestones
      37–38 have concrete inputs and open limitations.
- [ ] Freeze record links exact source, corpus and hosted evidence to the milestone
      34 verified distribution baseline; no unpublished artifact is called a release.

Only then mark milestone 36 frozen in the roadmap. Later compatibility changes
must update the contract, matrix, fixtures and release notes together.
