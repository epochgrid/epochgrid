# Milestone 34 — release publication and supply-chain verification

**Implementation started; release acceptance remains pending.** Current delivery status remains in the
[roadmap](milestones.md). This plan builds on milestone 32's
[Linux bundle contract](operator/linux-artifacts.md) and milestone 33's
[candidate-image plan](https://github.com/epochgrid/epochgrid/blob/1a42ed7/docs/milestone-33-plan.md).
Implementation must reconcile with the merged milestone 33 interfaces and evidence.
Planning authorizes no publication, tag creation or repository/package setting change.

### Implementation progress — 2026-11-11

Implementation now includes `release.yaml`, the shared qualification receipt,
strict release identity/manifest validation, compiled/native inventory capture,
SPDX schema checks, pinned vulnerability scanning, signed consumer verification,
protected draft/publish operations, collision/resume handling, and durable signed
distribution receipts. The operator contract is in [release operations](operator/releases.md).
The workspace is versioned `0.1.0-engineering.1`; this does not publish a release.

Rehearsal is read-only and retains a proposed manifest with an unset registry
digest. Publication requires fresh native/bundle/image qualification, reviewed
vulnerability dispositions and native coverage, a fresh candidate registry pull,
and the hosted protection settings. Only then can the workflow sign and promote
exact bytes. The consumer command requires the final durable distribution proof,
not just build provenance. No hosted signing or publication has been performed.

Hosted acceptance is blocked by the missing `release` environment, disabled
immutable Releases, the short-lived settings-read credential setup, outstanding
milestone 33 candidate transport, and the absence
of a reviewed vulnerability assessment. The real local Rust/native inventory scan
reported 11 findings across SQLite and rustls; they have not been accepted or
waived. Local tests and explicitly local artifacts are not hosted release evidence.
See the roadmap and handoff for validation results and the retained keyring failure.

## Outcome and boundaries

Provide a manually invoked path from one qualified main revision to a versioned
GitHub prerelease and GHCR image, with signed provenance and a consumer verifier
that rejects an unexpected publisher, revision, workflow or artifact digest.
Promote the exact qualified archive and image; never rebuild during promotion.

Keep Ubuntu 24.04 x86-64, Linux native container UID mapping, separate backend
accounts/keyrings, SQLCipher, peer-UID checks and operator-owned NATS unchanged.
This milestone adds distribution trust and durable evidence, not runtime features,
new platforms, an installer, automatic upgrades or reproducible-build claims.
TD-001/002/003 remain open. Signing does not establish that software is safe.

Milestone 34 may qualify publication with an explicitly authorized engineering
prerelease. It does not declare alpha readiness: milestones 35–38 must supply
adversarial, compatibility and operator-workflow evidence for that supported scope.
Initial automation refuses stable releases, `latest`, and moving major/minor aliases.

## 1. Fix release identity before building

Use a protected-main manual workflow, proposed as `.github/workflows/release.yaml`.
Resolve main once to a full SHA, record it, and use that checkout in every job.
Reject other dispatch refs, fork repositories, dirty/local candidates and arbitrary
artifact URLs or run IDs. Main advancing afterward does not change the selected SHA.
The workflow definition and selected source must belong to that same main revision.

Require an explicit SemVer prerelease version without build metadata; Git tag and
GHCR tag are both `v<VERSION>`. Workspace version, Cargo lock metadata, both binary
version outputs, bundle metadata and image labels must agree before publication.
Version changes belong in a reviewed main commit before dispatch. Do not stamp a
new version into already-built binaries or reinterpret protocol/storage versions.

Keep the existing candidate archive filename and internal layout as release assets;
the containing release identifies its promotion. This preserves the exact qualified
archive checksum and avoids inventing a second packaging format.

Create a strict, versioned `RELEASE.json` manifest recording:

- Release version/tag, repository identity, selected full commit and source digest.
- Workflow path/revision, run ID/attempt, target/platform and verification-policy version.
- Archive filename/size/SHA-256, `BUILD.json` hash and both executable hashes.
- GHCR repository and registry manifest digest, image config ID, base digest and
  transport checksum as distinct fields.
- Exact names and hashes of qualification reports, SBOMs and shipped notices;
  build/toolchain/lockfile identity through the referenced build manifests.
- Supported scope, known limitations and the explicit release-readiness decision.

Reject unknown schemas, duplicate asset names, unsafe paths and inconsistent
identities. The manifest cannot hash itself or its own signature; publish its
attestation separately. Release notes summarize this evidence without replacing it.

## 2. Build once, qualify, then promote

Reuse milestone 32/33 build and qualification logic. The release run builds the
selected clean main revision, verifies its Linux bundle, constructs its image,
and runs the normal regression gate plus all five bundle suites and all six image
checks. Bind every passing report to the same source and appropriate payload hashes.
Failed, missing, skipped, cancelled or mixed-revision results block promotion.
Preserve existing case deadlines, quarantine boundaries and failure evidence.

Do not consume PR merge-candidate builds or expired Actions artifacts. Moving
qualified bytes between jobs requires hash verification and allowlisted contents.
No compilation, repackaging or image rebuilding is permitted in publishing jobs.
If evidence expires, start a new complete build/qualification run.

Use milestone 33's unique candidate tag and registry round-trip check to establish
the registry digest. Attest that digest, verify on a fresh runner, and only then
add the version tag to the same manifest. Verify that tagging preserved the digest.
The versioned Git tag must point to the selected source SHA, never the current head
resolved again at publication time.

## 3. Signed provenance and verification policy

Use GitHub artifact attestations with short-lived Actions OIDC identity as the
initial signing mechanism; no maintained private signing key or long-lived PAT.
Attest the archive, registry image digest and final release manifest. Generate build
provenance in the workflow that actually built the subjects; identify the final
manifest as release metadata rather than claiming it compiled the software.
Keep build and qualification evidence distinct. Use a documented custom predicate
if binding promotion evidence requires claims beyond generated build provenance.

GitHub supports binary/image provenance and signed SBOM attestations; availability
depends on repository visibility and plan. Confirm support before implementing the
hosted proof; unavailable signing blocks release rather than falling back unsigned.
See [GitHub's attestation workflow requirements](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

Check cryptographic verification before consuming any claimed metadata. The policy
must require the expected repository/owner (and stable repository ID), trusted
issuer, approved signer workflow, main source ref, selected source commit, expected
predicate type and exact subject digest. A valid signature from a different workflow
or a fork is insufficient. Compare signed release evidence with verified build
provenance and actual downloaded contents. Do not trust unsigned JSON parsing as
proof that an attestation was verified.

Implement a small wrapper around a pinned, tested GitHub CLI verification version;
use its identity/source restrictions and machine-readable verified output where
needed. Document required tooling, registry authentication and explicit failures.
The CLI supports artifact/OCI verification and downloaded attestation bundles;
see its [verification reference](https://cli.github.com/manual/gh_attestation_verify).
Online verification is required for initial acceptance. Archive downloadable
attestation bundles for evidence; offline trust-root distribution is deferred.

Publish SPDX JSON inventories for the compiled Rust dependency graph and image OS
packages, including statically bundled SQLCipher/OpenSSL and other nested native
components. Distinguish build-only dependencies from shipped runtime components.
Validate the schema, tool versions, coverage and linkage to exact subjects; retain
milestone 32 license/notices checks. An SBOM does not certify absence of vulnerabilities.
Record a dated vulnerability assessment and reviewed dispositions before publication;
unreviewed findings block the release decision. Automatic vulnerability remediation
and a claimed SLSA level are outside this milestone.

## 4. Publication permissions and durable evidence

PR jobs remain read-only. Pin third-party actions by reviewed commit and tools by
version/checksum. Scope `id-token: write` and `attestations: write` to attestation
jobs, `packages: write` to image publication/registry-attestation jobs, and
`contents: write` to Git tag/Release publication. Build/test jobs receive no
publication credentials. Never expose these privileges through untrusted PR code
or interpolated dispatch input. Use the repository's protected release environment
and serialize publication so concurrent runs cannot claim the same version.

Preflight repository ownership, environment/ruleset protection, token access,
package visibility and release immutability. Record missing settings as setup work;
do not change them implicitly. Require immutable GitHub Releases for the public
release path. GitHub recommends preparing all assets in a draft before publication
locks assets and the tag; see [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).
GHCR tags remain references: consumers deploy by verified digest.

Create a draft containing the exact archive, checksums, `RELEASE.json`, SBOMs,
sanitized qualification evidence and downloadable attestations. All required evidence
must survive the seven-day Actions retention window as release assets or persisted
registry attestations. Exclude credentials, homes, caches and private fixture state.
GitHub-generated source archives are not the qualified executable distribution.

Before making the prerelease visible, a fresh job downloads the draft assets and
pulls the versioned image by digest, verifies signatures/policy/hashes, extracts via
the strict bundle verifier and checks both binaries' help/version. It compares the
image payload with `BUILD.json`. After publication repeat retrieval/verification
through the documented consumer path and record the immutable release identity.
Public artifacts require an unauthenticated download/pull check; private artifacts
require a minimally scoped consumer credential. Visibility must match the agreed
distribution contract, not change to make a test pass.

## 5. Partial failures and recovery

Publication spans GitHub and GHCR and is not atomic. Record each completed side
effect and its identity. A failed attestation, upload or verification leaves an
incomplete candidate/draft; never emit release success or promote it automatically.
Use an authenticated run record to distinguish this run's existing objects from
collisions. Refuse existing versions/tags/assets by default, even if names look right.

Provide an explicit resume path only for the same run's exact verified bytes and
evidence, with read-back checks at every step. Never overwrite an asset, move a tag,
delete an existing release or rebuild underneath the same version. If safe resume
is impossible, preserve evidence and require a new reviewed version/run. Test lost
responses after successful writes as well as failures before writes.

Document withdrawal/advisory handling for a bad release and selection of a previously
verified digest. Rolling back binaries does not make encrypted database schemas
backward-compatible. Preserve operator homes/keyrings and existing migration rules.

## 6. Acceptance and implementation order

| Gate | Required evidence |
| --- | --- |
| Identity | Version/source agreement; reject dirty/local, PR-ref, stale and mixed-run inputs |
| Qualification | Cold hosted normal, bundle and image gates pass for one selected main SHA |
| Authenticity | Real archive/image/manifest attestations accepted only by the expected policy |
| Rejection | Altered payload/manifest, wrong digest/source/ref/workflow/repository/issuer, missing signature and wrong predicate all fail before execution |
| Supply-chain inventory | Valid subject-bound SBOMs, native dependency/notices coverage and recorded vulnerability dispositions |
| Permissions | PRs cannot publish; non-main dispatch fails; only designated jobs can sign/publish |
| Recovery | Collision, concurrent dispatch, expired evidence, partial upload and interrupted resume cannot replace released bytes |
| Distribution | One explicitly authorized engineering prerelease survives fresh consumer verification; durable assets and registry evidence match |
| Documentation | Binary and image verification, authentication, release policy, failure recovery and support limits exercised from the published artifacts |

1. Implement strict release manifest/version/policy validation and negative fixtures
   in proposed `scripts/release/release.py` and `test-release.py`.
2. Share qualification workflow logic with PR/candidate paths; add read-only release
   rehearsal producing a complete proposed manifest and asset list without writes.
3. Add provenance/SBOM generation and the consumer verifier; test actual hosted
   signing and negative identity cases, not only mocked API success.
4. Add protected publication, collision/resume handling and draft verification;
   extend the normal harness with meaningful rejection and recovery tests.
5. Add `docs/operator/releases.md`, link existing bundle/container guides, update
   CI documentation and run one explicitly authorized prerelease round trip.

Implementation can begin while milestone 33 finishes CI, but final hosted acceptance
depends on its merge and qualified candidate publication. Milestone 34 is complete
only with the hosted distribution/signature evidence above. Until then report
planning, implementation, rehearsal and publication separately in the roadmap.
