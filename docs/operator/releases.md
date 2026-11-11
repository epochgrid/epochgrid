# Engineering prereleases and consumer verification

Milestone 34 supplies a manually invoked release path for Ubuntu 24.04 x86-64.
See the [roadmap](../milestones.md) for actual hosted acceptance. An engineering
prerelease is not an alpha readiness declaration. TD-001/002/003 remain open;
dynamic attachments and short-lease messaging remain outside qualified scope.

## Review and prepare a release

The workspace prerelease version, Cargo lockfile, binaries, bundle and image must
agree. Version changes are reviewed source changes; promotion never stamps or
rebuilds binaries. The initial version is `0.1.0-engineering.1`. The 2026-11-11 local scans found
11 Rust/native findings and 19 combined image findings; these are unreviewed
scanner results, not exploitability conclusions or accepted release risk. See the
[dated local scan](../archive/milestone-34-local-scan.json) for the sanitized findings. No stable release,
`latest`, moving major/minor alias or alternative platform is supported.

The workflow `.github/workflows/release.yaml` accepts manual dispatch on protected
main only. The dispatch SHA selects both source and workflow. Rehearsal uses the
same CI workflow as PR qualification: native regression, five extracted-bundle
suites, five image suites and the separate-role boundary proof must all pass.
Every report is checked against that source and the appropriate payload hash.
A failed, skipped, cancelled, missing or foreign report blocks progress.

First dispatch with `mode=rehearse` and the exact workspace version. This path
has read-only repository credentials. It builds the bundle and image once,
assembles sanitized qualification reports, generates SPDX inventories, scans them
with the pinned Grype version and retains `release-proposal-SHA` for seven days.
`PROPOSAL.json` has no registry digest and is deliberately not a signed release
manifest. Rehearsal never creates registry tags, Git tags or Releases.

Inspect both vulnerability scan files and the inventory, including build-only
Rust dependencies and the separately recorded SQLCipher, SQLite, OpenSSL and
ring-vendored native source. Scanner coverage is not proof of absence of native
vulnerabilities; review nested native components explicitly. SPDX schema validation
checks structure, while the manifest binds the inventories to the exact archive
and image config ID. The final registry digest is separately bound to that config.

Place reviewed dispositions in `docs/release-review.json` through normal source
review. The schema is:

```json
{
  "schema": 1,
  "reviewed_on": "YYYY-MM-DD",
  "reviewer": "reviewer identity",
  "native_review": [
    {
      "name": "SQLCipher",
      "version": "exact inventory version",
      "source_sha256": "exact inventory source hash",
      "rationale": "Native vulnerability review evidence"
    }
  ],
  "dispositions": [
    {
      "id": "CVE identifier from scan",
      "package": "exact scanned package name",
      "version": "exact scanned package version",
      "decision": "not-affected",
      "rationale": "Evidence supporting this decision"
    }
  ]
}
```

Use `accepted-risk` only with a concrete reviewed rationale. The review must be
no older than seven days at finalization. Its finding set must exactly match the
fresh scans; new, removed, duplicate or unreviewed findings block publication.
An empty disposition list is valid only when both scans contain no findings.
`native_review` must cover every recorded native component, version and source
hash, including SQLite, OpenSSL and ring-vendored crypto as well as SQLCipher.
Do not copy the example into main as a claim that a review has occurred.

## Required hosted settings

Before publishing, an administrator must configure and verify:

- Public repository `epochgrid/epochgrid`, stable repository ID `1360374944`,
  protected default branch `main`, and reviewed release code on that branch.
- A `release` environment restricted to protected branches. Any additional
  organization-configured environment reviewer rules remain enforced by GitHub.
- Immutable GitHub Releases enabled.
- A short-lived, repository-scoped `RELEASE_SETTINGS_TOKEN` secret with
  administration-read permission, supplied before publication dispatch. It is
  used only for the immutable-release settings GET; writes still use the
  job-scoped `GITHUB_TOKEN`. Do not provision a long-lived PAT or a signing key.
  Use a short-lived GitHub App installation token with enough remaining lifetime
  for the run; expiration fails closed. Rehearsal needs no settings credential.
- Public GHCR package `ghcr.io/epochgrid/epochgrid`, owned by epochgrid, linked
  to this repository, with Actions push/read access; milestone 33's candidate
  transport round trip must already be qualified.
- GitHub artifact attestations available for the repository and the intended
  Actions token scopes permitted by repository/organization policy.

The workflow checks these settings and fails rather than changing them.
GitHub's [immutable-release settings endpoint](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository)
requires administration-read access, which is unavailable through ordinary
`GITHUB_TOKEN` workflow permissions. This is why the separate read-only credential
is required. Its value is never written into evidence or used for publishing. On
2026-11-11 the repository had no `release` environment, immutable releases were
disabled, and no manually dispatched candidate run was recorded. Those are
outstanding hosted acceptance prerequisites, not successful publication evidence.
Initial milestone 34 automation supports public distribution only.

After reviewing rehearsal evidence and settings, explicitly dispatch `mode=publish`
with `confirm_public_distribution=true`. This rebuilds and requalifies the selected
main SHA in that publication run; it does not consume arbitrary prior artifacts.
Within the run, qualified bytes are only transported and promoted. Protected jobs
push the unique candidate tag, verify its digest on a fresh runner, sign archive,
image digest and release metadata, create a draft and verify downloaded draft
assets on another runner before publishing. The final job rechecks signatures,
help/version and image payload, publishes the immutable prerelease and checks
public asset retrieval. A final signed distribution receipt is persisted in GHCR
and checked through the consumer policy, so that evidence survives Actions artifact
expiry. The release run is incomplete until this receipt verifies. No publish job compiles or repackages application bytes.

Only attestation jobs receive OIDC/attestation write permissions, only image
publication receives package write, and only draft/release jobs receive contents
write. PR jobs remain read-only. Publication is serialized and never cancelled
by another release dispatch.

## Verify as a consumer

Use a trusted checkout of the verification scripts (review its revision separately
from the downloaded release). Python 3.11+, `jsonschema`, GNU `readelf`/binutils and
GitHub CLI 2.100.0 are required. The checksum-pinned installer can install `gh`
into a new directory:

```sh
python3 scripts/release/install-tools.py --output /tmp/epochgrid-release-tools gh
export PATH="/tmp/epochgrid-release-tools:$PATH"
```

Obtain the expected full source commit and version from the reviewed release
announcement. Download its assets into a new directory using GitHub Releases.
Do not execute the downloaded binaries before verification. Run:

```sh
python3 scripts/release/verify-release.py \
  --assets /path/to/downloaded/assets \
  --commit FULL_REVIEWED_SOURCE_SHA \
  --version 0.1.0-engineering.1
```

Online verification uses GitHub's attestation service and trust roots. Authenticate
`gh` with read access if required by the service; registry access must permit pulls.
The verifier first authenticates `RELEASE.json`, then reads it. It requires the
expected repository ID, issuer, protected-main source ref, workflow/source SHA,
GitHub-hosted runner, predicate type, subject digest and original signing run.
It checks signed bundle/image provenance, the durable immutable-distribution
receipt, asset hashes, qualification reports,
SPDX subjects and extracted bundle metadata. On supported Linux, `--execute`
also checks both verified executables' help/version. Failure is nonzero; never
bypass a failed policy check with an unsigned checksum file.

Deploy images by the verified registry digest in `RELEASE.json`, not merely by
the version tag. Registry manifest digest, image config ID and Docker-save
transport checksum are distinct identities. Signature bundles are durable release
assets; offline trust-root distribution is outside the initial supported contract.
The consumer policy follows the [GitHub CLI attestation interface](https://cli.github.com/manual/gh_attestation_verify).

## Partial failure and withdrawal

GitHub and GHCR publication are not atomic. A failure can leave a candidate,
version tag or incomplete draft. The process never deletes released bytes, moves
a Git tag, overwrites an asset or rebuilds under an already claimed version.
Preserve failed Actions logs and artifacts before their seven-day expiry.

At dispatch, `allow_same_run_resume=true` explicitly permits failed draft/publish
job reruns to resume; it defaults to false. Re-run failed jobs only, preserving the
signed artifact from the original attempt. Candidate/attestation-stage recovery
requires a fresh run and, if a release version was claimed, a new version.
The publisher exposes an explicit `--resume` mode for the same run/source and
already signed bytes. It authenticates the manifest and the draft's run record,
checks the exact Git commit and hashes every existing remote asset before adding
missing assets. It refuses an unowned tag, another run's record, changed content,
partial-upload placeholders or missing/expired evidence. A tag created before a
lost response, without a matching authenticated draft, cannot safely resume:
leave evidence intact and use a new reviewed version and complete run. Full-job
reruns that rebuild artifacts are not a safe way to recover a claimed version.

If a released artifact is bad, publish an advisory/withdrawal notice and select a
previously verified digest. Do not replace immutable release assets or silently
move tags. Binary rollback does not establish database schema downgrade support;
preserve operator homes/keyrings and follow the existing migration and recovery
contracts. A new release must have a new version and fresh qualification.
