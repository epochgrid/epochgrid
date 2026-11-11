#!/usr/bin/env python3
"""Online consumer verification. Authenticate metadata before parsing its claims."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

from artifact import BINS, digest, verify
from evidence import SUITES, qualifications
from inventory import validate_spdx
from release import HEX, REPOSITORY, SHA, WORKFLOW, matches, prerelease, read_json, require, validate_manifest

GH_VERSION = '2.100.0'
REPOSITORY_ID = '1360374944'
ISSUER = 'https://token.actions.githubusercontent.com'
PROVENANCE = 'https://slsa.dev/provenance/v1'
METADATA = 'https://epochgrid.org/attestations/release/v1'
DISTRIBUTION = 'https://epochgrid.org/attestations/distribution/v1'


def verified_statement(results, subject_digest, commit, predicate, run=None, later_attempt=False):
    require(isinstance(results, list) and bool(results), 'No verified attestations')
    for result in results:
        try:
            verified = result['verificationResult']
            cert = verified['signature']['certificate']
            expected = dict(issuer=ISSUER, sourceRepositoryURI='https://github.com/' + REPOSITORY,
                            sourceRepositoryIdentifier=REPOSITORY_ID, sourceRepositoryDigest=commit,
                            sourceRepositoryRef='refs/heads/main', buildSignerDigest=commit,
                            subjectAlternativeName='https://github.com/' + REPOSITORY + '/' + WORKFLOW + '@refs/heads/main',
                            runnerEnvironment='github-hosted')
            require(all(cert.get(k) == v for k, v in expected.items()), 'Certificate identity mismatch')
            if run is not None:
                prefix = 'https://github.com/' + REPOSITORY + '/actions/runs/' + run['run_id'] + '/attempts/'
                invocation = cert.get('runInvocationURI', '')
                require(invocation.startswith(prefix), 'Signing run differs')
                attempt = invocation.removeprefix(prefix)
                require(matches(r'[1-9][0-9]*', attempt) and
                        (int(attempt) >= int(run['run_attempt']) if later_attempt else attempt == run['run_attempt']),
                        'Signing attempt differs')
            statement = verified['statement']
            require(statement['_type'] == 'https://in-toto.io/Statement/v1'
                    and statement['predicateType'] == predicate, 'Attestation statement type mismatch')
            require(any(s.get('digest') == {'sha256': subject_digest} for s in statement['subject']),
                    'Attestation subject mismatch')
            require(bool(verified['verifiedTimestamps']), 'Missing verified signing timestamp')
            return statement
        except (ValueError, KeyError, TypeError):
            continue
    raise ValueError('No attestation satisfies the complete release policy')


def attest(subject, commit, predicate, subject_digest, run=None, later_attempt=False):
    # No unsigned bundle decoding or user-supplied verification JSON is accepted.
    require(subprocess.check_output(['gh', '--version'], text=True).splitlines()[0].startswith(
        'gh version ' + GH_VERSION + ' '), 'Unsupported GitHub CLI version')
    command = ['gh', 'attestation', 'verify', str(subject), '--repo', REPOSITORY,
               '--hostname', 'github.com', '--cert-oidc-issuer', ISSUER,
               '--signer-workflow', REPOSITORY + '/' + WORKFLOW,
               '--signer-digest', commit, '--source-digest', commit, '--source-ref', 'refs/heads/main',
               '--deny-self-hosted-runners', '--predicate-type', predicate, '--format', 'json']
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return verified_statement(json.loads(result.stdout), subject_digest, commit, predicate, run, later_attempt)


def verify_release(directory, commit, version, execute=False, distribution=False):
    require(matches(SHA, commit), 'Expected full source SHA is required')
    prerelease(version)
    manifest_path = directory / 'RELEASE.json'
    require(not manifest_path.is_symlink(), 'Linked release manifest')
    statement = attest(manifest_path, commit, METADATA, digest(manifest_path))
    data = read_json(manifest_path)
    identity = data['identity']
    require(identity['repository'] == REPOSITORY and identity['repository_id'] == REPOSITORY_ID
            and identity['commit'] == commit and identity['version'] == version
            and identity['tag'] == prerelease(version) and identity['workflow'] == WORKFLOW,
            'Authenticated manifest differs from requested release')
    require(matches(r'[1-9][0-9]*', identity['run_id']) and matches(r'[1-9][0-9]*', identity['run_attempt']),
            'Invalid release run identity')
    # Verify the run again now that its identity is read from authenticated bytes.
    attest(manifest_path, commit, METADATA, digest(manifest_path), identity)
    require(statement['predicate'] == {'identity': identity, 'kind': 'release-metadata',
                                      'policy_version': 1}, 'Release predicate mismatch')
    validate_manifest(data, identity, directory)
    required_assets = {'BUILD.json', 'image.json', 'rust.spdx.json', 'image.spdx.json',
                       'vulnerability-assessment.json', 'qualification-native.json', 'candidate-pull.json',
                       *(f'qualification-bundle-{s}.json' for s in SUITES),
                       *(f'qualification-image-{s}.json' for s in (*SUITES, 'boundary'))}
    require(required_assets <= {x['name'] for x in data['assets']}, 'Unbound or missing release evidence')
    run = dict(GITHUB_REPOSITORY_ID=identity['repository_id'], GITHUB_SHA=commit,
               GITHUB_RUN_ID=identity['run_id'], GITHUB_RUN_ATTEMPT=identity['run_attempt'])
    built = read_json(directory / 'BUILD.json')
    image_build = read_json(directory / 'image.json')
    qualifications(read_json(directory / 'qualification-native.json'),
                   {s: read_json(directory / f'qualification-bundle-{s}.json') for s in SUITES},
                   {s: read_json(directory / f'qualification-image-{s}.json') for s in (*SUITES, 'boundary')},
                   image_build, built, identity, data['source_sha256'], run)
    require(digest(directory / 'BUILD.json') == data['build']['manifest_sha256']
            and image_build['image_id'] == data['image']['config_id']
            and image_build['transport_sha256'] == data['image']['transport_sha256'], 'Evidence/payload identity differs')
    pulled = read_json(directory / 'candidate-pull.json')
    require(pulled['result'] == 'qualified' and pulled['registry_digest'] == data['image']['registry_digest']
            and pulled['commit'] == commit and pulled['source_sha256'] == data['source_sha256']
            and pulled['image_id'] == data['image']['config_id'], 'Missing or foreign registry round-trip evidence')
    archive = next(x for x in data['assets'] if x['role'] == 'archive')
    require(image_build['bundle_sha256'] == archive['sha256'], 'Archive/image binding differs')
    validate_spdx(read_json(directory / 'rust.spdx.json'), archive['sha256'])
    validate_spdx(read_json(directory / 'image.spdx.json'), data['image']['config_id'].removeprefix('sha256:'))
    require(read_json(directory / 'vulnerability-assessment.json')['result'] == 'reviewed', 'Missing vulnerability decision')
    attest(directory / archive['name'], commit, PROVENANCE, archive['sha256'], identity)
    image = data['image']
    attest('oci://' + image['repository'] + '@' + image['registry_digest'], commit, PROVENANCE,
           image['registry_digest'].removeprefix('sha256:'), identity)
    if distribution:
        proof = attest('oci://' + image['repository'] + '@' + image['registry_digest'], commit, DISTRIBUTION,
                       image['registry_digest'].removeprefix('sha256:'), identity, later_attempt=True)['predicate']
        require(proof['result'] == 'verified' and proof['immutable'] is True and proof['draft'] is False
                and type(proof['release_id']) is int and proof['release_id'] > 0 and proof['identity'] == identity,
                'Missing immutable distribution evidence')
    with tempfile.TemporaryDirectory(prefix='epochgrid-consumer-') as temporary:
        root = Path(temporary)
        sums = root / 'SHA256SUMS'
        sums.write_text(archive['sha256'] + '  ' + archive['name'] + '\n')
        bundle = root / 'bundle'
        verify(argparse.Namespace(archive=directory / archive['name'], checksums=sums, output=bundle,
                                  require_candidate=True, commit=commit))
        built = read_json(bundle / 'BUILD.json')
        require(digest(bundle / 'BUILD.json') == data['build']['manifest_sha256']
                and built['version'] == version and built['source_sha256'] == data['source_sha256']
                and built['lock_sha256'] == data['build']['lock_sha256'], 'Verified bundle identity mismatch')
        for name in BINS:
            require(digest(bundle / 'bin' / name) == data['build']['binary_sha256'][name], 'Binary digest mismatch')
            if execute:
                require(subprocess.check_output([str(bundle / 'bin' / name), '--version'], text=True,
                                                timeout=30).strip() == name + ' ' + version, 'Binary version mismatch')
                subprocess.run([str(bundle / 'bin' / name), '--help'], check=True, timeout=30,
                               stdout=subprocess.DEVNULL)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--execute', action='store_true', help='Run verified bundle help/version on supported Linux')
    args = parser.parse_args()
    verify_release(args.assets, args.commit, args.version, args.execute, distribution=True)
    print('Release signatures, policy and bundle integrity verified')


if __name__ == '__main__':
    main()
