#!/usr/bin/env python3
"""Read-only release identity and manifest checks; does not verify signatures or publish."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tomllib

from artifact import BINS, ROOT, TARGET, digest, output, source

REPOSITORY = 'epochgrid/epochgrid'
WORKFLOW = '.github/workflows/release.yaml'
HEX = r'[0-9a-f]{64}'
SHA = r'[0-9a-f]{40}'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'Unexpected object fields')


def prerelease(version):
    number = r'(?:0|[1-9][0-9]*)'
    require(matches(rf'{number}\.{number}\.{number}-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*', version),
            'An explicit SemVer prerelease without build metadata is required')
    for part in version.split('-', 1)[1].split('.'):
        require(not part.isdecimal() or part == '0' or not part.startswith('0'),
                'Numeric prerelease identifiers cannot have leading zeros')
    require(len('v' + version) <= 128, 'Version exceeds registry tag limit')
    return 'v' + version


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate JSON key')
        value[key] = item
    return value


def read_json(path):
    require(path.stat().st_size <= 4 * 1024 * 1024, 'Metadata exceeds size limit')
    def invalid_constant(_):
        raise ValueError('Non-finite JSON number')
    return json.loads(path.read_text(), object_pairs_hook=unique_object, parse_constant=invalid_constant)


def selection(env, version):
    tag = prerelease(version)
    require((env.get('GITHUB_REPOSITORY'), env.get('GITHUB_REF'), env.get('GITHUB_REF_PROTECTED'),
             env.get('GITHUB_EVENT_NAME')) == (REPOSITORY, 'refs/heads/main', 'true', 'workflow_dispatch'),
            'Release selection requires manual dispatch from protected main')
    commit = env.get('GITHUB_SHA')
    require(matches(SHA, commit), 'Invalid selected commit')
    require(env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/main'
            and env.get('GITHUB_WORKFLOW_SHA') == commit, 'Workflow/source identity mismatch')
    ids = [env.get(key) for key in ('GITHUB_REPOSITORY_ID', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')]
    require(all(matches(r'[1-9][0-9]*', value) for value in ids), 'Invalid repository/run identity')
    require(ids[0] == '1360374944', 'Unexpected repository ID')
    return dict(repository=REPOSITORY, repository_id=ids[0], commit=commit, version=version, tag=tag,
                workflow=WORKFLOW, run_id=ids[1], run_attempt=ids[2])


def checkout(identity):
    require(output('git', 'rev-parse', 'HEAD') == identity['commit'], 'Checkout differs from selected SHA')
    require(not output('git', 'status', '--porcelain', '--untracked-files=all'), 'Release checkout is dirty')
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    require(version == identity['version'], 'Workspace version differs from requested release')
    locked = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    # Every workspace package currently inherits the workspace version. Check
    # each manifest and its unique source-less lock entry, including libraries.
    manifests = list((ROOT / 'crates').glob('*/Cargo.toml'))
    require(bool(manifests), 'Missing workspace packages')
    for manifest in manifests:
        package = tomllib.loads(manifest.read_text())['package']
        require(package['version'] == {'workspace': True}, 'Workspace version inheritance changed')
        entries = [p for p in locked if p['name'] == package['name'] and 'source' not in p]
        require(len(entries) == 1 and entries[0]['version'] == version, 'Workspace lock version mismatch')
    return dict(schema=1, policy_version=1, target=TARGET, source_sha256=source(),
                lock_sha256=digest(ROOT / 'Cargo.lock'), **identity)


def validate_manifest(data, expected, directory):
    """Validate untrusted metadata and file integrity against caller-selected identity.

    This is deliberately not an authenticity decision. A future consumer must
    authenticate the manifest before using any of its claims as trust inputs.
    """
    fields(data, 'schema policy_version identity source_sha256 target build image assets support')
    require(type(data['schema']) is int and data['schema'] == 1 and
            type(data['policy_version']) is int and data['policy_version'] == 1, 'Unknown manifest policy/schema')
    fields(data['identity'], 'repository repository_id commit version tag workflow run_id run_attempt')
    require(data['identity'] == expected, 'Manifest differs from selected release identity')
    require(data['target'] == TARGET and matches(HEX, data['source_sha256']), 'Invalid source or target')
    fields(data['build'], 'manifest_sha256 lock_sha256 binary_sha256')
    fields(data['build']['binary_sha256'], ' '.join(BINS))
    require(all(matches(HEX, item) for item in [data['build']['manifest_sha256'],
            data['build']['lock_sha256'], *data['build']['binary_sha256'].values()]), 'Invalid build digest')
    fields(data['image'], 'repository platform registry_digest config_id base transport_sha256')
    image = data['image']
    require(image['repository'] == 'ghcr.io/' + REPOSITORY and image['platform'] == 'linux/amd64',
            'Unexpected image repository/platform')
    require(all(matches('sha256:' + HEX, image[key]) for key in ('registry_digest', 'config_id'))
            and matches(r'ubuntu:24\.04@sha256:' + HEX, image['base'])
            and matches(HEX, image['transport_sha256']), 'Invalid image digests')
    fields(data['support'], 'scope limitations readiness')
    require(data['support']['readiness'] == 'engineering-prerelease', 'Alpha/stable readiness is not authorized')
    require(all(isinstance(data['support'][key], list) and data['support'][key]
                and all(isinstance(x, str) and x.strip() for x in data['support'][key])
                for key in ('scope', 'limitations')), 'Missing supported scope/limitations')
    require(isinstance(data['assets'], list) and 1 <= len(data['assets']) <= 100, 'Invalid asset inventory')
    roles = {'archive', 'qualification', 'sbom-rust', 'sbom-image', 'notices', 'vulnerability-assessment'}
    optional_roles = {'build-manifest', 'image-build', 'checksums', 'attestation', 'scan'}
    names, found = set(), []
    for asset in data['assets']:
        fields(asset, 'name role size sha256')
        name = asset['name']
        require(matches(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}', name)
                and name.casefold() not in {'release.json', 'release.json.sigstore.json'}, 'Unsafe or reserved asset name')
        require(name.casefold() not in names, 'Duplicate asset name')
        names.add(name.casefold())
        require(asset['role'] in roles | optional_roles and type(asset['size']) is int and asset['size'] > 0
                and matches(HEX, asset['sha256']), 'Invalid asset metadata')
        found.append(asset['role'])
        path = directory / name
        require(not path.is_symlink() and path.is_file(), 'Missing or linked asset')
        require(path.stat().st_size == asset['size'] and digest(path) == asset['sha256'], 'Asset integrity mismatch')
        if asset['role'] == 'archive':
            require(name == f'epochgrid-{expected["version"]}-candidate.{expected["commit"]}-{TARGET}.tar.gz',
                    'Archive must retain the qualified candidate filename')
    require(roles <= set(found) and all(found.count(role) == 1 for role in roles - {'qualification'}),
            'Missing or ambiguous release assets')
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['preflight', 'check-manifest'])
    parser.add_argument('--version', required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--assets', type=Path)
    args = parser.parse_args()
    if args.command == 'check-manifest' and (args.manifest is None or args.assets is None):
        parser.error('check-manifest requires --manifest and --assets')
    os.chdir(ROOT)
    try:
        identity = selection(os.environ, args.version)
        selected = checkout(identity)
        if args.command == 'check-manifest':
            manifest = validate_manifest(read_json(args.manifest), identity, args.assets)
            require(manifest['source_sha256'] == selected['source_sha256']
                    and manifest['build']['lock_sha256'] == selected['lock_sha256'], 'Source/lock digest mismatch')
        print(json.dumps(selected, sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'Release input rejected: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
