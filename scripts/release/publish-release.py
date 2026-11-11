#!/usr/bin/env python3
"""Fail-closed release promotion. Never rebuild, replace assets, or move tags."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import urllib.parse
import urllib.request

from artifact import ROOT, digest, output, source, write_json
from evidence import assessment
from release import checkout, read_json, require, selection, validate_manifest


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


candidate = module('publish-image')
consumer = module('verify-release')
REPO = 'repos/epochgrid/epochgrid'


def journal(event, **details):
    path = ROOT / 'target/release-journal.jsonl'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as stream:
        stream.write(json.dumps(dict(event=event, **details), sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def api(endpoint, method='GET', data=None, missing=False, settings_read=False):
    env = os.environ.copy()
    settings_token = env.pop('RELEASE_SETTINGS_TOKEN', None)
    if settings_read:
        require(method == 'GET' and endpoint == REPO + '/immutable-releases',
                'Settings credential is restricted to the immutable-release read endpoint')
        require(bool(settings_token), 'Missing short-lived administration-read settings credential')
        env['GH_TOKEN'] = settings_token
    command = ['gh', 'api', '--hostname', 'github.com', '-X', method, endpoint]
    if data is not None:
        command += ['--input', '-']
    if method != 'GET':
        journal('github-write-started', method=method, endpoint=endpoint)
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, timeout=60, env=env)
    if missing and result.returncode and '(HTTP 404)' in result.stderr:
        return None
    require(result.returncode == 0, 'GitHub API operation failed: ' + method + ' ' + endpoint)
    value = json.loads(result.stdout) if result.stdout.strip() else None
    if method != 'GET':
        journal('github-write-returned', method=method, endpoint=endpoint,
                id=value.get('id') if isinstance(value, dict) else None)
    return value


def settings():
    repository = api(REPO)
    require(repository['id'] == 1360374944 and repository['visibility'] == 'public'
            and repository['default_branch'] == 'main', 'Unexpected repository identity/distribution contract')
    require(api(REPO + '/immutable-releases', settings_read=True)['enabled'] is True, 'Immutable releases must be enabled')
    environment = api(REPO + '/environments/release')
    require(environment['deployment_branch_policy'] == {'protected_branches': True, 'custom_branch_policies': False},
            'Release environment must allow protected branches only')
    branch = api(REPO + '/branches/main')
    require(branch['protected'] is True, 'Main must be protected')
    candidate.package(os.environ['GH_TOKEN'], 'public', False)


def finalize(directory, publication):
    data = read_json(directory / 'PROPOSAL.json')
    expected = selection(os.environ, data['identity']['version'])
    require(data['identity'] == expected, 'Proposal belongs to another run')
    checkout(expected)
    require(publication['result'] == 'qualified' and publication['commit'] == expected['commit']
            and publication['source_sha256'] == data['source_sha256']
            and publication['image_id'] == data['image']['config_id']
            and publication['package'] == data['image']['repository']
            and publication['visibility'] == 'public', 'Fresh candidate pull is not qualified')
    review = read_json(directory / 'vulnerability-assessment.json')
    require(review['result'] == 'reviewed', 'Vulnerabilities have not been reviewed')
    assessment([read_json(directory / (kind + '-vulnerabilities.json')) for kind in ('rust', 'image')], review['review'],
               [x for x in read_json(directory / 'BUILD.json')['components'] if x['kind'] == 'native'])
    data['image']['registry_digest'] = publication['registry_digest']
    pull_report = directory / 'candidate-pull.json'
    require(not pull_report.exists(), 'Candidate pull report already exists')
    write_json(pull_report, publication)
    data['assets'].append(dict(name=pull_report.name, role='qualification',
                               size=pull_report.stat().st_size, sha256=digest(pull_report)))
    validate_manifest(data, expected, directory)
    target = directory / 'RELEASE.json'
    require(not target.exists(), 'Release manifest already exists')
    write_json(target, data)
    write_json(directory / 'release-predicate.json', dict(identity=expected, kind='release-metadata', policy_version=1))


def current(data):
    identity = data['identity']
    selected = selection(os.environ, identity['version'])
    # A failed-job rerun may resume the original run's authenticated payloads.
    # Rebuilding all jobs requires a new version; earlier signed bytes win.
    require(all(identity[k] == selected[k] for k in identity if k != 'run_attempt')
            and int(identity['run_attempt']) <= int(selected['run_attempt']), 'Not the same release run/source')
    checkout(selected)
    require(data['source_sha256'] == source(), 'Release source changed')


def marker(data, directory):
    record = json.dumps(dict(kind='epochgrid-release-v1', identity=data['identity'],
                             manifest_sha256=digest(directory / 'RELEASE.json')), sort_keys=True)
    return ('Engineering prerelease for Ubuntu 24.04 x86-64. Unaudited development software; '
            'this is not an alpha readiness declaration. TD-001/002/003 remain open. '
            'Dynamic attachments and short-lease messaging are not qualified.\n\n'
            'Verify RELEASE.json, archive/image provenance and the durable distribution '
            'attestation before execution. Deploy containers by verified digest. '
            'The attached SPDX inventories, notices, vulnerability assessment and '
            'qualification reports describe the supported scope.\n\n'
            '<!-- epochgrid-run ' + record + ' -->')


def tag_state(tag):
    return api(REPO + '/git/ref/tags/' + tag, missing=True)


def release_state(tag):
    # Drafts must be found through the authenticated listing (tag lookup can omit them).
    found = []
    page = 1
    while True:
        releases = api(REPO + f'/releases?per_page=100&page={page}')
        found += [r for r in releases if r['tag_name'] == tag]
        if len(releases) < 100:
            break
        page += 1
    require(len(found) <= 1, 'Ambiguous release tag')
    return found[0] if found else None


def assets(directory, data):
    names = [x['name'] for x in data['assets']] + ['RELEASE.json', 'archive.sigstore.json',
                                                 'image.sigstore.json', 'release.sigstore.json']
    require(len(names) == len(set(names)), 'Duplicate release asset inventory')
    return {name: directory / name for name in names}


def download_asset(asset, destination):
    with destination.open('xb') as stream:
        subprocess.run(['gh', 'api', '--hostname', 'github.com', '-H', 'Accept: application/octet-stream',
                        REPO + '/releases/assets/' + str(asset['id'])], stdout=stream, check=True, timeout=180)


def compare_remote_assets(release, expected, complete=False):
    remote = api(REPO + '/releases/' + str(release['id']) + '/assets?per_page=100')
    require(len(remote) < 100, 'Too many assets')
    names = [item['name'] for item in remote]
    require(len(names) == len(set(names)) and set(names) <= set(expected), 'Unexpected/duplicate remote asset')
    if complete:
        require(set(names) == set(expected), 'Incomplete release assets')
    for item in remote:
        path = expected[item['name']]
        require(item['state'] == 'uploaded' and item['size'] == path.stat().st_size
                and item.get('digest') == 'sha256:' + digest(path), 'Existing asset differs; do not overwrite')
    return set(names)


def prepare(directory, data, resume):
    tag = data['identity']['tag']
    record = marker(data, directory)
    release, ref = release_state(tag), tag_state(tag)
    if release is not None:
        require(resume and release['body'] == record and release['prerelease'] is True
                and release['author']['login'] == 'github-actions[bot]', 'Release collision or unauthenticated resume')
        require(ref is not None and ref['object'] == {'type': 'commit', 'sha': data['identity']['commit'],
                'url': 'https://api.github.com/' + REPO + '/git/commits/' + data['identity']['commit']},
                'Existing tag differs')
    else:
        require(ref is None, 'Tag exists without this run record; use a new version')
        # A lost response after tag creation is deliberately not guessed away.
        api(REPO + '/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': data['identity']['commit']})
        release = api(REPO + '/releases', 'POST', dict(tag_name=tag, target_commitish=data['identity']['commit'],
                      name=tag + ' engineering prerelease', body=record, draft=True, prerelease=True, make_latest='false'))
    expected = assets(directory, data)
    present = compare_remote_assets(release, expected)
    require(release['draft'] is True or present == set(expected), 'Published release cannot be repaired')
    for name in sorted(set(expected) - present):
        # gh refuses collisions unless --clobber is explicitly supplied; never use it.
        journal('asset-upload-started', release_id=release['id'], name=name, sha256=digest(expected[name]))
        subprocess.run(['gh', 'release', 'upload', tag, str(expected[name]), '--repo', 'epochgrid/epochgrid'],
                       check=True, timeout=180)
        journal('asset-upload-returned', release_id=release['id'], name=name)
    compare_remote_assets(release, expected, complete=True)
    return release


def promote_image(data, resume):
    token = candidate.registry_token(os.environ['GITHUB_ACTOR'], os.environ['GH_TOKEN'], write=True)
    tag, wanted = data['identity']['tag'], data['image']['registry_digest']
    url = 'https://ghcr.io/v2/epochgrid/epochgrid/manifests/'
    headers = {'Authorization': 'Bearer ' + token, 'Accept': candidate.ACCEPT}
    raw, original_headers = candidate.request(url + wanted, headers)
    require('sha256:' + hashlib.sha256(raw).hexdigest() == wanted, 'Source registry digest differs')
    old, _ = candidate.request(url + tag, headers, missing=True)
    if old is not None:
        require(resume and old == raw, 'Versioned image tag already exists or differs')
    else:
        journal('registry-tag-started', tag=tag, digest=wanted)
        request = urllib.request.Request(url + tag, data=raw, method='PUT',
                    headers={**headers, 'Content-Type': original_headers['Content-Type']})
        with urllib.request.urlopen(request, timeout=60) as response:
            require(response.status == 201, 'Registry promotion failed')
    readback, _ = candidate.request(url + tag, headers)
    require(readback == raw, 'Registry promotion changed the manifest')
    journal('registry-tag-verified', tag=tag, digest=wanted)


def retrieve(directory, data):
    release = release_state(data['identity']['tag'])
    require(release is not None and release['body'] == marker(data, directory), 'Release ownership differs')
    expected = assets(directory, data)
    compare_remote_assets(release, expected, complete=True)
    target = directory.parent / 'downloaded-release'
    target.mkdir(exist_ok=False)
    for asset in api(REPO + '/releases/' + str(release['id']) + '/assets?per_page=100'):
        download_asset(asset, target / asset['name'])
    consumer.verify_release(target, data['identity']['commit'], data['identity']['version'], execute=True)
    # Fresh pull must prove the registry payload, not just its signature.
    built = read_json(directory / 'image.json')
    reference = data['image']['repository'] + '@' + data['image']['registry_digest']
    subprocess.run(['docker', 'pull', reference], check=True, timeout=180)
    require(output('docker', 'image', 'inspect', reference, '--format', '{{.Id}}') == built['image_id'],
            'Pulled image config differs')
    candidate.payload(os.environ.copy(), reference, built)
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['settings', 'finalize', 'draft', 'verify', 'publish'])
    parser.add_argument('--assets', type=Path)
    parser.add_argument('--publication', type=Path)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--published', action='store_true')
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.command == 'settings':
        settings()
        return
    require(args.assets is not None, 'Assets directory required')
    if args.command == 'finalize':
        require(args.publication is not None, 'Fresh pull report required')
        finalize(args.assets, read_json(args.publication))
        return
    data = consumer.verify_release(args.assets, os.environ['GITHUB_SHA'], os.environ['RELEASE_VERSION'])
    current(data)
    if args.command == 'verify':
        release = retrieve(args.assets, data)
        if args.published:
            require(release['draft'] is False and release['immutable'] is True, 'Release is not published and immutable')
        write_json(ROOT / 'target/release-state.json', dict(result='verified', release_id=release['id'],
                   immutable=release.get('immutable', False), draft=release['draft'], identity=data['identity']))
        return
    settings()
    if args.command == 'draft':
        # Ownership is established before adding a versioned registry reference.
        prepare(args.assets, data, args.resume)
        promote_image(data, args.resume)
    else:
        release = retrieve(args.assets, data)
        if not release['draft']:
            require(args.resume and release['immutable'] is True, 'Unexpected published release')
            return
        api(REPO + '/releases/' + str(release['id']), 'PATCH', {'draft': False, 'make_latest': 'false'})
        published = release_state(data['identity']['tag'])
        require(published['draft'] is False and published['immutable'] is True, 'Release is not immutable')
        # Public distribution must be readable without the runner credential.
        for name, path in assets(args.assets, data).items():
            url = 'https://github.com/epochgrid/epochgrid/releases/download/' + data['identity']['tag'] + '/' + urllib.parse.quote(name)
            value = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=60) as response:
                while block := response.read(1024 * 1024):
                    value.update(block)
            require(value.hexdigest() == digest(path), 'Public asset download mismatch')
    release = release_state(data['identity']['tag'])
    write_json(ROOT / 'target/release-state.json', dict(result=args.command, release_id=release['id'],
               immutable=release.get('immutable', False), draft=release['draft'], identity=data['identity']))


if __name__ == '__main__':
    main()
