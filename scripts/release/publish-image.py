#!/usr/bin/env python3
"""Explicit GHCR candidate transport; never promotes release/version/latest tags."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from artifact import BINS, ROOT, digest, output, source, write_json
from image import check_identity, inspect_archive

REPOSITORY = 'epochgrid/epochgrid'
PACKAGE = 'ghcr.io/' + REPOSITORY
SUITES = ('smoke', 'configuration_standalone', 'configuration_cluster',
          'operator_jwt_standalone', 'operator_jwt_cluster')
ACCEPT = 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'


def context(env):
    if (env.get('GITHUB_REPOSITORY'), env.get('GITHUB_REF'), env.get('GITHUB_REF_PROTECTED'),
        env.get('GITHUB_EVENT_NAME')) != (REPOSITORY, 'refs/heads/main', 'true', 'workflow_dispatch'):
        raise ValueError('Publication requires manual dispatch from protected main')
    sha, run, attempt = (env.get(key, '') for key in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    if not re.fullmatch('[0-9a-f]{40}', sha) or not run.isdecimal() or not attempt.isdecimal():
        raise ValueError('Invalid candidate identity')
    return 'candidate-' + sha + '-' + run + '-' + attempt


def qualifications(directory, built):
    for name in [*('qualification-' + suite for suite in SUITES), 'boundary']:
        report = json.loads((directory / (name + '.json')).read_text())
        if report['result'] != 'passed' or any(report[key] != built[key] for key in
                ('image_id', 'commit', 'source_sha256')):
            raise ValueError('Missing, failed or mismatched image qualification')
        if name != 'boundary' and report.get('suite') != name.removeprefix('qualification-'):
            raise ValueError('Qualification suite identity mismatch')


def request(url, headers, missing=False):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
            return response.read(8 * 1024 * 1024), response.headers
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None, error.headers
        raise


def package(token, visibility, allow_create=False):
    raw, _ = request('https://api.github.com/orgs/epochgrid/packages/container/epochgrid',
                     {'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                      'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'epochgrid-candidate'}, missing=True)
    if raw is None:
        if not allow_create or visibility != 'private':
            raise ValueError('Package absent/inaccessible; creation requires explicit private-package approval')
        return
    data = json.loads(raw)
    if (data.get('owner', {}).get('login'), data.get('visibility'), data.get('name'),
        data.get('package_type')) != ('epochgrid', visibility, 'epochgrid', 'container'):
        raise ValueError('Package ownership or visibility differs')
    # The Packages API may omit repository linkage. Dispatch requires the
    # operator to confirm Actions access/linkage; never infer it from absence.
    linked = data.get('repository')
    if linked and linked.get('full_name') != REPOSITORY:
        raise ValueError('Package repository linkage differs')


def registry_token(actor, token, write=False):
    actions = 'pull,push' if write else 'pull'
    query = urllib.parse.urlencode(dict(service='ghcr.io', scope='repository:' + REPOSITORY + ':' + actions))
    credential = base64.b64encode((actor + ':' + token).encode()).decode()
    raw, _ = request('https://ghcr.io/token?' + query, {'Authorization': 'Basic ' + credential})
    return json.loads(raw)['token']


def manifest(reference, token, missing=False):
    if not re.fullmatch(r'(?:candidate-[0-9a-f]{40}-[0-9]+-[0-9]+|sha256:[0-9a-f]{64})', reference):
        raise ValueError('Invalid candidate reference')
    raw, headers = request('https://ghcr.io/v2/' + REPOSITORY + '/manifests/' + reference,
                           {'Authorization': 'Bearer ' + token, 'Accept': ACCEPT}, missing)
    if raw is None:
        return None
    digest_value = 'sha256:' + hashlib.sha256(raw).hexdigest()
    if headers.get('Docker-Content-Digest') != digest_value:
        raise ValueError('Registry manifest digest mismatch')
    value = json.loads(raw)
    if value.get('schemaVersion') != 2 or 'config' not in value:
        raise ValueError('Expected a single-platform image manifest')
    return digest_value, value['config']['digest']


def docker(env, *command, **kwargs):
    return subprocess.run(['docker', *map(str, command)], env=env, check=True, timeout=180, **kwargs)


def payload(env, image, built):
    container = subprocess.check_output(['docker', 'create', image], env=env, text=True, timeout=30).strip()
    try:
        with tempfile.TemporaryDirectory() as directory:
            for filename, expected in {'BUILD.json': built['manifest_sha256'], **built['binary_sha256']}.items():
                location = '/usr/local/bin/' if filename in BINS else '/usr/share/epochgrid/'
                path = Path(directory) / filename
                docker(env, 'cp', f'{container}:{location}{filename}', path)
                if digest(path) != expected:
                    raise ValueError('Registry image payload differs from qualified image')
            data = json.loads((Path(directory) / 'BUILD.json').read_text())
            check_identity(data, False)
    finally:
        docker(env, 'rm', container, stdout=subprocess.DEVNULL)
    for binary in BINS:
        command = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--entrypoint', '/usr/local/bin/' + binary, image]
        result = subprocess.check_output(['docker', *command, '--version'], env=env, text=True, timeout=30).strip()
        if result != f'{binary} {built["version"]}':
            raise ValueError('Registry image executable version mismatch')
        docker(env, *command, '--help', stdout=subprocess.DEVNULL)


def transport(args, result):
    tag = context(os.environ)
    built = json.loads(args.image_report.read_text())
    if (built['schema'] != 1 or built['result'] != 'passed' or built['local'] or built['commit'] != os.environ['GITHUB_SHA']
            or built['source_sha256'] != source()):
        raise ValueError('Only a clean, selected-main image can be published')
    result.update(tag=tag, package=PACKAGE, image_id=built['image_id'], commit=built['commit'],
                  source_sha256=built['source_sha256'], visibility=args.visibility)
    token, actor = os.environ['GITHUB_TOKEN'], os.environ['GITHUB_ACTOR']
    with tempfile.TemporaryDirectory(prefix='epochgrid-ghcr-') as configuration:
        env = dict(os.environ, DOCKER_CONFIG=configuration)
        result['phase'] = 'package_access'
        package(token, args.visibility, args.create_private and args.mode == 'push')
        docker(env, 'login', 'ghcr.io', '--username', actor, '--password-stdin',
               input=token.encode(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        access = registry_token(actor, token, args.mode == 'push')
        if args.mode == 'push':
            qualifications(args.qualifications, built)
            result['phase'] = 'pre_push'
            if manifest(tag, access, missing=True) is not None:
                raise ValueError('Candidate tag already exists; refusing overwrite')
            archive = args.image_report.with_name('image.tar')
            if digest(archive) != built['transport_sha256']:
                raise ValueError('Qualified image transport checksum mismatch')
            inspect_archive(archive, built['image_id'], built)
            docker(env, 'load', '--input', archive, stdout=subprocess.DEVNULL)
            payload(env, built['image_id'], built)
            result['phase'] = 'push'
            docker(env, 'tag', built['image_id'], PACKAGE + ':' + tag)
            docker(env, 'push', PACKAGE + ':' + tag, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            remote = manifest(tag, registry_token(actor, token))
            if remote[1] != built['image_id']:
                raise ValueError('Published manifest references a different image config')
            result['registry_digest'] = remote[0]
            package(token, args.visibility)
            # Only the separate fresh-runner verification may report qualified.
            result.update(result='pushed', phase='awaiting_fresh_pull')
        else:
            pushed = json.loads(args.publication_report.read_text())
            if (pushed.get('result') != 'pushed' or any(pushed.get(key) != result[key] for key in
                    ('tag', 'package', 'image_id', 'commit', 'source_sha256', 'visibility'))):
                raise ValueError('Publication report identity mismatch')
            digest_value = pushed['registry_digest']
            if manifest(digest_value, access) != (digest_value, built['image_id']):
                raise ValueError('Registry round-trip manifest mismatch')
            existing = subprocess.run(['docker', 'image', 'inspect', built['image_id']], env=env,
                                      capture_output=True, timeout=15)
            if existing.returncode == 0:
                raise ValueError('Pull verification requires a fresh runner without the built image')
            result['phase'] = 'pull'
            reference = PACKAGE + '@' + digest_value
            docker(env, 'pull', reference, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            actual = subprocess.check_output(['docker', 'image', 'inspect', reference, '--format', '{{.Id}}'],
                                             env=env, text=True, timeout=30).strip()
            if actual != built['image_id']:
                raise ValueError('Pulled image config differs from qualified image')
            payload(env, reference, built)
            result.update(result='qualified', phase='complete', registry_digest=digest_value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['push', 'verify'])
    parser.add_argument('--image-report', type=Path, required=True)
    parser.add_argument('--qualifications', type=Path)
    parser.add_argument('--publication-report', type=Path)
    parser.add_argument('--visibility', choices=['private', 'public'], required=True)
    parser.add_argument('--create-private', action='store_true')
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'push' and args.qualifications is None or args.mode == 'verify' and args.publication_report is None:
        parser.error('push requires qualification reports; verify requires a publication report')
    os.chdir(ROOT)
    args.result.parent.mkdir(parents=True, exist_ok=True)
    if args.result.exists():
        parser.error('result already exists')
    report = dict(schema=1, result='failed', phase='preflight')
    try:
        transport(args, report)
    except Exception as error:
        report['error_type'] = type(error).__name__
        print(f'Candidate transport failed in {report["phase"]}: {type(error).__name__}', file=sys.stderr)
        return 1
    finally:
        write_json(args.result, report)
    return 0


if __name__ == '__main__':
    sys.exit(main())
