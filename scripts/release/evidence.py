#!/usr/bin/env python3
"""Assemble same-run qualification evidence; no publication or signing permissions."""
import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from artifact import BINS, ROOT, digest, output, source, verify, write_json
from inventory import spdx, validate_spdx
from release import checkout, fields, read_json, require, selection

SUITES = ('smoke', 'configuration_standalone', 'configuration_cluster',
          'operator_jwt_standalone', 'operator_jwt_cluster')
JOBS = {'build', 'tests', 'byo-nats', 'linux-build', 'linux-qualify', 'image-build', 'image-qualify'}


def run_identity():
    return {key: os.environ[key] for key in ('GITHUB_REPOSITORY_ID', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')}


def gate(results):
    require(set(results) == JOBS and all(x['result'] == 'success' for x in results.values()),
            'Every normal, bundle and image qualification job must succeed')
    return dict(schema=1, result='passed', jobs=results, source_sha256=source(), run=run_identity())


def qualifications(native, linux, images, built, build_manifest, identity, expected_source=None, expected_run=None):
    expected_source = source() if expected_source is None else expected_source
    expected_run = run_identity() if expected_run is None else expected_run
    require(type(native['schema']) is int and native['schema'] == 1 and native['result'] == 'passed' and native['run'] == expected_run
            and native['source_sha256'] == built['source_sha256'], 'Native qualification identity differs')
    require(set(native['jobs']) == JOBS and all(x['result'] == 'success' for x in native['jobs'].values()),
            'Native qualification gate incomplete')
    require(built['result'] == 'passed' and built['local'] is False and built['commit'] == identity['commit']
            and built['version'] == identity['version'] and built['source_sha256'] == expected_source,
            'Image build does not belong to selected clean revision')
    require(build_manifest['local'] is False and build_manifest['dirty'] is False
            and build_manifest['commit'] == identity['commit'] and build_manifest['version'] == identity['version']
            and build_manifest['source_sha256'] == built['source_sha256'], 'Bundle/image source mismatch')
    require(set(linux) == set(SUITES) and set(images) == {*SUITES, 'boundary'}, 'Missing/extra qualification suite')
    for suite, report in linux.items():
        require(type(report['schema']) is int and report['schema'] == 1 and report['result'] == 'passed' and report['suite'] == suite
                and report['commit'] == identity['commit']
                and report['manifest_sha256'] == built['manifest_sha256']
                and report['binary_sha256'] == built['binary_sha256'], 'Bundle qualification mismatch')
    for suite, report in images.items():
        require(type(report['schema']) is int and report['schema'] == 1 and report['result'] == 'passed'
                and report['commit'] == identity['commit'] and report['source_sha256'] == built['source_sha256']
                and report['image_id'] == built['image_id'], 'Image qualification mismatch')
        if suite != 'boundary':
            require(report['suite'] == suite, 'Image suite identity mismatch')


def assessment(scans, review, native=()):
    fields(review, 'schema reviewed_on reviewer dispositions native_review')
    require(type(review['schema']) is int and review['schema'] == 1 and isinstance(review['reviewer'], str) and review['reviewer'].strip(),
            'Missing vulnerability review identity')
    age = (datetime.date.today() - datetime.date.fromisoformat(review['reviewed_on'])).days
    require(0 <= age <= 7, 'Vulnerability review must be dated within seven days')
    observed = set()
    for scan in scans:
        require(scan['descriptor']['name'] == 'grype' and scan['descriptor']['version'] == '0.121.3',
                'Unexpected vulnerability scanner')
        require(scan['descriptor']['db']['status']['valid'] is True, 'Invalid vulnerability database')
        for match in scan['matches']:
            observed.add((match['vulnerability']['id'], match['artifact']['name'], match['artifact']['version']))
    approved = set()
    for item in review['dispositions']:
        fields(item, 'id package version decision rationale')
        require(item['decision'] in {'not-affected', 'accepted-risk'} and isinstance(item['rationale'], str)
                and item['rationale'].strip(), 'Unreviewed vulnerability finding')
        key = (item['id'], item['package'], item['version'])
        require(key not in approved, 'Duplicate disposition')
        approved.add(key)
    require(observed == approved, 'Vulnerability findings differ from reviewed dispositions')
    reviewed_native = {}
    for item in review['native_review']:
        fields(item, 'name version source_sha256 rationale')
        require(item['name'] not in reviewed_native and isinstance(item['rationale'], str) and item['rationale'].strip(),
                'Missing or duplicate native component review')
        reviewed_native[item['name']] = (item['version'], item['source_sha256'])
    require(reviewed_native == {x['name']: (x['version'], x['source_sha256']) for x in native},
            'Native source coverage differs from reviewed assessment')
    return dict(schema=1, result='reviewed', review=review, findings=len(observed))


def sanitize_scan(raw, sbom):
    """Allowlist scanner evidence; exclude paths, credentials and configuration dumps."""
    descriptor = raw['descriptor']
    require(descriptor['name'] == 'grype' and descriptor['version'] == '0.121.3', 'Unexpected scanner version')
    database = descriptor['db']['status']
    require(database['valid'] is True, 'Invalid vulnerability database')
    built = datetime.datetime.fromisoformat(database['built'].replace('Z', '+00:00'))
    require(datetime.timedelta(0) <= datetime.datetime.now(datetime.timezone.utc) - built <= datetime.timedelta(days=7),
            'Vulnerability database is stale or future-dated')
    return dict(schema=1, sbom_sha256=digest(sbom), descriptor=dict(name=descriptor['name'], version=descriptor['version'],
                timestamp=descriptor['timestamp'], db=dict(status={key: database[key] for key in ('built', 'valid', 'schemaVersion')})),
                matches=[dict(vulnerability={key: match['vulnerability'][key] for key in ('id', 'severity', 'dataSource')},
                              artifact={key: match['artifact'][key] for key in ('name', 'version', 'type', 'purl')})
                         for match in raw['matches']])


def assemble(args):
    identity = selection(os.environ, args.version)
    selected = checkout(identity)
    require(not args.output.exists(), 'Evidence output already exists')
    built = read_json(args.image / 'image.json')
    archives = list(args.linux.glob('*.tar.gz'))
    require(len(archives) == 1, 'Expected exactly one candidate archive')
    archive = archives[0]
    require(digest(archive) == built['bundle_sha256'], 'Image/bundle payload mismatch')
    require(digest(args.image / 'image.tar') == built['transport_sha256'], 'Image transport mismatch')
    with tempfile.TemporaryDirectory(prefix='epochgrid-release-evidence-') as temporary:
        bundle = Path(temporary) / 'bundle'
        verify(argparse.Namespace(archive=archive, checksums=args.linux / 'SHA256SUMS', output=bundle,
                                  require_candidate=True, commit=identity['commit']))
        build = read_json(bundle / 'BUILD.json')
        require(digest(bundle / 'BUILD.json') == built['manifest_sha256'], 'Build manifest differs from image')
        require(all(digest(bundle / 'bin' / name) == built['binary_sha256'][name] for name in BINS),
                'Image binary hashes differ')
        linux = {s: read_json(args.reports / f'linux-qualification-{s}-{identity["commit"]}' / f'qualification-{s}.json')
                 for s in SUITES}
        images = {s: read_json(args.reports / f'image-results-{s}-{identity["commit"]}' / f'qualification-{s}.json')
                  for s in SUITES}
        images['boundary'] = read_json(args.reports / f'image-results-smoke-{identity["commit"]}' / 'boundary.json')
        native = read_json(args.reports / f'qualification-gate-{identity["commit"]}' / 'gate.json')
        qualifications(native, linux, images, built, build, identity)
        args.output.mkdir(parents=True)
        assets = []
        def add(name, role, path=None, data=None):
            target = args.output / name
            if path is not None:
                shutil.copyfile(path, target)
            else:
                write_json(target, data)
            assets.append(dict(name=name, role=role, sha256=digest(target), size=target.stat().st_size))
        add(archive.name, 'archive', path=archive)
        add('SHA256SUMS', 'checksums', path=args.linux / 'SHA256SUMS')
        add('BUILD.json', 'build-manifest', path=bundle / 'BUILD.json')
        add('THIRD_PARTY_NOTICES', 'notices', path=bundle / 'THIRD_PARTY_NOTICES')
        add('image.json', 'image-build', data=built)
        add('qualification-native.json', 'qualification', data=native)
        for prefix, reports in [('bundle', linux), ('image', images)]:
            for suite, report in reports.items():
                add(f'qualification-{prefix}-{suite}.json', 'qualification', data=report)
        rust_sbom = spdx(build['components'], archive.name, digest(archive), build['source_epoch'])
        validate_spdx(rust_sbom, digest(archive))
        add('rust.spdx.json', 'sbom-rust', data=rust_sbom)
        # Inspect the exact transported image, not the runner's installed packages.
        subprocess.run(['docker', 'load', '--input', str(args.image / 'image.tar')], check=True,
                       timeout=180, stdout=subprocess.DEVNULL)
        packages = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--entrypoint', 'dpkg-query', built['image_id'],
            '-W', '-f=${Package}\t${Version}\n'], text=True, timeout=30)
        components = [dict(name=name, version=version, kind='deb', usage='runtime', license='NOASSERTION')
                      for name, version in (line.split('\t') for line in packages.splitlines())]
        # Runtime image also contains the statically linked Rust/native graph.
        components += [x for x in build['components'] if x['usage'] == 'runtime']
        image_sbom = spdx(components, 'epochgrid-runtime-image', built['image_id'].removeprefix('sha256:'), build['source_epoch'])
        validate_spdx(image_sbom, built['image_id'].removeprefix('sha256:'))
        add('image.spdx.json', 'sbom-image', data=image_sbom)
        scans = []
        for kind in ('rust', 'image'):
            command = ['grype', 'sbom:' + str(args.output / (kind + '.spdx.json')), '-o', 'json']
            if kind == 'image':
                command += ['--distro', 'ubuntu:24.04']
            raw = json.loads(subprocess.check_output(command, text=True, timeout=300,
                            env=dict(os.environ, GRYPE_CHECK_FOR_APP_UPDATE='false')))
            scan = sanitize_scan(raw, args.output / (kind + '.spdx.json'))
            scans.append(scan)
            add(kind + '-vulnerabilities.json', 'scan', data=scan)
        review_result = dict(schema=1, result='unreviewed')
        if args.review:
            review_result = assessment(scans, read_json(args.review), [x for x in build['components'] if x['kind'] == 'native'])
        add('vulnerability-assessment.json', 'vulnerability-assessment', data=review_result)
        data = dict(schema=1, policy_version=1, identity=identity, source_sha256=selected['source_sha256'],
                    target=selected['target'], build=dict(manifest_sha256=built['manifest_sha256'],
                    binary_sha256=built['binary_sha256'], lock_sha256=build['lock_sha256']),
                    image=dict(repository='ghcr.io/epochgrid/epochgrid', platform='linux/amd64',
                    registry_digest=None, config_id=built['image_id'], base=built['base'],
                    transport_sha256=built['transport_sha256']), assets=assets,
                    support=dict(scope=['Ubuntu 24.04 x86-64; operator-owned NATS; separate Linux roles/keyrings'],
                    limitations=['Unaudited engineering prerelease', 'TD-001/002/003 remain open',
                                 'Dynamic attachments and short-lease messaging are not qualified'],
                    readiness='engineering-prerelease'))
        write_json(args.output / 'PROPOSAL.json', data)
        if args.require_review:
            require(review_result['result'] == 'reviewed', 'Publishing requires a reviewed vulnerability assessment')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    g = sub.add_parser('gate')
    g.add_argument('--output', type=Path, required=True)
    a = sub.add_parser('assemble')
    for name in ('linux', 'image', 'reports', 'output'):
        a.add_argument('--' + name, type=Path, required=True)
    a.add_argument('--review', type=Path)
    a.add_argument('--require-review', action='store_true')
    a.add_argument('--version', required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    if args.command == 'gate':
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.output, gate(json.loads(os.environ['RESULTS'])))
    else:
        assemble(args)


if __name__ == '__main__':
    main()
