#!/usr/bin/env python3
"""Run retained qualification assertions against exact application image bytes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from artifact import ROOT, digest, output, source, write_json
from image import check_identity, inspect_archive

CASES = ('configuration_standalone', 'configuration_cluster',
         'operator_jwt_standalone', 'operator_jwt_cluster', 'audit-upgrade', 'smoke')


def mount(path, destination, readonly=True):
    return ['--mount', f'type=bind,src={path},dst={destination}' + (',readonly' if readonly else '')]


def docker(*args, **options):
    return subprocess.run(['docker', *map(str, args)], check=True, **options)


def qualify(args, report):
    setup_started = time.monotonic()
    image_report = json.loads(args.image_report.read_text())
    image = image_report['image_id']
    report.update(image_id=image, source_sha256=image_report['source_sha256'], commit=image_report['commit'])
    if image_report['result'] != 'passed' or image_report['source_sha256'] != source():
        raise ValueError('Image construction failed or source changed')
    archive = args.image_report.with_name('image.tar')
    if digest(archive) != image_report['transport_sha256']:
        raise ValueError('Image transport checksum mismatch')
    # Validate transport before allowing Docker to load it. Its config ID binds
    # the layers; the in-image manifest is then checked against the build report.
    inspect_archive(archive, image, dict(commit=image_report['commit'], version=args.version))
    docker('load', '--input', archive, stdout=subprocess.DEVNULL, timeout=90)
    raw = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--read-only',
                 '--entrypoint', '/bin/cat', image, '/usr/share/epochgrid/BUILD.json'], timeout=30)
    data = json.loads(raw)
    check_identity(data, True)
    if __import__('hashlib').sha256(raw).hexdigest() != image_report['manifest_sha256']:
        raise ValueError('Image manifest differs from construction report')
    manifest = json.loads(args.runtime_manifest.read_text())
    spec = importlib.util.spec_from_file_location('runtime', ROOT / 'scripts/ci/runtime.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if manifest['source'] != runtime.source_digest() or manifest['revision'] != data['commit']:
        raise ValueError('Test harness source/revision differs from image')
    if manifest['platform'][:3] != ['ubuntu', '24.04', 'x86_64']:
        raise ValueError('Image test tools require Ubuntu 24.04 amd64')
    harness = next(item['path'] for item in manifest['tests'] if item['name'] == 'registration')
    prefix = 'eg-image-' + uuid.uuid4().hex[:12]
    report['fixture_prefix'] = prefix
    host = prefix + '-host'
    fixture = output('docker', 'image', 'inspect', args.fixture_image, '--format', '{{.Id}}')
    report['fixture_image_id'] = fixture
    with tempfile.TemporaryDirectory(prefix='eg-image-') as temporary:
        root = Path(temporary)
        scratch = root / 'tmp'
        scratch.mkdir(mode=0o1777)
        scratch.chmod(0o1777)
        wrappers = root / 'bin'
        wrappers.mkdir()
        (root / 'docker-config').mkdir()
        for name in ('epochgrid', 'epochgrid-service'):
            shutil.copyfile(ROOT / 'scripts/release/image-process.py', wrappers / name)
            (wrappers / name).chmod(0o755)
        config = root / 'config.json'
        write_json(config, dict(image=image, prefix=prefix, host=host, scratch=str(scratch)))
        command = ['create', '--name', host, '--network', 'none', '--hostname', 'epochgrid-test',
                   '--add-host', 'epochgrid-test:127.0.0.1', '--user', '0:0', '--workdir', str(ROOT),
                   '-e', 'EPOCHGRID_IMAGE_BIN_DIR=/opt/image-bin', '-e', 'EPOCHGRID_ROLE_NATIVE=1',
                   '-e', 'EPOCHGRID_PROFILE=production', '-e', 'NATS_SERVER=/opt/nats/nats-server']
        for name in [harness, 'target/debug/examples/encrypted-query', 'target/debug/examples/backend-role-probe']:
            path = args.runtime_manifest.parent.parent / name.removeprefix('target/')
            if manifest['files'].get(name) != digest(path):
                raise ValueError('Missing/corrupt image test tool')
            command += mount(path, Path(manifest['checkout']) / name)
        command += mount(scratch, '/tmp', False)
        command += mount(wrappers, '/opt/image-bin')
        command += mount(root / 'docker-config', '/opt/docker-config')
        command += mount(config, '/etc/epochgrid-image-fixture.json')
        command += mount(ROOT / 'scripts', ROOT / 'scripts')
        command += mount(ROOT / '.dev/nats-image', '/opt/nats')
        # Docker access is exclusive to this disposable orchestration host. No
        # application mount constructed by image-process.py can reference it.
        command += mount(Path(shutil.which('docker')).resolve(), '/opt/docker')
        command += mount(Path('/var/run/docker.sock'), '/var/run/docker.sock', False)
        bootstrap = '''import grp,os,subprocess,sys
gid=os.stat('/var/run/docker.sock').st_gid
try: group=grp.getgrgid(gid).gr_name
except KeyError:
    group='fixture-docker'
    subprocess.run(['groupadd','--gid',str(gid),group],check=True)
for account in ('ubuntu','nobody','daemon'):
    subprocess.run(['usermod','-aG',group,account],check=True)
subprocess.run(['python3','scripts/release/test-qualification.py',
               'QualificationTests.test_public_nats_fixture_access'],check=True)
os.initgroups('ubuntu',1000)
os.setgid(1000)
os.setuid(1000)
os.execvp(sys.argv[1],sys.argv[1:])
'''
        case = 'artifact_audit_upgrade' if args.suite == 'audit-upgrade' else 'byo_nats::' + args.suite
        test = [str(Path(manifest['checkout']) / harness), case, '--exact', '--nocapture', '--test-threads=1']
        if args.suite == 'smoke':
            test = ['python3', 'scripts/release/qualify-image.py', '--inside-smoke',
                    str(Path(manifest['checkout']) / harness)]
        elif args.suite != 'audit-upgrade':
            test.append('--ignored')
        wrapped = test if args.suite == 'smoke' else ['scripts/dev/with-test-keyring.sh', *test]
        command += [fixture, 'python3', '-c', bootstrap, 'python3', 'scripts/dev/run-bounded.py',
                    '300', *wrapped]
        report['phase'] = 'execute'
        execution_started = None
        try:
            docker(*command, stdout=subprocess.DEVNULL, timeout=30)
            report['setup_seconds'] = round(time.monotonic() - setup_started, 3)
            execution_started = time.monotonic()
            docker('start', '--attach', host, timeout=330)
            if output('docker', 'inspect', '--format', '{{.State.ExitCode}}', host) != '0':
                raise ValueError('Image qualification case failed')
            if source() != data['source_sha256']:
                raise ValueError('Source changed during image qualification')
        finally:
            if execution_started is not None:
                report['execution_seconds'] = round(time.monotonic() - execution_started, 3)
            original_error = sys.exception()
            cleanup_errors = []
            def cleanup(*command):
                try:
                    docker(*command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                except (OSError, subprocess.SubprocessError):
                    cleanup_errors.append(command[0])
            try:
                ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter',
                      'label=epochgrid.image-fixture=' + prefix], text=True, timeout=15).split()
            except (OSError, subprocess.SubprocessError):
                ids = []
                cleanup_errors.append('list_containers')
            if ids:
                cleanup('rm', '--force', *ids)
            cleanup('rm', '--force', host)
            cleanup('run', '--rm', '--network', 'none', '--user', '0:0', *mount(scratch, '/fixture', False),
                   fixture, 'python3', '-c',
                   'import pathlib,shutil; [(shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()) '
                   'for p in pathlib.Path("/fixture").iterdir()]')
            if cleanup_errors:
                report['cleanup_errors'] = cleanup_errors
                if original_error is None:
                    raise ValueError('Image fixture cleanup failed')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--inside-smoke':
        for seconds, command in [
            (90, ['python3', 'scripts/dev/test-secrets-live.py']),
            (60, [sys.argv[2], 'artifact_audit_upgrade', '--exact', '--nocapture']),
            (180, ['python3', 'scripts/dev/dynamic-tui-smoke.py', '--disconnect-before-join']),
        ]:
            subprocess.run(['python3', 'scripts/dev/run-bounded.py', str(seconds),
                            'scripts/dev/with-test-keyring.sh', *command], check=True)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-report', type=Path, required=True)
    parser.add_argument('--runtime-manifest', type=Path, default=ROOT / 'target/ci/manifest.json')
    parser.add_argument('--fixture-image', default='epochgrid-artifact-tests:local')
    parser.add_argument('--suite', choices=CASES, required=True)
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    args.image_report = args.image_report.resolve()
    args.runtime_manifest = args.runtime_manifest.resolve()
    args.version = __import__('tomllib').loads((ROOT / 'Cargo.toml').read_text())['workspace']['package']['version']
    args.result.parent.mkdir(parents=True, exist_ok=True)
    if args.result.exists():
        parser.error('result already exists')
    started = time.monotonic()
    report = dict(schema=1, suite=args.suite, result='failed', phase='preflight')
    try:
        qualify(args, report)
        report.update(result='passed', phase='complete')
    except Exception as error:
        report['error_type'] = type(error).__name__
        raise
    finally:
        report['seconds'] = round(time.monotonic() - started, 3)
        write_json(args.result, report)


if __name__ == '__main__':
    main()
