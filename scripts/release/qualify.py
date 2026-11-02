#!/usr/bin/env python3
"""Run exact extracted bundle bytes in a clean, network-isolated Ubuntu runtime."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from artifact import BINS, ROOT, digest, output, validate_stage


def inside(args):
    if shutil.which('cargo') or shutil.which('rustc'):
        raise ValueError('Qualification runtime contains a compiler')
    if any((ROOT / 'target/debug' / name).exists() for name in BINS):
        raise ValueError('Debug application binary exposed to runtime')
    data = validate_stage(args.bundle)
    for name in BINS:
        path = args.bundle / 'bin' / name
        if output(str(path), '--version') != f'{name} {data["version"]}':
            raise ValueError('Extracted binary version mismatch')
        subprocess.run([str(path), '--help'], check=True, stdout=subprocess.DEVNULL, timeout=10,
                       env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent'))
        if 'not found' in output('ldd', str(path)):
            raise ValueError('Unresolved native library')
    env = dict(os.environ, EPOCHGRID_RELEASE_BIN_DIR=str(args.bundle / 'bin'),
               EPOCHGRID_ROLE_NATIVE='1', NATS_SERVER='/opt/nats/nats-server',
               EPOCHGRID_PROFILE='production')
    def run(seconds, command):
        subprocess.run(['python3', 'scripts/dev/run-bounded.py', str(seconds),
                        'scripts/dev/with-test-keyring.sh', *command], env=env, check=True)
    if args.suite == 'smoke':
        run(90, ['python3', 'scripts/dev/test-secrets-live.py'])
        run(60, [args.harness, 'artifact_audit_upgrade', '--exact', '--nocapture'])
        for script, options, seconds in [('tui-smoke.py', [], 180),
                                         ('tui-smoke.py', ['--relationships-only'], 90),
                                         ('tui-smoke.py', ['--participants-only'], 120),
                                         ('dynamic-tui-smoke.py', ['--disconnect-before-join'], 180)]:
            run(seconds, ['python3', 'scripts/dev/' + script, *options])
    else:
        env['EPOCHGRID_PROFILE'] = 'production'
        run(300, [args.harness, 'byo_nats::' + args.suite, '--ignored', '--exact',
                  '--test-threads=1', '--nocapture'])
    print('Extracted release binaries qualified: ' + args.suite, flush=True)


def outside(args):
    data = validate_stage(args.bundle)
    manifest = json.loads(args.runtime_manifest.read_text())
    spec = importlib.util.spec_from_file_location('runtime', ROOT / 'scripts/ci/runtime.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if manifest['revision'] != data['commit'] or manifest['source'] != runtime.source_digest():
        raise ValueError('Test harness source/revision differs from bundle checkout')
    if data['source_sha256'] != __import__('artifact').source():
        raise ValueError('Bundle source differs from qualification checkout')
    if manifest['platform'][:3] != ['ubuntu', '24.04', 'x86_64']:
        raise ValueError('Qualification test harness must be built on Ubuntu 24.04 x86-64')
    harness = next(t['path'] for t in manifest['tests'] if t['name'] == 'registration')
    checkout = Path(manifest['checkout'])
    selected = [harness, 'target/debug/examples/encrypted-query', 'target/debug/examples/backend-role-probe']
    command = ['docker', 'run', '--rm', '--network', 'none', '--hostname', 'epochgrid-test',
               '--add-host', 'epochgrid-test:127.0.0.1', '--user', '1000:1000',
               '--workdir', str(checkout)]
    def mount(source, destination):
        command.extend(['--mount', f'type=bind,src={source},dst={destination},readonly'])
    for name in selected:
        path = args.runtime_manifest.parent.parent / name.removeprefix('target/')
        if name not in manifest['files'] or digest(path) != manifest['files'][name]:
            raise ValueError('Missing/corrupt qualification test tool')
        mount(path, checkout / name)
    mount(ROOT / 'scripts', checkout / 'scripts')
    mount(ROOT / '.dev/nats-image', Path('/opt/nats'))
    # Fixed path includes spaces to qualify relocation without special shell quoting.
    relocated = Path('/opt/epochgrid candidate')
    mount(args.bundle, relocated)
    command += [args.image, 'python3', 'scripts/release/qualify.py', '--inside',
                '--bundle', str(relocated), '--suite', args.suite,
                '--harness', str(checkout / harness)]
    subprocess.run(command, check=True)
    result = dict(schema=1, suite=args.suite, result='passed', commit=data['commit'],
                  manifest_sha256=digest(args.bundle / 'BUILD.json'),
                  binary_sha256={name: digest(args.bundle / 'bin' / name) for name in BINS},
                  image=output('docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'))
    if args.result:
        args.result.parent.mkdir(parents=True, exist_ok=True)
        with args.result.open('x') as stream:
            json.dump(result, stream, indent=2)
            stream.write('\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--runtime-manifest', type=Path, default=ROOT / 'target/ci/manifest.json')
    parser.add_argument('--suite', choices=['smoke', 'configuration_standalone', 'configuration_cluster',
                                          'operator_jwt_standalone', 'operator_jwt_cluster'], required=True)
    parser.add_argument('--image', default='epochgrid-artifact-tests:local')
    parser.add_argument('--result', type=Path)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--harness')
    args = parser.parse_args()
    args.bundle = args.bundle.resolve()
    args.runtime_manifest = args.runtime_manifest.resolve()
    os.chdir(ROOT)
    try:
        (inside if args.inside else outside)(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'Artifact qualification failed: {error}', file=sys.stderr)
        sys.exit(1)
