#!/usr/bin/env python3
"""Build a revision-bound runtime bundle and run libtest without invoking Cargo."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / 'target/ci/manifest.json'
DYNAMIC = 'auth_callout::dynamic_enrollment_inbox_isolation_revocation_without_reload'
BYO = ['byo_nats::' + name for name in (
    'configuration_standalone', 'configuration_cluster',
    'operator_jwt_standalone', 'operator_jwt_cluster')]


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_digest():
    # Includes uncommitted local edits; excludes runtime state and generated files.
    paths = sorted({*ROOT.glob('Cargo.*'), *ROOT.glob('rust-toolchain.toml'),
                    *ROOT.glob('crates/**/Cargo.toml'), *ROOT.glob('crates/**/*.rs')})
    return hashlib.sha256(''.join(str(p.relative_to(ROOT)) + digest(p) for p in paths).encode()).hexdigest()


def host():
    release = platform.freedesktop_os_release()
    return [release['ID'], release['VERSION_ID'], platform.machine(), *platform.libc_ver()]


def build():
    files, tests = {}, []
    for args in [('build', '--workspace', '--bins', '--examples'),
                 ('test', '--workspace', '--no-run')]:
        process = subprocess.Popen(['cargo', *args, '--locked', '--message-format=json'],
                                   stdout=subprocess.PIPE, text=True)
        for line in process.stdout:
            item = json.loads(line)
            if item.get('reason') == 'compiler-message':
                print(item['message'].get('rendered', ''), end='', file=sys.stderr)
            if item.get('reason') != 'compiler-artifact' or not item.get('executable'):
                continue
            path = Path(item['executable']).resolve().relative_to(ROOT).as_posix()
            files[path] = digest(ROOT / path)
            if item['profile']['test']:
                tests.append({'path': path, 'name': item['target']['name'],
                              'kind': item['target']['kind']})
        if process.wait():
            raise SystemExit(process.returncode)
    data = dict(revision=output('git', 'rev-parse', 'HEAD'), source=source_digest(),
                checkout=str(ROOT), platform=host(), files=files, tests=tests)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(data, indent=2) + '\n')
    validate(data)
    packed_at = time.monotonic()
    with tarfile.open(MANIFEST.parent / 'runtime.tar.gz', 'w:gz', compresslevel=1) as bundle:
        for path in sorted(files):
            bundle.add(ROOT / path, arcname=path, recursive=False)
        bundle.add(MANIFEST, arcname='target/ci/manifest.json')
    print(f'Runtime artifact: {(MANIFEST.parent / "runtime.tar.gz").stat().st_size} bytes; compression {time.monotonic() - packed_at:.3f}s', flush=True)


def validate(data):
    if data['revision'] != output('git', 'rev-parse', 'HEAD') or data['source'] != source_digest():
        raise ValueError('Runtime artifact is stale; run verify.sh build')
    if data['checkout'] != str(ROOT):
        raise ValueError('Checkout path differs from embedded CARGO_BIN_EXE paths')
    if data["platform"] != host():
        raise ValueError("Runtime artifact OS, architecture or libc differs")
    # Hosted kernels may differ; userspace ABI must match.
    for name, expected in data['files'].items():
        path = ROOT / name
        if not name.startswith('target/debug/') or '..' in Path(name).parts:
            raise ValueError('Invalid runtime artifact path')
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK) or digest(path) != expected:
            raise ValueError(f'Missing, corrupt or non-executable runtime file: {name}')
    for test in data['tests']:
        if test['path'] not in data['files']:
            raise ValueError('Test executable absent from runtime manifest')


def listed(path, ignored=False):
    args = [str(ROOT / path), '--list', '--format=terse']
    if ignored:
        args.append('--ignored')
    return sorted(line[:-6] for line in output(*args).splitlines() if line.endswith(': test'))


def partition(names):
    if len(names) != len(set(names)) or not set(BYO + [DYNAMIC]).issubset(names):
        raise ValueError('Duplicate or missing qualification/quarantine cases')
    retained = sorted(set(names) - set(BYO + [DYNAMIC]))
    # Discover, then distribute every retained test exactly once, including new tests.
    return [retained[index::4] for index in range(4)]


def bounded(seconds, command, keyring=False, **environment):
    env = os.environ.copy()
    env.update(environment)
    for key in ('EPOCHGRID_TLS_CA_PATH', 'EPOCHGRID_TLS_FIRST', 'EPOCHGRID_TLS_MIN_VERSION'):
        env.pop(key, None)
    args = ['python3', 'scripts/dev/run-bounded.py', str(seconds)]
    if keyring:
        args += ['scripts/dev/with-test-keyring.sh']
    subprocess.run(args + command, env=env, check=True)


def run(phase, case=None):
    data = json.loads(MANIFEST.read_text())
    validate(data)
    registration = next(t['path'] for t in data['tests'] if t['name'] == 'registration')
    core = next(t['path'] for t in data['tests'] if t['name'] == 'epochgrid_core')
    if phase == 'check':
        partition(listed(registration, True))
    elif phase == 'unit':
        for test in data['tests']:
            args = [str(ROOT / test['path'])]
            if os.environ.get('EPOCHGRID_TEST_THREADS'):
                args += ['--test-threads=' + os.environ['EPOCHGRID_TEST_THREADS']]
            bounded(180, args, keyring=True, EPOCHGRID_CHECK_LABEL='unit-' + test['name'])
    elif phase == 'secrets':
        for name in ('secrets::tests::live_keyring_restart_binding_duplicate_and_lock',
                     'validation::tests::live_validation_duplicate_swapped_and_locked_credentials',
                     'secrets::tests::live_unavailable_bus_is_bounded'):
            unavailable = name.endswith('live_unavailable_bus_is_bounded')
            env = {'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/nonexistent/epochgrid-test-bus'} if unavailable else {}
            bounded(30 if unavailable else 120, [str(ROOT / core), name, '--ignored', '--exact'],
                    keyring=not unavailable, EPOCHGRID_CHECK_LABEL=name, **env)
        bounded(60, ['python3', 'scripts/dev/test-secrets-live.py'], keyring=True)
    else:
        groups = partition(listed(registration, True))
        if phase == 'byo-nats':
            selected = BYO if case is None else ['byo_nats::' + case]
            if not set(selected).issubset(BYO):
                raise ValueError('Unknown BYO case')
        elif phase == 'nats-dynamic':
            selected = [DYNAMIC]
        elif phase == 'nats':
            print('SKIP TD-002: dynamic Auth Callout; use nats-dynamic explicitly', flush=True)
            if case is not None and case not in ('0', '1', '2', '3'):
                raise ValueError('NATS group must be 0, 1, 2 or 3')
            selected = sum(groups, []) if case is None else groups[int(case)]
        else:
            raise ValueError('Unknown phase')
        for name in selected:
            isolated = name in BYO or name == 'tls::production_tls_enrollment_negative_trust_and_certificate_rotation'
            if isolated and os.environ.get('EPOCHGRID_ROLE_NATIVE') != '1':
                case = name.removeprefix('byo_nats::') if name in BYO else 'tls'
                subprocess.run(['python3', 'scripts/dev/test-role-isolation.py', case], check=True)
                continue
            bounded(260 if name in BYO else 180,
                    [str(ROOT / registration), name, '--ignored', '--exact', '--test-threads=1', '--nocapture'],
                    keyring=True, EPOCHGRID_PROFILE='production' if name in BYO else 'development',
                    NATS_SERVER=str(ROOT / '.dev/nats-image/nats-server'), EPOCHGRID_CHECK_LABEL=name)


if __name__ == '__main__':
    os.chdir(ROOT)
    try:
        if sys.argv[1] == 'build':
            build()
        else:
            run(*sys.argv[1:])
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f'CI runtime failure: {error}', file=sys.stderr)
        sys.exit(getattr(error, 'returncode', 1))
