#!/usr/bin/env python3
"""Opt-in disposable compiled-dependency cache experiment; never used by the gate.

Build cold, remove workspace products, archive at most 1 GiB of dependencies,
restore into the SAME target path, then rebuild. Reports failures without retry.
The archive and build tree are deleted on exit. Network transfer still needs a
hosted-runner experiment; local compression timings alone do not justify caching.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

records = {}
env = dict(os.environ, CARGO_PROFILE_DEV_DEBUG='1', CARGO_PROFILE_TEST_DEBUG='1', CARGO_INCREMENTAL='0')


def measured(label, action):
    started = time.monotonic()
    try:
        return action()
    finally:
        records[label] = round(time.monotonic() - started, 3)
        print(json.dumps(records), flush=True)


def compile_workspace():
    for args in (['build', '--workspace', '--bins', '--examples'], ['test', '--workspace', '--no-run']):
        subprocess.run(['python3', 'scripts/dev/run-bounded.py', '900', 'cargo', *args, '--locked'], env=env, check=True)


with tempfile.TemporaryDirectory(prefix='epochgrid-cache-benchmark-') as directory:
    root = Path(directory)
    target = root / 'target'
    env['CARGO_TARGET_DIR'] = str(target)
    records['key'] = hashlib.sha256(Path('Cargo.lock').read_bytes() +
        subprocess.check_output(['rustc', '-vV']) + b'debug=1;incremental=0;workspace-default-features;' +
        subprocess.check_output(['uname', '-m']) + Path('/etc/os-release').read_bytes()).hexdigest()
    measured('cold_compile_seconds', compile_workspace)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--no-deps', '--format-version=1']))
    for package in metadata['packages']:
        if package['id'] in metadata['workspace_members']:
            subprocess.run(['cargo', 'clean', '-p', package['name']], env=env, check=True)
    files = [p for p in target.rglob('*') if p.is_file()]
    records['uncompressed_bytes'] = sum(p.stat().st_size for p in files)
    if records['uncompressed_bytes'] > 1024 ** 3:
        print(json.dumps(records))
        raise SystemExit('Dependency cache exceeds 1 GiB experiment limit; do not retain it')
    archive = root / 'dependencies.tar.gz'

    def pack():
        with tarfile.open(archive, 'w:gz', compresslevel=1) as bundle:
            bundle.add(target, arcname='target')

    measured('compress_seconds', pack)
    records['archive_bytes'] = archive.stat().st_size
    shutil.rmtree(target)  # Only the temporary directory allocated above.

    def restore():
        with tarfile.open(archive) as bundle:
            bundle.extractall(root, filter='data')

    measured('restore_seconds', restore)
    measured('warm_compile_seconds', compile_workspace)
    records['local_seconds_saved_before_transfer'] = records['cold_compile_seconds'] - records['warm_compile_seconds'] - records['compress_seconds'] - records['restore_seconds']
    print(json.dumps(records))
