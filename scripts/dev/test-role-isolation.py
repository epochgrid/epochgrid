#!/usr/bin/env python3
"""Run revision-checked BYO cases with distinct UIDs/keyrings in disposable containers."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('runtime', ROOT / 'scripts/ci/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
data = json.loads(runtime.MANIFEST.read_text())
runtime.validate(data)
harness = next(t['path'] for t in data['tests'] if t['name'] == 'registration')
cases = [name.removeprefix('byo_nats::') for name in runtime.BYO]
selected = sys.argv[1:] or cases
if not set(selected).issubset(cases + ['tls']):
    raise SystemExit('unknown role-isolation case')
for case in selected:
    command = ['docker', 'run', '--rm', '--network', 'none', '--user', '0:0', '--hostname', 'epochgrid-test',
               '--add-host', 'epochgrid-test:127.0.0.1']
    for source, destination in [(ROOT / 'target/debug', ROOT / 'target/debug'),
                                (ROOT / 'scripts', ROOT / 'scripts'),
                                (ROOT / '.dev/nats-image', Path('/opt/nats'))]:
        command += ['--mount', f'type=bind,src={source},dst={destination},readonly']
    command += ['-w', str(ROOT), '-e', 'NATS_SERVER=/opt/nats/nats-server',
                'epochgrid-role-tests:local',
                # Reproduce hosted runners with an inaccessible checkout ancestor.
                # ROOT itself is container-owned, not one of the read-only mounts.
                # Only fixture bootstrap runs as root; tests run as UID 1000 and
                # the worker as nobody. No host directory permissions are changed.
                'python3', '-c',
                'import os, subprocess, sys; '
                'os.chown(sys.argv[1], 1000, 1000); os.chmod(sys.argv[1], 0o700); '
                'subprocess.run(["sudo", "-n", "-u", "nobody", "--", "test", "!", "-x", sys.argv[1]], check=True); '
                'os.setgroups([]); os.setgid(1000); os.setuid(1000); '
                'os.execvp(sys.argv[2], sys.argv[2:])', str(ROOT),
                'python3', 'scripts/dev/run-bounded.py', '300',
                'scripts/dev/with-test-keyring.sh', harness, '--ignored', '--exact',
                ('tls::production_tls_enrollment_negative_trust_and_certificate_rotation'
                 if case == 'tls' else 'byo_nats::' + case), '--nocapture']
    subprocess.run(command, check=True)
