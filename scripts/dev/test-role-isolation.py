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
    command = ['docker', 'run', '--rm', '--network', 'none', '--hostname', 'epochgrid-test',
               '--add-host', 'epochgrid-test:127.0.0.1']
    for source, destination in [(ROOT / 'target/debug', ROOT / 'target/debug'),
                                (ROOT / 'scripts', ROOT / 'scripts'),
                                (ROOT / '.dev/nats-image', Path('/opt/nats'))]:
        command += ['--mount', f'type=bind,src={source},dst={destination},readonly']
    command += ['-w', str(ROOT), '-e', 'NATS_SERVER=/opt/nats/nats-server',
                'epochgrid-role-tests:local',
                'python3', 'scripts/dev/run-bounded.py', '300',
                'scripts/dev/with-test-keyring.sh', harness, '--ignored', '--exact',
                ('tls::production_tls_enrollment_negative_trust_and_certificate_rotation'
                 if case == 'tls' else 'byo_nats::' + case), '--nocapture']
    subprocess.run(command, check=True)
