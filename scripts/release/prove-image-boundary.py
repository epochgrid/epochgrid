#!/usr/bin/env python3
"""First M33 gate: separate runtime containers, UIDs, keyrings and read-only IPC.

This focused configuration/R1 proof is not the four-case BYO qualification matrix.
All helpers remain outside the application containers; no runtime binary mounts.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from artifact import ROOT, output, source, write_json
from image import check_identity


def docker(*args, check=True, timeout=30):
    result = subprocess.run(['docker', *map(str, args)], capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Local diagnostic only; reports never retain subprocess output.
        raise RuntimeError(f'Docker operation {args[0]} failed: {result.stderr.decode(errors="replace")[-2000:]}')
    return result


def mount(source, destination, readonly=False):
    return ['--mount', f'type=bind,src={source},dst={destination}' + (',readonly' if readonly else '')]


def prove(args):
    image = output('docker', 'image', 'inspect', args.image, '--format', '{{.Id}}')
    helper = output('docker', 'image', 'inspect', args.fixture_image, '--format', '{{.Id}}')
    prefix = 'eg-boundary-' + uuid.uuid4().hex[:12]
    containers = []
    report = dict(schema=1, result='failed', image_id=image, fixture_image_id=helper,
                  authority_uid=21001, worker_uid=21002, host_uid=os.getuid(), checks=[], phase='setup')
    started = time.monotonic()
    network = False
    with tempfile.TemporaryDirectory(prefix='eg-boundary-') as temporary:
        root = Path(temporary)
        fixture = ROOT / 'scripts/release/image-fixture.py'
        try:
            data = json.loads(docker('run', '--rm', '--network', 'none', '--read-only',
                              '--cap-drop=ALL', '--security-opt=no-new-privileges',
                              '--entrypoint', '/bin/cat', image, '/usr/share/epochgrid/BUILD.json').stdout)
            check_identity(data, True)
            report.update(commit=data['commit'], source_sha256=data['source_sha256'])
            # Retain the M32 root-owned/public-fixture regression in this runner.
            docker('run', '--rm', '--network', 'none', '--user', '0:0',
                   *mount(ROOT / 'scripts', ROOT / 'scripts', True), '-w', ROOT, helper,
                   'python3', 'scripts/release/test-qualification.py',
                   'QualificationTests.test_public_nats_fixture_access')
            docker('network', 'create', '--internal', prefix)
            network = True
            for role, uid in [('authority', 21001), ('control', 21002)]:
                (root / role).mkdir()
                name = prefix + '-' + role + '-keyring'
                containers.append(name)
                docker('run', '-d', '--name', name, '--network', 'none', '--user', '0:0',
                       *mount(root / role, '/fixture'), *mount(fixture, '/helper.py', True),
                       helper, 'python3', '/helper.py', 'keyring', str(uid))
                deadline = time.monotonic() + 15
                while docker('exec', name, 'test', '-f', '/fixture/bus/ready', check=False).returncode:
                    if time.monotonic() > deadline:
                        raise RuntimeError('Independent keyring readiness deadline')
                    time.sleep(.1)
            (root / 'ipc').mkdir()
            (root / 'broker').mkdir()
            # Fixture-only provisioning; no root startup wrapper in the image.
            docker('run', '--rm', '--network', 'none', '--user', '0:0', *mount(root / 'ipc', '/ipc'),
                   helper, 'python3', '-c', 'import os; os.chown("/ipc",21001,21001); os.chmod("/ipc",0o755)')

            def base(role, uid=None, bus=True):
                role_uid = 21001 if role == 'authority' else 21002
                command = ['--network', prefix, '--user', f'{uid or role_uid}:{uid or role_uid}',
                           '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                           '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m',
                           '--pids-limit', '128', '--memory', '256m',
                           '-e', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/bus/socket']
                command += mount(root / role / 'state', '/state')
                if bus:
                    command += mount(root / role / 'bus', '/bus', True)
                command += mount(root / 'ipc', '/eg-ipc', role != 'authority')
                if (root / 'broker/ca.pem').exists():
                    command += mount(root / 'broker/ca.pem', '/trust/ca.pem', True)
                    command += ['-e', 'EPOCHGRID_TLS_CA_PATH=/trust/ca.pem']
                return command

            def app(role, *command, check=True, uid=None, bus=True):
                return docker('run', '--rm', *base(role, uid, bus), image,
                              '--home', '/state', '--server', 'tls://broker:4222', *command,
                              check=check, timeout=30)

            def read(role, path):
                return docker('run', '--rm', *base(role), '--entrypoint', '/bin/cat', image, path).stdout

            report['phase'] = 'initialize'
            app('authority', 'auth-init', '--replicas', '1')
            key = app('control', 'worker-init').stdout.decode().strip()
            if len(key) != 56 or not key.startswith('U'):
                raise RuntimeError('Invalid public worker identity')
            bound = app('authority', 'role-bind', '--worker-uid', '21002', '--worker-nkey', key,
                        '--socket', '/eg-ipc/control.sock').stdout
            bindings = json.loads(bound)
            if bindings['authority_uid'] != 21001 or bindings['worker_uid'] != 21002:
                raise RuntimeError('Role binding UID mismatch')
            (root / 'bindings.json').write_bytes(bound)
            docker('run', '--rm', *base('control'), *mount(root / 'bindings.json', '/bindings.json', True),
                   image, '--home', '/state', 'worker-configure', '--bindings', '/bindings.json')
            for name in ('nats-reference.conf', 'CHAT.json', 'MAILBOX.json', 'KV_IDENTITIES.json',
                         'KV_CHANNELS.json', 'KV_TRANSPARENCY.json'):
                (root / 'broker' / name).write_bytes(read('authority', '/state/deployment-artifacts/' + name))
            report['checks'].append('separate_uid_initialization_and_binding')
            references = []
            for path in ('/state/credentials.json', '/state/control/credentials.json'):
                metadata = json.loads(read('authority', path))
                references += [slot['id'] for slot in metadata['slots'].values()]
            config = json.loads(read('authority', '/state/auth.json'))
            references += [config[slot]['id'] for slot in ('issuer', 'encryption', 'connection')]
            for reference in set(references):
                denied = docker('exec', '--user', '21002:21002', '-e',
                                'DBUS_SESSION_BUS_ADDRESS=unix:path=/fixture/bus/socket',
                                prefix + '-control-keyring', 'secret-tool', 'lookup',
                                'application', 'org.epochgrid.credentials.v1', 'id', reference, check=False)
                if denied.returncode != 1 or denied.stdout:
                    raise RuntimeError('Worker keyring exposed an authority credential')
            for path in ('/state/auth.json', '/state/auth.sqlite'):
                denied = docker('run', '--rm', *base('control'), '--entrypoint', '/bin/cat', image, path, check=False)
                if denied.returncode == 0 or denied.stdout:
                    raise RuntimeError('Authority state entered control container')
            report['checks'].append('independent_keyrings_and_private_authority_state')

            report['phase'] = 'broker'
            broker = prefix + '-broker'
            containers.append(broker)
            docker('run', '-d', '--name', broker, '--network', prefix, '--network-alias', 'broker',
                   '--user', '0:0', *mount(root / 'broker', '/fixture'),
                   *mount(fixture, '/helper.py', True), *mount(ROOT / '.dev/nats-image', '/opt/nats', True),
                   helper, 'python3', '/helper.py', 'broker')
            deadline = time.monotonic() + 15
            while docker('exec', broker, 'python3', '-c',
                         'import socket; socket.create_connection(("127.0.0.1",4222),1).close()',
                         check=False).returncode:
                if time.monotonic() > deadline:
                    raise RuntimeError('Broker readiness deadline')
                time.sleep(.1)
            docker('exec', broker, 'python3', '/helper.py', 'provision')
            app('authority', 'validate', '--auth-config', '/state/auth.json', '--offline', '--format', 'json')
            app('control', 'validate-control', '--offline', '--format', 'json')

            def start(role):
                name = prefix + '-' + role
                containers.append(name)
                command = ['serve-authority', '--auth-config', '/state/auth.json'] if role == 'authority' else ['serve-control']
                docker('run', '-d', '--name', name, *base(role), image,
                       '--home', '/state', '--server', 'tls://broker:4222', *command)
                return name

            def status(role, ready):
                deadline = time.monotonic() + 20
                while True:
                    result = app(role, 'status', '--role', role, '--format', 'json', check=False)
                    if result.stdout:
                        observed = json.loads(result.stdout)
                        if ready and result.returncode == 0 and observed['readiness'] == 'ready':
                            return observed
                        if not ready and (observed.get('observations') or {}).get('reconciled') is True:
                            return observed
                    if output('docker', 'inspect', '--format', '{{.State.Running}}', prefix + '-' + role) != 'true':
                        logs = docker('logs', '--tail', '15', prefix + '-' + role)
                        raise RuntimeError('Role startup failed: ' + (logs.stdout + logs.stderr).decode(errors='replace'))
                    if time.monotonic() > deadline:
                        raise RuntimeError('Authenticated role readiness deadline: ' + role)
                    time.sleep(.1)

            report['phase'] = 'runtime'
            authority = start('authority')
            status('authority', False)
            control = start('control')
            status('control', True)
            status('authority', True)
            for role in ('authority', 'control'):
                inspected = json.loads(docker('inspect', prefix + '-' + role).stdout)[0]
                mounts = {item['Destination']: item for item in inspected['Mounts']}
                if (set(mounts) != {'/state', '/bus', '/eg-ipc', '/trust/ca.pem'}
                        or set(inspected['HostConfig']['Tmpfs']) != {'/tmp'}):
                    raise RuntimeError('Unexpected application mount')
                if mounts['/bus']['RW'] or mounts['/eg-ipc']['RW'] != (role == 'authority'):
                    raise RuntimeError('Application mount policy mismatch')
            app('authority', 'validate', '--auth-config', '/state/auth.json', '--online',
                '--endpoint', 'tls://broker:4222', '--format', 'json')
            report['checks'].append('production_tls_standalone_readiness')

            # The peer-credential handshake and status calls above exercise actual
            # cross-container kernel UIDs. The worker mount cannot replace sockets.
            for path in ('/eg-ipc/control.sock', '/eg-ipc/control.sock.status'):
                denied = docker('run', '--rm', *base('control'), '--entrypoint', '/bin/rm', image, path, check=False)
                if denied.returncode == 0:
                    raise RuntimeError('Control replaced authority socket')
            denied = app('control', 'status', '--role', 'control', '--format', 'json', uid=21003, check=False)
            if denied.returncode == 0:
                raise RuntimeError('Unrelated UID received role diagnostics')
            docker('run', '--rm', '--network', 'none', '--user', '21003:21003',
                   *mount(root / 'ipc', '/eg-ipc', True), helper, 'python3', '-c',
                   'import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); '
                   's.connect("/eg-ipc/control.sock.status"); assert s.recv(1)==b""')
            report['checks'].append('readonly_ipc_and_unrelated_uid_denial')

            report['phase'] = 'stop_and_recreate'
            before = read('control', '/state/credentials.json')
            docker('stop', '--time', '8', control, timeout=12)
            if output('docker', 'inspect', '--format', '{{.State.ExitCode}}', control) != '0':
                raise RuntimeError('Control did not exit cleanly on Docker stop')
            deadline = time.monotonic() + 6
            while True:
                observed = app('authority', 'status', '--role', 'authority', '--format', 'json', check=False)
                if not json.loads(observed.stdout)['observations']['worker_live']:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError('Worker loss did not close admission')
                time.sleep(.1)
            docker('rm', control)
            containers.remove(control)
            control = start('control')
            status('control', True)
            if read('control', '/state/credentials.json') != before:
                raise RuntimeError('Recreation changed worker binding')
            report['checks'].append('docker_sigint_stop_and_worker_recreation')
            docker('stop', '--time', '8', control, timeout=12)
            docker('stop', '--time', '8', authority, timeout=12)
            if output('docker', 'inspect', '--format', '{{.State.ExitCode}}', authority) != '0':
                raise RuntimeError('Authority did not exit cleanly on Docker stop')
            for path in ('/eg-ipc/control.sock', '/eg-ipc/control.sock.status'):
                docker('run', '--rm', *base('authority'), '--entrypoint', '/usr/bin/test', image, '!', '-e', path)
            docker('rm', authority)
            containers.remove(authority)
            authority = start('authority')
            observed = status('authority', False)
            if observed['observations']['worker_live']:
                raise RuntimeError('Authority restart reused a stale worker session')
            docker('rm', control)
            containers.remove(control)
            control = start('control')
            status('control', True)
            status('authority', True)
            docker('stop', '--time', '8', control, authority, timeout=22)
            report['checks'].append('authority_socket_cleanup_and_fresh_worker_restart')
            missing = app('control', 'validate-control', '--offline', '--format', 'json', bus=False, check=False)
            if missing.returncode == 0 or read('control', '/state/credentials.json') != before:
                raise RuntimeError('Missing keyring accepted or replaced credentials')
            report['checks'].append('missing_keyring_preserves_binding')
            docker('exec', '--user', '21002:21002', '-e', 'DBUS_SESSION_BUS_ADDRESS=unix:path=/fixture/bus/socket',
                   prefix + '-control-keyring', 'gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets',
                   '--object-path', '/org/freedesktop/secrets', '--method', 'org.freedesktop.Secret.Service.Lock',
                   "['/org/freedesktop/secrets/collection/login']")
            locked = app('control', 'validate-control', '--offline', '--format', 'json', check=False)
            if locked.returncode == 0 or read('control', '/state/credentials.json') != before:
                raise RuntimeError('Locked keyring accepted or replaced credentials')
            report['checks'].append('locked_keyring_preserves_binding')
            if source() != data['source_sha256']:
                raise RuntimeError('Qualification source changed during proof')
            report.update(result='passed', phase='complete')
        finally:
            original_error = sys.exception()
            cleanup_errors = []

            def cleanup(*command):
                try:
                    if docker(*command, check=False).returncode:
                        cleanup_errors.append(command[0])
                except (OSError, subprocess.TimeoutExpired):
                    cleanup_errors.append(command[0])

            for name in reversed(containers):
                cleanup('rm', '-f', name)
            if network:
                cleanup('network', 'rm', prefix)
            # Remove only this run's disposable fixture contents under the exact
            # temporary mount; application state outside it is never involved.
            cleanup('run', '--rm', '--network', 'none', '--user', '0:0', *mount(root, '/fixture'),
                   helper, 'python3', '-c',
                   'import pathlib,shutil; [(shutil.rmtree(p) if p.is_dir() else p.unlink()) for p in pathlib.Path("/fixture").iterdir()]')
            if original_error:
                report['error_type'] = type(original_error).__name__
            if cleanup_errors:
                report.update(result='failed', cleanup_errors=cleanup_errors)
            report['seconds'] = round(time.monotonic() - started, 3)
            write_json(args.result, report)
            if cleanup_errors and original_error is None:
                raise RuntimeError('Boundary fixture cleanup failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='locally built image ID (resolved before execution)')
    parser.add_argument('--fixture-image', default='epochgrid-artifact-tests:local')
    parser.add_argument('--result', type=Path, required=True)
    args = parser.parse_args()
    args.result.parent.mkdir(parents=True, exist_ok=True)
    if args.result.exists():
        parser.error('result already exists')
    prove(args)
