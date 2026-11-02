#!/usr/bin/env python3
"""Disposable separate-UID worker for BYO qualification; requires passwordless sudo.

Public exchange files contain bindings, lifecycle commands and sanitized logs only.
The keyring/home live under the worker UID and are never copied into the exchange.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def check_diagnostics(command, bindings, env):
    # Actual worker UID with deliberately unusable dependencies: status only needs
    # public bindings and authenticated local IPC.
    diagnostic_env = env.copy()
    diagnostic_env['DBUS_SESSION_BUS_ADDRESS'] = 'unix:path=/missing/PRIVATE_MARKER'
    diagnostic_env['EPOCHGRID_NATS_URL'] = 'PRIVATE_MARKER'
    result = subprocess.run(command + ['status', '--role', 'control', '--format', 'json'],
                            env=diagnostic_env, capture_output=True, timeout=7)
    if result.returncode != 0 or result.stderr or b'PRIVATE_MARKER' in result.stdout:
        raise RuntimeError('worker diagnostic command failed')
    report = json.loads(result.stdout)
    if report['role'] != 'control' or report['readiness'] != 'ready':
        raise RuntimeError('worker diagnostic state mismatch')
    expected = {'reconciled', 'worker_live', 'worker_lease_age_ms', 'worker_lease_limit_ms',
                'auth_requests', 'control_requests', 'ipc_disconnects',
                'reconciliation_success', 'reconciliation_failure', 'reconciliation_age_ms',
                'control_queue_used', 'control_queue_limit', 'auth_connection',
                'control_connection', 'permission_denied_observed', 'audit'}
    if set(report['observations']) != expected:
        raise RuntimeError('worker diagnostic field disclosure')
    audit = report['observations']['audit']
    if audit is not None and (set(audit) != {'events', 'bytes', 'admission_capacity',
            'known_coverage_gaps', 'unresolved_effects', 'observation_loss', 'age_ms'}
            or any(not isinstance(value, (int, bool)) for value in audit.values())):
        raise RuntimeError('worker audit health disclosed non-aggregate data')
    denied = subprocess.run(command + ['status', '--role', 'authority', '--format', 'json'],
                            env=diagnostic_env, capture_output=True, timeout=7)
    if denied.returncode != 2 or json.loads(denied.stdout)['observations'] is not None:
        raise RuntimeError('worker selected authority view')
    address = json.loads(bindings.read_text())['socket'] + '.status'
    # A caller-supplied view is not a capability. Unknown fields/versions and
    # oversized requests close the connection without returning private content.
    for operation in ({'operation': 'diagnose', 'version': 1, 'role': 'authority'},
                      {'operation': 'diagnose', 'version': 999}, None):
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(6)
            peer.connect(address)
            if operation is None:
                peer.sendall(struct.pack('>I', 257))
            else:
                data = json.dumps({'version': 1, 'sequence': 0, 'operation': operation}).encode()
                peer.sendall(struct.pack('>I', len(data)) + data)
            try:
                output = peer.recv(1)
            except ConnectionResetError:
                output = b''
            if output:
                raise RuntimeError('invalid diagnostic request returned content')
    def inspect_once(_):
        data = json.dumps({'version': 1, 'sequence': 0,
                           'operation': {'operation': 'diagnose', 'version': 1}}).encode()
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(6)
            peer.connect(address)
            peer.sendall(struct.pack('>I', len(data)) + data)
            def receive(size):
                result = b''
                while len(result) < size:
                    chunk = peer.recv(size - len(result))
                    if not chunk:
                        raise RuntimeError('diagnostic response ended')
                    result += chunk
                return result
            size = struct.unpack('>I', receive(4))[0]
            if not 0 < size <= 16384:
                raise RuntimeError('diagnostic response bounds')
            report = json.loads(receive(size))['operation']['report']
            if set(report['observations']) != expected or report['role'] != 'control':
                raise RuntimeError('diagnostic flood exposed authority view')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(inspect_once, range(32)))
    # One silent peer expires within the total deadline while the independent
    # worker heartbeat keeps admission live.
    with socket.socket(socket.AF_UNIX) as slow:
        slow.settimeout(6)
        slow.connect(address)
        if slow.recv(1):
            raise RuntimeError('silent diagnostic peer returned content')
    checked = subprocess.run(command + ['status', '--role', 'control', '--format', 'json'],
                             env=diagnostic_env, capture_output=True, timeout=7)
    if checked.returncode != 0:
        raise RuntimeError('diagnostic slow peer starved worker heartbeat')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['launch', 'session'])
    parser.add_argument('--exchange', type=Path, required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--url', required=True)
    args = parser.parse_args()
    if os.geteuid() in (0, args.exchange.stat().st_uid):
        raise RuntimeError('fixture requires a distinct non-root worker UID')
    if args.mode == 'launch':
        os.setsid()
        print(f'WORKER_PID={os.getpid()}', flush=True)
        runner = Path(__file__).with_name('with-test-keyring.sh')
        os.execv(str(runner), [str(runner), sys.executable, __file__, 'session',
                              '--exchange', str(args.exchange), '--binary', args.binary,
                              '--url', args.url])
    os.environ['EPOCHGRID_PROFILE'] = 'production'
    os.environ['EPOCHGRID_TLS_CA_PATH'] = str(args.exchange / 'ca.pem')
    child = None

    def stop(*_):
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        child = None

    def terminate(*_):
        stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    with tempfile.TemporaryDirectory(prefix='epochgrid-worker-') as home:
        command = [args.binary, '--home', home, '--server', args.url]
        key = subprocess.check_output(command + ['worker-init'], text=True, timeout=15).strip()
        if len(key) != 56 or not key.startswith('U'):
            raise RuntimeError('invalid worker-init output')
        probe = json.loads((args.exchange / 'probe.json').read_text())
        for filename in ('auth.json', 'auth.sqlite', 'credentials.json'):
            try:
                (Path(probe['authority_home']) / filename).read_bytes()
            except PermissionError:
                pass
            else:
                raise RuntimeError('worker accessed authority state')
        for bus in (os.environ['DBUS_SESSION_BUS_ADDRESS'], probe['authority_bus']):
            env = os.environ.copy()
            env['DBUS_SESSION_BUS_ADDRESS'] = bus
            for reference in probe['references']:
                result = subprocess.run(['secret-tool', 'lookup', 'application',
                                         'org.epochgrid.credentials.v1', 'id', reference],
                                        env=env, capture_output=True, timeout=10)
                if result.returncode == 0 or result.stdout:
                    raise RuntimeError('worker accessed authority credential')
        print('ISOLATION_PROBES=passed', flush=True)
        print(f'WORKER_NKEY={key}', flush=True)
        bindings = args.exchange / 'bindings.json'
        deadline = time.monotonic() + 120
        while not bindings.exists():
            if time.monotonic() > deadline:
                raise RuntimeError('fixture binding deadline')
            time.sleep(.05)
        subprocess.run(command + ['worker-configure', '--bindings', str(bindings)],
                       check=True, timeout=15)
        subprocess.run(command + ['validate-control', '--offline', '--format', 'json'],
                       check=True, timeout=15)
        generation = None
        try:
            while True:
                path = args.exchange / 'command.json'
                if path.exists():
                    request = json.loads(path.read_text())
                    if request['generation'] != generation:
                        stop()
                        generation = request['generation']
                        if request['running']:
                            # Only an explicit lifecycle command starts a process.
                            # No automatic retry of test failures or failed startups.
                            env = os.environ.copy()
                            env['EPOCHGRID_TLS_FIRST'] = 'true' if request.get('tls_first') else 'false'
                            child = subprocess.Popen(command + ['serve-control'], env=env)
                            deadline = time.monotonic() + 10
                            while True:
                                checked = subprocess.run(command + ['validate-control', '--online', '--format', 'json'],
                                                         env=env, capture_output=True, timeout=10)
                                if checked.returncode == 0:
                                    break
                                if child.poll() is not None or time.monotonic() >= deadline:
                                    raise RuntimeError('worker readiness validation failed')
                                time.sleep(.05)
                            probe = Path(args.binary).parent / 'examples/backend-role-probe'
                            subprocess.run([str(probe), '--disposable-fixture', 'worker', home, args.url],
                                           env=env, check=True, timeout=30)
                            check_diagnostics(command, bindings, env)
                            print('WORKER_VALIDATED=passed', flush=True)
                time.sleep(.05)
        finally:
            stop()


if __name__ == '__main__':
    main()
