#!/usr/bin/env python3
"""Disposable separate-UID worker for BYO qualification; requires passwordless sudo.

Public exchange files contain bindings, lifecycle commands and sanitized logs only.
The keyring/home live under the worker UID and are never copied into the exchange.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


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
                            print('WORKER_VALIDATED=passed', flush=True)
                time.sleep(.05)
        finally:
            stop()


if __name__ == '__main__':
    main()
