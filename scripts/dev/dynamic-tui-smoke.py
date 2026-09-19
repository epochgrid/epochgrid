#!/usr/bin/env python3
"""Bounded real-PTY chat over Auth Callout, without static device users."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('tui_smoke', Path(__file__).with_name('tui-smoke.py'))
tui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tui)
SERVICE = str(Path('target/debug/epochgrid-service').resolve())


def run():
    processes = []
    with tempfile.TemporaryDirectory(prefix='epochgrid-dynamic-tui-') as directory:
        root = Path(directory)
        backend = root / 'backend'
        def service(*args, **kwargs):
            return subprocess.run([SERVICE, '--home', str(backend), *args],
                                  capture_output=True, check=True, timeout=10, **kwargs)
        service('auth-init')
        config_path = backend / 'auth.json'
        config = json.loads(config_path.read_text())
        config.update(development_plaintext=True, authorization_ttl_seconds=6)
        config_path.write_text(json.dumps(config))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        url = f'nats://127.0.0.1:{port}'
        nats_config = (f'listen: 127.0.0.1:{port}\nmax_payload: 65536\n'
                       f'jetstream {{store_dir: "{root / "jetstream"}"}}\n' +
                       (backend / 'nats-reference.conf').read_text())
        (root / 'nats.conf').write_text(nats_config)
        try:
            with (root / 'nats.log').open('wb') as log:
                broker = subprocess.Popen([tui.SERVER, '-c', str(root / 'nats.conf')], stdout=log, stderr=log)
            processes.append(broker)
            def listening():
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                        return True
                except OSError:
                    return False
            tui.wait(listening, 'NATS listener', timeout=10)
            with (root / 'backend.log').open('wb') as log:
                daemon = subprocess.Popen([SERVICE, '--home', str(backend), '--server', url,
                    'serve', '--auth-config', str(config_path)], stdout=log, stderr=log)
            processes.append(daemon)
            tui.wait(lambda: 'service ready' in (root / 'backend.log').read_text(), 'Auth Callout ready', timeout=10)
            users = {}
            for name in ('alice', 'bob'):
                token = service('user-invite', '--handle', name).stdout.strip()
                users[name] = token.decode().split('.')[1]
                subprocess.run([tui.BINARY, '--home', str(root / name), '--server', url, 'identity', 'enroll'],
                               input=token, capture_output=True, check=True, timeout=10)
            alice = tui.Client(root, 'alice', url)
            bob = tui.Client(root, 'bob', url)
            tui.wait(lambda: all('Online' in c.screen.text for c in (alice, bob)), 'dynamic TUI online')
            alice.type('/create engineering\r')
            tui.wait(lambda: tui.query(root, 'alice', 'SELECT COUNT(*) FROM groups') == 1, 'create channel')
            alice.type(f'/invite {users["bob"]} laptop\r')
            tui.wait(lambda: 'Invitation delivered' in alice.screen.text, 'dynamic invitation')
            bob.type(f'/join {users["alice"]} laptop\r')
            tui.wait(lambda: tui.query(root, 'bob', 'SELECT COUNT(*) FROM groups') == 1, 'dynamic join')
            secrets = ['DYNAMIC_TUI_ALICE_91F3', 'DYNAMIC_TUI_BOB_28A4', 'DYNAMIC_TUI_OFFLINE_45B1']
            alice.type(secrets[0] + '\r')
            tui.wait(lambda: tui.has(root, 'bob', secrets[0]) and secrets[0] in bob.screen.text, 'Alice to Bob')
            bob.type(secrets[1] + '\r')
            tui.wait(lambda: tui.has(root, 'alice', secrets[1]) and secrets[1] in alice.screen.text, 'Bob to Alice')
            bob.close()
            alice.type(secrets[2] + '\r')
            tui.wait(lambda: tui.query(root, 'alice', 'SELECT COUNT(*) FROM transcript WHERE plaintext=? AND stream_sequence IS NOT NULL', (secrets[2].encode(),)) == 1, 'offline message persisted')
            bob = tui.Client(root, 'bob', url)
            tui.wait(lambda: all(tui.has(root, 'bob', message) for message in secrets)
                     and secrets[2] in bob.screen.text, 'restart and offline catch-up')
            assert (root / 'nats.conf').read_text() == nats_config
            tui.finish(root, [alice, bob], processes, secrets)
            print('EpochGrid dynamic TUI create/invite/join, bidirectional MLS chat, restart/offline history and ciphertext-only storage passed')
        finally:
            for client in tui.CLIENTS:
                client.cleanup()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)


if __name__ == '__main__':
    run()
