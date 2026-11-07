#!/usr/bin/env python3
"""Disposable image-boundary helpers. Never copied into the application image."""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path('/fixture')


def keyring(uid):
    # D-Bus resolves its service UID through passwd even with numeric EXTERNAL
    # authentication. These accounts exist only in the disposable helper host.
    subprocess.run(['groupadd', '--gid', str(uid), 'fixture'], check=True)
    subprocess.run(['useradd', '--uid', str(uid), '--gid', str(uid), '--no-create-home',
                    '--home-dir', '/fixture/state', 'fixture'], check=True)
    for name in ('state', 'bus', 'data', 'config', 'runtime'):
        directory = ROOT / name
        directory.mkdir(exist_ok=True, mode=0o700)
        os.chown(directory, uid, uid)
    os.chmod(ROOT, 0o755)
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    os.environ.update(HOME=str(ROOT / 'state'), XDG_DATA_HOME=str(ROOT / 'data'),
                      XDG_CONFIG_HOME=str(ROOT / 'config'), XDG_RUNTIME_DIR=str(ROOT / 'runtime'),
                      DBUS_SESSION_BUS_ADDRESS='unix:path=/fixture/bus/socket')
    bus = subprocess.Popen(['dbus-daemon', '--session', '--nofork', '--address=unix:path=/fixture/bus/socket'])
    try:
        deadline = time.monotonic() + 10
        while not (ROOT / 'bus/socket').exists():
            if bus.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('bus startup failed')
            time.sleep(.05)
        subprocess.run(['gnome-keyring-daemon', '--unlock', '--components=secrets'],
                       input=os.urandom(32).hex().encode() + b'\n', check=True,
                       stdout=subprocess.DEVNULL, timeout=10)
        subprocess.run(['secret-tool', 'store', '--label=disposable-readiness',
                        'application', 'epochgrid-image-fixture'], input=b'ready', check=True, timeout=10)
        subprocess.run(['secret-tool', 'clear', 'application', 'epochgrid-image-fixture'], check=True, timeout=10)
        (ROOT / 'bus/ready').touch()
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        signal.pause()
    finally:
        bus.terminate()
        bus.wait(timeout=5)


def broker():
    os.chdir(ROOT)
    (ROOT / 'server.extensions').write_text('basicConstraints=critical,CA:FALSE\n'
        'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
        'subjectAltName=DNS:broker\n')
    for command in [
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
         '-out', 'ca.pem', '-days', '2', '-subj', '/CN=disposable-image-fixture'],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key',
         '-out', 'server.csr', '-subj', '/CN=broker'],
        ['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
         '-CAcreateserial', '-days', '2', '-extfile', 'server.extensions', '-out', 'server.pem'],
    ]:
        subprocess.run(['openssl', *command], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
    password = os.urandom(32).hex()
    (ROOT / 'admin.json').write_text(json.dumps(dict(user='fixture-admin', password=password)))
    snippet = (ROOT / 'nats-reference.conf').read_text()
    original = '"EPOCHGRID" { jetstream: enabled }'
    if snippet.count(original) != 1 or snippet.count('auth_users: [') != 1:
        raise ValueError('Unexpected generated broker configuration')
    snippet = snippet.replace(original, '"EPOCHGRID" { jetstream: enabled, users: [{user: "fixture-admin", password: "' + password + '"}] }')
    snippet = snippet.replace('auth_users: [', 'auth_users: ["fixture-admin", ')
    (ROOT / 'nats.conf').write_text('listen: 0.0.0.0:4222\nmax_payload: 65536\n'
        'jetstream {store_dir: "/fixture/js"}\n'
        'tls {cert_file: "/fixture/server.pem", key_file: "/fixture/server.key", min_version: "1.3"}\n' + snippet)
    os.execv('/opt/nats/nats-server', ['/opt/nats/nats-server', '-c', '/fixture/nats.conf'])


def provision():
    """Minimal fixture administrator; only creates the generated stream specs."""
    context = ssl.create_default_context(cafile=str(ROOT / 'ca.pem'))
    with socket.create_connection(('127.0.0.1', 4222), timeout=5) as plain:
        # NATS sends INFO before upgrading the connection to TLS.
        line = b''
        while not line.endswith(b'\r\n'):
            line += plain.recv(1)
            if len(line) > 65536 or not line:
                raise RuntimeError('Invalid broker greeting')
        if not line.startswith(b'INFO '):
            raise RuntimeError('Missing broker greeting')
        with context.wrap_socket(plain, server_hostname='broker') as peer:
            admin = json.loads((ROOT / 'admin.json').read_text())
            peer.sendall(b'CONNECT ' + json.dumps(dict(user=admin['user'], **{'pass': admin['password']},
                         verbose=False, pedantic=True, tls_required=True)).encode() + b'\r\n')
            stream = peer.makefile('rb')
            for index, name in enumerate(('CHAT', 'MAILBOX', 'KV_IDENTITIES', 'KV_CHANNELS', 'KV_TRANSPARENCY')):
                payload = (ROOT / (name + '.json')).read_bytes()
                inbox = f'_INBOX.fixture.{index}'
                peer.sendall(f'SUB {inbox} {index + 1}\r\nPUB $JS.API.STREAM.CREATE.{name} {inbox} {len(payload)}\r\n'.encode() + payload + b'\r\n')
                while True:
                    line = stream.readline(65536)
                    if line == b'PING\r\n':
                        peer.sendall(b'PONG\r\n')
                    elif line.startswith(b'MSG '):
                        size = int(line.split()[-1])
                        if not 0 < size <= 65536:
                            raise RuntimeError('Oversized provisioning reply')
                        response = json.loads(stream.read(size))
                        if stream.read(2) != b'\r\n' or 'error' in response or response.get('config', {}).get('name') != name:
                            raise RuntimeError('Resource provisioning failed')
                        break
                    elif line != b'+OK\r\n':
                        raise RuntimeError('Broker rejected fixture administration')


if __name__ == '__main__':
    if sys.argv[1] == 'keyring':
        keyring(int(sys.argv[2]))
    elif sys.argv[1] == 'broker':
        broker()
    elif sys.argv[1] == 'provision':
        provision()
    else:
        raise SystemExit('unknown fixture operation')
