#!/usr/bin/env python3
"""Fresh CLI/backend provisioning and recovery using a disposable real keyring."""
import json
import os
from pathlib import Path
import subprocess
import socket
import threading
import time
import tempfile

CLIENT = str(Path('target/debug/epochgrid').resolve())
SERVICE = str(Path('target/debug/epochgrid-service').resolve())


def run(*args, ok=True, env=None):
    result = subprocess.run(args, capture_output=True, timeout=20, env=env)
    assert (result.returncode == 0) == ok, (args[0], result.stderr.decode(errors='replace'))
    return result


def scan(home):
    refs = []
    for metadata in home.rglob('credentials.json'):
        for slot in json.loads(metadata.read_text())['slots'].values():
            assert slot['public_key']
            refs.append(slot)
    assert refs
    secrets = [run('secret-tool', 'lookup', 'application', 'org.epochgrid.credentials.v1', 'id', ref['id']).stdout.strip() for ref in refs]
    secrets += [bytes.fromhex(secret.decode()) for ref, secret in zip(refs, secrets) if ref['kind'] == 'database']
    for path in home.rglob('*'):
        if path.is_file():
            content = path.read_bytes()
            assert all(secret and secret not in content for secret in secrets), path
    return refs


with tempfile.TemporaryDirectory(prefix='epochgrid-secret-test-') as directory:
    root = Path(directory)
    home = root / 'device'
    run(CLIENT, '--home', str(home), 'identity', 'init', 'alice')
    original = run(CLIENT, '--home', str(home), 'identity', 'show').stdout
    inspector = ['target/debug/examples/encrypted-query', str(home / 'identity.sqlite')]
    query = subprocess.run(inspector, input=json.dumps({'sql': 'SELECT COUNT(*) FROM local_identity', 'values': []}),
                           text=True, capture_output=True, timeout=10)
    assert query.returncode == 0 and json.loads(query.stdout) == 1, query.stderr
    write = subprocess.run(inspector, input=json.dumps({'sql': 'DELETE FROM local_identity', 'values': []}),
                           text=True, capture_output=True, timeout=10)
    assert write.returncode != 0
    refs = scan(home)
    run(CLIENT, '--home', str(home), 'identity', 'init', 'alice', ok=False)
    assert original == run(CLIENT, '--home', str(home), 'identity', 'show').stdout
    package, recovery_secret = root / 'backup.egrecovery', root / 'backup.egsecret'
    run(CLIENT, '--home', str(home), 'recovery', 'export', '--output', str(package), '--secret-file', str(recovery_secret))
    restored = root / 'restored'
    run(CLIENT, '--home', str(restored), 'recovery', 'restore', '--input', str(package), '--secret-file', str(recovery_secret))
    assert original == run(CLIENT, '--home', str(restored), 'identity', 'show').stdout
    assert b'administration' in run(CLIENT, '--home', str(restored), 'recovery', 'status').stdout
    scan(restored)
    assert json.loads((home / 'credentials.json').read_text())['slots']['device']['id'] != json.loads((restored / 'credentials.json').read_text())['slots']['device']['id']
    backend = root / 'backend'
    run(SERVICE, '--home', str(backend), 'auth-init')
    config = json.loads((backend / 'auth.json').read_text())
    assert config['version'] == 2
    assert all(config[name]['public_key'] for name in ('issuer', 'encryption', 'connection'))
    assert not list(backend.glob('*.seed'))
    assert len(scan(backend)) == 6
    run(SERVICE, '--home', str(backend), 'auth-init', ok=False)
    run('secret-tool', 'clear', 'application', 'org.epochgrid.credentials.v1', 'id', config['issuer']['id'])
    denied = run(SERVICE, '--home', str(backend), '--server', 'tls://127.0.0.1:1',
                 'serve', '--auth-config', str(backend / 'auth.json'), ok=False)
    assert b'credential missing from keyring' in denied.stderr
    assert b'service ready' not in denied.stdout + denied.stderr
    assert json.loads((backend / 'auth.json').read_text()) == config
    unavailable = dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent/epochgrid-bus')
    failed = run(CLIENT, '--home', str(root / 'failed'), 'identity', 'init', 'bob', ok=False, env=unavailable)
    assert b'Secret Service unavailable' in failed.stderr
    # The pending home resumes on the same healthy session; no plaintext fallback.
    run(CLIENT, '--home', str(root / 'failed'), 'identity', 'init', 'bob')
    scan(root / 'failed')
    # A reachable but silent D-Bus socket must not hang the application.
    listener = socket.socket(socket.AF_UNIX)
    socket_path = str(root / 'silent-bus')
    listener.bind(socket_path)
    listener.listen(1)
    listener.settimeout(10)
    stop = threading.Event()
    def silent_bus():
        try:
            connection, _ = listener.accept()
            with connection:
                stop.wait(10)
        except OSError:
            pass
    thread = threading.Thread(target=silent_bus, daemon=True)
    thread.start()
    started = time.monotonic()
    try:
        stalled = run(CLIENT, '--home', str(root / 'stalled'), 'identity', 'init', 'bob', ok=False,
                      env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS='unix:path=' + socket_path))
        assert b'Secret Service operation timed out' in stalled.stderr
        assert time.monotonic() - started < 8
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
    # Offline access also requires the database key. Failure must preserve state.
    db_path = home / 'identity.sqlite'
    before = db_path.read_bytes()
    unavailable_read = run(CLIENT, '--home', str(home), 'identity', 'show', ok=False, env=unavailable)
    assert b'Secret Service unavailable' in unavailable_read.stderr
    metadata_path = home / 'identity.database.json'
    metadata = metadata_path.read_bytes()
    swapped = json.loads(metadata)
    swapped['key'] = json.loads((restored / 'identity.database.json').read_text())['key']
    metadata_path.write_text(json.dumps(swapped))
    wrong = run(CLIENT, '--home', str(home), 'identity', 'show', ok=False)
    assert b'cannot be decrypted' in wrong.stderr
    assert db_path.read_bytes() == before
    metadata_path.write_bytes(metadata)
    key_id = json.loads(metadata)['key']['id']
    run('secret-tool', 'clear', 'application', 'org.epochgrid.credentials.v1', 'id', key_id)
    missing = run(CLIENT, '--home', str(home), 'identity', 'show', ok=False)
    assert b'credential missing from keyring' in missing.stderr
    assert db_path.read_bytes() == before
    assert metadata_path.read_bytes() == metadata
    run('secret-tool', 'lookup', 'application', 'org.epochgrid.credentials.v1', 'id', key_id, ok=False)
    print('Protected credentials, encrypted databases, recovery, restart and bounded key failures passed')
