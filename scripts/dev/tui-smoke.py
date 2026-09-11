#!/usr/bin/env python3
"""Real pseudo-terminal Alice/Bob session, using isolated host NATS and SQLite."""
import codecs
from contextlib import closing
import re
import fcntl
import os
from pathlib import Path
import pty
import socket
import sqlite3
import struct
import subprocess
import tempfile
import termios
import time

BINARY = str(Path('target/debug/epochgrid').resolve())
SERVER = os.environ.get('NATS_SERVER', str(Path('.dev/nats-image/nats-server').resolve()))
CLIENTS = []

class Screen:
    """The cursor/erase subset emitted by Crossterm; assertions use rendered cells."""
    def __init__(self):
        self.cells = [[' '] * 120 for _ in range(32)]
        self.x = self.y = 0
        self.pending = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')

    def feed(self, data):
        self.pending += self.decoder.decode(data)
        while self.pending:
            if self.pending == '\x1b':
                return
            if self.pending.startswith('\x1b['):
                match = re.match(r'\x1b\[([0-?]*)([ -/]*)([@-~])', self.pending)
                if not match:
                    return
                raw, _, command = match.groups()
                self.pending = self.pending[match.end():]
                if raw.startswith('?'):
                    continue
                numbers = [int(n or '0') for n in raw.split(';')]
                n = numbers[0] or 1
                if command in 'Hf':
                    self.y = n - 1
                    self.x = (numbers[1] or 1) - 1 if len(numbers) > 1 else 0
                elif command == 'A': self.y -= n
                elif command == 'B': self.y += n
                elif command == 'C': self.x += n
                elif command == 'D': self.x -= n
                elif command == 'G': self.x = n - 1
                elif command == 'J' and numbers[0] == 2:
                    self.cells = [[' '] * 120 for _ in range(32)]
                elif command == 'K':
                    start, end = (0, 120) if numbers[0] == 2 else (self.x, 120)
                    self.cells[self.y][start:end] = [' '] * (end - start)
                self.x, self.y = max(0, min(self.x, 119)), max(0, min(self.y, 31))
                continue
            char, self.pending = self.pending[0], self.pending[1:]
            if char == '\r': self.x = 0
            elif char == '\n': self.y = min(31, self.y + 1)
            elif char >= ' ':
                if self.x >= 120:
                    self.x, self.y = 0, min(31, self.y + 1)
                self.cells[self.y][self.x] = char
                self.x += 1

    @property
    def text(self):
        return '\n'.join(''.join(row) for row in self.cells)

class Client:
    def __init__(self, root, user, url):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 32, 120, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        os.set_blocking(self.master, False)
        self.process = subprocess.Popen([BINARY, '--home', str(root / user), '--server', url, 'tui'],
            stdin=self.slave, stdout=self.slave, stderr=self.slave, env={**os.environ, 'TERM': 'xterm-256color'})
        self.output = b''
        self.screen = Screen()
        CLIENTS.append(self)

    def pump(self):
        try:
            for _ in range(16):
                data = os.read(self.master, 65536)
                if not data:
                    break
                self.output += data
                self.screen.feed(data)
        except BlockingIOError:
            pass

    def type(self, text):
        os.write(self.master, text.encode())

    def close(self):
        if self.process.poll() is None:
            self.type('\x03')
            self.process.wait(timeout=8)
        assert self.process.returncode == 0, self.output[-1500:]
        assert termios.tcgetattr(self.slave) == self.original, 'terminal mode not restored'
        self.pump()
        assert b'\x1b[?1049l' in self.output, 'alternate screen not restored'

    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        os.close(self.master)
        os.close(self.slave)


def wait(predicate, label, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for client in CLIENTS:
            client.pump()
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError((label, [c.screen.text for c in CLIENTS]))


def query(root, user, sql, values=(), *, timeout=5):
    # The running client owns a rollback-journal database and briefly takes an
    # exclusive lock while committing MLS state. That is not a failed assertion.
    # A connection context manager alone does not close its connection.
    uri = (root / user / 'identity.sqlite').resolve().as_uri() + '?mode=ro'
    deadline = time.monotonic() + timeout
    while True:
        try:
            with closing(sqlite3.connect(uri, uri=True, timeout=0)) as connection:
                return connection.execute(sql, values).fetchone()[0]
        except sqlite3.OperationalError as error:
            code = getattr(error, 'sqlite_errorcode', 0) & 0xff
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f'TUI database read remained locked for {timeout}s: {user}') from error
            time.sleep(min(0.025, remaining))


def has(root, user, text):
    return query(root, user, 'SELECT COUNT(*) FROM transcript WHERE plaintext=?', (text.encode(),)) == 1


def run():
    processes = []
    with tempfile.TemporaryDirectory(prefix='epochgrid-tui-') as directory:
        root = Path(directory)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        url = f'nats://127.0.0.1:{port}'
        subprocess.run([BINARY, 'dev-config', '--root', str(root), '--port', str(port)], check=True, capture_output=True)
        def nats():
            process = subprocess.Popen([SERVER, '-c', str(root / 'nats.conf')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(process)
            return process
        def cli(user, *args):
            return subprocess.run([BINARY, '--home', str(root / user), '--server', url, *args], capture_output=True, timeout=10)
        def register(user):
            return cli(user, 'identity', 'register').returncode == 0
        added = cli('alice-desktop', 'device', 'add', 'alice', '--device', 'desktop')
        assert added.returncode == 0, added.stderr
        binding = added.stdout.decode().split('Operator enrollment: ')[1].strip()
        subprocess.run([BINARY, 'dev-config', '--root', str(root), '--port', str(port),
                        '--enroll', binding], check=True, capture_output=True)
        try:
            broker = nats()
            with socket.socket() as probe:
                wait(lambda: probe.connect_ex(('127.0.0.1', port)) == 0, 'NATS startup')
            service = subprocess.Popen(['./target/debug/epochgrid-service', '--home', str(root / 'service'), '--enrollment', str(root / 'enrollment.json'), '--server', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(service)
            wait(lambda: register('alice'), 'service startup')
            assert register('bob')
            assert register('alice-desktop')
            alice, bob = Client(root, 'alice', url), Client(root, 'bob', url)
            wait(lambda: all('Online' in c.screen.text for c in [alice, bob]), 'TUI online')
            alice.type('/create engineering\r')
            wait(lambda: query(root, 'alice', 'SELECT COUNT(*) FROM groups') == 1, 'TUI create')
            alice.type('UNSENT_DRAFT_BEFORE_INVITE\r')
            wait(lambda: 'draft retained' in alice.screen.text, 'failed send retains composition')
            assert query(root, 'alice', 'SELECT COUNT(*) FROM transcript') == 0
            alice.type('\x1b')
            wait(lambda: 'UNSENT_DRAFT_BEFORE_INVITE' not in alice.screen.text, 'Esc clears draft')
            alice.type('/invite bob\r')
            wait(lambda: 'Invitation delivered' in alice.screen.text, 'TUI invite')
            bob.type('/join alice\r')
            wait(lambda: query(root, 'bob', 'SELECT COUNT(*) FROM groups') == 1, 'TUI join')
            alice.type('draft typing without sending')
            wait(lambda: 'alice is typing' in bob.screen.text, 'encrypted live typing indicator')
            assert query(root, 'bob', 'SELECT COUNT(*) FROM transcript') == 0
            alice.type('\x1b')
            wait(lambda: 'alice is typing' not in bob.screen.text, 'typing stop or natural expiry')
            secrets = ['TUI_ALICE_FIRST_91F3', 'TUI_BOB_REPLY_72A1', 'TUI_OFFLINE_QUEUE_5BC7', 'TUI_RECONNECTED_BOB_1D90']
            alice.type(secrets[0] + '\r')
            wait(lambda: has(root, 'bob', secrets[0]) and secrets[0] in bob.screen.text, 'Alice -> Bob render')
            # Switching away must keep background-channel unread state.
            alice.type('/create other\r')
            wait(lambda: query(root, 'alice', 'SELECT COUNT(*) FROM groups') == 2, 'second local channel')
            bob.type(secrets[1] + '\r')
            wait(lambda: has(root, 'alice', secrets[1]), 'Bob -> Alice background arrival')
            assert query(root, 'alice', 'SELECT displayed FROM transcript WHERE plaintext=?', (secrets[1].encode(),)) == 0
            alice.type('\t')
            wait(lambda: query(root, 'alice', 'SELECT displayed FROM transcript WHERE plaintext=?', (secrets[1].encode(),)) == 1, 'selected history clears local unread')
            broker.kill()
            broker.wait(timeout=5)
            # Input remains responsive during failed network operations and is persisted once.
            alice.type(secrets[2] + '\r')
            wait(lambda: has(root, 'alice', secrets[2]), 'offline encrypted queue')
            assert query(root, 'alice', 'SELECT stream_sequence IS NULL FROM transcript WHERE plaintext=?', (secrets[2].encode(),)) == 1
            bob.close()
            bob = Client(root, 'bob', url)
            wait(lambda: secrets[0] in bob.screen.text, 'history visible while offline')
            broker = nats()
            wait(lambda: has(root, 'bob', secrets[2]) and secrets[2] in bob.screen.text, 'automatic reconnect delivery')
            bob.type(secrets[3] + '\r')
            wait(lambda: has(root, 'alice', secrets[3]) and secrets[3] in alice.screen.text, 'reply after reconnect')
            for user in ['alice', 'bob']:
                assert query(root, user, 'SELECT COUNT(*) FROM transcript') == 4
            desktop = Client(root, 'alice-desktop', url)
            wait(lambda: 'Online' in desktop.screen.text, 'desktop TUI online')
            alice.type('/invite alice desktop\r')
            wait(lambda: 'Invitation delivered' in alice.screen.text, 'desktop invitation')
            desktop.type('/join alice\r')
            wait(lambda: query(root, 'alice-desktop', 'SELECT COUNT(*) FROM groups') == 1, 'desktop joins')
            # Bob's persistent worker must merge the Commit before its next send.
            wait(lambda: query(root, 'bob', "SELECT COUNT(*) FROM chat_deliveries WHERE subject LIKE '%.handshake' AND state='processed'") == 2, 'Bob Commit catch-up')
            bob.type('/members\r')
            wait(lambda: 'Members: alice, bob' in bob.screen.text, 'logical membership display')
            bob.type('/devices\r')
            wait(lambda: 'alice/desktop' in bob.screen.text, 'device leaves display')
            secrets.extend(['TUI_BOTH_ALICES_8DC4', 'TUI_DESKTOP_REPLY_A192'])
            bob.type(secrets[4] + '\r')
            wait(lambda: all(has(root, user, secrets[4]) for user in ['alice', 'alice-desktop']), 'Bob to both Alice devices')
            desktop.type(secrets[5] + '\r')
            wait(lambda: all(has(root, user, secrets[5]) for user in ['alice', 'bob']), 'desktop to existing clients')
            for user in ['alice', 'bob']:
                assert query(root, user, 'SELECT COUNT(*) FROM transcript') == 6
            assert query(root, 'alice-desktop', 'SELECT COUNT(*) FROM transcript') == 2, 'no pre-join history'
            revoked = cli('service', 'device', 'revoke', 'alice', 'desktop')
            assert revoked.returncode == 0, revoked.stderr
            wait(lambda: 'Online' not in desktop.screen.text, 'revoked desktop disconnected')
            wait(lambda: query(root, 'bob', "SELECT COUNT(*) FROM chat_deliveries WHERE subject LIKE '%.handshake' AND state='processed'") == 3, 'automatic removal Commit')
            secrets.append('TUI_AFTER_DEVICE_REVOCATION_91F3')
            bob.type(secrets[-1] + '\r')
            wait(lambda: has(root, 'alice', secrets[-1]), 'remaining clients continue after revocation')
            assert not has(root, 'alice-desktop', secrets[-1]), 'revoked device received new plaintext'
            attachment_secret = 'TUI_ATTACHMENT_CIPHERTEXT_ONLY_91F3'
            secrets.append(attachment_secret)
            attachment = root / 'private attachment.txt'
            attachment.write_text(attachment_secret * 4096)
            alice.type('/attach ' + str(attachment) + '\r')
            wait(lambda: query(root, 'bob', 'SELECT COUNT(*) FROM attachments') == 1, 'TUI attachment arrival')
            wait(lambda: 'private attachment.txt' in bob.screen.text, 'safe attachment summary')
            attachment_id = query(root, 'bob', 'SELECT object_id FROM attachments LIMIT 1')
            destination = root / 'saved attachment.txt'
            bob.type('/save ' + attachment_id + ' ' + str(destination) + '\r')
            wait(lambda: destination.exists() and destination.read_bytes() == attachment.read_bytes(), 'TUI authenticated attachment save')
            desktop.close()
            alice.close()
            bob.close()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            for path in (root / 'jetstream').rglob('*'):
                if path.is_file():
                    data = path.read_bytes()
                    assert all(secret.encode() not in data for secret in secrets), 'TUI plaintext in NATS storage'
            print('EpochGrid three-device TUI enrollment, create/invite/join, membership, asynchronous messages, unread, offline queue, reconnect, history, revocation, encrypted attachments, ephemeral typing and terminal restoration passed')
        finally:
            for client in CLIENTS:
                client.cleanup()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)

if __name__ == '__main__':
    run()
