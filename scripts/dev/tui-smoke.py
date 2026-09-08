#!/usr/bin/env python3
"""Real pseudo-terminal Alice/Bob session, using isolated host NATS and SQLite."""
import codecs
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
            while data := os.read(self.master, 65536):
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
        self.process.wait()
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


def query(root, user, sql, values=()):
    with sqlite3.connect(root / user / 'identity.sqlite', timeout=1) as connection:
        return connection.execute(sql, values).fetchone()[0]


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
        try:
            broker = nats()
            with socket.socket() as probe:
                wait(lambda: probe.connect_ex(('127.0.0.1', port)) == 0, 'NATS startup')
            service = subprocess.Popen(['./target/debug/epochgrid-service', '--home', str(root / 'service'), '--enrollment', str(root / 'enrollment.json'), '--server', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(service)
            wait(lambda: register('alice'), 'service startup')
            assert register('bob')
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
            broker.wait()
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
            alice.close()
            bob.close()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()
            for path in (root / 'jetstream').rglob('*'):
                if path.is_file():
                    data = path.read_bytes()
                    assert all(secret.encode() not in data for secret in secrets), 'TUI plaintext in NATS storage'
            print('EpochGrid TUI create/invite/join, asynchronous messages, unread, offline queue, reconnect, history and terminal restoration passed')
        finally:
            for client in CLIENTS:
                client.cleanup()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()

if __name__ == '__main__':
    run()
