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


def wait_for_typing(sender, receiver, timeout=25):
    # Separate bursts reset the TUI's two-second refresh cadence. Continually
    # appending to one draft can phase-lock every update to a busy sync worker.
    # Keep pauses deterministic but varied, and never extend the outer deadline.
    next_edit = time.monotonic()
    clear = True
    burst = 0

    def observed():
        nonlocal next_edit, clear, burst
        if 'alice is typing' in receiver.screen.text:
            return True
        now = time.monotonic()
        if now >= next_edit:
            if clear:
                sender.type('\x1b')
                # Give the terminal loop time to observe an empty draft and stop.
                next_edit = now + 0.3
            else:
                sender.type('draft typing without sending')
                next_edit = now + (1.1, 1.7, 2.3)[burst % 3]
                burst += 1
            clear = not clear
        return False

    wait(observed, 'encrypted live typing indicator', timeout=timeout)


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



def receipt_is(root, owner, plaintext, device, state):
    return query(root, owner,
                 'SELECT COUNT(*) FROM device_receipts r JOIN transcript t ON t.id=r.transcript_id WHERE t.plaintext=? AND r.device=? AND r.state=?',
                 (plaintext.encode(), device, state)) == 1


def exercise_relationships(root, alice, bob, secrets):
    relation_original = 'TUI_RELATION_ORIGINAL_91F3'
    relation_edited = 'TUI_RELATION_EDITED_728B'
    relation_reply = 'TUI_RELATION_REPLY_62F0'
    secrets.extend([relation_original, relation_edited, relation_reply])
    alice.type(relation_original + '\r')
    wait(lambda: has(root, 'bob', relation_original), 'relationship original arrives')
    relation_id = query(root, 'alice', 'SELECT e.message_id FROM message_events e JOIN transcript t ON t.id=e.transcript_id WHERE t.plaintext=?', (relation_original.encode(),))
    alice.type('/edit ' + relation_id[:12] + ' ' + relation_edited + '\r')
    wait(lambda: relation_edited in bob.screen.text and relation_original not in bob.screen.text, 'TUI current edited content')
    bob.type('/reply ' + relation_id[:12] + ' ' + relation_reply + '\r')
    wait(lambda: relation_reply in alice.screen.text and 'reply to alice/laptop' in alice.screen.text, 'TUI reply relationship')
    bob.type('/react ' + relation_id[:12] + ' +\r')
    wait(lambda: 'reaction +: bob' in alice.screen.text, 'TUI reaction summary')
    bob.type('/unreact ' + relation_id[:12] + ' +\r')
    wait(lambda: '[reaction remove' in alice.screen.text and 'reaction +: bob' not in alice.screen.text, 'TUI reaction removal')
    assert has(root, 'alice', relation_original), 'edit must preserve original plaintext locally'


def finish(root, clients, processes, secrets):
    for client in clients:
        client.close()
    for process in processes:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
    for path in (root / 'jetstream').rglob('*'):
        if path.is_file():
            data = path.read_bytes()
            assert all(secret.encode() not in data for secret in secrets), 'TUI plaintext in NATS storage'


def run(relationships_only=False, participants_only=False):
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
        if participants_only:
            added = cli('status', 'device', 'add', 'status', '--device', 'service')
            assert added.returncode == 0, added.stderr
            binding = added.stdout.decode().split('Operator enrollment: ')[1].strip()
            subprocess.run([BINARY, 'dev-config', '--root', str(root), '--port', str(port),
                            '--enroll', binding], check=True, capture_output=True, timeout=10)
        try:
            broker = nats()
            with socket.socket() as probe:
                wait(lambda: probe.connect_ex(('127.0.0.1', port)) == 0, 'NATS startup')
            service = subprocess.Popen(['./target/debug/epochgrid-service', '--dev-static', '--home', str(root / 'service'), '--enrollment', str(root / 'enrollment.json'), '--server', url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(service)
            wait(lambda: register('alice'), 'service startup')
            assert register('bob')
            assert register('alice-desktop')
            if participants_only:
                assert register('status')
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
            # The SQLite group row precedes completion of Welcome processing.
            wait(lambda: 'Channel joined' in bob.screen.text
                 and '> #engineering' in bob.screen.text
                 and all('Online' in c.screen.text for c in [alice, bob]),
                 'TUI join ready for live activity')
            alice.type('draft typing without sending')
            wait_for_typing(alice, bob)
            assert query(root, 'bob', 'SELECT COUNT(*) FROM transcript') == 0
            alice.type('\x1b')
            wait(lambda: 'alice is typing' not in bob.screen.text, 'typing stop or natural expiry')
            if participants_only:
                alice.type('/invite status service\r')
                # A previous invitation notice can remain visible while this action queues.
                wait(lambda: query(root, 'alice',
                     "SELECT COUNT(*) FROM outbox WHERE subject='epochgrid.v1.user.status.service.inbox' AND sent=1") == 1,
                     'specific service Welcome accepted by JetStream')
                joined = cli('status', 'channel', 'join', '--from', 'alice')
                assert joined.returncode == 0, joined.stderr
                participant = subprocess.Popen([BINARY, '--home', str(root / 'status'), '--server', url,
                                                'participant', 'run', 'engineering'],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(participant)
                alice.type('/members\r')
                wait(lambda: '@status [service]' in alice.screen.text, 'visible service member')
                alice.type('/status\r')
                wait(lambda: 'EpochGrid service online' in alice.screen.text, 'TUI encrypted status reply')
                wait(lambda: 'EpochGrid service online' in bob.screen.text, 'Bob sees explicit service reply')
                alice.close()
                removed = cli('alice', 'channel', 'remove', 'engineering', 'status', '--device', 'service')
                assert removed.returncode == 0, removed.stderr
                wait(lambda: participant.poll() is not None, 'removed service exits')
                assert participant.returncode != 0
                alice = Client(root, 'alice', url)
                wait(lambda: 'Online' in alice.screen.text, 'Alice resumes after removal')
                bob.type('TUI_AFTER_SERVICE_REMOVAL_91F3\r')
                wait(lambda: has(root, 'alice', 'TUI_AFTER_SERVICE_REMOVAL_91F3'), 'remaining members continue')
                assert not has(root, 'status', 'TUI_AFTER_SERVICE_REMOVAL_91F3')
                finish(root, [alice, bob], processes,
                       ['/status', 'EpochGrid service online', 'TUI_AFTER_SERVICE_REMOVAL_91F3'])
                print('EpochGrid TUI explicit service membership, encrypted status replies and removal passed')
                return
            if relationships_only:
                secrets = []
                exercise_relationships(root, alice, bob, secrets)
                finish(root, [alice, bob], processes, secrets)
                print('EpochGrid TUI stable IDs, replies, edits, reactions, immutable originals and ciphertext-only storage passed')
                return
            secrets = ['TUI_ALICE_FIRST_91F3', 'TUI_BOB_REPLY_72A1', 'TUI_OFFLINE_QUEUE_5BC7', 'TUI_RECONNECTED_BOB_1D90']
            alice.type(secrets[0] + '\r')
            wait(lambda: has(root, 'bob', secrets[0]) and secrets[0] in bob.screen.text, 'Alice -> Bob render')
            wait(lambda: receipt_is(root, 'alice', secrets[0], 'bob/laptop', 1)
                 and 'bob/laptop: read' in alice.screen.text, 'authenticated read receipt display')
            # Switching away must keep background-channel unread state.
            alice.type('/create other\r')
            wait(lambda: query(root, 'alice', 'SELECT COUNT(*) FROM groups') == 2, 'second local channel')
            bob.type(secrets[1] + '\r')
            wait(lambda: has(root, 'alice', secrets[1]), 'Bob -> Alice background arrival')
            assert query(root, 'alice', 'SELECT displayed FROM transcript WHERE plaintext=?', (secrets[1].encode(),)) == 0
            wait(lambda: receipt_is(root, 'bob', secrets[1], 'alice/laptop', 0), 'background delivery is not read')
            alice.type('\t')
            wait(lambda: query(root, 'alice', 'SELECT displayed FROM transcript WHERE plaintext=?', (secrets[1].encode(),)) == 1, 'selected history clears local unread')
            wait(lambda: receipt_is(root, 'bob', secrets[1], 'alice/laptop', 1), 'viewing upgrades delivered to read')
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
            wait(lambda: all(receipt_is(root, 'bob', secrets[4], device, 1) for device in ['alice/laptop', 'alice/desktop']), 'independent device read receipts')
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
            finish(root, [desktop, alice, bob], processes, secrets)
            print('EpochGrid three-device TUI enrollment, create/invite/join, membership, asynchronous messages, unread, offline queue, reconnect, history, revocation, encrypted attachments, ephemeral typing, device receipts and terminal restoration passed')
        finally:
            for client in CLIENTS:
                client.cleanup()
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--relationships-only', action='store_true')
    modes.add_argument('--participants-only', action='store_true')
    args = parser.parse_args()
    run(args.relationships_only, args.participants_only)
