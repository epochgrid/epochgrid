#!/usr/bin/env python3
"""Exercise two independent interactive clients, including process restart."""
import queue
import subprocess
import threading
import time


def exchange(abrupt=False):
    events = queue.Queue()
    processes = {}

    def collect(user, stream):
        for line in stream:
            events.put((user, line.rstrip()))

    def wait_for(user, text):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            source, line = events.get(timeout=max(0.01, deadline - time.monotonic()))
            if source == user and text in line:
                return
            if 'failed' in line or 'Error:' in line:
                raise AssertionError(f'{source}: {line}')
        raise AssertionError(f'{user} did not display {text}')

    try:
        for user in ('alice', 'bob'):
            process = subprocess.Popen(
                ['./target/debug/epochgrid', '--home', f'.dev/{user}', 'chat', 'engineering'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            processes[user] = process
            threading.Thread(target=collect, args=(user, process.stdout), daemon=True).start()
            wait_for(user, '[engineering]')
        marker = f'EPOCHGRID_CLI_SECRET_91F3_{time.monotonic_ns()}'
        processes['alice'].stdin.write(marker + '\n')
        processes['alice'].stdin.flush()
        wait_for('bob', 'alice/laptop> ' + marker)
        processes['bob'].stdin.write('confirmed by Bob\n')
        processes['bob'].stdin.flush()
        wait_for('alice', 'bob/laptop> confirmed by Bob')
        for user in processes:
            locked = subprocess.run(
                ['./target/debug/epochgrid', '--home', f'.dev/{user}', 'channel', 'list'],
                capture_output=True, text=True, timeout=5,
            )
            assert locked.returncode != 0 and 'already in use' in locked.stderr
        for process in processes.values():
            if abrupt:
                process.kill()  # SIGKILL on Unix: no graceful shutdown or destructors.
            else:
                process.stdin.write('/quit\n')
                process.stdin.flush()
        for process in processes.values():
            result = process.wait(timeout=5)
            assert (result != 0) if abrupt else (result == 0)
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


exchange(abrupt=True)
exchange()  # New CLI processes load the existing group and advanced ratchets.
print('EpochGrid two-client interactive chat, forced termination, lock release and restart passed')


def cli(user, *args, data=None, check=True):
    return subprocess.run(
        ['./target/debug/epochgrid', '--home', f'.dev/{user}', *args],
        input=data, text=True, capture_output=True, check=check, timeout=15,
    )


# Neither interactive process is running while Alice publishes this backlog.
marker = f'EPOCHGRID_OFFLINE_CLI_{time.monotonic_ns()}'
first, second, third = (f'{marker}_{i}' for i in range(3))
cli('alice', 'message', 'send', 'engineering', data=first)
cli('alice', 'message', 'send', 'engineering', data=second)
transcript = cli('bob', 'message', 'history', 'engineering', '--limit', '2').stdout
assert transcript.index(first) < transcript.index(second), transcript
assert transcript.count(first) == transcript.count(second) == 1
second_sequence = transcript.splitlines()[-1].split(']', 1)[0][1:]
page = cli('bob', 'message', 'history', 'engineering', '--offline', '--limit', '1', '--before', second_sequence).stdout
assert first in page and second not in page, page
# History browsing does not consume the unread queue; repeated receive processes do.
assert first in cli('bob', 'message', 'receive', 'engineering', '--timeout', '2').stdout
assert second in cli('bob', 'message', 'receive', 'engineering', '--timeout', '2').stdout
assert '0 decrypted' in cli('bob', 'channel', 'sync', 'engineering').stdout
# An unreachable server is ignored for local history display.
local = cli('bob', '--server', 'nats://127.0.0.1:1', 'message', 'history', 'engineering', '--offline', '--limit', '2').stdout
assert first in local and second in local
cli('alice', 'message', 'send', 'engineering', data=third)
joined = cli('bob', 'chat', 'engineering', data='/quit\n').stdout
assert third in joined, joined
resumed = cli('bob', 'chat', 'engineering', data='/quit\n').stdout
assert third not in resumed, resumed
assert third in cli('bob', 'message', 'history', 'engineering', '--offline', '--limit', '1').stdout
print('EpochGrid offline CLI history, pagination, receive and automatic catch-up passed')
