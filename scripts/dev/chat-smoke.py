#!/usr/bin/env python3
"""Exercise two independent interactive clients, including process restart."""
import queue
import subprocess
import threading
import time


def exchange():
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
        processes['alice'].stdin.write('EPOCHGRID_CLI_SECRET_91F3\n')
        processes['alice'].stdin.flush()
        wait_for('bob', 'alice/laptop> EPOCHGRID_CLI_SECRET_91F3')
        processes['bob'].stdin.write('confirmed by Bob\n')
        processes['bob'].stdin.flush()
        wait_for('alice', 'bob/laptop> confirmed by Bob')
        for process in processes.values():
            process.stdin.write('/quit\n')
            process.stdin.flush()
        for process in processes.values():
            assert process.wait(timeout=5) == 0
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
            process.wait()


exchange()
exchange()  # New CLI processes load the existing group and advanced ratchets.
print('EpochGrid two-client interactive chat and restart passed')
