#!/usr/bin/env python3
"""Run one verification phase with a wall-clock deadline and process-group cleanup."""
import os
import signal
import subprocess
import sys
import time


def run(seconds, command):
    started = time.monotonic()
    print(f'EpochGrid check: {command[0]} (deadline {seconds}s)', flush=True)
    process = subprocess.Popen(command, start_new_session=True)

    def stop(signum, frame):
        raise InterruptedError("verification interrupted")

    previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        while True:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0:
                break
            try:
                return process.wait(timeout=min(remaining, 10))
            except subprocess.TimeoutExpired:
                print(f'EpochGrid check still running: {command[0]} ({int(time.monotonic() - started)}s)', flush=True)
        print(f'EpochGrid check TIMED OUT: {command}', file=sys.stderr, flush=True)
        return 124
    except InterruptedError:
        print(f'EpochGrid check interrupted: {command}', file=sys.stderr, flush=True)
        return 130
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        # Clean descendants even if their parent exited first. No unbounded wait.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            if sig == signal.SIGTERM:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print('EpochGrid cleanup: child did not exit after SIGKILL', file=sys.stderr)
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == '__main__':
    if len(sys.argv) < 3 or float(sys.argv[1]) <= 0:
        raise SystemExit('usage: run-bounded.py SECONDS COMMAND [ARG ...]')
    sys.exit(run(float(sys.argv[1]), sys.argv[2:]))
