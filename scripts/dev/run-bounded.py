#!/usr/bin/env python3
"""Run one verification phase with a wall-clock deadline and process-group cleanup."""
import json
from pathlib import Path
import os
import signal
import subprocess
import sys
import time


def run(seconds, command):
    started = time.monotonic()
    result = 1
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
                result = process.wait(timeout=min(remaining, 10))
                return result
            except subprocess.TimeoutExpired:
                print(f'EpochGrid check still running: {command[0]} ({int(time.monotonic() - started)}s)', flush=True)
        print(f'EpochGrid check TIMED OUT: {command}', file=sys.stderr, flush=True)
        result = 124
        return result
    except InterruptedError:
        print(f'EpochGrid check interrupted: {command}', file=sys.stderr, flush=True)
        result = 130
        return result
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
        category = {0: 'passed', 124: 'watchdog_timeout', 130: 'cancelled'}.get(result, 'command_failure')
        record = dict(label=os.environ.get('EPOCHGRID_CHECK_LABEL', Path(command[0]).name),
                      seconds=round(time.monotonic() - started, 3), exit_code=result,
                      category=category)
        print('EpochGrid timing: ' + json.dumps(record), flush=True)
        if os.environ.get('EPOCHGRID_TIMING_FILE'):
            path = Path(os.environ['EPOCHGRID_TIMING_FILE'])
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('a') as stream:
                stream.write(json.dumps(record) + '\n')


if __name__ == '__main__':
    if len(sys.argv) < 3 or float(sys.argv[1]) <= 0:
        raise SystemExit('usage: run-bounded.py SECONDS COMMAND [ARG ...]')
    sys.exit(run(float(sys.argv[1]), sys.argv[2:]))
