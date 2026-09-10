#!/usr/bin/env python3
"""Failure injection for deadline, signal and descendant cleanup behavior."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RUNNER = str(Path(__file__).with_name('run-bounded.py'))


class BoundedTests(unittest.TestCase):
    def test_exit_code(self):
        result = subprocess.run([sys.executable, RUNNER, '5', sys.executable, '-c', 'raise SystemExit(7)'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 7)

    def test_hung_process_and_descendant(self):
        with tempfile.TemporaryDirectory() as root:
            pidfile = Path(root) / 'child'
            code = 'import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); child=os.fork(); open(' + repr(str(pidfile)) + ',"w").write(str(os.getpid())) if child == 0 else None; time.sleep(60)'
            started = time.monotonic()
            result = subprocess.run([sys.executable, RUNNER, '1', sys.executable, '-c', code], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertLess(time.monotonic() - started, 9)
            self.assertIn(b'TIMED OUT', result.stderr)
            pid = int(pidfile.read_text())
            # Linux may briefly retain an orphaned zombie; it must no longer run.
            status = Path(f'/proc/{pid}/stat')
            deadline = time.monotonic() + 2
            while status.exists() and status.read_text().split()[2] != 'Z' and time.monotonic() < deadline:
                time.sleep(0.02)
            if status.exists():
                self.assertEqual(status.read_text().split()[2], 'Z')

    def test_cancellation(self):
        process = subprocess.Popen([sys.executable, RUNNER, '60', sys.executable, '-c', 'import time; time.sleep(60)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.3)
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=8)
            self.assertEqual(process.returncode, 130)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
