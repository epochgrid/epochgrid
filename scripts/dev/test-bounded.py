#!/usr/bin/env python3
"""Failure injection for deadline, signal and descendant cleanup behavior."""
import os
from contextlib import closing
import importlib.util
import sqlite3
import threading
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

RUNNER = str(Path(__file__).with_name('run-bounded.py'))


spec = importlib.util.spec_from_file_location('tui_smoke', Path(__file__).with_name('tui-smoke.py'))
tui = importlib.util.module_from_spec(spec)
previous_bytecode_setting = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    spec.loader.exec_module(tui)
finally:
    sys.dont_write_bytecode = previous_bytecode_setting


class DatabaseReadTests(unittest.TestCase):
    def test_transient_lock_retries_and_connections_close(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'alice').mkdir()
            path = root / 'alice' / 'identity.sqlite'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE sample(value INTEGER)')
                db.execute('INSERT INTO sample VALUES(7)')
                db.commit()
            locked = threading.Event()
            def writer():
                with closing(sqlite3.connect(path)) as db:
                    db.execute('BEGIN EXCLUSIVE')
                    locked.set()
                    time.sleep(0.2)
                    db.commit()
            thread = threading.Thread(target=writer, daemon=True)
            thread.start()
            try:
                self.assertTrue(locked.wait(2))
                self.assertEqual(tui.query(root, 'alice', 'SELECT value FROM sample'), 7)
            finally:
                thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            # No inspection connection may leave a read transaction holding a lock.
            with closing(sqlite3.connect(path, timeout=0)) as db:
                db.execute('BEGIN EXCLUSIVE')
                started = time.monotonic()
                with self.assertRaises(TimeoutError):
                    tui.query(root, 'alice', 'SELECT value FROM sample', timeout=0.1)
                self.assertLess(time.monotonic() - started, 1)
                db.rollback()
            # Retry only lock contention; genuine SQL errors must remain failures.
            with self.assertRaises(sqlite3.OperationalError):
                tui.query(root, 'alice', 'SELECT * FROM missing')
            with self.assertRaises(sqlite3.OperationalError):
                tui.query(root, 'alice', 'INSERT INTO sample VALUES(8)')
            self.assertEqual(tui.query(root, 'alice', 'SELECT COUNT(*) FROM sample'), 1)


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
