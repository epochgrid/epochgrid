#!/usr/bin/env python3
"""Deterministic checks of the bounded, loss-tolerant typing probe."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('tui_smoke', Path(__file__).with_name('tui-smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class TypingProbeTests(unittest.TestCase):
    def probe(self, deliver_after=None):
        clock = [0.0]
        edits = []
        receiver = SimpleNamespace(screen=SimpleNamespace(text=''))

        def edit(text):
            edits.append((clock[0], text))
            if deliver_after is not None and clock[0] >= deliver_after:
                receiver.screen.text = 'alice is typing'

        def sleep(seconds):
            clock[0] += seconds

        return clock, edits, SimpleNamespace(type=edit), receiver, sleep

    def test_continued_edits_survive_initial_activity_loss(self):
        clock, edits, sender, receiver, sleep = self.probe(deliver_after=6)
        with patch.object(smoke, 'CLIENTS', []), patch.object(smoke.time, 'monotonic', lambda: clock[0]), patch.object(smoke.time, 'sleep', sleep):
            smoke.wait_for_typing(sender, receiver, timeout=10)
        self.assertGreaterEqual(clock[0], 6)
        self.assertLess(clock[0], 10)
        self.assertGreater(len(edits), 10)
        self.assertTrue(all(text == '.' for _, text in edits))
        self.assertTrue(all(b[0] - a[0] >= 0.5 for a, b in zip(edits, edits[1:])))

    def test_missing_indicator_still_hits_fixed_deadline(self):
        clock, edits, sender, receiver, sleep = self.probe()
        with patch.object(smoke, 'CLIENTS', []), patch.object(smoke.time, 'monotonic', lambda: clock[0]), patch.object(smoke.time, 'sleep', sleep):
            with self.assertRaisesRegex(AssertionError, 'encrypted live typing indicator'):
                smoke.wait_for_typing(sender, receiver, timeout=4)
        self.assertGreaterEqual(clock[0], 4)
        self.assertLess(clock[0], 4.1)
        self.assertLessEqual(len(edits), 8)


if __name__ == '__main__':
    unittest.main()
