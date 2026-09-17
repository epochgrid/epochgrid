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
    def probe(self, deliver_after=None, periodic_sync=False):
        clock = [0.0]
        edits = []
        receiver = SimpleNamespace(screen=SimpleNamespace(text=''))
        announced = [None]

        def edit(text):
            edits.append((clock[0], text))
            if text == '\x1b':
                announced[0] = None
                return
            if periodic_sync:
                # Mirror DraftActivity: edits within the refresh interval do not
                # generate another action; clearing the draft resets it.
                if announced[0] is not None and clock[0] - announced[0] < 2:
                    return
                announced[0] = clock[0]
            if ((deliver_after is not None and clock[0] >= deliver_after)
                    or (periodic_sync and clock[0] % 2 >= 1.2)):
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
        self.assertGreater(len(edits), 4)
        self.assertTrue(all(text == '\x1b' for _, text in edits[::2]))
        self.assertTrue(all(text == 'draft typing without sending' for _, text in edits[1::2]))
        self.assertTrue(all(b[0] - a[0] >= 0.29 for a, b in zip(edits, edits[1:])))
        self.assertTrue(all('\r' not in text and '\n' not in text for _, text in edits))

    def test_continuous_edits_can_remain_phase_locked(self):
        clock, _, sender, receiver, sleep = self.probe(periodic_sync=True)
        for _ in range(50):
            sender.type('.')
            sleep(0.5)
        self.assertEqual(clock[0], 25)
        self.assertEqual(receiver.screen.text, '')

    def test_bursts_escape_periodic_delayed_sync_window(self):
        # A worker busy for the first 1.2s of each 2s period drops activity
        # arriving at a fixed two-second refresh cadence. New bursts must shift
        # phase, not merely add characters to the same continuously active draft.
        clock, edits, sender, receiver, sleep = self.probe(periodic_sync=True)
        with patch.object(smoke, 'CLIENTS', []), patch.object(smoke.time, 'monotonic', lambda: clock[0]), patch.object(smoke.time, 'sleep', sleep):
            smoke.wait_for_typing(sender, receiver, timeout=4)
        self.assertGreaterEqual(clock[0], 1.2)
        self.assertLess(clock[0], 4)
        self.assertGreaterEqual(len(edits), 4)

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
