#!/usr/bin/env python3
"""Readiness handles connection reset, fragmented INFO, and a silent broker."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('wait_nats', Path(__file__).with_name('wait-nats.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ReadinessTests(unittest.TestCase):
    def test_retries_closed_socket_then_accepts_fragmented_info(self):
        clock = [0.0]
        first, second = MagicMock(), MagicMock()
        first.__enter__.return_value.recv.return_value = b''
        second.__enter__.return_value.recv.side_effect = [b'IN', b'FO {}\r\n']
        with patch.object(probe.socket, 'create_connection', side_effect=[first, second]) as connect, \
             patch.object(probe.time, 'monotonic', lambda: clock[0]), \
             patch.object(probe.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            probe.wait_for_nats('nats://127.0.0.1:4222', timeout=1)
            self.assertEqual(connect.call_count, 2)

    def test_silent_broker_has_overall_deadline(self):
        clock = [0.0]
        with patch.object(probe.socket, 'create_connection', side_effect=TimeoutError), \
             patch.object(probe.time, 'monotonic', lambda: clock[0]), \
             patch.object(probe.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaises(TimeoutError):
                probe.wait_for_nats('nats://127.0.0.1:4222', timeout=0.2)
            self.assertAlmostEqual(clock[0], 0.2)


if __name__ == '__main__':
    unittest.main()
