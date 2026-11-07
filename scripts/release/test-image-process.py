#!/usr/bin/env python3
"""Mount-boundary regressions for the external image process adapter."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from stat import ST_UID

spec = importlib.util.spec_from_file_location('adapter', Path(__file__).with_name('image-process.py'))
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class MountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        self.config = dict(scratch='/host/disposable')

    def selected(self, *args, uid=None, env=None):
        return adapter.mounts(['--home', str(self.home), *args], env or {}, self.config,
                              os.getuid() if uid is None else uid)

    def test_worker_has_only_own_home_bus_ca_and_readonly_ipc(self):
        ipc = self.root / 'ipc'
        ipc.mkdir(mode=0o755)
        bindings = dict(socket=str(ipc / 'control.sock'), authority_uid=os.getuid() + 1)
        (self.home / 'worker.json').write_text(json.dumps(dict(bindings=bindings)))
        original_stat = Path.stat
        def stat(path, **kwargs):
            result = original_stat(path, **kwargs)
            if path != ipc:
                return result
            # Python 3.12's is_symlink() reaches this mock through lstat().
            # Preserve the real file metadata; only ownership is simulated.
            fields = list(result)
            fields[ST_UID] = os.getuid() + 1
            return os.stat_result(fields)
        with patch.object(Path, 'stat', stat):
            values = self.selected()
        self.assertEqual(len(values), 4)
        self.assertTrue(any(value.endswith('dst=' + str(ipc) + ',readonly') for value in values))
        self.assertFalse(any('docker.sock' in value or 'scripts' in value for value in values))
        # A third UID must receive no authority home or IPC mounts.
        self.assertEqual(self.selected(uid=os.getuid() + 1), [])

    def test_no_unbounded_parent_mount_for_export(self):
        with self.assertRaises(ValueError):
            self.selected('--output', str(self.root / 'export.jsonl'))
        destination = self.root / 'audit-output'
        destination.mkdir()
        selected = self.selected('--output', str(destination / 'export.jsonl'))
        self.assertTrue(any('dst=' + str(destination) in value for value in selected))
        self.assertFalse(any(value.endswith('dst=' + str(self.root)) for value in selected))

    def test_rejects_mount_escape_and_symlinks(self):
        for path in ('/var/run/docker.sock', '/tmp', '/tmp/../etc/shadow', 'relative'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                adapter.translated(path, self.config)
        link = self.root / 'ca.pem'
        link.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):
            self.selected(env={'EPOCHGRID_TLS_CA_PATH': str(link)})

    def test_no_implicit_home_or_binary_fallback(self):
        with self.assertRaises(ValueError):
            adapter.mounts(['serve-authority'], {}, self.config, os.getuid())
        self.assertEqual(adapter.mounts(['--help'], {}, self.config, os.getuid()), [])


if __name__ == '__main__':
    unittest.main()
