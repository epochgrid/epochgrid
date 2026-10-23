#!/usr/bin/env python3
"""Coverage and artifact trust-boundary regressions; no broker/keyring needed."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def test_partition_covers_new_cases_once_and_only_excludes_named_cases(self):
        names = runtime.BYO + [runtime.DYNAMIC] + [f'case-{i}' for i in range(17)]
        groups = runtime.partition(names)
        selected = sum(groups, [])
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(set(selected), {f'case-{i}' for i in range(17)})
        self.assertLessEqual(max(map(len, groups)) - min(map(len, groups)), 1)
        with self.assertRaises(ValueError):
            runtime.partition(names + [names[0]])
        with self.assertRaises(ValueError):
            runtime.partition(names[1:])

    def test_restoration_rejects_stale_corrupt_missing_and_non_executable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'target/debug/test'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'executable fixture')
            path.chmod(0o755)
            data = dict(revision='revision', source='source', checkout=str(root),
                        platform=runtime.host(), files={'target/debug/test': runtime.digest(path)},
                        tests=[{'path': 'target/debug/test'}])
            with patch.object(runtime, 'ROOT', root), patch.object(runtime, 'output', return_value='revision'), patch.object(runtime, 'source_digest', return_value='source'):
                runtime.validate(data)
                # Round-trip the actual archive format into the original checkout
                # path; modes must survive download-style restoration.
                archive = root / 'runtime.tar.gz'
                with tarfile.open(archive, 'w:gz') as bundle:
                    bundle.add(path, arcname='target/debug/test')
                path.unlink()
                with tarfile.open(archive) as bundle:
                    bundle.extractall(root, filter='data')
                runtime.validate(data)
                for field in ('revision', 'source', 'checkout', 'platform'):
                    invalid = copy.deepcopy(data)
                    invalid[field] = 'other'
                    with self.assertRaises(ValueError):
                        runtime.validate(invalid)
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    runtime.validate(data)
                path.chmod(0o755)
                path.write_bytes(b'corruption')
                with self.assertRaises(ValueError):
                    runtime.validate(data)
                path.unlink()
                with self.assertRaises(ValueError):
                    runtime.validate(data)


if __name__ == '__main__':
    unittest.main()
