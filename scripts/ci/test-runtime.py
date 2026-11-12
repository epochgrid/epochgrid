#!/usr/bin/env python3
"""Coverage and artifact trust-boundary regressions; no broker/keyring needed."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def test_unit_campaigns_run_once_under_memory_budget_and_fail_gate(self):
        cases = json.loads((runtime.ROOT / 'scripts/ci/adversarial-cases.json').read_text())
        names = {value[0] for value in cases.values()} | {'registration'}
        data = {'tests': [{'name': name, 'path': name} for name in names]}
        with patch.object(runtime.MANIFEST.__class__, 'read_text', return_value=json.dumps(data)), \
             patch.object(runtime, 'validate'), \
             patch.object(runtime, 'required_security_cases', return_value=cases), \
             patch.object(runtime, 'bounded') as bounded:
            runtime.run('unit')
            calls = bounded.call_args_list
            for case in runtime.PARSER_CASES:
                name, test = cases[case]
                campaign = [call for call in calls if call.kwargs['EPOCHGRID_CHECK_LABEL'] == case]
                self.assertEqual(len(campaign), 1)
                self.assertEqual(campaign[0].args[0], 180)
                self.assertEqual(campaign[0].args[1][:3], ['python3', 'scripts/dev/limit-memory.py', '512'])
                self.assertIn(test, campaign[0].args[1])
                unit = next(call for call in calls if call.kwargs['EPOCHGRID_CHECK_LABEL'] == 'unit-' + name)
                args = unit.args[1]
                self.assertIn('--exact', args)
                self.assertEqual(args[args.index(test) - 1], '--skip')
            def fail_campaign(*args, **kwargs):
                if kwargs['EPOCHGRID_CHECK_LABEL'] == runtime.PARSER_CASES[-1]:
                    raise RuntimeError('campaign failed')
            bounded.side_effect = fail_campaign
            with self.assertRaises(RuntimeError):
                runtime.run('unit')

    def test_required_security_cases_reject_missing_ignored_and_missing_binary(self):
        cases = json.loads((runtime.ROOT / 'scripts/ci/adversarial-cases.json').read_text())
        names = {value[0] for value in cases.values()}
        data = {'tests': [{'name': name, 'path': name} for name in names]}
        def listed(path, ignored=False):
            return [] if ignored else [case for name, case in cases.values() if name == path]
        with patch.object(runtime, 'listed', side_effect=listed):
            runtime.required_security_cases(data)
            with self.assertRaises(ValueError):
                runtime.required_security_cases({'tests': data['tests'][1:]})
        missing = next(iter(cases.values()))[1]
        with patch.object(runtime, 'listed', side_effect=lambda path, ignored=False: [case for case in listed(path, ignored) if case != missing]):
            with self.assertRaises(ValueError):
                runtime.required_security_cases(data)
        with patch.object(runtime, 'listed', side_effect=lambda path, ignored=False: listed(path)):
            with self.assertRaises(ValueError):
                runtime.required_security_cases(data)

    def test_partition_covers_new_cases_once_and_only_excludes_named_cases(self):
        required = list(runtime.SECURITY_NATS.values())
        names = runtime.BYO + [runtime.DYNAMIC] + required + [f'case-{i}' for i in range(17)]
        groups = runtime.partition(names)
        selected = sum(groups, [])
        self.assertEqual(len(selected), len(set(selected)))
        self.assertEqual(set(selected), set(required) | {f'case-{i}' for i in range(17)})
        self.assertLessEqual(max(map(len, groups)) - min(map(len, groups)), 1)
        with self.assertRaises(ValueError):
            runtime.partition(names + [names[0]])
        with self.assertRaises(ValueError):
            runtime.partition(names[1:])
        for name in required:
            with self.assertRaises(ValueError):
                runtime.partition([item for item in names if item != name])

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
