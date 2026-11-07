#!/usr/bin/env python3
"""Offline image input identity and failure-report regressions."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import image


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.data = dict(commit='a' * 40, source_sha256='b' * 64, local=False, dirty=False,
                         environment=dict(os='ubuntu', version='24.04'),
                         native={name: dict(glibc_max='2.39') for name in image.BINS})
        self.addCleanup(patch.stopall)
        patch.object(image, 'source', return_value='b' * 64).start()
        self.output = patch.object(image, 'output', side_effect=lambda *args: 'a' * 40 if 'HEAD' in args else '').start()

    def test_local_override_never_bypasses_source_or_baseline(self):
        for field, value in [('commit', 'c' * 40), ('source_sha256', 'd' * 64),
                             ('environment', dict(os='ubuntu', version='26.04')),
                             ('native', {'epochgrid': dict(glibc_max='2.40')})]:
            for local in (False, True):
                data = copy.deepcopy(self.data)
                data[field] = value
                with self.subTest(field=field, local=local), self.assertRaises(ValueError):
                    image.check_identity(data, local)

    def test_candidate_rejects_local_dirty_bundle_and_checkout(self):
        image.check_identity(self.data, False)
        for field in ('local', 'dirty'):
            data = dict(self.data, **{field: True})
            with self.subTest(field=field), self.assertRaises(ValueError):
                image.check_identity(data, False)
            image.check_identity(data, True)
        self.output.side_effect = lambda *args: 'a' * 40 if 'HEAD' in args else ' M changed'
        with self.assertRaises(ValueError):
            image.check_identity(self.data, False)

    def test_corrupt_input_stops_before_docker_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(work=Path(temporary) / 'image', archive=Path('bad.tar.gz'),
                                      checksums=Path('SHA256SUMS'), local=True)
            with patch.object(image, 'verify', side_effect=ValueError('private sentinel')), \
                 patch.object(image.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    image.build(args)
                run.assert_not_called()
            report = json.loads((args.work / 'image.json').read_text())
            self.assertEqual(report, dict(schema=1, result='failed', phase='verify'))
            with self.assertRaises(ValueError):
                image.build(args)

    def test_saved_layers_reject_deleted_private_inputs_and_corruption(self):
        data = dict(commit='a' * 40, version='0.1.0')
        for forbidden in (None, 'state/credentials.json', 'usr/bin/sudo', 'root/.cargo/config.toml'):
            with self.subTest(forbidden=forbidden), tempfile.TemporaryDirectory() as temporary:
                layer = io.BytesIO()
                with tarfile.open(fileobj=layer, mode='w') as tar:
                    member = tarfile.TarInfo(forbidden or 'usr/share/doc/base-files/copyright')
                    member.size = 4
                    tar.addfile(member, io.BytesIO(b'test'))
                payload = layer.getvalue()
                config = dict(os='linux', architecture='amd64', rootfs=dict(diff_ids=[
                    'sha256:' + hashlib.sha256(payload).hexdigest()]), config=dict(
                    User='65532:65532', Entrypoint=['/usr/local/bin/epochgrid-service'],
                    Cmd=['--help'], StopSignal='SIGINT', Env=['EPOCHGRID_PROFILE=production'],
                    Labels={'org.opencontainers.image.' + key: value for key, value in dict(
                        source='https://github.com/epochgrid/epochgrid', revision=data['commit'],
                        version=data['version'], licenses='MIT').items()}))
                raw = json.dumps(config).encode()
                identity = 'sha256:' + hashlib.sha256(raw).hexdigest()
                path = Path(temporary) / 'image.tar'
                with tarfile.open(path, 'w') as tar:
                    for name, contents in [('config.json', raw), ('layer.tar', payload),
                            ('manifest.json', json.dumps([dict(Config='config.json', Layers=['layer.tar'])]).encode())]:
                        member = tarfile.TarInfo(name)
                        member.size = len(contents)
                        tar.addfile(member, io.BytesIO(contents))
                if forbidden:
                    with self.assertRaises(ValueError):
                        image.inspect_archive(path, identity, data)
                else:
                    self.assertEqual(image.inspect_archive(path, identity, data)['layers'], 1)
                    with self.assertRaises(ValueError):
                        image.inspect_archive(path, 'sha256:' + '0' * 64, data)
                    with self.assertRaises(ValueError):
                        image.inspect_archive(path, identity, dict(data, commit='b' * 40))


if __name__ == '__main__':
    unittest.main()
