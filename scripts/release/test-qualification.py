#!/usr/bin/env python3
"""Offline qualification regressions; root runs also exercise a distinct UID."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import qualify


class QualificationTests(unittest.TestCase):
    def test_public_nats_fixture_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            (root / 'scripts/dev').mkdir(parents=True)
            (root / 'config').mkdir()
            (root / 'config/nats.Dockerfile').write_text('FROM scratch\n')
            archive = root / 'fixture.tar.gz'
            arch = 'arm64' if os.uname().machine in ('aarch64', 'arm64') else 'amd64'
            with tarfile.open(archive, 'w:gz') as tar:
                for name, data, mode in [('nats-server', b'#!/bin/sh\necho fixture-nats\n', 0o755),
                                         ('LICENSE', b'public fixture', 0o644)]:
                    member = tarfile.TarInfo(f'nats-server-v2.14.5-linux-{arch}/' + name)
                    member.size, member.mode = len(data), mode
                    tar.addfile(member, io.BytesIO(data))
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            script = (qualify.ROOT / 'scripts/dev/download-nats.sh').read_text()
            script = script.replace('5e3b603d47c447bda1f77f9ac16dbf91c90aac4ff3681f8fbbc7201e4ed99355', checksum)
            script = script.replace('673a98d3faa79dde3f9ebf16d6dfac36a5f694e7ad2015e4954dd7939c85cd4c', checksum)
            # Network is replaced; real checksum verification, tar and chmod run.
            script = script.replace('curl --fail', 'fixture_curl --fail')
            script = script.replace('set -euo pipefail', 'set -euo pipefail\nfixture_curl() { cp "$FIXTURE_ARCHIVE" "${@: -1}"; }')
            download = root / 'scripts/dev/download-nats.sh'
            download.write_text(script)
            # Cover an existing private cache as well as a fresh download.
            for existing in (False, True):
                if existing:
                    (root / '.dev/nats-image').chmod(0o700)
                    (root / '.dev/nats-image/nats-server').chmod(0o700)
                subprocess.run(['bash', str(download)], check=True,
                               env=dict(os.environ, FIXTURE_ARCHIVE=str(archive)))
                fixture = root / '.dev/nats-image'
                self.assertEqual(fixture.stat().st_mode & 0o777, 0o755)
                self.assertEqual((fixture / 'nats-server').stat().st_mode & 0o777, 0o755)
                for name in ('LICENSE', 'Dockerfile'):
                    self.assertEqual((fixture / name).stat().st_mode & 0o777, 0o644)
                # Mounting fixture bypasses .dev's deliberately private parent.
                exposed = root / 'mounted-nats'
                shutil.copytree(fixture, exposed, dirs_exist_ok=True)
                def different_uid():
                    os.setgroups([])
                    os.setgid(1000)
                    os.setuid(1000)
                result = subprocess.run([str(exposed / 'nats-server')], check=True,
                                        capture_output=True, text=True,
                                        preexec_fn=different_uid if os.getuid() == 0 else None)
                self.assertEqual(result.stdout, 'fixture-nats\n')

    def test_reports_preserve_failure_and_exclude_raw_errors(self):
        for error in (ValueError('private sentinel'), PermissionError('private sentinel'),
                      subprocess.CalledProcessError(101, ['private sentinel'])):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as temporary:
                args = argparse.Namespace(suite='smoke', result=Path(temporary) / 'result.json')
                with patch.object(qualify, 'outside', side_effect=error):
                    with self.assertRaises(type(error)):
                        qualify.qualify(args)
                report = json.loads(args.result.read_text())
                self.assertEqual(report['result'], 'failed')
                self.assertEqual(report['error_type'], type(error).__name__)
                self.assertNotIn('private sentinel', args.result.read_text())
                if isinstance(error, subprocess.CalledProcessError):
                    self.assertEqual(report['exit_code'], 101)

    def test_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = argparse.Namespace(suite='smoke', result=Path(temporary) / 'result.json')
            result = dict(schema=1, suite='smoke', result='passed', commit='a' * 40)
            with patch.object(qualify, 'outside', return_value=result):
                qualify.qualify(args)
            self.assertEqual(json.loads(args.result.read_text()), result)


if __name__ == '__main__':
    unittest.main()
