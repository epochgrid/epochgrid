#!/usr/bin/env python3
"""Adversarial archive/manifest tests, independent of Cargo and live keyrings."""
import argparse
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('artifact', Path(__file__).with_name('artifact.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / 'stage'
        (self.stage / 'bin').mkdir(parents=True)
        self.data = dict(schema=1, version='0.1.0', target=a.TARGET, profile='release',
                         commit='a' * 40, local=False, dirty=False, source_epoch=123,
                         native={name: {'needed': ['libc.so.6']} for name in a.BINS}, files={})
        for name, mode in a.PAYLOAD.items():
            path = self.stage / name
            path.write_bytes(b'fixture ' + name.encode())
            path.chmod(mode)
            if name != 'BUILD.json':
                self.data['files'][name] = dict(sha256=a.digest(path), size=path.stat().st_size, mode=mode)
        a.write_json(self.stage / 'BUILD.json', self.data)
        self.archive = self.root / f'epochgrid-0.1.0-candidate.{"a" * 40}-{a.TARGET}.tar.gz'
        self.checksums = self.root / 'SHA256SUMS'
        self.output = self.root / 'relocated path with spaces'
        self.addCleanup(patch.stopall)
        patch.object(a, 'elf', return_value={'needed': ['libc.so.6']}).start()

    def pack(self):
        a.archive(self.stage, self.archive, self.data)
        self.sum()

    def sum(self):
        self.checksums.write_text(f'{a.digest(self.archive)}  {self.archive.name}\n')

    def verify(self):
        a.verify(argparse.Namespace(archive=self.archive, checksums=self.checksums,
                                   output=self.output, require_candidate=True, commit='a' * 40))

    def rewrite(self, mutate):
        with tarfile.open(self.archive) as tar:
            members = [(item, tar.extractfile(item).read()) for item in tar]
        mutate(members)
        self.archive.unlink()
        with tarfile.open(self.archive, 'w:gz') as tar:
            for info, content in members:
                tar.addfile(info, io.BytesIO(content))
        self.sum()

    def reject(self):
        with self.assertRaises((ValueError, OSError, EOFError, tarfile.TarError)):
            self.verify()
        self.assertFalse(self.output.exists())

    def test_roundtrip_relocation_and_no_overwrite(self):
        self.pack()
        self.verify()
        self.assertEqual((self.output / 'bin/epochgrid').stat().st_mode & 0o777, 0o755)
        with self.assertRaises(ValueError):
            self.verify()

    def test_deterministic_packaging(self):
        self.pack()
        other = self.root / 'other.gz'
        a.archive(self.stage, other, self.data)
        self.assertEqual(a.digest(self.archive), a.digest(other))

    def test_checksum_corruption(self):
        self.pack()
        self.archive.write_bytes(self.archive.read_bytes() + b'corrupt')
        self.reject()

    def test_truncation(self):
        self.pack()
        self.archive.write_bytes(self.archive.read_bytes()[:100])
        self.sum()
        self.reject()

    def test_missing_payload(self):
        self.pack()
        self.rewrite(lambda members: members.pop())
        self.reject()

    def test_modified_binary(self):
        self.pack()
        def mutate(members):
            info, content = members[-1]
            members[-1] = (info, b'X' * len(content))
        self.rewrite(mutate)
        self.reject()

    def test_duplicate_member(self):
        self.pack()
        self.rewrite(lambda members: members.append(members[-1]))
        self.reject()

    def test_unsafe_members(self):
        for name in ('../outside', '/absolute', 'bin/../../outside', 'unexpected'):
            with self.subTest(name=name):
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                self.rewrite(lambda members: setattr(members[-1][0], 'name', name))
                self.reject()
        self.assertFalse((self.root / 'outside').exists())

    def test_links_and_modes(self):
        for change in ('symlink', 'hardlink', 'mode'):
            with self.subTest(change=change):
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                def mutate(members):
                    info = members[-1][0]
                    if change == 'mode':
                        info.mode = 0o4755
                    else:
                        info.type = tarfile.SYMTYPE if change == 'symlink' else tarfile.LNKTYPE
                        info.linkname = '/tmp/outside'
                        info.size = 0
                self.rewrite(mutate)
                self.reject()

    def test_manifest_target_revision_and_local(self):
        for key, value in [('target', 'aarch64-unknown-linux-gnu'), ('schema', 2),
                           ('commit', 'b' * 40), ('local', True), ('dirty', True),
                           ('version', '../../bad')]:
            with self.subTest(key=key):
                data = copy.deepcopy(self.data)
                data[key] = value
                a.write_json(self.stage / 'BUILD.json', data)
                if self.archive.exists():
                    self.archive.unlink()
                self.pack()
                self.reject()

    def test_native_manifest_mismatch(self):
        self.pack()
        with patch.object(a, 'elf', return_value={'needed': ['unexpected.so']}):
            self.reject()

    def test_missing_license_and_extra_file(self):
        (self.stage / 'THIRD_PARTY_NOTICES').unlink()
        with self.assertRaises(ValueError):
            a.validate_stage(self.stage)
        (self.stage / 'private.seed').write_text('sentinel')
        with self.assertRaises(ValueError):
            a.validate_stage(self.stage)

    def test_dirty_candidate_rejected(self):
        with patch.object(a, 'output', return_value=' M file'):
            with self.assertRaisesRegex(ValueError, 'clean checkout'):
                a.identity(False)


if __name__ == '__main__':
    unittest.main()
