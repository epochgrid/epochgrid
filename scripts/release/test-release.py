#!/usr/bin/env python3
"""Release input rejection tests; no network, signing credentials or publication."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release as r


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(GITHUB_REPOSITORY=r.REPOSITORY, GITHUB_REF='refs/heads/main',
                        GITHUB_REF_PROTECTED='true', GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_SHA='a' * 40, GITHUB_REPOSITORY_ID='1360374944', GITHUB_RUN_ID='456',
                        GITHUB_RUN_ATTEMPT='1', GITHUB_WORKFLOW_SHA='a' * 40,
                        GITHUB_WORKFLOW_REF=r.REPOSITORY + '/' + r.WORKFLOW + '@refs/heads/main')
        self.identity = r.selection(self.env, '0.1.0-alpha.1')
        self.manifest = dict(schema=1, policy_version=1, identity=self.identity,
                             source_sha256='b' * 64, target=r.TARGET,
                             build=dict(manifest_sha256='c' * 64, lock_sha256='d' * 64,
                                        binary_sha256={name: 'e' * 64 for name in r.BINS}),
                             image=dict(repository='ghcr.io/' + r.REPOSITORY, platform='linux/amd64',
                                        registry_digest='sha256:' + '1' * 64, config_id='sha256:' + '2' * 64,
                                        base='ubuntu:24.04@sha256:' + '3' * 64, transport_sha256='4' * 64),
                             support=dict(scope=['Ubuntu 24.04 x86-64'], limitations=['TD-001/002/003 open'],
                                          readiness='engineering-prerelease'), assets=[])
        for role in ('archive', 'qualification', 'sbom-rust', 'sbom-image', 'notices', 'vulnerability-assessment'):
            name = (f'epochgrid-0.1.0-alpha.1-candidate.{"a" * 40}-{r.TARGET}.tar.gz'
                    if role == 'archive' else role + '.json')
            path = self.root / name
            path.write_text('fixture ' + role)
            self.manifest['assets'].append(dict(name=name, role=role, size=path.stat().st_size,
                                               sha256=r.digest(path)))

    def validate(self, manifest=None):
        return r.validate_manifest(self.manifest if manifest is None else manifest, self.identity, self.root)

    def test_prerelease_grammar(self):
        for version in ('0.1.0-alpha.1', '1.2.3-0', '10.0.0-rc-1.abc'):
            self.assertEqual(r.prerelease(version), 'v' + version)
        for version in ('0.1.0', 'latest', 'v0.1.0-alpha.1', '01.2.3-rc', '1.2.3-01',
                        '1.2.3-rc.00', '1.2.3-rc+build', '1.2.3-', '1.2.3-a..b',
                        '1.2.3-rc\n', '1.2.3-' + 'a' * 128, None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                r.prerelease(version)

    def test_reject_untrusted_dispatch(self):
        for key, value in [('GITHUB_REPOSITORY', 'fork/epochgrid'), ('GITHUB_REF', 'refs/pull/1/merge'),
                           ('GITHUB_REF_PROTECTED', 'false'), ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_SHA', 'a' * 7), ('GITHUB_WORKFLOW_SHA', 'b' * 40),
                           ('GITHUB_WORKFLOW_REF', 'other'), ('GITHUB_RUN_ID', '0'),
                           ('GITHUB_RUN_ATTEMPT', '-1'), ('GITHUB_REPOSITORY_ID', '１２３')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.selection(dict(self.env, **{key: value}), '0.1.0-alpha.1')
        for key in self.env:
            env = self.env.copy()
            del env[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                r.selection(env, '0.1.0-alpha.1')

    def test_checkout_identity_and_versions(self):
        (self.root / 'Cargo.toml').write_text('[workspace.package]\nversion = "0.1.0-alpha.1"\n')
        lock = self.root / 'Cargo.lock'
        lock.write_text('[[package]]\nname = "epochgrid-client"\nversion = "0.1.0-alpha.1"\n')
        crate = self.root / 'crates/client'
        crate.mkdir(parents=True)
        (crate / 'Cargo.toml').write_text('[package]\nname = "epochgrid-client"\nversion.workspace = true\n')
        with patch.object(r, 'ROOT', self.root), patch.object(r, 'source', return_value='b' * 64):
            with patch.object(r, 'output', side_effect=['a' * 40, '']):
                self.assertEqual(r.checkout(self.identity)['version'], '0.1.0-alpha.1')
            for responses in (['b' * 40], ['a' * 40, '?? unexpected']):
                with patch.object(r, 'output', side_effect=responses), self.assertRaises(ValueError):
                    r.checkout(self.identity)
            lock.write_text('[[package]]\nname = "epochgrid-client"\nversion = "0.1.0"\n')
            with patch.object(r, 'output', side_effect=['a' * 40, '']), self.assertRaises(ValueError):
                r.checkout(self.identity)

    def test_valid_manifest_and_distinct_digest_types(self):
        self.validate()
        self.assertNotEqual(self.manifest['image']['config_id'], self.manifest['image']['registry_digest'])

    def test_unknown_schema_fields_and_wrong_identities(self):
        for path, value in [(('schema',), True), (('schema',), 2), (('policy_version',), 2),
                            (('unexpected',), 1), (('target',), 'aarch64-unknown-linux-gnu'),
                            (('identity', 'commit'), 'b' * 40), (('identity', 'repository_id'), '999'),
                            (('identity', 'run_id'), '789'), (('identity', 'tag'), 'latest'),
                            (('identity', 'workflow'), '.github/workflows/ci.yaml'),
                            (('image', 'registry_digest'), '2' * 64),
                            (('image', 'repository'), 'ghcr.io/fork/epochgrid'),
                            (('support', 'readiness'), 'alpha'), (('support', 'limitations'), [])]:
            data = copy.deepcopy(self.manifest)
            obj = data
            for key in path[:-1]:
                obj = obj[key]
            obj[path[-1]] = value
            with self.subTest(path=path, value=value), self.assertRaises(ValueError):
                self.validate(data)

    def test_missing_fields_and_asset_roles(self):
        for key in self.manifest:
            data = copy.deepcopy(self.manifest)
            del data[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(data)
        for index in range(len(self.manifest['assets'])):
            data = copy.deepcopy(self.manifest)
            del data['assets'][index]
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.validate(data)

    def test_asset_paths_duplicates_and_reserved_names(self):
        for name in ('../outside', '/tmp/outside', 'folder/file', 'folder\\file', '.hidden',
                     'RELEASE.json', 'RELEASE.json.sigstore.json', 'name\n'):
            data = copy.deepcopy(self.manifest)
            data['assets'][0]['name'] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(data)
        self.manifest['assets'].append(copy.deepcopy(self.manifest['assets'][0]))
        with self.assertRaises(ValueError):
            self.validate()

    def test_corrupt_missing_and_linked_assets(self):
        path = self.root / self.manifest['assets'][0]['name']
        path.write_text('corruption')
        with self.assertRaises(ValueError):
            self.validate()
        path.unlink()
        with self.assertRaises(ValueError):
            self.validate()
        path.symlink_to(self.root / self.manifest['assets'][1]['name'])
        with self.assertRaises(ValueError):
            self.validate()

    def test_strict_json(self):
        path = self.root / 'input.json'
        for content in ('{"schema":1,"schema":2}', '{"nested":{"x":1,"x":2}}',
                        '{"value":NaN}', '{"value":Infinity}'):
            path.write_text(content)
            with self.subTest(content=content), self.assertRaises(ValueError):
                r.read_json(path)
        path.write_text(json.dumps(self.manifest))
        self.assertEqual(r.read_json(path), self.manifest)


if __name__ == '__main__':
    unittest.main()
