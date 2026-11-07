#!/usr/bin/env python3
"""Offline candidate authorization, report identity and registry failure tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import argparse
from unittest.mock import patch
import urllib.error

spec = importlib.util.spec_from_file_location('publication', Path(__file__).with_name('publish-image.py'))
publication = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publication)


class PublicationTests(unittest.TestCase):
    def test_existing_tag_is_refused_before_load_tag_or_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'image.json'
            built = dict(schema=1, result='passed', local=False, image_id='sha256:' + 'a' * 64,
                         commit='b' * 40, source_sha256='c' * 64)
            path.write_text(json.dumps(built))
            args = argparse.Namespace(image_report=path, visibility='private', create_private=False,
                                      mode='push', qualifications=Path(temporary))
            with patch.object(publication, 'context', return_value='candidate-fixture'), \
                 patch.dict(publication.os.environ, GITHUB_SHA='b' * 40, GITHUB_TOKEN='private sentinel', GITHUB_ACTOR='fixture'), \
                 patch.object(publication, 'source', return_value='c' * 64), \
                 patch.object(publication, 'package'), patch.object(publication, 'qualifications'), \
                 patch.object(publication, 'registry_token', return_value='fixture'), \
                 patch.object(publication, 'manifest', return_value=('sha256:' + 'd' * 64, built['image_id'])), \
                 patch.object(publication, 'docker') as docker:
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    publication.transport(args, {})
                self.assertEqual([call.args[1] for call in docker.call_args_list], ['login'])

    def test_only_manually_selected_protected_main_can_publish(self):
        env = dict(GITHUB_REPOSITORY='epochgrid/epochgrid', GITHUB_REF='refs/heads/main',
                   GITHUB_REF_PROTECTED='true', GITHUB_EVENT_NAME='workflow_dispatch',
                   GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2')
        self.assertEqual(publication.context(env), 'candidate-' + 'a' * 40 + '-123-2')
        for key, value in [('GITHUB_REPOSITORY', 'other/epochgrid'), ('GITHUB_REF', 'refs/pull/1/merge'),
                           ('GITHUB_REF_PROTECTED', 'false'), ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_SHA', 'latest'), ('GITHUB_RUN_ID', '../escape')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                publication.context(dict(env, **{key: value}))

    def test_every_suite_and_boundary_must_match_the_exact_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            built = dict(image_id='sha256:' + 'a' * 64, commit='b' * 40, source_sha256='c' * 64)
            reports = {**{'qualification-' + suite: dict(built, result='passed', suite=suite)
                         for suite in publication.SUITES}, 'boundary': dict(built, result='passed')}
            for name, report in reports.items():
                (root / (name + '.json')).write_text(json.dumps(report))
            publication.qualifications(root, built)
            for name, report in reports.items():
                path = root / (name + '.json')
                for key, value in [('result', 'failed'), ('image_id', 'sha256:' + 'd' * 64),
                                   ('commit', 'e' * 40), ('source_sha256', 'f' * 64)]:
                    path.write_text(json.dumps(dict(report, **{key: value})))
                    with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                        publication.qualifications(root, built)
                path.write_text(json.dumps(report))
            (root / 'boundary.json').unlink()
            with self.assertRaises(FileNotFoundError):
                publication.qualifications(root, built)

    def test_registry_auth_and_server_errors_are_not_missing_tags(self):
        for code in (401, 403, 429, 500):
            error = urllib.error.HTTPError('https://ghcr.io/fixture', code, 'fixture', {}, None)
            with patch.object(publication.urllib.request, 'urlopen', side_effect=error), self.assertRaises(urllib.error.HTTPError):
                publication.request('https://ghcr.io/fixture', {}, missing=True)
        error = urllib.error.HTTPError('https://ghcr.io/fixture', 404, 'fixture', {}, None)
        with patch.object(publication.urllib.request, 'urlopen', side_effect=error):
            self.assertIsNone(publication.request('https://ghcr.io/fixture', {}, missing=True)[0])

    def test_manifest_digest_and_candidate_tag_contract(self):
        raw = json.dumps(dict(schemaVersion=2, config=dict(digest='sha256:' + 'a' * 64))).encode()
        expected = 'sha256:' + hashlib.sha256(raw).hexdigest()
        with patch.object(publication, 'request', return_value=(raw, {'Docker-Content-Digest': expected})):
            self.assertEqual(publication.manifest(expected, 'fixture'), (expected, 'sha256:' + 'a' * 64))
            for reference in ('latest', 'v0.1.0', 'candidate-short', '../other'):
                with self.assertRaises(ValueError):
                    publication.manifest(reference, 'fixture')
        with patch.object(publication, 'request', return_value=(raw, {'Docker-Content-Digest': 'wrong'})):
            with self.assertRaises(ValueError):
                publication.manifest(expected, 'fixture')

    def test_no_implicit_package_creation_or_visibility_changes(self):
        with patch.object(publication, 'request', return_value=(None, {})):
            with self.assertRaises(ValueError):
                publication.package('fixture', 'private')
            with self.assertRaises(ValueError):
                publication.package('fixture', 'public', True)
            publication.package('fixture', 'private', True)
        data = dict(owner=dict(login='epochgrid'), visibility='private', name='epochgrid', package_type='container')
        with patch.object(publication, 'request', return_value=(json.dumps(data).encode(), {})):
            publication.package('fixture', 'private')
            with self.assertRaises(ValueError):
                publication.package('fixture', 'public')


if __name__ == '__main__':
    unittest.main()
