#!/usr/bin/env python3
"""Negative qualification, signature-policy, inventory and publication recovery cases."""
import copy
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import evidence as e
import inventory as i


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


v = module('verify-release')
p = module('publish-release')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.commit = 'a' * 40
        self.sha = 'b' * 64
        self.run = dict(run_id='42', run_attempt='1')
        cert = dict(issuer=v.ISSUER, sourceRepositoryURI='https://github.com/' + v.REPOSITORY,
                    sourceRepositoryIdentifier=v.REPOSITORY_ID, sourceRepositoryDigest=self.commit,
                    sourceRepositoryRef='refs/heads/main', buildSignerDigest=self.commit,
                    subjectAlternativeName='https://github.com/' + v.REPOSITORY + '/' + v.WORKFLOW + '@refs/heads/main',
                    runnerEnvironment='github-hosted', runInvocationURI='https://github.com/' + v.REPOSITORY +
                    '/actions/runs/42/attempts/1')
        self.result = [dict(verificationResult=dict(signature=dict(certificate=cert), verifiedTimestamps=[{}],
                           statement=dict(_type='https://in-toto.io/Statement/v1', predicateType=v.PROVENANCE,
                                          subject=[dict(name='artifact', digest={'sha256': self.sha})], predicate={})))]

    def check(self, value=None):
        return v.verified_statement(self.result if value is None else value, self.sha, self.commit, v.PROVENANCE, self.run)

    def test_complete_identity(self):
        self.check()

    def test_distribution_retry_is_same_run_only(self):
        certificate = self.result[0]['verificationResult']['signature']['certificate']
        certificate['runInvocationURI'] = 'https://github.com/' + v.REPOSITORY + '/actions/runs/42/attempts/2'
        v.verified_statement(self.result, self.sha, self.commit, v.PROVENANCE, self.run, later_attempt=True)
        with self.assertRaises(ValueError):
            self.check()
        certificate['runInvocationURI'] = 'https://github.com/' + v.REPOSITORY + '/actions/runs/43/attempts/2'
        with self.assertRaises(ValueError):
            v.verified_statement(self.result, self.sha, self.commit, v.PROVENANCE, self.run, later_attempt=True)

    def test_every_certificate_constraint_is_required(self):
        for key in self.result[0]['verificationResult']['signature']['certificate']:
            for missing in (False, True):
                value = copy.deepcopy(self.result)
                cert = value[0]['verificationResult']['signature']['certificate']
                if missing:
                    del cert[key]
                else:
                    cert[key] = 'unexpected'
                with self.subTest(key=key, missing=missing), self.assertRaises(ValueError):
                    self.check(value)

    def test_predicate_digest_timestamp_and_empty_output(self):
        for key, bad in [('predicateType', v.METADATA), ('_type', 'old'), ('subject', []),
                         ('subject', [dict(digest={'sha256': 'c' * 64})])]:
            value = copy.deepcopy(self.result)
            value[0]['verificationResult']['statement'][key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(value)
        with self.assertRaises(ValueError):
            self.check([])
        self.result[0]['verificationResult']['verifiedTimestamps'] = []
        with self.assertRaises(ValueError):
            self.check()

    def test_failed_crypto_is_not_parsed(self):
        with patch.object(v.subprocess, 'check_output', return_value='gh version 2.100.0 (date)\n'), \
             patch.object(v.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')), \
             patch.object(v, 'verified_statement') as policy:
            with self.assertRaises(subprocess.CalledProcessError):
                v.attest('artifact', self.commit, v.PROVENANCE, self.sha)
            policy.assert_not_called()

    def test_verifier_flags_and_tool_version(self):
        with patch.object(v.subprocess, 'check_output', return_value='gh version 2.100.0 (date)\n'), \
             patch.object(v.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(self.result))) as run:
            v.attest('artifact', self.commit, v.PROVENANCE, self.sha, self.run)
            command = run.call_args.args[0]
            for flag in ('--source-digest', '--signer-digest', '--source-ref', '--signer-workflow',
                         '--cert-oidc-issuer', '--deny-self-hosted-runners'):
                self.assertIn(flag, command)
        with patch.object(v.subprocess, 'check_output', return_value='gh version 2.99.0 (date)\n'), self.assertRaises(ValueError):
            v.attest('artifact', self.commit, v.PROVENANCE, self.sha)

    def test_manifest_not_read_before_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'RELEASE.json').write_text('not even JSON')
            with patch.object(v, 'attest', side_effect=ValueError('bad signature')), patch.object(v, 'read_json') as read:
                with self.assertRaises(ValueError):
                    v.verify_release(path, self.commit, '1.0.0-rc.1')
                read.assert_not_called()


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.identity = dict(commit='a' * 40, version='1.0.0-rc.1')
        self.source = 'b' * 64
        self.run = {'id': 'test-run'}
        self.native = dict(schema=1, result='passed', run=self.run, source_sha256=self.source,
                           jobs={key: {'result': 'success'} for key in e.JOBS})
        self.built = dict(result='passed', local=False, **self.identity, source_sha256=self.source,
                          manifest_sha256='c' * 64, binary_sha256={'epochgrid': 'd' * 64}, image_id='sha256:' + 'e' * 64)
        self.build = dict(local=False, dirty=False, **self.identity, source_sha256=self.source)
        self.linux = {suite: dict(schema=1, result='passed', suite=suite, commit=self.identity['commit'],
                     manifest_sha256=self.built['manifest_sha256'], binary_sha256=self.built['binary_sha256']) for suite in e.SUITES}
        self.images = {suite: dict(schema=1, result='passed', suite=suite, commit=self.identity['commit'],
                      source_sha256=self.source, image_id=self.built['image_id']) for suite in (*e.SUITES, 'boundary')}

    def check(self):
        e.qualifications(self.native, self.linux, self.images, self.built, self.build, self.identity, self.source, self.run)

    def test_qualified_run(self):
        self.check()

    def test_missing_suite(self):
        for reports in (self.linux, self.images):
            for suite in list(reports):
                report = reports.pop(suite)
                with self.subTest(suite=suite), self.assertRaises(ValueError):
                    self.check()
                reports[suite] = report

    def test_each_gate_failure_and_skips(self):
        for job in self.native['jobs'].values():
            for status in ('failure', 'cancelled', 'skipped'):
                job['result'] = status
                with self.subTest(status=status), self.assertRaises(ValueError):
                    self.check()
            job['result'] = 'success'

    def test_foreign_run_and_payload(self):
        for obj, key, value in [(self.native, 'run', {}), (self.native, 'source_sha256', 'bad'),
                                (self.built, 'local', True), (self.build, 'dirty', True),
                                (self.linux['smoke'], 'manifest_sha256', 'bad'),
                                (self.images['boundary'], 'image_id', 'bad'),
                                (self.images['smoke'], 'suite', 'other')]:
            old = obj[key]
            obj[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()
            obj[key] = old

    def test_vulnerability_dispositions(self):
        scan = dict(descriptor=dict(name='grype', version='0.121.3', db={'status': {'valid': True}}),
                    matches=[dict(vulnerability={'id': 'CVE-1'}, artifact=dict(name='openssl', version='1'))])
        review = dict(schema=1, reviewed_on=datetime.date.today().isoformat(), reviewer='reviewer', dispositions=[], native_review=[])
        with self.assertRaises(ValueError):
            e.assessment([scan], review)
        review['dispositions'] = [dict(id='CVE-1', package='openssl', version='1', decision='accepted-risk', rationale='test fixture')]
        self.assertEqual(e.assessment([scan], review)['result'], 'reviewed')
        review['reviewed_on'] = '2000-01-01'
        with self.assertRaises(ValueError):
            e.assessment([scan], review)

    def test_spdx_schema_subject_and_relationships(self):
        data = i.spdx([dict(name='crate', version='1.2', kind='rust', usage='build', license='MIT')], 'test', 'a' * 64, 0)
        i.validate_spdx(data, 'a' * 64)
        self.assertEqual(data['relationships'][1]['relatedSpdxElement'], 'SPDXRef-Subject')
        with self.assertRaises(ValueError):
            i.validate_spdx(data, 'b' * 64)
        data['relationships'][1]['relatedSpdxElement'] = 'SPDXRef-missing'
        with self.assertRaises(ValueError):
            i.validate_spdx(data, 'a' * 64)

    def test_scan_sanitization_and_database_age(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sbom.json'
            path.write_text('{}')
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            raw = dict(descriptor=dict(name='grype', version='0.121.3', timestamp=now,
                       configuration={'secret': 'must-not-leak'}, db={'status': dict(valid=True, built=now,
                       schemaVersion='v6', path='/private/cache')}), matches=[])
            result = e.sanitize_scan(raw, path)
            self.assertNotIn('must-not-leak', json.dumps(result))
            self.assertNotIn('/private', json.dumps(result))
            self.assertEqual(result['sbom_sha256'], e.digest(path))
            raw['descriptor']['db']['status']['built'] = '2000-01-01T00:00:00Z'
            with self.assertRaises(ValueError):
                e.sanitize_scan(raw, path)

    def test_native_review_cannot_be_omitted(self):
        review = dict(schema=1, reviewed_on=datetime.date.today().isoformat(), reviewer='reviewer',
                      dispositions=[], native_review=[])
        native = [dict(name='SQLCipher', version='1', source_sha256='a' * 64)]
        with self.assertRaises(ValueError):
            e.assessment([], review, native)
        review['native_review'] = [dict(native[0], rationale='Test review evidence')]
        self.assertEqual(e.assessment([], review, native)['result'], 'reviewed')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'RELEASE.json').write_text('{}')
        self.data = dict(identity=dict(tag='v1.0.0-rc.1', commit='a' * 40))
        self.release = dict(id=1, draft=True, prerelease=True, body=p.marker(self.data, self.root),
                            author={'login': 'github-actions[bot]'})

    def test_settings_credential_is_read_only_and_separate(self):
        with patch.dict(os.environ, GH_TOKEN='publication-test', RELEASE_SETTINGS_TOKEN='settings-test'), \
             patch.object(p.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{}', '')) as run:
            p.api(p.REPO + '/immutable-releases', settings_read=True)
            self.assertEqual(run.call_args.kwargs['env']['GH_TOKEN'], 'settings-test')
            self.assertNotIn('RELEASE_SETTINGS_TOKEN', run.call_args.kwargs['env'])
            p.api(p.REPO)
            self.assertEqual(run.call_args.kwargs['env']['GH_TOKEN'], 'publication-test')
            with self.assertRaises(ValueError):
                p.api(p.REPO + '/immutable-releases', 'PUT', settings_read=True)
            self.assertEqual(run.call_count, 2)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            p.api(p.REPO + '/immutable-releases', settings_read=True)

    def test_ref_without_authenticated_run_record_refused(self):
        with patch.object(p, 'release_state', return_value=None), patch.object(p, 'tag_state', return_value={}), \
             patch.object(p, 'api') as api:
            with self.assertRaises(ValueError):
                p.prepare(self.root, self.data, True)
            api.assert_not_called()

    def test_existing_release_requires_explicit_resume(self):
        with patch.object(p, 'release_state', return_value=self.release), patch.object(p, 'tag_state', return_value={}), \
             patch.object(p, 'api') as api:
            with self.assertRaises(ValueError):
                p.prepare(self.root, self.data, False)
            api.assert_not_called()

    def test_foreign_run_record_refused(self):
        self.release['body'] = 'foreign'
        with patch.object(p, 'release_state', return_value=self.release), patch.object(p, 'tag_state', return_value={}), \
             patch.object(p, 'api') as api:
            with self.assertRaises(ValueError):
                p.prepare(self.root, self.data, True)
            api.assert_not_called()

    def test_asset_corruption_and_partial_upload(self):
        path = self.root / 'payload'
        path.write_bytes(b'good')
        good = dict(name='payload', state='uploaded', size=4, digest='sha256:' + p.digest(path))
        for changed in ({'digest': 'sha256:' + 'a' * 64}, {'size': 1}, {'state': 'starter'}, {'name': 'foreign'}):
            with patch.object(p, 'api', return_value=[dict(good, **changed)]), self.assertRaises(ValueError):
                p.compare_remote_assets(self.release, {'payload': path})
        with patch.object(p, 'api', return_value=[]), self.assertRaises(ValueError):
            p.compare_remote_assets(self.release, {'payload': path}, complete=True)

    def test_lost_tag_response_does_not_continue(self):
        with patch.object(p, 'release_state', return_value=None), patch.object(p, 'tag_state', return_value=None), \
             patch.object(p, 'api', side_effect=TimeoutError('response lost')) as api:
            with self.assertRaises(TimeoutError):
                p.prepare(self.root, self.data, False)
            self.assertEqual(api.call_count, 1)
            self.assertIn('/git/refs', api.call_args.args[0])

    def test_lost_upload_response_resumes_without_replacing_bytes(self):
        payload = self.root / 'payload'
        payload.write_text('immutable')
        remote = []
        ref = dict(object=dict(type='commit', sha='a' * 40,
                    url='https://api.github.com/' + p.REPO + '/git/commits/' + 'a' * 40))
        def upload(*args, **kwargs):
            remote.append(dict(name='payload', state='uploaded', size=payload.stat().st_size,
                               digest='sha256:' + p.digest(payload)))
            raise TimeoutError('response lost after upload')
        with patch.object(p, 'release_state', return_value=self.release), patch.object(p, 'tag_state', return_value=ref), \
             patch.object(p, 'assets', return_value={'payload': payload}), patch.object(p, 'api', side_effect=lambda *a: remote), \
             patch.object(p, 'journal'), patch.object(p.subprocess, 'run', side_effect=upload) as run:
            with self.assertRaises(TimeoutError):
                p.prepare(self.root, self.data, True)
            self.assertEqual(p.prepare(self.root, self.data, True)['id'], 1)
            self.assertEqual(run.call_count, 1)

    def test_registry_lost_response_resume_and_collision(self):
        raw = b'{"schemaVersion":2}'
        wanted = 'sha256:' + p.hashlib.sha256(raw).hexdigest()
        data = dict(identity={'tag': 'v1.0.0-rc.1'}, image={'registry_digest': wanted})
        state = {'tag': None}
        def request(url, headers, missing=False):
            return (state['tag'] if url.endswith('v1.0.0-rc.1') else raw), {'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}
        def put(*args, **kwargs):
            state['tag'] = raw
            raise TimeoutError('response lost after put')
        with patch.dict(os.environ, GITHUB_ACTOR='actor', GH_TOKEN='test'), \
             patch.object(p.candidate, 'registry_token', return_value='test'), patch.object(p.candidate, 'request', side_effect=request), \
             patch.object(p.urllib.request, 'urlopen', side_effect=put) as write, patch.object(p, 'journal'):
            with self.assertRaises(TimeoutError):
                p.promote_image(data, False)
            p.promote_image(data, True)
            self.assertEqual(write.call_count, 1)
            state['tag'] = b'foreign'
            with self.assertRaises(ValueError):
                p.promote_image(data, True)


if __name__ == '__main__':
    unittest.main()
