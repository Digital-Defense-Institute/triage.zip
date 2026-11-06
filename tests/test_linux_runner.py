"""Exercise runner lifecycle with synthetic executables, never host collection."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/run_linux_collection.py'
SPEC = importlib.util.spec_from_file_location('linux_runner', SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


@unittest.skipUnless(os.name == 'posix', 'POSIX process groups')
class LinuxRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.work = self.folder / 'work'
        self.work.mkdir()
        self.executable = self.folder / 'fake-collector'

    def fake(self, body):
        self.executable.write_text('#!/bin/sh\n' + body + '\n')
        self.executable.chmod(0o700)

    def test_process_success_and_logs(self):
        self.fake('echo synthetic-output; echo synthetic-error >&2')
        runner.run_collector(self.executable, self.work, 5)
        self.assertIn('synthetic-output', (self.work / 'process.stdout.log').read_text())
        self.assertIn('synthetic-error', (self.work / 'process.stderr.log').read_text())

    def test_nonzero_exit_is_failure(self):
        self.fake('exit 7')
        with self.assertRaisesRegex(runner.RunnerFailure, 'collector_nonzero_exit'):
            runner.run_collector(self.executable, self.work, 5)

    def test_timeout_terminates_parent_and_descendant(self):
        self.fake('sleep 60 &\necho "$!" > child.pid\nwait')
        start = time.monotonic()
        with self.assertRaisesRegex(runner.RunnerFailure, 'execution_timeout'):
            runner.run_collector(self.executable, self.work, 0.5)
        self.assertLess(time.monotonic() - start, 5)
        pid = (self.work / 'child.pid').read_text().strip()
        # A killed orphan may briefly remain a zombie until init reaps it.
        result = subprocess.run(['ps', '-o', 'stat=', '-p', pid], capture_output=True, text=True)
        self.assertTrue(result.returncode != 0 or result.stdout.strip().startswith('Z'), result.stdout)

    def test_environment_excludes_ci_credentials_and_keeps_native_paths(self):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'PRIVATE', 'ACTIONS_RUNTIME_TOKEN': 'PRIVATE',
                                     'PATH': '/usr/sbin:/usr/bin:/bin'}, clear=False):
            environment = runner.collector_environment()
        self.assertNotIn('GITHUB_TOKEN', environment)
        self.assertNotIn('ACTIONS_RUNTIME_TOKEN', environment)
        self.assertIn('/usr/sbin', environment['PATH'])
        self.assertEqual(environment['LC_ALL'], 'C.UTF-8')

    def invoke(self, extra=()):
        argv = [str(SCRIPT), '--collector', str(self.executable),
                '--output-directory', str(self.folder / 'collection'),
                '--report-directory', str(self.folder / 'reports'), *extra]
        with patch.object(sys, 'argv', argv), patch.object(sys, 'platform', 'linux'), \
             patch.object(os, 'geteuid', return_value=0), \
             patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted'}):
            return runner.main()

    def report(self):
        return json.loads((self.folder / 'reports/validation-report.json').read_text())

    def test_execution_failure_writes_safe_report_and_removes_evidence(self):
        self.fake('echo PRIVATE-LOG; touch fake-evidence; exit 9')
        self.assertEqual(self.invoke(), 1)
        report = self.report()
        self.assertFalse(report['valid'])
        self.assertEqual(report['stage'], 'execution')
        self.assertEqual(report['failure_reason'], 'collector_nonzero_exit')
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertFalse((self.folder / 'collection').exists())

    def test_zero_exit_without_collection_fails(self):
        self.fake('exit 0')
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.report()['failure_reason'], 'expected_one_collection_zip')
        self.assertFalse((self.folder / 'collection').exists())

    def collection_fixture(self, malformed=False):
        from test_linux_collection import fixture
        files = fixture()
        if malformed:
            files['log.json'] = '{"level":"ERROR","message":"PRIVATE-EVIDENCE"}\n'
        archive_path = self.folder / 'synthetic.zip'
        with zipfile.ZipFile(archive_path, 'w') as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        return archive_path

    def test_success_validates_collection_and_preserves_executable_hash(self):
        archive = self.collection_fixture()
        self.fake('cp ' + shlex.quote(str(archive)) + ' Triage-fixture.zip')
        digest = runner.sha256(self.executable)
        self.assertEqual(self.invoke(), 0)
        report = self.report()
        self.assertTrue(report['valid'])
        self.assertEqual(report['stage'], 'complete')
        self.assertEqual(report['collector_sha256'], digest)
        self.assertEqual(report['verified_uac_uploads'], 1)
        self.assertFalse((self.folder / 'collection').exists())

    def test_validator_rejection_preserves_diagnostic_and_cleans_evidence(self):
        archive = self.collection_fixture(malformed=True)
        self.fake('cp ' + shlex.quote(str(archive)) + ' Triage-fixture.zip')
        self.assertEqual(self.invoke(), 1)
        report = self.report()
        self.assertFalse(report['valid'])
        self.assertEqual(report['failure_reason'], 'container_validation_failed')
        self.assertIn('fatal error', report['error'])
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertFalse((self.folder / 'collection').exists())

    def test_collector_mutation_is_rejected(self):
        archive = self.collection_fixture()
        self.fake('cp ' + shlex.quote(str(archive)) + ' Triage-fixture.zip\necho "# changed" >> "$0"\nexit 0')
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.report()['failure_reason'], 'collector_bytes_changed')

    def test_live_facts_inspect_only_failed_sources_and_bind_archive(self):
        from test_linux_collection import UPLOADS, fixture, jsonl
        target = self.folder / 'directory-target'
        target.mkdir()
        link = self.folder / 'directory-link'
        link.symlink_to(target)
        files = fixture()
        files[UPLOADS] += jsonl({'SourceFile': str(link), 'Upload': {'Error': 'is a directory'}},
                               {'SourceFile': 'relative-secret', 'Upload': {'Error': 'failure'}})
        archive_path = self.folder / 'sources.zip'
        with zipfile.ZipFile(archive_path, 'w') as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        facts = runner.live_source_facts(archive_path)
        self.assertEqual(facts['collection_sha256'], runner.sha256(archive_path))
        self.assertEqual(set(facts['sources']), {str(link)})
        self.assertEqual(facts['sources'][str(link)]['source_type'], 'symlink')
        self.assertEqual(facts['sources'][str(link)]['target_type'], 'directory')
        self.assertNotIn('link_target', facts['sources'][str(link)])

    def test_live_facts_distinguish_missing_link_target_and_regular_file(self):
        link = self.folder / 'dangling-link'
        link.symlink_to(self.folder / 'missing')
        facts = runner.describe_source(link)
        self.assertEqual(facts['source_type'], 'symlink')
        self.assertEqual(facts['target_type'], 'missing')
        self.assertEqual(facts['target_errno'], 2)
        regular = self.folder / 'regular'
        regular.write_text('synthetic')
        self.assertEqual(runner.describe_source(regular)['source_type'], 'regular_file')
        self.assertEqual(runner.describe_source(self.folder / 'missing')['source_type'], 'missing')

    def test_malformed_collection_fails_and_cleans_up(self):
        self.fake('echo not-a-zip > Triage-fixture.zip')
        self.assertEqual(self.invoke(), 1)
        self.assertFalse(self.report()['valid'])
        self.assertEqual(self.report()['failure_reason'], 'validation_runner_failed')
        self.assertFalse((self.folder / 'collection').exists())

    def test_preexisting_output_refused_and_preserved(self):
        self.fake('exit 0')
        output = self.folder / 'collection'
        output.mkdir()
        marker = output / 'user-data'
        marker.write_text('keep')
        with self.assertRaises(SystemExit):
            self.invoke()
        self.assertEqual(marker.read_text(), 'keep')

    def test_nested_report_directory_refused(self):
        self.fake('exit 0')
        with self.assertRaises(SystemExit):
            self.invoke(('--report-directory', str(self.folder / 'collection/reports')))

    def test_refuses_non_hosted_execution(self):
        environment = dict(os.environ, GITHUB_ACTIONS='false', RUNNER_ENVIRONMENT='self-hosted')
        result = subprocess.run([sys.executable, str(SCRIPT), '--collector', str(self.executable),
                                 '--output-directory', str(self.folder / 'collection'),
                                 '--report-directory', str(self.folder / 'reports')],
                                env=environment, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disposable GitHub-hosted Linux runner', result.stderr)
        self.assertFalse((self.folder / 'collection').exists())


if __name__ == '__main__':
    unittest.main()
