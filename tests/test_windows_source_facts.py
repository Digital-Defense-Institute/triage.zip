"""Synthetic archives; native Windows coverage touches only an owned temp file."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/windows_source_facts.py'
SPEC = importlib.util.spec_from_file_location('windows_facts', SCRIPT)
facts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(facts)


class WindowsSourceFactsTests(unittest.TestCase):
    def test_rejects_nonordinary_paths_without_probe(self):
        for path in (r'\\.\C:\Users\user\AppData\Local\Temp\a.exe',
                     r'\\?\C:\Windows\Temp\a.exe', r'\\host\share\a.exe',
                     r'C:relative.exe', r'C:\Windows\Temp\..\a.exe',
                     r'C:\Windows\Temp\a.exe:stream', r'C:\Windows\Temp\NUL.exe',
                     r'C:\Windows\Temp\COM1', r'C:\Windows\Temp\trailing.',
                     r'C:\Windows\Temp\bad?.exe', r'C:\Program Files\app.exe', 'relative.exe'):
            with self.subTest(path=path), patch.object(facts.os, 'lstat') as probe:
                self.assertEqual(facts.describe_source(path)['source_type'], 'unsupported_path')
                probe.assert_not_called()

    def test_missing_requires_native_file_or_path_not_found(self):
        for code, expected in ((2, 'missing'), (3, 'missing'), (5, 'other'), (None, 'other')):
            with self.subTest(code=code):
                error = OSError('PRIVATE-PATH')
                error.winerror = code
                with patch.object(facts.os, 'lstat', side_effect=error):
                    report = facts.describe_source(r'C:\Windows\Temp\fixture.exe')
                self.assertEqual(report['source_type'], expected)
                self.assertNotIn('PRIVATE', json.dumps(report))

    def test_existing_file_cannot_be_called_missing(self):
        with patch.object(facts.os, 'lstat', return_value=SimpleNamespace(st_size=42)):
            self.assertEqual(facts.describe_source(r'C:\Windows\Temp\fixture.exe'),
                             {'source_type': 'existing', 'source_size': 42})

    def test_probes_only_failed_sources_and_binds_collection_hash(self):
        source = r'C:\Windows\Temp\fixture.exe'
        with tempfile.TemporaryDirectory() as folder:
            archive = Path(folder) / 'collection.zip'
            rows = [{'SourceFile': source, 'Upload': {'Error': 'missing'}},
                    {'SourceFile': source, 'Upload': {'Error': 'missing'}},
                    {'SourceFile': 'PRIVATE-SUCCESS', 'Upload': {'StoredSize': 10}}]
            with zipfile.ZipFile(archive, 'w') as output:
                output.writestr('results/Windows.Triage.Targets%2FUploads.json',
                                ''.join(json.dumps(row) + '\n' for row in rows))
            with patch.object(facts, 'describe_source', return_value={'source_type': 'missing'}) as probe:
                result = facts.gather_facts(archive)
            self.assertEqual(result['collection_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(set(result['sources']), {source})
            probe.assert_called_once_with(source)

    @unittest.skipUnless(sys.platform == 'win32', 'requires native Windows filesystem errors')
    def test_native_deleted_temp_file_facts_qualify_synthetic_collection(self):
        # This creates and deletes literal fixture bytes; no collector or .exe
        # is executed. Only the source-facts probe uses the native filesystem.
        from test_windows_collection import fixture, jsonl, TRIAGE_RESULT
        temp_root = os.environ.get('TEMP') or tempfile.gettempdir()
        with tempfile.TemporaryDirectory(dir=temp_root) as folder:
            source = Path(folder) / 'fake.exe'
            source.write_bytes(b'literal fixture bytes, never executable')
            positive_size = source.stat().st_size
            self.assertGreater(positive_size, 0)
            source_path = str(source)
            scope = facts._eligibility.windows_temp_scope(source_path)
            self.assertIsNotNone(scope, 'Windows TEMP must be in an eligible local temporary scope')
            source.unlink()

            files = fixture()
            files[TRIAGE_RESULT] += jsonl({
                'SourceFile': source_path, 'FileSize': positive_size,
                'Upload': {'Error': 'CreateFile fixture: The system cannot find the file specified.'}})
            files['results/Windows.Triage.Targets%2FAll_Matches_Metadata.json'] = jsonl({
                'SourceFile': source_path, 'Size': positive_size, 'Type': 'PsList/From_Pslist'})
            archive = Path(folder) / 'synthetic-collection.zip'
            with zipfile.ZipFile(archive, 'w') as output:
                for name, data in files.items():
                    output.writestr(name, data)

            report_facts = facts.gather_facts(archive)
            observed = report_facts['sources'][source_path]
            self.assertEqual(observed['source_type'], 'missing')
            self.assertIn(observed['source_winerror'], (2, 3))
            self.assertEqual(report_facts['collection_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            report = facts._eligibility.validate(archive, report_facts)
            self.assertTrue(report['valid'])
            self.assertEqual(report['vanished_temporary_targets'][scope], 1)
            self.assertEqual(sum(report['vanished_temporary_targets'].values()), 1)
            self.assertEqual(report['verified_triage_uploads'], 1)
            self.assertNotIn(source_path, json.dumps(report))

    def test_refuses_nonhosted_cli_without_creating_facts(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'facts.json'
            environment = dict(os.environ, GITHUB_ACTIONS='false', RUNNER_ENVIRONMENT='self-hosted')
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'missing.zip', '--output', str(output)],
                                    env=environment, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn('Administrator on a hosted Windows runner', result.stderr)


if __name__ == '__main__':
    unittest.main()
