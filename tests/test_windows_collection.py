"""Synthetic containers use the upstream collect() JSON/JSONL layout.

Schema references: vql/tools/collector/fixtures/TestCollectionWithUpload.golden,
crypto/proto/jobs.proto (VeloStatus), flows/proto/artifact_collector.proto.
No collector is executed by these tests.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/validate_windows_collection.py'
SPEC = importlib.util.spec_from_file_location('windows_validator', SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)
TRIAGE_RESULT = 'results/Windows.Triage.Targets%2FUploads.json'
AUTORUNS_RESULT = 'results/Windows.Sysinternals.Autoruns.json'
EVIDENCE = 'uploads/auto/C%3A/Windows/example.evtx'


def jsonl(*rows):
    return ''.join(json.dumps(row) + '\n' for row in rows)


def fixture():
    return {
        'collection_context.json': json.dumps({
            'state': 2, 'request': {'artifacts': [validator.TRIAGE, validator.AUTORUNS]},
            'query_stats': [{'result_rows': 1}, {'status': 0, 'result_rows': 2}],
            'total_collected_rows': 3}),
        'client_info.json': json.dumps({'OS': 'windows', 'Hostname': 'fixture'}),
        'requests.json': json.dumps({'items': [{'VQLClientAction': {'Query': []}}]}),
        'log.json': jsonl({'level': 'DEFAULT', 'message': 'Collected 1 rows for Windows.Triage.Targets/Uploads\n'}),
        'uploads.json': jsonl({'_Components': ['uploads', 'auto', 'C:', 'Windows', 'example.evtx'],
                               'file_size': 8, 'uploaded_size': 8, 'Type': ''}),
        TRIAGE_RESULT: jsonl({'SourceFile': r'C:\Windows\example.evtx', 'FileSize': 8,
                              'Upload': {'StoredName': '/' + EVIDENCE, 'StoredSize': 8}}),
        AUTORUNS_RESULT: jsonl({'Entry': '', 'Category': 'Boot Execute'},
                              {'Entry': 'autocheck autochk *', 'Category': 'Boot Execute',
                               'Image Path': r'c:\windows\system32\autochk.exe'}),
        EVIDENCE: b'evidence',
    }


class WindowsCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'collection.zip'
        self.files = fixture()

    def write(self, duplicate=False):
        with zipfile.ZipFile(self.path, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, data in self.files.items():
                archive.writestr(name, data)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr('log.json', self.files['log.json'])

    def context(self, **updates):
        context = json.loads(self.files['collection_context.json'])
        context.update(updates)
        self.files['collection_context.json'] = json.dumps(context)

    def invalid(self, message):
        self.write()
        with self.assertRaisesRegex(validator.InvalidCollection, message):
            validator.validate(self.path)

    def test_valid_upstream_layout(self):
        self.write()
        report = validator.validate(self.path)
        self.assertTrue(report['valid'])
        self.assertEqual(report['verified_triage_uploads'], 1)
        self.assertEqual(report['autoruns_entries'], 1)
        self.assertNotIn('fixture', json.dumps(report))
        self.assertNotIn('example.evtx', json.dumps(report))

    def test_missing_metadata(self):
        for name in ('collection_context.json', 'client_info.json', 'requests.json'):
            with self.subTest(name=name):
                self.files = fixture()
                del self.files[name]
                self.invalid('metadata')

    def test_malformed_metadata(self):
        self.files['collection_context.json'] = '[1, 2]'
        self.invalid('not an object')

    def test_wrong_platform(self):
        self.files['client_info.json'] = '{"OS":"linux"}'
        self.invalid('not from Windows')

    def test_incomplete_or_error_state(self):
        for state in (0, 1, 3, 4, 5, 'ERROR', None):
            with self.subTest(state=state):
                self.context(state=state)
                self.invalid('did not finish')

    def test_collection_error_status(self):
        self.context(status='secret error detail')
        self.invalid('error status')

    def test_wrong_artifact_request(self):
        self.context(request={'artifacts': [validator.TRIAGE]})
        self.invalid('not requested')

    def test_query_failure(self):
        for stats in ([{'status': 10}], [{'error_message': 'error'}], [], None):
            with self.subTest(stats=stats):
                self.context(query_stats=stats)
                self.invalid('query')

    def test_explicit_log_errors_always_fail(self):
        for level in ('ERROR', 'FATAL', 'PANIC'):
            with self.subTest(level=level):
                # Do not exempt permission errors by text matching.
                self.files['log.json'] = jsonl({'level': level, 'message': 'Access denied'})
                self.invalid('fatal error')

    def test_default_level_fatal_messages(self):
        for message in ('Timeout Error: Collection timed out', 'context canceled',
                        'progress timeout', 'panic: failure', 'While closing container: failure'):
            with self.subTest(message=message):
                self.files['log.json'] = jsonl({'level': 'DEFAULT', 'message': message})
                self.invalid('fatal error')

    def test_optional_target_warnings_are_counted(self):
        self.files['log.json'] += jsonl({'level': 'WARN', 'message': 'No VSS snapshots found'})
        self.write()
        self.assertEqual(validator.validate(self.path)['warning_rows'], 1)

    def test_missing_empty_and_malformed_logs(self):
        for data in ('', '{bad json', jsonl({'level': 'DEFAULT'})):
            with self.subTest(data=data):
                self.files['log.json'] = data
                self.invalid('log|JSONL')

    def test_empty_triage(self):
        self.files[TRIAGE_RESULT] = ''
        self.invalid('triage produced no result')

    def test_autoruns_headers_are_not_real_entries(self):
        self.files[AUTORUNS_RESULT] = jsonl({'Entry': '', 'Category': 'Boot Execute'})
        self.invalid('meaningful entries')

    def test_no_upload(self):
        self.files[TRIAGE_RESULT] = jsonl({'SourceFile': 'file', 'Upload': None})
        self.invalid('no verified')

    def test_missing_referenced_upload(self):
        del self.files[EVIDENCE]
        self.invalid('missing evidence')

    def test_zero_length_upload(self):
        self.files[EVIDENCE] = b''
        self.files[TRIAGE_RESULT] = jsonl({'SourceFile': 'file', 'Upload': {
            'StoredName': '/' + EVIDENCE, 'StoredSize': 0}})
        self.invalid('no verified')

    def test_upload_size_mismatch(self):
        self.files[EVIDENCE] = b'short'
        self.invalid('size does not match')

    def test_all_result_streams_are_parsed(self):
        for data in ('{"bad":', '[]', 'null'):
            with self.subTest(data=data):
                self.files['results/Windows.Other.json'] = data
                self.invalid('JSONL')

    def test_multisource_upstream_row_count_can_undercount(self):
        self.context(total_collected_rows=2)
        self.write()
        self.assertTrue(validator.validate(self.path)['valid'])

    def test_upload_metadata_is_required_and_fully_parsed(self):
        for data in ('', '{}\nnot-json', '[]'):
            with self.subTest(data=data):
                self.files['uploads.json'] = data
                self.invalid('upload metadata|JSONL')

    def test_partial_upload_errors_fail(self):
        self.files[TRIAGE_RESULT] = jsonl({'SourceFile': 'file', 'Upload': {
            'StoredName': '/' + EVIDENCE, 'StoredSize': 8, 'Error': 'partial'}})
        self.invalid('upload reports an error')

    def test_all_upload_errors_are_counted_and_redacted(self):
        failures = [
            {'Error': r'open C:\SECRET: The system cannot find the file specified.'},
            {'Error': r'open C:\SECRET: The system cannot find the path specified.'},
            {'Error': r'open C:\SECRET: Access is denied.'},
            {'Error': r'open C:\SECRET: The process cannot access the file because it is being used by another process.'},
            {'Error': 'SECRET partial copy failed', 'StoredName': '/' + EVIDENCE, 'StoredSize': 4},
            {'Error': 'SECRET unknown failure', 'StoredName': '/' + EVIDENCE, 'StoredSize': 'bad'},
        ]
        self.files[TRIAGE_RESULT] += jsonl(*({'SourceFile': 'SECRET', 'Upload': upload}
                                          for upload in failures))
        self.context(total_collected_rows=9)
        self.write()
        report_path = Path(self.temp.name) / 'report.json'
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path),
                                 '--report', str(report_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        report = json.loads(report_path.read_text())
        errors = report['diagnostics']['upload_errors']
        self.assertEqual(errors['missing_file']['count'], 2)
        self.assertEqual(errors['access_denied']['count'], 1)
        self.assertEqual(errors['sharing_violation']['count'], 1)
        self.assertEqual(errors['other']['count'], 2)
        self.assertEqual(errors['other']['stored_name_present'], 2)
        self.assertEqual(errors['other']['nonzero_stored_size'], 1)
        self.assertEqual(errors['other']['stored_bytes'], 4)
        self.assertEqual(errors['other']['malformed_stored_size'], 1)
        self.assertEqual(report['diagnostics']['verified_triage_uploads'], 1)
        self.assertNotIn('SECRET', result.stdout + result.stderr + report_path.read_text())
        self.assertNotIn(EVIDENCE, result.stdout + result.stderr + report_path.read_text())

    def test_unknown_and_localized_upload_errors_remain_other(self):
        for error in ('The device is not ready.', 'Zugriff verweigert', {'Error': 'bad'}):
            self.assertEqual(validator.upload_error_category(error), 'other')

    def test_row_count_detects_missing_result_stream(self):
        self.context(total_collected_rows=100)
        self.invalid('row count')

    def test_duplicate_zip_members(self):
        self.write(duplicate=True)
        with self.assertRaisesRegex(validator.InvalidCollection, 'duplicate'):
            validator.validate(self.path)

    def test_corrupted_evidence_crc(self):
        self.write()
        data = self.path.read_bytes()
        self.path.write_bytes(data.replace(b'evidence', b'corrupt!', 1))
        with self.assertRaisesRegex(validator.InvalidCollection, 'integrity'):
            validator.validate(self.path)

    def test_cli_report_and_failure_redaction(self):
        self.files['log.json'] = jsonl({'level': 'ERROR', 'message': 'SECRET HOST CONTENT'})
        self.write()
        report = Path(self.temp.name) / 'nested' / 'report.json'
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path), '--report', str(report)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(report.read_text())['valid'])
        self.assertNotIn('SECRET', result.stdout + result.stderr + report.read_text())

    def test_cli_rejects_non_zip(self):
        self.path.write_bytes(b'not a ZIP')
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['valid'])


if __name__ == '__main__':
    unittest.main()
