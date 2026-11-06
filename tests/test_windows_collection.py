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
from unittest.mock import MagicMock, patch
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
        # Keep English category fixtures deterministic on Windows too; native
        # lookup behavior is separately tested with controlled system messages.
        self.native_lookup = validator.windows_system_error_messages
        native_messages = patch.object(validator, 'windows_system_error_messages', return_value={})
        native_messages.start()
        self.addCleanup(native_messages.stop)
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
        self.assertFalse(json.loads(report_path.read_text())['valid'])
        # The subprocess correctly uses native Windows numeric signatures.
        # Test portable English aggregation under the controlled lookup mock.
        with self.assertRaises(validator.InvalidCollection) as failure:
            validator.validate(self.path)
        report = {'diagnostics': failure.exception.diagnostics}
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
        for error in ('Unrecognized failure.', 'Zugriff verweigert', {'Error': 'bad'}):
            self.assertEqual(validator.upload_error_category(error), 'other')

    def test_omitted_zero_stored_size_matches_upstream(self):
        self.files['uploads/auto/empty'] = b''
        self.files[TRIAGE_RESULT] += jsonl({'SourceFile': 'empty', 'Upload': {
            'StoredName': '/uploads/auto/empty', 'Size': 0}})
        self.context(total_collected_rows=4)
        self.write()
        report = validator.validate(self.path)
        self.assertTrue(report['valid'])
        self.assertEqual(report['verified_triage_uploads'], 1)

    def test_sparse_physical_size_can_differ_from_logical(self):
        self.files[TRIAGE_RESULT] = jsonl({'SourceFile': 'sparse', 'Upload': {
            'StoredName': '/' + EVIDENCE, 'StoredSize': 8, 'Size': 100000}})
        self.files[EVIDENCE + '.idx'] = json.dumps({'ranges': [
            {'file_offset': 0, 'original_offset': 0, 'file_length': 8, 'length': 8},
            {'file_offset': 8, 'original_offset': 8, 'file_length': 0, 'length': 99992}]})
        self.write()
        self.assertTrue(validator.validate(self.path)['valid'])

    def test_mixed_upload_failures_all_survive_size_mismatch(self):
        rows = [
            {'StoredName': '/' + EVIDENCE},
            {'StoredName': '/' + EVIDENCE, 'StoredSize': 4},
            {'StoredName': '/' + EVIDENCE, 'StoredSize': 12},
            {'StoredName': '/' + EVIDENCE, 'StoredSize': 'bad'},
            {'StoredName': '/uploads/missing', 'StoredSize': 10},
            {'Error': 'Access is denied.'},
            {'Error': 'partial', 'StoredName': '/' + EVIDENCE, 'StoredSize': 8},
        ]
        self.files[TRIAGE_RESULT] += jsonl(*({'SourceFile': 'SECRET', 'Upload': row} for row in rows))
        self.write()
        with self.assertRaises(validator.InvalidCollection) as failure:
            validator.validate(self.path)
        diagnostic = failure.exception.diagnostics
        self.assertEqual(diagnostic['upload_errors']['access_denied']['count'], 1)
        self.assertEqual(diagnostic['upload_errors']['other']['count'], 1)
        self.assertEqual(diagnostic['upload_references']['missing_evidence'], 1)
        sizes = diagnostic['upload_sizes']
        self.assertEqual(sizes['missing_stored_size'], 1)
        self.assertEqual(sizes['missing_size_actual_nonzero'], 1)
        self.assertEqual(sizes['expected_smaller_than_actual'], 2)
        self.assertEqual(sizes['expected_larger_than_actual'], 1)
        self.assertEqual(sizes['malformed_stored_size'], 1)
        self.assertEqual(diagnostic['verified_triage_uploads'], 1)
        self.assertNotIn('SECRET', json.dumps(diagnostic))

    def test_fixed_upload_error_signatures(self):
        cases = {
            'unexpected EOF': 'unexpected_eof', 'EOF': 'eof',
            'The parameter is incorrect.': 'invalid_parameter',
            'read SECRET: bad file descriptor': 'invalid_handle',
            'SECRET is a directory': 'directory',
            'Not supported': 'unsupported', 'No NTFS Magic': 'ntfs_format',
            'File not found': 'missing_file', 'Not found': 'missing_file',
            'attribute not found': 'ntfs_attribute',
            'LZNT1 decompression error': 'ntfs_compression',
            'The device is not ready.': 'device_read',
            'A disk read fault occurred': 'read_fault',
            'seek: The system cannot move the file pointer': 'seek_error',
            'not enough memory': 'resource_exhausted',
        }
        for error, category in cases.items():
            with self.subTest(error=error):
                self.assertEqual(validator.upload_error_category(error), category)

    def test_error_diagnostics_use_only_fixed_path_families(self):
        for source, target in ((r'\\.\C:\$BadClus:$Bad', 'ntfs_badclus'),
                               (r'\\.\C:\$Extend\$UsnJrnl:$J', 'ntfs_usnjrnl'),
                               (r'C:\SECRET\private.evtx', 'extension_evtx'),
                               (r'C:\SECRET\private.UNKNOWN', 'other')):
            with self.subTest(source=source):
                self.files = fixture()
                self.files['uploads/ntfs/system'] = b''
                self.files[TRIAGE_RESULT] += jsonl({'SourceFile': source, 'Upload': {
                    'Error': 'unexpected EOF SECRET', 'StoredName': '/uploads/ntfs/system', 'Size': 500}})
                self.write()
                with self.assertRaises(validator.InvalidCollection) as failure:
                    validator.validate(self.path)
                diagnostic = failure.exception.diagnostics
                summary = diagnostic['upload_errors']['unexpected_eof']
                self.assertEqual(summary['target_types'], {target: 1})
                self.assertEqual(summary['accessors'], {'ntfs': 1})
                self.assertEqual(summary['archive_member_present'], 1)
                self.assertEqual(summary['archive_bytes'], 0)
                self.assertEqual(summary['logical_bytes'], 500)
                self.assertEqual(summary['logical_size_positive'], 1)
                self.assertNotIn('SECRET', json.dumps(diagnostic))
                self.assertNotIn('private', json.dumps(diagnostic))

    def test_native_lookup_uses_format_message_and_caches(self):
        import ctypes
        kernel = MagicMock()
        def format_message(flags, source, code, language, buffer, length, arguments):
            self.assertEqual(flags, 0x1200)
            self.assertIsNone(source)
            self.assertIsNone(arguments)
            buffer.value = {1: 'Incorrect function.\r\n', 87: 'The parameter is incorrect.\r\n'}[code]
            return len(buffer.value)
        kernel.FormatMessageW.side_effect = format_message
        self.native_lookup.cache_clear()
        self.addCleanup(self.native_lookup.cache_clear)
        with patch.object(validator.os, 'name', 'nt'), \
             patch.object(ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(validator, 'range', return_value=(1, 87), create=True):
            first = self.native_lookup()
            second = self.native_lookup()
        self.assertEqual(first, {'incorrect function': 1, 'the parameter is incorrect': 87})
        self.assertIs(first, second)
        self.assertEqual(kernel.FormatMessageW.call_count, 2)

    def test_native_win32_error_signatures_are_numeric_and_redacted(self):
        messages = {
            'incorrect function': 1,
            'the parameter is incorrect': 87,
            'the request is not supported': 50,
        }
        with patch.object(validator, 'windows_system_error_messages', return_value=messages):
            self.assertEqual(validator.upload_error_category('read SECRET: Incorrect function.'), 'win32_error_1')
            self.assertEqual(validator.upload_error_category('The parameter is incorrect.\r\n'), 'win32_error_87')
            self.assertEqual(validator.upload_error_category('SECRET: The request is not supported.'), 'win32_error_50')
            self.assertEqual(validator.upload_error_category('SECRET incorrect function trailing'), 'unsupported')
            diagnostic = {}
            validator.record_upload_error(diagnostic, {'Error': 'read SECRET: Incorrect function.'})
            self.assertEqual(diagnostic['win32_error_1']['error_tokens'], {'read': 1, 'incorrect': 1, 'function': 1})
            self.assertNotIn('SECRET', json.dumps(diagnostic))

    def test_unknown_error_vocabulary_is_finite(self):
        diagnostic = {}
        validator.record_upload_error(diagnostic, {'Error': 'SECRET CUSTOMTOKEN read buffer closed volume'})
        self.assertEqual(diagnostic['other']['error_tokens'], {'read': 1, 'buffer': 1, 'closed': 1, 'volume': 1})
        self.assertNotIn('secret', json.dumps(diagnostic))
        self.assertNotIn('customtoken', json.dumps(diagnostic))

    def test_additional_forensic_extensions_are_fixed(self):
        for extension in ('blf', 'etl', 'regtrans-ms', 'hve', 'log1', 'log2', 'jfm', 'automaticdestinations-ms', 'edb'):
            self.assertEqual(validator.upload_target_type('SECRET.' + extension), 'extension_' + extension)

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
