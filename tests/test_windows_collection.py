"""Synthetic containers use the upstream collect() JSON/JSONL layout.

Schema references: vql/tools/collector/fixtures/TestCollectionWithUpload.golden,
crypto/proto/jobs.proto (VeloStatus), flows/proto/artifact_collector.proto.
No collector is executed by these tests.
"""
import importlib.util
import hashlib
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

    def directory_fixture(self, error='read SECRET: Incorrect function.', stored_size=None,
                          name='uploads/auto/C%3A/Windows/System32/config/RegBack/', data=b''):
        self.files[name] = data
        upload = {'Error': error, 'StoredName': '/' + name, 'Size': 4096}
        if stored_size is not None:
            upload['StoredSize'] = stored_size
        self.files[TRIAGE_RESULT] += jsonl({
            'SourceFile': r'C:\Windows\System32\config\RegBack',
            'Details': {'Stat': {'IsDir': True}}, 'Upload': upload})
        self.context(total_collected_rows=4)

    def test_exact_error_one_empty_directory_is_reported_and_skipped(self):
        for stored_size in (None, 0):
            with self.subTest(stored_size=stored_size):
                self.files = fixture()
                self.directory_fixture(stored_size=stored_size)
                self.write()
                report = validator.validate(self.path)
                self.assertTrue(report['valid'])
                self.assertEqual(report['verified_triage_uploads'], 1)
                self.assertEqual(report['skipped_directory_uploads'], 1)
                diagnostic = report['skipped_directory_diagnostics']['unsupported']
                self.assertEqual(diagnostic['archive_directories'], 1)
                self.assertEqual(diagnostic['details_stat_is_dir_true'], 1)
                self.assertEqual(diagnostic['source_json_types'], {'string': 1})
                self.assertEqual(diagnostic['stored_target_types'], {'no_extension': 1})
                self.assertEqual(diagnostic['path_families'], {'windows_registry_regback': 1})
                self.assertNotIn('SECRET', json.dumps(report))

    def test_directory_skip_accepts_native_error_one_signature(self):
        self.directory_fixture(error='LOCALIZED SYSTEM MESSAGE')
        self.write()
        with patch.object(validator, 'windows_system_error_messages', return_value={'localized system message': 1}):
            self.assertEqual(validator.validate(self.path)['skipped_directory_uploads'], 1)

    def test_regular_file_error_one_still_fails(self):
        self.directory_fixture(name='uploads/auto/regular-file')
        self.invalid('upload reports an error')

    def test_directory_skip_rejects_wrong_error_or_substring(self):
        for error in ('Access is denied.', 'not supported', 'SECRET Incorrect function. trailing',
                      'SECRET Incorrect function.', 'invalid function'):
            with self.subTest(error=error):
                self.files = fixture()
                self.directory_fixture(error=error)
                self.invalid('upload reports an error')

    def test_directory_skip_rejects_nonzero_or_malformed_size(self):
        for size, data in ((0, b'nonempty'), (4, b''), ('0', b''), (False, b'')):
            with self.subTest(size=size, data=data):
                self.files = fixture()
                self.directory_fixture(stored_size=size, data=data)
                self.invalid('upload reports an error')

    def test_directory_skip_never_replaces_nonempty_evidence(self):
        self.files[TRIAGE_RESULT] = ''
        self.directory_fixture()
        self.invalid('no verified nonempty')

    def test_nonempty_malformed_directory_is_never_verified_file(self):
        self.files[TRIAGE_RESULT] = ''
        self.directory_fixture(error='', stored_size=4, data=b'data')
        self.invalid('no verified nonempty')

    def live_temporary_case(self, source=r'C:\Windows\Temp\SECRET.exe'):
        row = {'SourceFile': source, 'FileSize': 42, 'Upload': {
            'Error': 'CreateFile SECRET: The system cannot find the path specified.'}}
        metadata = {'SourceFile': source, 'Size': 42, 'Type': 'PsList/From_Pslist'}
        self.files[TRIAGE_RESULT] += jsonl(row)
        self.files['results/Windows.Triage.Targets%2FAll_Matches_Metadata.json'] = jsonl(metadata)
        self.write()
        facts = {'collection_sha256': hashlib.sha256(self.path.read_bytes()).hexdigest(),
                 'sources': {source: {'source_type': 'missing', 'source_winerror': 3}}}
        return row, metadata, facts

    def update_live_temporary(self, row, metadata, facts):
        baseline = json.loads(fixture()[TRIAGE_RESULT])
        self.files[TRIAGE_RESULT] = jsonl(baseline, row)
        name = 'results/Windows.Triage.Targets%2FAll_Matches_Metadata.json'
        if metadata is None:
            self.files.pop(name, None)
        else:
            self.files[name] = jsonl(metadata)
        self.write()
        facts['collection_sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_windows_temporary_path_scopes_are_local_and_canonical(self):
        for source, scope in ((r'C:\Windows\Temp\SECRET.exe', 'windows_temp'),
                              (r'D:\Users\runneradmin\AppData\Local\Temp\SECRET.dat', 'user_temp'),
                              (r'D:\a\_temp\SECRET.exe', 'github_runner_temp')):
            self.assertEqual(validator.windows_temp_scope(source), scope)
        for source in (r'D:\Windows\Temp\SECRET.exe', r'C:Windows\Temp\SECRET.exe',
                       r'\\server\share\Temp\SECRET.exe', r'\\?\C:\Windows\Temp\SECRET.exe',
                       r'\\.\C:\Windows\Temp\SECRET.exe', r'C:\Windows\Temp\SECRET.exe:stream',
                       r'C:\Windows\Temp\..\SECRET.exe', r'C:\Windows\Temp\.\SECRET.exe',
                       r'C:\Windows\Temp\SECRET.exe.', r'C:\Windows\Temp\SECRET.exe ',
                       r'C:\Windows\Temporary\SECRET.exe', r'C:\Windows\System32\SECRET.exe',
                       r'D:\a\_tempx\SECRET.exe', r'C:\Users\x\Temp\SECRET.exe'):
            self.assertIsNone(validator.windows_temp_scope(source), source)

    def test_each_confirmed_windows_temp_scope_is_reported(self):
        for source, scope in ((r'C:\Windows\Temp\SECRET.exe', 'windows_temp'),
                              (r'D:\Users\runneradmin\AppData\Local\Temp\SECRET.exe', 'user_temp'),
                              (r'D:\a\_temp\SECRET.exe', 'github_runner_temp')):
            self.files = fixture()
            row, metadata, facts = self.live_temporary_case(source)
            with self.assertRaises(validator.InvalidCollection):
                validator.validate(self.path)
            report = validator.validate(self.path, facts)
            self.assertEqual(report['vanished_temporary_targets'][scope], 1)
            self.assertTrue(report['live_source_facts_used'])
            self.assertEqual(report['verified_triage_uploads'], 1)
            self.assertNotIn('SECRET', json.dumps(report))

    def test_windows_live_facts_require_exact_collection_hash(self):
        row, metadata, facts = self.live_temporary_case()
        for invalid in ({}, {'sources': {}, 'collection_sha256': 'SECRET'},
                        {'sources': {}, 'collection_sha256': '0' * 64}):
            with self.assertRaisesRegex(validator.InvalidCollection, 'live source facts'):
                validator.validate(self.path, invalid)

    def test_windows_temp_snapshot_must_confirm_missing_with_winerror_two_or_three(self):
        for change in ({'source_type': 'existing'}, {'source_type': 'other'},
                       {'source_winerror': 5}, {'source_winerror': None},
                       {'source_winerror': True}, {'source_winerror': 3.0}, {'source_size': 0}):
            self.files = fixture()
            row, metadata, facts = self.live_temporary_case()
            facts['sources'][row['SourceFile']].update(change)
            with self.assertRaises(validator.InvalidCollection):
                validator.validate(self.path, facts)
        self.files = fixture()
        row, metadata, facts = self.live_temporary_case()
        facts['sources'][row['SourceFile']]['source_winerror'] = 2
        row['Upload']['Error'] = 'CreateFile SECRET: The system cannot find the file specified.'
        self.update_live_temporary(row, metadata, facts)
        self.assertTrue(validator.validate(self.path, facts)['valid'])

    def test_windows_temporary_original_metadata_must_match_positive_size(self):
        for change in (None, {'SourceFile': 'OTHER'}, {'Size': 41}, {'Size': 0}, {'Size': True}, {'Size': '42'}):
            self.files = fixture()
            row, metadata, facts = self.live_temporary_case()
            metadata = None if change is None else {**metadata, **change}
            self.update_live_temporary(row, metadata, facts)
            with self.assertRaises(validator.InvalidCollection):
                validator.validate(self.path, facts)

    def test_windows_temp_rejects_other_errors_and_any_output(self):
        for change in ({'Error': 'Access is denied.'}, {'Error': 'Incorrect function.'},
                       {'Error': 'SECRET The system cannot find the path specified.'},
                       {'StoredName': ''}, {'StoredName': '/' + EVIDENCE},
                       {'StoredSize': 0}, {'StoredSize': 42}):
            self.files = fixture()
            row, metadata, facts = self.live_temporary_case()
            row['Upload'].update(change)
            self.update_live_temporary(row, metadata, facts)
            with self.assertRaises(validator.InvalidCollection):
                validator.validate(self.path, facts)

    def test_windows_missing_source_outside_temp_remains_fatal(self):
        self.files = fixture()
        row, metadata, facts = self.live_temporary_case(r'C:\Windows\System32\SECRET.exe')
        with self.assertRaises(validator.InvalidCollection) as failure:
            validator.validate(self.path, facts)
        diagnostic = failure.exception.diagnostics
        categories = diagnostic['upload_errors']
        self.assertEqual(next(iter(categories.values()))['windows_temp_scopes'], {'outside': 1})

    def test_windows_temp_skips_do_not_satisfy_real_evidence(self):
        row, metadata, facts = self.live_temporary_case()
        self.files[TRIAGE_RESULT] = jsonl(row)
        self.write()
        facts['collection_sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(validator.InvalidCollection, 'no verified nonempty'):
            validator.validate(self.path, facts)

    def test_windows_live_facts_cli_is_explicit_and_redacted(self):
        row, metadata, facts = self.live_temporary_case()
        facts_path = Path(self.temp.name) / 'facts.json'
        facts_path.write_text(json.dumps(facts))
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path),
                                 '--live-source-facts', str(facts_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)['valid'])
        self.assertNotIn('SECRET', result.stdout + result.stderr)
        facts_path.write_text('SECRET malformed')
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path),
                                 '--live-source-facts', str(facts_path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('SECRET', result.stdout + result.stderr)

    def test_windows_temp_scope_rejects_dos_devices_and_invalid_characters(self):
        for basename in ('NUL.exe', 'CON', 'PRN.txt', 'AUX', 'COM1.exe', 'LPT9',
                         'COM¹', 'CONIN$', 'CONOUT$', 'CLOCK$', 'bad?.exe',
                         'bad*.exe', 'bad|name', 'bad<name', 'bad>name', 'bad"name', 'bad\nname'):
            self.assertIsNone(validator.windows_temp_scope('C:\\Windows\\Temp\\' + basename))

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
