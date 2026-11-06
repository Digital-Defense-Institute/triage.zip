"""Faithful synthetic Linux.Triage.UAC containers; no host workload runs here."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/validate_linux_collection.py'
SPEC = importlib.util.spec_from_file_location('linux_validator', SCRIPT)
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)
TRIAGE = validator.TRIAGE
SEARCH = 'results/Linux.Triage.UAC%2FSearchGlobs.json'
METADATA = 'results/Linux.Triage.UAC%2FAll Matches Metadata.json'
UPLOADS = 'results/Linux.Triage.UAC%2FUploads.json'
EVIDENCE = 'uploads/auto/etc/passwd'
PASSWD = b'root:x:0:0:root:/root:/bin/bash\n'


def jsonl(*items):
    return ''.join(json.dumps(item) + '\n' for item in items)


def fixture():
    return {
        'collection_context.json': json.dumps({
            'state': 2, 'request': {'artifacts': [TRIAGE], 'specs': [{
                'artifact': TRIAGE, 'parameters': {'env': [{'key': 'Targets', 'value': '["_All"]'}]}}]},
            'query_stats': [{'result_rows': 1}], 'total_collected_rows': 1}),
        'client_info.json': '{"OS":"linux","Hostname":"SECRET"}',
        'requests.json': '{"items":[{"VQLClientAction":{"Query":[]}}]}',
        'log.json': jsonl({'level': 'INFO', 'message': 'Collection finished'}),
        'uploads.json': jsonl({'_Components': ['uploads', 'auto', 'etc', 'passwd'],
                              'uploaded_size': len(PASSWD)}),
        SEARCH: jsonl({'Rule': 'Etc/', 'Glob': '/etc'}),
        METADATA: jsonl({'Type': 'Glob', 'SourceFile': '/etc/passwd', 'Size': len(PASSWD)}),
        UPLOADS: jsonl({'SourceFile': '/etc/passwd', 'FileSize': len(PASSWD), 'Upload': {
            'StoredName': '/' + EVIDENCE, 'StoredSize': len(PASSWD), 'Size': len(PASSWD)}}),
        EVIDENCE: PASSWD,
    }


class LinuxCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'collection.zip'
        self.files = fixture()

    def write(self):
        with zipfile.ZipFile(self.path, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, data in self.files.items():
                archive.writestr(name, data)

    def context(self, **updates):
        value = json.loads(self.files['collection_context.json'])
        value.update(updates)
        self.files['collection_context.json'] = json.dumps(value)

    def upload(self, **updates):
        row = json.loads(self.files[UPLOADS])
        row['Upload'].update(updates)
        self.files[UPLOADS] = jsonl(row)

    def invalid(self, diagnostic):
        self.write()
        with self.assertRaisesRegex(validator.InvalidCollection, diagnostic):
            validator.validate(self.path)

    def test_valid_real_uac_schema(self):
        self.write()
        report = validator.validate(self.path)
        self.assertTrue(report['valid'])
        self.assertEqual(report['verified_system_baselines'], ['passwd_uid_zero'])
        self.assertEqual(report['verified_uac_uploads'], 1)
        self.assertNotIn('root:x', json.dumps(report))
        self.assertNotIn('SECRET', json.dumps(report))

    def test_os_release_baseline(self):
        for source in ('/etc/os-release', '/usr/lib/os-release'):
            with self.subTest(source=source):
                self.files = fixture()
                content = b'NAME="Fixture OS"\nID=ubuntu\n'
                self.files[EVIDENCE] = content
                self.files[UPLOADS] = jsonl({'SourceFile': source, 'Upload': {
                    'StoredName': '/' + EVIDENCE, 'StoredSize': len(content)}})
                self.write()
                self.assertEqual(validator.validate(self.path)['verified_system_baselines'], ['os_release_id'])

    def test_baseline_requires_meaningful_content(self):
        for content in (b'arbitrary evidence', b'root:x:notUID:0::/root:/bin/bash\n'):
            with self.subTest(content=content):
                self.files[EVIDENCE] = content
                self.upload(StoredSize=len(content))
                self.invalid('meaningful system baseline')

    def test_missing_metadata_and_wrong_os(self):
        del self.files['collection_context.json']
        self.invalid('metadata')
        self.files = fixture()
        self.files['client_info.json'] = '{"OS":"windows"}'
        self.invalid('not from Linux')

    def test_incomplete_and_query_error(self):
        self.context(state=4)
        self.invalid('did not finish')
        self.context(state=2, query_stats=[{'status': 10, 'error_message': 'SECRET'}])
        self.invalid('query reports an error')

    def test_production_artifact_required(self):
        self.context(request={'artifacts': ['Other']})
        self.invalid('production artifacts')

    def test_all_parameter_required_and_unambiguous(self):
        for targets in ('[]', '["Etc"]', '"_All"', 'not-json'):
            with self.subTest(targets=targets):
                self.files = fixture()
                context = json.loads(self.files['collection_context.json'])
                context['request']['specs'][0]['parameters']['env'][0]['value'] = targets
                self.context(request=context['request'])
                self.invalid('production UAC')
        self.files = fixture()
        context = json.loads(self.files['collection_context.json'])
        context['request']['specs'][0]['parameters']['env'].append({'key': 'Targets', 'value': '["_All"]'})
        self.context(request=context['request'])
        self.invalid('ambiguous')

    def test_targets_missing_spec_or_env(self):
        for specs in (None, [], [{'artifact': TRIAGE}], [{'artifact': TRIAGE, 'parameters': {}}]):
            with self.subTest(specs=specs):
                self.files = fixture()
                self.context(request={'artifacts': [TRIAGE], 'specs': specs})
                self.invalid('production UAC')

    def test_requires_meaningful_rules_and_metadata(self):
        self.files[SEARCH] = jsonl({'Rule': '', 'Glob': ''})
        self.invalid('meaningful target rules')
        self.files = fixture()
        self.files[METADATA] = jsonl({'SourceFile': None})
        self.invalid('meaningful file metadata')

    def test_error_log_and_default_timeout_are_fatal(self):
        for level, message in (('ERROR', 'SECRET'), ('DEFAULT', 'Timeout Error: timed out')):
            with self.subTest(level=level):
                self.files['log.json'] = jsonl({'level': level, 'message': message})
                self.invalid('fatal error')

    def test_results_and_upload_metadata_are_all_jsonl(self):
        for name in ('results/Other.json', 'uploads.json'):
            with self.subTest(name=name):
                self.files = fixture()
                self.files[name] = '{}\nSECRET malformed'
                self.invalid('JSONL')

    def test_partial_and_regular_file_errors_remain_fatal(self):
        for error in ('input/output error', 'read SECRET: is a directory', 'no such file or directory'):
            with self.subTest(error=error):
                self.files = fixture()
                self.upload(Error=error)
                self.invalid('upload validation failed')

    def test_missing_and_size_mismatched_evidence(self):
        del self.files[EVIDENCE]
        self.invalid('upload validation failed')
        self.files = fixture()
        self.upload(StoredSize=4)
        self.invalid('upload validation failed')

    def test_empty_omitted_stored_size_does_not_count(self):
        self.files[EVIDENCE] = b''
        self.files[UPLOADS] = jsonl({'SourceFile': '/etc/passwd', 'Upload': {'StoredName': '/' + EVIDENCE}})
        self.invalid('no verified nonempty')

    def test_sparse_stored_physical_size_is_checked(self):
        self.upload(Size=100000)
        self.files[EVIDENCE + '.idx'] = '{"ranges":[]}'
        self.write()
        self.assertTrue(validator.validate(self.path)['valid'])
        self.upload(StoredSize=100000)
        self.invalid('upload validation failed')

    def test_duplicate_members_and_crc_corruption(self):
        self.write()
        with zipfile.ZipFile(self.path, 'a') as archive:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                archive.writestr('log.json', self.files['log.json'])
        with self.assertRaisesRegex(validator.InvalidCollection, 'duplicate'):
            validator.validate(self.path)
        self.write()
        self.path.write_bytes(self.path.read_bytes().replace(PASSWD, b'x' * len(PASSWD)))
        with self.assertRaisesRegex(validator.InvalidCollection, 'integrity'):
            validator.validate(self.path)

    def directory(self, error='read SECRET: is a directory', size=None, data=b'', name='uploads/auto/etc/directory/'):
        self.files[name] = data
        upload = {'StoredName': '/' + name, 'Size': 4096, 'Error': error}
        if size is not None:
            upload['StoredSize'] = size
        self.files[UPLOADS] += jsonl({'SourceFile': '/etc/directory', 'Upload': upload})

    def test_empty_directory_eisdir_is_reported(self):
        self.directory()
        self.write()
        report = validator.validate(self.path)
        self.assertEqual(report['skipped_directory_uploads'], 1)
        self.assertEqual(report['verified_uac_uploads'], 1)

    def test_directory_exception_is_narrow(self):
        for kwargs in ({'error': 'permission denied'}, {'error': 'SECRET is a directory'},
                       {'size': '0'}, {'size': False}, {'size': 4}, {'data': b'not empty'}):
            with self.subTest(kwargs=kwargs):
                self.files = fixture()
                self.directory(**kwargs)
                self.invalid('upload validation failed')

    def test_directory_alone_cannot_satisfy_evidence(self):
        self.files[UPLOADS] = ''
        self.directory()
        self.invalid('no verified nonempty')

    def test_cli_failure_report_is_redacted(self):
        self.upload(Error='SECRET unknown failure')
        self.write()
        report = Path(self.temp.name) / 'nested' / 'report.json'
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path), '--report', str(report)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        data = json.loads(report.read_text())
        self.assertFalse(data['valid'])
        self.assertEqual(data['diagnostics']['upload_errors']['other']['count'], 1)
        self.assertNotIn('SECRET', report.read_text() + result.stdout + result.stderr)
        self.assertNotIn('root:x', report.read_text())

    def test_cli_non_zip_is_safe_failure(self):
        self.path.write_bytes(b'SECRET')
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)['valid'])
        self.assertNotIn('SECRET', result.stdout + result.stderr)

    def test_posix_errno_signatures_are_fixed_identifiers(self):
        messages = {'no such file or directory': 'ENOENT', 'is a directory': 'EISDIR',
                    'permission denied': 'EACCES', 'too many levels of symbolic links': 'ELOOP'}
        with patch.object(validator, 'posix_error_messages', return_value=messages):
            for message, code in messages.items():
                self.assertEqual(validator.error_category('open SECRET: ' + message), 'errno_' + code)
            self.assertEqual(validator.error_category('SECRET unknown message'), 'other')
        self.assertEqual(validator.error_category('Only regular files supported (not /SECRET)'), 'non_regular_file')

    def test_symlink_error_diagnostics_are_correlated_and_redacted(self):
        self.files[METADATA] += jsonl({'SourceFile': '/etc/SECRET', 'Size': 9, 'Accessor': 'auto'})
        self.files[UPLOADS] += jsonl({'SourceFile': '/etc/SECRET', 'Details': {'Stat': {
            'Mode': 1 << 27, 'ModeStr': 'Lrwxrwxrwx', 'Data': {'Link': '/dev/null'}}},
            'Upload': {'Error': 'Only regular files supported (not /SECRET)'}})
        self.write()
        with self.assertRaises(validator.InvalidCollection) as error:
            validator.validate(self.path)
        diagnostic = error.exception.diagnostics['upload_errors']['non_regular_file']
        self.assertEqual(diagnostic['metadata_join'], {'matched': 1})
        self.assertEqual(diagnostic['detail_file_shapes'], {'symlink': 1})
        self.assertEqual(diagnostic['metadata_file_shapes'], {'unknown': 1})
        self.assertEqual(diagnostic['detail_mode_types'], {'number': 1})
        self.assertEqual(diagnostic['source_families'], {'etc': 1})
        self.assertEqual(diagnostic['link_target_shapes'], {'absolute': 1})
        self.assertEqual(diagnostic['fixed_link_targets'], {'dev_null': 1})
        self.assertNotIn('SECRET', json.dumps(diagnostic))
        self.assertNotIn('/dev/null', json.dumps(diagnostic))

    def test_file_shape_supports_go_mode_and_modestr(self):
        for stat, expected in (({'Mode': 1 << 31}, 'directory'),
                               ({'Mode': 1 << 25}, 'fifo'), ({'Mode': 1 << 24}, 'socket'),
                               ({'Mode': 420}, 'regular_file'),
                               ({'ModeStr': 'Lrwxrwxrwx'}, 'symlink'),
                               ({'Data': {'Link': '../SECRET'}}, 'symlink')):
            self.assertEqual(validator.file_shape(stat), expected)

    def test_row_count_must_be_positive_and_plausible(self):
        for value in (0, 100000, '1', True):
            with self.subTest(value=value):
                self.context(total_collected_rows=value)
                self.invalid('row count')


if __name__ == '__main__':
    unittest.main()
