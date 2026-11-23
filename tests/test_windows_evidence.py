"""Feature-level regressions use synthetic ZIPs, never host evidence."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import quote
import zipfile

from test_windows_collection import fixture, jsonl, validator

E = validator._evidence
STREAM = r'\\.\C:\Users\Public\synthetic.bin:Zone.Identifier'
BODY = b'[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/\r\n'
COMPONENTS = ['uploads', 'ntfs', r'\\.\C:', 'Users', 'Public', 'synthetic.bin:Zone.Identifier']
MEMBER = '/'.join(quote(x, safe='') for x in COMPONENTS)
META = 'results/Generic.Collectors.File%2FAll Matches Metadata.json'
UPLOAD = 'results/Generic.Collectors.File%2FUploads.json'


def features():
    files = fixture()
    context = json.loads(files['collection_context.json'])
    context['request']['artifacts'] += list(E.PARSERS) + [E.MOTW]
    files['collection_context.json'] = json.dumps(context)
    parser_rows = {
        E.PARSERS[0] + '/Network Usage': {'App': 'synthetic.exe', 'TimeStamp': '2026-01-01T00:00:00Z', 'BytesSent': 5, 'BytesRecvd': 3},
        E.PARSERS[1]: {'Binary': 'synthetic.exe', 'Bam_time': '2026-01-01T00:00:00Z', 'SID': 'S-1-5-21-1'},
        E.PARSERS[2]: {'Name': 'synthetic.exe', 'User': 'synthetic', 'LastExecution': '', 'NumberOfExecutions': 1},
        E.PARSERS[3]: {'Path': 'synthetic.exe', 'ModificationTime': '2026-01-01T00:00:00Z'},
        E.PARSERS[4] + '/InventoryApplicationFile': {'FullPath': 'synthetic.exe', 'Timestamp': '2026-01-01T00:00:00Z'},
    }
    for source, row in parser_rows.items():
        files['results/' + quote(source, safe='.') + '.json'] = jsonl(row)
    times = {name: '2026-01-01T00:00:00Z' for name in ('Created', 'Changed', 'Modified', 'LastAccessed')}
    files[META] = jsonl({'SourceFile': STREAM, 'Size': len(BODY), **times})
    files[UPLOAD] = jsonl({'SourceFile': STREAM, 'DestinationFile': STREAM,
                          'FileSize': len(BODY), 'SourceFileSha256': hashlib.sha256(BODY).hexdigest(), **times})
    files['uploads.json'] += jsonl({'vfs_path': STREAM, '_Components': COMPONENTS,
                                    'file_size': len(BODY), 'uploaded_size': len(BODY), 'Type': ''})
    files[MEMBER] = BODY
    return files


class WindowsEvidenceTests(unittest.TestCase):
    def validate(self, files, seeds=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'synthetic.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                for name, data in files.items():
                    archive.writestr(name, data)
            return validator.validate(path, windows_evidence=True, seed_manifest=seeds)

    def invalid(self, files, message):
        with self.assertRaisesRegex(validator.InvalidCollection, message):
            self.validate(files)

    def test_resolves_source_path_through_upload_metadata_and_escaped_member(self):
        report = self.validate(features())
        self.assertEqual(report['verified_motw_streams'], 1)
        self.assertEqual(report['srum_network_usage_rows'], 1)
        self.assertTrue(all(report['parser_meaningful_rows'].values()))
        text = json.dumps(report)
        for private in ('synthetic.exe', 'Public', 'HostUrl', 'S-1-5-21', 'example.invalid'):
            self.assertNotIn(private, text)

    def test_missing_new_artifacts_cannot_pass_the_feature_gate(self):
        self.invalid(fixture(), 'not requested')

    def test_requested_but_absent_parser_results_cannot_pass(self):
        files = features()
        del files['results/' + E.PARSERS[1] + '.json']
        self.invalid(files, 'no meaningful')

    def test_missing_and_partial_stream_evidence_fail(self):
        for body in (None, BODY[:-1]):
            files = features()
            if body is None:
                del files[MEMBER]
            else:
                files[MEMBER] = body
            self.invalid(files, 'missing evidence|size differs')

    def test_corrupted_same_size_stream_fails_hash(self):
        files = features()
        files[MEMBER] = b'x' * len(BODY)
        self.invalid(files, 'hash differs')

    def test_missing_upload_record_or_result_fails(self):
        files = features()
        files['uploads.json'] = fixture()['uploads.json']
        self.invalid(files, 'missing evidence')
        files = features()
        del files[UPLOAD]
        self.invalid(files, 'sources differ')

    def test_upload_record_sizes_and_projected_source_are_bound(self):
        files = features()
        files['uploads.json'] = files['uploads.json'].replace('"uploaded_size": ' + str(len(BODY)), '"uploaded_size": 0')
        self.invalid(files, 'size differs')
        files = features()
        row = json.loads(files[UPLOAD])
        row['DestinationFile'] = 'different-source'
        files[UPLOAD] = jsonl(row)
        self.invalid(files, 'source differs')

    def test_schema_and_network_counter_failures(self):
        name = 'results/' + quote(E.PARSERS[0] + '/Network Usage', safe='.') + '.json'
        for counter in (None, -1, '5', True):
            files = features()
            row = json.loads(files[name])
            row['BytesSent'] = counter
            files[name] = jsonl(row)
            self.invalid(files, 'counters')
        files = features()
        files[name] = jsonl({'App': 'synthetic'})
        self.invalid(files, 'schema')

    def test_timestamp_mismatch_and_duplicate_sources_fail(self):
        files = features()
        row = json.loads(files[UPLOAD])
        row['Modified'] = '2026-01-02T00:00:00Z'
        files[UPLOAD] = jsonl(row)
        self.invalid(files, 'timestamps differ')
        files = features()
        files[META] += files[META]
        self.invalid(files, 'duplicate MOTW')

    def test_parser_timestamp_and_execution_count_are_checked(self):
        files = features()
        name = 'results/' + E.PARSERS[1] + '.json'
        row = json.loads(files[name]); row['Bam_time'] = 'not a timestamp'
        files[name] = jsonl(row)
        self.invalid(files, 'timestamp is malformed')
        files = features()
        name = 'results/' + E.PARSERS[2] + '.json'
        row = json.loads(files[name]); row['NumberOfExecutions'] = -1
        files[name] = jsonl(row)
        self.invalid(files, 'execution count')

    def test_known_positive_and_negative_seeds_are_enforced(self):
        seeds = {'version': 1, 'streams': [
            {'path': STREAM.removeprefix('\\\\.\\'), 'include': True, 'size': len(BODY), 'sha256': hashlib.sha256(BODY).hexdigest(), 'modified': '2026-01-01T00:00:00Z'},
            {'path': r'D:\Redirected\synthetic.bin:Zone.Identifier', 'include': False, 'size': len(BODY), 'sha256': hashlib.sha256(BODY).hexdigest()},
        ]}
        self.assertEqual(self.validate(features(), seeds)['motw_seed_counts'], {'included': 1, 'excluded': 1})
        missing = copy.deepcopy(seeds)
        missing['streams'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(validator.InvalidCollection, 'not preserved'):
            self.validate(features(), missing)
        wrong_time = copy.deepcopy(seeds)
        wrong_time['streams'][0]['modified'] = '2026-01-02T00:00:00Z'
        with self.assertRaisesRegex(validator.InvalidCollection, 'timestamp differs'):
            self.validate(features(), wrong_time)
        forbidden = copy.deepcopy(seeds)
        forbidden['streams'][0]['include'] = False
        with self.assertRaisesRegex(validator.InvalidCollection, 'out-of-scope'):
            self.validate(features(), forbidden)

    def test_empty_stream_is_real_evidence(self):
        files = features()
        files[MEMBER] = b''
        for name, size_key in ((META, 'Size'), (UPLOAD, 'FileSize')):
            row = json.loads(files[name]); row[size_key] = 0
            if name == UPLOAD:
                row['SourceFileSha256'] = hashlib.sha256(b'').hexdigest()
            files[name] = jsonl(row)
        files['uploads.json'] = fixture()['uploads.json'] + jsonl({
            'vfs_path': STREAM, '_Components': COMPONENTS, 'file_size': 0, 'uploaded_size': 0, 'Type': ''})
        self.assertEqual(self.validate(files)['verified_motw_bytes'], 0)

    def test_feature_gate_is_required_in_production_workflow(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn('-QualifyWindowsEvidence', (root / '.github/workflows/ci.yml').read_text())
        runner = (root / 'scripts/run_windows_collection.ps1').read_text()
        self.assertIn("$validatorArgs += '--windows-evidence'", runner)
        self.assertIn('-ValidateWindowsEvidence -MotwSeeds $manifest',
                      (root / 'scripts/qualify_windows_collection.ps1').read_text())
