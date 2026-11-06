#!/usr/bin/env python3
"""Validate a production Windows offline collection without extracting evidence.

The container schema follows Velociraptor vql/tools/collector and reporting.
See https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/.
The report contains counts and fixed diagnostics only, never evidence or log text.
"""
import argparse
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote
import zipfile

TRIAGE = 'Windows.Triage.Targets'
AUTORUNS = 'Windows.Sysinternals.Autoruns'
# These messages can be DEFAULT-level VQL logs. Missing optional targets and
# ordinary warning logs are not fatal; explicit ERROR logs have no exemptions.
FATAL_MESSAGE = re.compile(
    r'(?i)(timeout error:|collection timed out|progress timeout|'
    r'context (?:canceled|cancelled|deadline exceeded)|'
    r'vql (?:parse|syntax) error|panic:|while closing container:)')


class InvalidCollection(ValueError):
    def __init__(self, diagnostic, diagnostics=None):
        super().__init__(diagnostic)
        self.diagnostics = diagnostics or {}


def upload_error_category(error):
    """Classify English Windows/Go errors without returning source text.

    vql/networking/upload.go preserves accessor Open errors in Upload.Error;
    reporting/container.go can also attach errors after a partial copy. These
    categories are diagnostics only: every category still fails validation.
    Unknown/localized errors deliberately remain other.
    """
    message = error.casefold() if isinstance(error, str) else ''
    if any(text in message for text in ('sharing violation', 'used by another process')):
        return 'sharing_violation'
    if any(text in message for text in ('access is denied', 'access denied', 'permission denied')):
        return 'access_denied'
    if any(text in message for text in ('cannot find the file specified',
                                       'cannot find the path specified',
                                       'no such file or directory', 'file does not exist')):
        return 'missing_file'
    return 'other'


def record_upload_error(diagnostics, upload):
    category = upload_error_category(upload.get('Error'))
    summary = diagnostics.setdefault(category, {
        'count': 0, 'stored_name_present': 0, 'nonzero_stored_size': 0,
        'stored_bytes': 0, 'malformed_stored_size': 0})
    summary['count'] += 1
    summary['stored_name_present'] += bool(upload.get('StoredName'))
    size = upload.get('StoredSize', 0)
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        summary['stored_bytes'] += size
        summary['nonzero_stored_size'] += size > 0
    else:
        summary['malformed_stored_size'] += 1


def require(condition, diagnostic):
    if not condition:
        raise InvalidCollection(diagnostic)


def object_json(archive, name):
    try:
        value = json.loads(archive.read(name))
    except (KeyError, UnicodeError, json.JSONDecodeError):
        raise InvalidCollection('missing or malformed collection metadata') from None
    require(isinstance(value, dict) and value, 'collection metadata is not an object')
    return value


def rows(archive, name):
    with archive.open(name) as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except (UnicodeError, json.JSONDecodeError):
                raise InvalidCollection('malformed JSONL in collection') from None
            require(isinstance(row, dict), 'JSONL contains a non-object row')
            yield row


def validate(path):
    """Return a payload-free summary, or raise InvalidCollection."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        unique_names = set(names)
        require(len(names) == len(unique_names), 'duplicate ZIP members')
        require(all(not (info.flag_bits & 1) for info in infos), 'encrypted ZIP member')
        # Reads all members and checks every CRC, including evidence uploads.
        require(archive.testzip() is None, 'ZIP integrity check failed')
        context = object_json(archive, 'collection_context.json')
        client = object_json(archive, 'client_info.json')
        requests = object_json(archive, 'requests.json')
        require(isinstance(client.get('OS'), str) and client['OS'].lower() == 'windows',
                'collection is not from Windows')
        require(context.get('state') in (2, 'FINISHED'), 'collection did not finish successfully')
        require(not context.get('status'), 'collection reports an error status')
        request = context.get('request')
        require(isinstance(request, dict), 'collection request is absent')
        require(isinstance(request.get('artifacts'), list) and
                {TRIAGE, AUTORUNS}.issubset(request['artifacts']),
                'production artifacts were not requested')
        require(isinstance(requests.get('items'), list) and requests['items'],
                'compiled collection requests are absent')
        stats = context.get('query_stats')
        require(isinstance(stats, list) and stats, 'query completion statistics are absent')
        for stat in stats:
            require(isinstance(stat, dict) and stat.get('status', 0) in (0, 'OK') and
                    not stat.get('error_message'), 'query reports an error')

        require('uploads.json' in unique_names, 'upload metadata is absent')
        upload_metadata_rows = sum(1 for _ in rows(archive, 'uploads.json'))
        require(upload_metadata_rows > 0, 'upload metadata is empty')

        require('log.json' in unique_names, 'collection log is absent')
        log_rows = warning_rows = 0
        for row in rows(archive, 'log.json'):
            log_rows += 1
            level = row.get('level')
            message = row.get('message')
            require(isinstance(level, str) and isinstance(message, str),
                    'collection log row is malformed')
            require(level.upper() not in ('ERROR', 'FATAL', 'PANIC') and
                    not FATAL_MESSAGE.search(message), 'collection log reports a fatal error')
            warning_rows += level.upper() in ('WARN', 'WARNING')
        require(log_rows > 0, 'collection log is empty')

        triage_rows = autoruns_rows = result_rows = successful_uploads = 0
        upload_errors = {}
        reference_errors = {'malformed_reference': 0, 'missing_evidence': 0}
        sizes = dict.fromkeys((
            'missing_stored_size', 'missing_size_actual_zero',
            'missing_size_actual_nonzero', 'expected_zero_actual_zero',
            'expected_smaller_than_actual', 'expected_larger_than_actual',
            'malformed_stored_size', 'matching_size', 'with_sparse_index',
            'expected_bytes', 'actual_bytes'), 0)
        for name in names:
            if not name.startswith('results/') or not name.endswith('.json'):
                continue
            artifact = unquote(name[len('results/'):-len('.json')])
            for row in rows(archive, name):
                result_rows += 1
                if artifact == AUTORUNS or artifact.startswith(AUTORUNS + '/'):
                    # Autoruns emits separator rows too; at least one real entry
                    # must have a nonempty Entry and Category, not just headers.
                    if row.get('Entry') and row.get('Category'):
                        autoruns_rows += 1
                if artifact == TRIAGE or artifact.startswith(TRIAGE + '/'):
                    if row:
                        triage_rows += 1
                    upload = row.get('Upload')
                    if not isinstance(upload, dict):
                        continue
                    errored = bool(upload.get('Error'))
                    if errored:
                        record_upload_error(upload_errors, upload)
                    stored_name = upload.get('StoredName')
                    if not stored_name:
                        continue
                    if not isinstance(stored_name, str):
                        reference_errors['malformed_reference'] += 1
                        continue
                    stored_name = stored_name.lstrip('/')
                    if not stored_name.startswith('uploads/') or stored_name not in unique_names:
                        reference_errors['missing_evidence'] += 1
                        continue
                    info = archive.getinfo(stored_name)
                    actual_size = info.file_size
                    sizes['actual_bytes'] += actual_size
                    # UploadResponse.AsDict and its JSON omitempty tag both omit
                    # StoredSize when zero (uploads/api.go). This is valid only
                    # for an empty ZIP member, never for nonempty evidence.
                    missing_size = 'StoredSize' not in upload
                    stored_size = upload.get('StoredSize', 0)
                    if not isinstance(stored_size, int) or isinstance(stored_size, bool) or stored_size < 0:
                        sizes['malformed_stored_size'] += 1
                        continue
                    sizes['expected_bytes'] += stored_size
                    if missing_size:
                        sizes['missing_stored_size'] += 1
                        sizes['missing_size_actual_zero' if actual_size == 0
                              else 'missing_size_actual_nonzero'] += 1
                    elif stored_size == 0 and actual_size == 0:
                        sizes['expected_zero_actual_zero'] += 1
                    if stored_size < actual_size:
                        sizes['expected_smaller_than_actual'] += 1
                    elif stored_size > actual_size:
                        sizes['expected_larger_than_actual'] += 1
                    else:
                        sizes['matching_size'] += 1
                    if stored_name + '.idx' in unique_names:
                        # Sparse containers retain physical bytes in the member;
                        # the .idx maps them back to the logical Upload.Size.
                        # StoredSize must still match physical bytes, exactly.
                        sizes['with_sparse_index'] += 1
                    if not errored and stored_size == actual_size and actual_size > 0 and row.get('SourceFile'):
                        successful_uploads += 1

        diagnostics = {
            'upload_errors': upload_errors, 'upload_sizes': sizes,
            'upload_references': reference_errors, 'result_rows': result_rows,
            'triage_rows': triage_rows, 'autoruns_entries': autoruns_rows,
            'verified_triage_uploads': successful_uploads}
        if upload_errors or any(reference_errors.values()) or any(sizes[key] for key in (
                'malformed_stored_size', 'expected_smaller_than_actual',
                'expected_larger_than_actual')):
            if upload_errors:
                diagnostic = 'triage upload reports an error'
            elif reference_errors['malformed_reference']:
                diagnostic = 'upload reference is malformed'
            elif reference_errors['missing_evidence']:
                diagnostic = 'triage upload references missing evidence'
            else:
                diagnostic = 'triage upload size does not match evidence'
            raise InvalidCollection(diagnostic, diagnostics)
        require(triage_rows > 0, 'triage produced no result rows')
        require(autoruns_rows > 0, 'Autoruns produced no meaningful entries')
        require(successful_uploads > 0, 'triage produced no verified nonempty evidence upload')
        # Upstream collectQuery overwrites query_stats.result_rows for each
        # source in an artifact; total_collected_rows may therefore undercount
        # multi-source artifacts. It must still be positive and plausible.
        total = context.get('total_collected_rows')
        require(isinstance(total, int) and not isinstance(total, bool) and
                0 < total <= result_rows, 'collection row count is invalid')
        return {'valid': True, 'result_rows': result_rows,
                'triage_rows': triage_rows, 'autoruns_entries': autoruns_rows,
                'verified_triage_uploads': successful_uploads,
                'log_rows': log_rows, 'warning_rows': warning_rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        report = validate(args.collection)
    except (InvalidCollection, OSError, zipfile.BadZipFile, RuntimeError, EOFError) as error:
        # Do not expose OS exceptions containing evidence paths or archive data.
        diagnostic = str(error) if isinstance(error, InvalidCollection) else 'cannot read valid collection ZIP'
        report = {'valid': False, 'error': diagnostic}
        if isinstance(error, InvalidCollection) and error.diagnostics:
            report['diagnostics'] = error.diagnostics
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['valid'] else 1


if __name__ == '__main__':
    sys.exit(main())
