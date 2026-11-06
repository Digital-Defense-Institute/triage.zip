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
    pass


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
                    require(not upload.get('Error'), 'triage upload reports an error')
                    if not upload.get('StoredName'):
                        continue
                    stored_name = upload['StoredName']
                    require(isinstance(stored_name, str), 'upload reference is malformed')
                    stored_name = stored_name.lstrip('/')
                    require(stored_name.startswith('uploads/') and stored_name in unique_names,
                            'triage upload references missing evidence')
                    info = archive.getinfo(stored_name)
                    stored_size = upload.get('StoredSize')
                    require(isinstance(stored_size, int) and not isinstance(stored_size, bool) and
                            stored_size == info.file_size, 'triage upload size does not match evidence')
                    if info.file_size > 0 and row.get('SourceFile'):
                        successful_uploads += 1

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
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['valid'] else 1


if __name__ == '__main__':
    sys.exit(main())
