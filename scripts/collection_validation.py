"""Shared read-only Velociraptor container integrity and safe reporting checks."""
import argparse
import json
from pathlib import Path
import re
import zipfile

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


def validate_container(archive, platform, required_artifacts, platform_label=None):
    """Check container envelope; platform-specific code must validate results."""
    platform_label = platform_label or platform
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
    require(isinstance(client.get('OS'), str) and client['OS'].lower() == platform,
            'collection is not from ' + platform_label)
    require(context.get('state') in (2, 'FINISHED'), 'collection did not finish successfully')
    require(not context.get('status'), 'collection reports an error status')
    request = context.get('request')
    require(isinstance(request, dict), 'collection request is absent')
    require(isinstance(request.get('artifacts'), list) and
            set(required_artifacts).issubset(request['artifacts']),
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

    return context, names, log_rows, warning_rows


def run_cli(validate, description):
    parser = argparse.ArgumentParser(description=description)
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


