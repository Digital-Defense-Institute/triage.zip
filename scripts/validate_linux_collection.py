#!/usr/bin/env python3
"""Validate the production Linux.Triage.UAC _All collection without extraction.

Schema: triage.velocidex.com/artifacts/Linux.Triage.UAC.zip, commit 78968d0.
Sources are SearchGlobs, All Matches Metadata, and Uploads. _All includes Etc,
which recursively collects /etc. No evidence content or raw errors enter reports.
"""
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote
import zipfile

_spec = spec_from_file_location('collection_validation', Path(__file__).with_name('collection_validation.py'))
_shared = module_from_spec(_spec)
_spec.loader.exec_module(_shared)
InvalidCollection = _shared.InvalidCollection
require = _shared.require
rows = _shared.rows
TRIAGE = 'Linux.Triage.UAC'


def production_targets(context):
    specs = context['request'].get('specs')
    require(isinstance(specs, list), 'production UAC parameters are absent')
    selected = [spec for spec in specs if isinstance(spec, dict) and spec.get('artifact') == TRIAGE]
    require(len(selected) == 1, 'production UAC parameters are absent or ambiguous')
    params = selected[0].get('parameters')
    env = params.get('env') if isinstance(params, dict) else None
    require(isinstance(env, list), 'production UAC parameters are absent')
    targets = [item.get('value') for item in env
               if isinstance(item, dict) and item.get('key') == 'Targets']
    require(len(targets) == 1 and isinstance(targets[0], str), 'production UAC Targets are absent or ambiguous')
    try:
        value = json.loads(targets[0])
    except json.JSONDecodeError:
        raise InvalidCollection('production UAC Targets are malformed') from None
    require(value == ['_All'], 'production UAC _All was not requested')


def error_category(error):
    message = error.casefold() if isinstance(error, str) else ''
    for category, signatures in (
            ('directory', ('is a directory',)),
            ('missing_file', ('no such file or directory', 'file not found')),
            ('permission_denied', ('permission denied', 'operation not permitted')),
            ('io_error', ('input/output error', 'i/o error')),
            ('eof', ('unexpected eof',)),
            ('unsupported', ('not supported', 'invalid argument')),
            ('context', ('context canceled', 'context cancelled', 'deadline exceeded'))):
        if any(signature in message for signature in signatures):
            return category
    return 'other'


def is_empty_directory_read_error(upload, archive):
    # UAC recursively enumerates directories without filtering IsDir. The
    # container writer marks stat.Mode.IsDir by a trailing slash. EISDIR has
    # no file content to acquire; never exempt regular files or partial writes.
    error = upload.get('Error')
    message = error.casefold().strip() if isinstance(error, str) else ''
    if message != 'is a directory' and not message.endswith(': is a directory'):
        return False
    size = upload.get('StoredSize', 0)
    name = upload.get('StoredName')
    if not isinstance(size, int) or isinstance(size, bool) or size != 0:
        return False
    if not isinstance(name, str) or not name.lstrip('/').startswith('uploads/'):
        return False
    try:
        info = archive.getinfo(name.lstrip('/'))
    except KeyError:
        return False
    return info.is_dir() and info.file_size == 0


def valid_system_file(archive, stored_name, source):
    """Inspect only fixed baseline files and return a fixed category or None."""
    if source not in ('/etc/passwd', '/etc/os-release', '/usr/lib/os-release'):
        return None
    info = archive.getinfo(stored_name)
    if not 0 < info.file_size <= 1024 * 1024:
        return None
    try:
        text = archive.read(stored_name).decode('utf-8')
    except UnicodeError:
        return None
    if source == '/etc/passwd':
        for line in text.splitlines():
            fields = line.split(':')
            if (len(fields) == 7 and fields[0] and fields[2] == '0' and
                    fields[3].isdigit() and fields[5].startswith('/')):
                return 'passwd_uid_zero'
    elif re.search(r'^ID=(?:[\'"])?[a-zA-Z0-9_.-]+(?:[\'"])?\s*$', text, re.MULTILINE):
        return 'os_release_id'
    return None


def validate(path):
    with zipfile.ZipFile(path) as archive:
        context, names, log_rows, warning_rows = _shared.validate_container(
            archive, 'linux', (TRIAGE,), 'Linux')
        production_targets(context)
        unique_names = set(names)
        counts = dict.fromkeys(('result_rows', 'uac_rows', 'search_glob_rows',
                                'metadata_rows', 'verified_uac_uploads',
                                'verified_upload_bytes'), 0)
        failures = dict.fromkeys(('malformed_reference', 'missing_evidence',
                                 'malformed_stored_size', 'size_mismatch'), 0)
        upload_errors = {}
        skipped_directory_uploads = 0
        baselines = set()
        for name in names:
            if not name.startswith('results/') or not name.endswith('.json'):
                continue
            source = unquote(name[len('results/'):-len('.json')])
            is_uac = source == TRIAGE or source.startswith(TRIAGE + '/')
            for row in rows(archive, name):
                counts['result_rows'] += 1
                if not is_uac:
                    continue
                counts['uac_rows'] += 1
                if source == TRIAGE + '/SearchGlobs':
                    if isinstance(row.get('Rule'), str) and row['Rule'] and isinstance(row.get('Glob'), str) and row['Glob']:
                        counts['search_glob_rows'] += 1
                if source == TRIAGE + '/All Matches Metadata':
                    if isinstance(row.get('SourceFile'), str) and row['SourceFile'] and isinstance(row.get('Size'), int):
                        counts['metadata_rows'] += 1
                if source != TRIAGE + '/Uploads':
                    continue
                upload = row.get('Upload')
                if not isinstance(upload, dict):
                    continue
                errored = bool(upload.get('Error'))
                if errored and is_empty_directory_read_error(upload, archive):
                    skipped_directory_uploads += 1
                    continue
                category = error_category(upload.get('Error')) if errored else None
                if errored:
                    summary = upload_errors.setdefault(category, {
                        'count': 0, 'stored_name_present': 0, 'archive_directories': 0,
                        'archive_bytes': 0, 'logical_bytes': 0})
                    summary['count'] += 1
                    summary['stored_name_present'] += bool(upload.get('StoredName'))
                    logical = upload.get('Size', 0)
                    if isinstance(logical, int) and not isinstance(logical, bool) and logical > 0:
                        summary['logical_bytes'] += logical
                stored_name = upload.get('StoredName')
                if not stored_name:
                    continue
                if not isinstance(stored_name, str):
                    failures['malformed_reference'] += 1
                    continue
                stored_name = stored_name.lstrip('/')
                if not stored_name.startswith('uploads/') or stored_name not in unique_names:
                    failures['missing_evidence'] += 1
                    continue
                info = archive.getinfo(stored_name)
                if errored:
                    summary['archive_directories'] += info.is_dir()
                    summary['archive_bytes'] += info.file_size
                # UploadResponse omits StoredSize when zero; sparse Size is
                # logical length while StoredSize equals physical ZIP bytes.
                stored_size = upload.get('StoredSize', 0)
                if not isinstance(stored_size, int) or isinstance(stored_size, bool) or stored_size < 0:
                    failures['malformed_stored_size'] += 1
                    continue
                if stored_size != info.file_size:
                    failures['size_mismatch'] += 1
                    continue
                if errored or info.is_dir() or info.file_size == 0:
                    continue
                source_file = row.get('SourceFile')
                if not isinstance(source_file, str) or not source_file:
                    continue
                counts['verified_uac_uploads'] += 1
                counts['verified_upload_bytes'] += info.file_size
                baseline = valid_system_file(archive, stored_name, source_file)
                if baseline:
                    baselines.add(baseline)
        diagnostics = {**counts, 'upload_errors': upload_errors, 'upload_failures': failures,
                       'verified_system_baselines': sorted(baselines),
                       'skipped_directory_uploads': skipped_directory_uploads}
        if upload_errors or any(failures.values()):
            raise InvalidCollection('UAC upload validation failed', diagnostics)
        require(counts['search_glob_rows'] > 0, 'UAC produced no meaningful target rules')
        require(counts['metadata_rows'] > 0, 'UAC produced no meaningful file metadata')
        require(counts['verified_uac_uploads'] > 0, 'UAC produced no verified nonempty evidence upload')
        require(baselines, 'UAC produced no meaningful system baseline file')
        total = context.get('total_collected_rows')
        require(isinstance(total, int) and not isinstance(total, bool) and
                0 < total <= counts['result_rows'], 'collection row count is invalid')
        return {'valid': True, **counts, 'verified_system_baselines': sorted(baselines),
                'log_rows': log_rows, 'warning_rows': warning_rows,
                'skipped_directory_uploads': skipped_directory_uploads}


def main():
    return _shared.run_cli(validate, __doc__)


if __name__ == '__main__':
    sys.exit(main())
