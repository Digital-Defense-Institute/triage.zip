#!/usr/bin/env python3
"""Validate the production Linux.Triage.UAC _All collection without extraction.

Schema: triage.velocidex.com/artifacts/Linux.Triage.UAC.zip, commit 78968d0.
Sources are SearchGlobs, All Matches Metadata, and Uploads. _All includes Etc,
which recursively collects /etc. No evidence content or raw errors enter reports.
"""
from importlib.util import module_from_spec, spec_from_file_location
import json
import hashlib
import argparse
import errno
import os
from functools import lru_cache
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


@lru_cache(maxsize=1)
def posix_error_messages():
    # Error strings come exclusively from the host's libc, never evidence.
    result = {}
    for code, symbol in sorted(errno.errorcode.items()):
        try:
            result.setdefault(os.strerror(code).casefold().strip(), symbol)
        except ValueError:
            continue
    return result


def fixed_path_family(path):
    if not isinstance(path, str):
        return 'non_string'
    for prefix, family in (('/proc/', 'proc'), ('/sys/', 'sys'), ('/dev/', 'dev'),
                           ('/run/', 'run'), ('/var/run/', 'var_run'),
                           ('/tmp/', 'tmp'), ('/var/tmp/', 'var_tmp'),
                           ('/etc/', 'etc'), ('/var/log/', 'var_log'),
                           ('/var/lib/', 'var_lib'), ('/home/', 'home'),
                           ('/root/', 'root'), ('/usr/', 'usr')):
        if path.startswith(prefix) or path == prefix[:-1]:
            return family
    return 'other'


def json_type(value):
    return ('null' if value is None else 'boolean' if isinstance(value, bool)
            else 'object' if isinstance(value, dict) else 'array' if isinstance(value, list)
            else 'string' if isinstance(value, str) else 'number' if isinstance(value, (int, float)) else 'other')


def file_shape(stat):
    if not isinstance(stat, dict):
        return 'absent'
    if stat.get('IsDir') is True:
        return 'directory'
    data = stat.get('Data')
    if stat.get('IsLink') is True or isinstance(data, dict) and isinstance(data.get('Link'), str) and data['Link']:
        return 'symlink'
    mode = stat.get('Mode', stat.get('ModeStr'))
    if isinstance(mode, str) and mode:
        return {'d': 'directory', 'l': 'symlink', 'p': 'fifo', 's': 'socket',
                'c': 'character_device', 'b': 'block_device', '-': 'regular_file'}.get(mode[0].casefold(), 'other')
    if isinstance(mode, int) and not isinstance(mode, bool):
        # Go os.FileMode stores type flags in its high bits.
        for bit, shape in ((31, 'directory'), (27, 'symlink'), (25, 'fifo'),
                           (24, 'socket'), (26, 'device')):
            if mode & (1 << bit):
                return shape
        return 'regular_or_permissions_only'
    return 'unknown'


def increment(summary, key, value):
    counts = summary.setdefault(key, {})
    counts[value] = counts.get(value, 0) + 1


def error_metadata(summary, row, metadata):
    source = row.get('SourceFile')
    increment(summary, 'source_json_types', json_type(source))
    increment(summary, 'source_families', fixed_path_family(source))
    increment(summary, 'metadata_join', 'matched' if metadata else 'absent')
    details = row.get('Details')
    stat = details.get('Stat') if isinstance(details, dict) else None
    increment(summary, 'detail_file_shapes', file_shape(stat))
    increment(summary, 'metadata_file_shapes', file_shape(metadata))
    mode = stat.get('Mode') if isinstance(stat, dict) else None
    increment(summary, 'detail_mode_types', json_type(mode))
    if isinstance(mode, int) and not isinstance(mode, bool):
        increment(summary, 'detail_mode_values', str(mode))
    mode_string = stat.get('ModeStr') if isinstance(stat, dict) else None
    if isinstance(mode_string, str):
        if re.fullmatch(r'[dalTLDugctpS?\-]{1,10}[rwxstST\-]{9}', mode_string):
            increment(summary, 'detail_mode_strings', mode_string)
        else:
            increment(summary, 'detail_mode_strings', 'unrecognized_format')
    fixed_fields = ('Mode', 'ModeStr', 'IsLink', 'IsDir', 'Data', 'Link', 'link',
                    'LinkTarget', 'Symlink', 'Name', 'FullPath')
    for field in fixed_fields:
        value_type = json_type(stat[field]) if isinstance(stat, dict) and field in stat else 'absent'
        increment(summary, 'stat_field_' + field + '_types', value_type)
    for field in ('IsLink', 'IsDir'):
        flag = stat.get(field) if isinstance(stat, dict) else None
        if isinstance(flag, bool):
            increment(summary, 'stat_' + field + '_values', 'true' if flag else 'false')
    full_path = stat.get('FullPath') if isinstance(stat, dict) else None
    if isinstance(source, str) and isinstance(full_path, str):
        increment(summary, 'detail_source_path_matches', 'true' if source == full_path else 'false')
    else:
        increment(summary, 'detail_source_path_matches', 'unavailable')
    stat_size = stat.get('Size') if isinstance(stat, dict) else None
    row_size = row.get('FileSize')
    if isinstance(stat_size, int) and isinstance(row_size, int):
        increment(summary, 'detail_source_size_matches', 'true' if stat_size == row_size else 'false')
    else:
        increment(summary, 'detail_source_size_matches', 'unavailable')
    data = stat.get('Data') if isinstance(stat, dict) else None
    link = data.get('Link') if isinstance(data, dict) else None
    increment(summary, 'link_target_types', json_type(link))
    for field in ('Link', 'link', 'LinkTarget', 'Symlink'):
        value_type = json_type(data[field]) if isinstance(data, dict) and field in data else 'absent'
        increment(summary, 'stat_data_' + field + '_types', value_type)
    if isinstance(link, str):
        shape = ('absolute' if link.startswith('/') else 'relative_parent' if link.startswith('../')
                 else 'relative_current' if link.startswith('./') else 'relative')
        increment(summary, 'link_target_shapes', shape)
        increment(summary, 'link_target_families', fixed_path_family(link))
        fixed_target = {'/dev/null': 'dev_null', '/dev/zero': 'dev_zero',
                        '/dev/random': 'dev_random', '/dev/urandom': 'dev_urandom',
                        '/proc/self': 'proc_self', '/proc/self/fd': 'proc_self_fd'}.get(link, 'other')
        increment(summary, 'fixed_link_targets', fixed_target)
    accessor = metadata.get('Accessor') if isinstance(metadata, dict) else None
    increment(summary, 'metadata_accessors', accessor if accessor in ('auto', 'file', 'raw_file') else 'other')


def error_category(error):
    message = error.casefold().strip() if isinstance(error, str) else ''
    for standard, symbol in sorted(posix_error_messages().items(), key=lambda item: len(item[0]), reverse=True):
        if message == standard or message.endswith(': ' + standard):
            return 'errno_' + symbol
    if message.startswith('only regular files supported (not ') and message.endswith(')'):
        return 'non_regular_file'
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


def validate_live_facts(path, facts):
    if facts is None:
        return {}
    require(isinstance(facts, dict) and isinstance(facts.get('sources'), dict),
            'live source facts are malformed')
    expected = facts.get('collection_sha256')
    require(isinstance(expected, str) and re.fullmatch(r'[a-f0-9]{64}', expected),
            'live source facts digest is malformed')
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    require(digest.hexdigest() == expected, 'live source facts do not match collection')
    return facts['sources']


def exact_error_suffix(error, fixed_message):
    message = error.casefold().strip() if isinstance(error, str) else ''
    return message == fixed_message or message.endswith(': ' + fixed_message)


def live_symlink_skip(row, archive, sources):
    """Apply only explicit, digest-bound same-runner symlink facts.

    This function never probes source paths. Offline archives alone cannot prove
    their symlink targets, and cached UAC Details.Stat need not match SourceFile.
    """
    source = row.get('SourceFile')
    if not isinstance(source, str):
        return None
    fact = sources.get(source)
    size = row.get('FileSize')
    if (not isinstance(fact, dict) or fact.get('source_type') != 'symlink' or
            fact.get('source_errno') not in (None, 0) or
            not isinstance(size, int) or isinstance(size, bool) or size <= 0 or
            not isinstance(fact.get('source_size'), int) or isinstance(fact['source_size'], bool) or
            fact['source_size'] != size):
        return None
    # Do not treat paths with lexical traversal as belonging to a fixed scope.
    if '..' in source.split('/') or '.' in source.split('/'):
        return None
    if fact.get('target_type') in ('directory', 'dev_null') and fact.get('target_errno') not in (None, 0):
        return None
    upload = row['Upload']
    error = upload.get('Error')
    if exact_error_suffix(error, 'is a directory') and fact.get('target_type') == 'directory':
        stored_size = upload.get('StoredSize', 0)
        name = upload.get('StoredName')
        if (not isinstance(stored_size, int) or isinstance(stored_size, bool) or stored_size != 0 or
                not isinstance(name, str) or not name.lstrip('/').startswith('uploads/')):
            return None
        try:
            info = archive.getinfo(name.lstrip('/'))
        except KeyError:
            return None
        if info.file_size == 0:
            return 'directory_symlink'
    no_stored_output = 'StoredName' not in upload and 'StoredSize' not in upload
    if (no_stored_output and fact.get('target_type') == 'dev_null' and
            isinstance(error, str) and error.casefold().startswith('only regular files supported (not ') and
            error.endswith(')') and any(source.startswith(prefix + '/') for prefix in (
                '/etc', '/usr/lib/systemd/system', '/lib/systemd/system'))):
        return 'dev_null_symlink'
    if (no_stored_output and source.startswith('/etc/') and fact.get('target_type') == 'missing' and
            fact.get('target_errno') == errno.ENOENT and
            exact_error_suffix(error, 'no such file or directory')):
        return 'dangling_symlink'
    return None


def live_error_metadata(summary, row, sources):
    source = row.get('SourceFile')
    fact = sources.get(source) if isinstance(source, str) else None
    increment(summary, 'live_fact_presence', 'present' if isinstance(fact, dict) else 'absent')
    if not isinstance(fact, dict):
        return
    source_type = fact.get('source_type')
    target_type = fact.get('target_type')
    increment(summary, 'live_source_types', source_type if source_type in (
        'symlink', 'regular_file', 'directory', 'other', 'missing') else 'unrecognized')
    increment(summary, 'live_target_types', target_type if target_type in (
        'directory', 'regular_file', 'dev_null', 'missing', 'other') else 'unrecognized')
    size = fact.get('source_size')
    row_size = row.get('FileSize')
    if (isinstance(size, int) and not isinstance(size, bool) and
            isinstance(row_size, int) and not isinstance(row_size, bool)):
        increment(summary, 'live_source_size_matches', 'true' if size == row_size else 'false')
    else:
        increment(summary, 'live_source_size_matches', 'unavailable')
    for key in ('source_errno', 'target_errno'):
        code = fact.get(key)
        value = ('absent' if code is None else str(code) if isinstance(code, int) and
                 not isinstance(code, bool) and (code == 0 or code in errno.errorcode) else 'unrecognized')
        increment(summary, 'live_' + key, value)


def validate(path, live_source_facts=None):
    live_sources = validate_live_facts(path, live_source_facts)
    live_skips = dict.fromkeys(('directory_symlink', 'dev_null_symlink', 'dangling_symlink'), 0)
    with zipfile.ZipFile(path) as archive:
        context, names, log_rows, warning_rows = _shared.validate_container(
            archive, 'linux', (TRIAGE,), 'Linux')
        production_targets(context)
        unique_names = set(names)
        metadata_by_source = {}
        for name in names:
            if name.startswith('results/') and name.endswith('.json') and unquote(name[len('results/'):-len('.json')]) == TRIAGE + '/All Matches Metadata':
                for item in rows(archive, name):
                    if isinstance(item.get('SourceFile'), str):
                        metadata_by_source[item['SourceFile']] = item
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
                live_skip = live_symlink_skip(row, archive, live_sources) if errored else None
                if live_skip:
                    live_skips[live_skip] += 1
                    continue
                category = error_category(upload.get('Error')) if errored else None
                if errored:
                    summary = upload_errors.setdefault(category, {
                        'count': 0, 'stored_name_present': 0, 'archive_directories': 0,
                        'archive_bytes': 0, 'logical_bytes': 0})
                    summary['count'] += 1
                    source_file = row.get('SourceFile')
                    metadata = metadata_by_source.get(source_file) if isinstance(source_file, str) else None
                    error_metadata(summary, row, metadata)
                    live_error_metadata(summary, row, live_sources)
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
                       'skipped_directory_uploads': skipped_directory_uploads,
                       'live_source_facts_used': live_source_facts is not None,
                       'live_source_fact_skips': live_skips}
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
                'skipped_directory_uploads': skipped_directory_uploads,
                       'live_source_facts_used': live_source_facts is not None,
                       'live_source_fact_skips': live_skips}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--live-source-facts', type=Path)
    args = parser.parse_args()
    try:
        facts = None
        if args.live_source_facts:
            try:
                facts = json.loads(args.live_source_facts.read_text(encoding='utf-8'))
            except (OSError, UnicodeError, json.JSONDecodeError):
                raise InvalidCollection('cannot read live source facts') from None
            require(isinstance(facts, dict), 'live source facts are malformed')
        report = validate(args.collection, facts)
    except (InvalidCollection, OSError, zipfile.BadZipFile, RuntimeError, EOFError) as error:
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
