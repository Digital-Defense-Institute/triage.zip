#!/usr/bin/env python3
"""Validate a production Windows offline collection without extracting evidence.

The container schema follows Velociraptor vql/tools/collector and reporting.
See https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/.
The report contains counts and fixed diagnostics only, never evidence or log text.
"""
import argparse
from functools import lru_cache
import os
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote
import zipfile

TRIAGE = 'Windows.Triage.Targets'
AUTORUNS = 'Windows.Sysinternals.Autoruns'
# Load beside this script for both direct CLI and importlib-based test callers.
from importlib.util import module_from_spec, spec_from_file_location
_shared_spec = spec_from_file_location('collection_validation', Path(__file__).with_name('collection_validation.py'))
_shared = module_from_spec(_shared_spec)
_shared_spec.loader.exec_module(_shared)
InvalidCollection = _shared.InvalidCollection
require = _shared.require
object_json = _shared.object_json
rows = _shared.rows
FATAL_MESSAGE = _shared.FATAL_MESSAGE


def normalize_system_message(message):
    return ' '.join(message.casefold().split()).strip(' .')


@lru_cache(maxsize=1)
def windows_system_error_messages():
    """Map native standard Win32 message strings to fixed numeric identifiers.

    No evidence text reaches this map: FormatMessageW supplies all keys. Ignore
    insert placeholders; do not substitute a path into a standard message. Some
    Windows codes share message text, so a match identifies a message signature,
    rather than proving the original syscall error number.
    """
    if os.name != 'nt':
        return {}
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    format_message = kernel.FormatMessageW
    format_message.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                               ctypes.c_uint32, ctypes.POINTER(ctypes.c_wchar),
                               ctypes.c_uint32, ctypes.c_void_p]
    format_message.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(4096)
    messages = {}
    # Win32 system error ranges, including filesystem, device and Winsock errors.
    for code in range(1, 16000):
        length = format_message(0x1000 | 0x200, None, code, 0,
                                buffer, len(buffer), None)
        if length:
            message = normalize_system_message(buffer.value)
            if message:
                messages.setdefault(message, code)
    return messages


def native_error_category(error):
    if not isinstance(error, str):
        return None
    message = normalize_system_message(error)
    for standard, code in sorted(windows_system_error_messages().items(),
                                 key=lambda item: len(item[0]), reverse=True):
        if message == standard or message.endswith(': ' + standard):
            return 'win32_error_' + str(code)
    return None


# Presence counts use only this finite vocabulary, never arbitrary error words.
ERROR_TOKENS = frozenset({
    'read', 'write', 'seek', 'buffer', 'eof', 'stream', 'context', 'closed',
    'invalid', 'argument', 'directory', 'device', 'volume', 'compression',
    'decompression', 'decompress', 'compressed', 'access', 'resource',
    'function', 'incorrect', 'parameter', 'handle', 'file', 'path', 'data',
    'size', 'offset', 'negative', 'unsupported', 'implemented', 'allocation',
    'memory', 'range', 'sparse', 'denied', 'not', 'found', 'unable', 'error',
    'operation', 'timeout', 'canceled', 'cancelled', 'permission', 'io',
    'lznt1', 'attribute', 'ntfs', 'mft', 'end', 'process', 'sharing',
})


def upload_error_category(error):
    """Classify English Windows/Go errors without returning source text.

    vql/networking/upload.go preserves accessor Open errors in Upload.Error;
    reporting/container.go can also attach errors after a partial copy. These
    categories are diagnostics only: every category still fails validation.
    Unknown/localized errors deliberately remain other.
    """
    native = native_error_category(error)
    if native:
        return native
    message = error.casefold() if isinstance(error, str) else ''
    if any(text in message for text in ('sharing violation', 'used by another process')):
        return 'sharing_violation'
    if any(text in message for text in ('access is denied', 'access denied', 'permission denied')):
        return 'access_denied'
    if any(text in message for text in ('cannot find the file specified',
                                       'cannot find the path specified',
                                       'no such file or directory', 'file does not exist')):
        return 'missing_file'
    # Error messages originate in Go io/os/syscall and the NTFS accessor.
    # Fixed classifications are diagnostics only, never an acceptance policy.
    if 'unexpected eof' in message:
        return 'unexpected_eof'
    if re.search(r'\beof\b', message):
        return 'eof'
    signatures = {
        'invalid_parameter': ('invalid argument', 'parameter is incorrect', 'invalid parameter'),
        'invalid_handle': ('bad file descriptor', 'handle is invalid', 'invalid handle', 'file already closed'),
        'directory': ('is a directory', 'directory name is invalid'),
        'unsupported': ('not supported', 'not implemented', 'invalid function', 'incorrect function'),
        'ntfs_attribute': ('attribute not found', 'no data attribute', 'no $data', 'unable to find attribute'),
        'ntfs_compression': ('decompression', 'lznt1', 'compressed block'),
        'read_fault': ('read fault', 'cannot read from the specified device', 'reached the end of the file'),
        'seek_error': ('seek error', 'seek: ', 'error seeking', 'attempt to move the file pointer'),
        'resource_exhausted': ('not enough memory', 'not enough storage', 'insufficient system resources', 'too many open files'),
        'path_error': ('filename, directory name, or volume label syntax is incorrect', 'file name is too long'),
        'ntfs_format': ('no ntfs magic', 'mft magic', 'unknown mft cluster size'),
        'device_read': ('input/output error', 'i/o device error', 'device is not ready',
                        'device is not functioning', 'data error (cyclic redundancy check)'),
        'negative_offset': ('negative offset', 'negative position'),
    }
    for category, phrases in signatures.items():
        if any(phrase in message for phrase in phrases):
            return category
    if message.strip() in ('file not found', 'not found'):
        # NTFS accessor OpenWithOSPath emits these exact fixed messages.
        return 'missing_file'
    return 'other'


def upload_target_type(source):
    # Return only fixed names of NTFS system metadata or known file formats.
    # Never report source basenames, extensions outside this set, or full paths.
    if not isinstance(source, str):
        return 'other'
    basename = source.replace('\\', '/').rsplit('/', 1)[-1].casefold()
    stem = basename.split(':', 1)[0]
    ntfs_names = {'$badclus', '$boot', '$mft', '$mftmirr', '$logfile', '$bitmap',
                  '$secure', '$upcase', '$attrdef', '$volume', '$usnjrnl',
                  '$objid', '$quota', '$reparse', '$t', '$txflog', '$tops'}
    if stem in ntfs_names:
        return 'ntfs_' + stem[1:]
    extension = basename.rsplit('.', 1)[-1] if '.' in basename else ''
    if extension in {'evtx', 'pf', 'lnk', 'exe', 'dll', 'sys', 'log', 'dat', 'db', 'sqlite',
                     'blf', 'etl', 'regtrans-ms', 'hve', 'log1', 'log2', 'jfm',
                     'tmp', 'automaticdestinations-ms', 'customdestinations-ms',
                     'reg', 'xml', 'csv', 'json', 'pol', 'cab', 'edb'}:
        return 'extension_' + extension
    return 'other'


def record_upload_error(diagnostics, upload, source=None, archive=None, row=None):
    category = upload_error_category(upload.get('Error'))
    summary = diagnostics.setdefault(category, {
        'count': 0, 'stored_name_present': 0, 'nonzero_stored_size': 0,
        'stored_bytes': 0, 'malformed_stored_size': 0,
        'archive_member_present': 0, 'archive_bytes': 0,
        'nonzero_archive_member': 0, 'logical_size_positive': 0,
        'logical_bytes': 0, 'accessors': {}, 'target_types': {}, 'error_tokens': {},
        'stored_target_types': {}, 'source_json_types': {}, 'path_families': {},
        'archive_directories': 0, 'stored_name_trailing_slash': 0,
        'details_stat_is_dir_true': 0, 'details_stat_is_dir_false': 0})
    summary['count'] += 1
    source_type = ('null' if source is None else 'boolean' if isinstance(source, bool)
                   else 'string' if isinstance(source, str) else 'object' if isinstance(source, dict)
                   else 'array' if isinstance(source, list) else 'number' if isinstance(source, (int, float))
                   else 'other')
    summary['source_json_types'][source_type] = summary['source_json_types'].get(source_type, 0) + 1
    details = row.get('Details') if isinstance(row, dict) else None
    stat = details.get('Stat') if isinstance(details, dict) else None
    if isinstance(stat, dict) and isinstance(stat.get('IsDir'), bool):
        summary['details_stat_is_dir_true' if stat['IsDir'] else 'details_stat_is_dir_false'] += 1
    error_text = upload.get('Error')
    if isinstance(error_text, str):
        tokens = set(re.findall(r'[a-z]+', error_text.casefold())) & ERROR_TOKENS
        for token in sorted(tokens):
            summary['error_tokens'][token] = summary['error_tokens'].get(token, 0) + 1
    stored_name = upload.get('StoredName')
    accessor = 'unknown'
    if isinstance(stored_name, str):
        summary['stored_name_trailing_slash'] += stored_name.endswith('/')
        decoded_name = unquote(stored_name).replace('\\', '/').casefold().rstrip('/')
        stored_target = upload_target_type(decoded_name)
        if stored_target == 'other':
            stored_target = 'unknown_extension' if '.' in decoded_name.rsplit('/', 1)[-1] else 'no_extension'
        summary['stored_target_types'][stored_target] = summary['stored_target_types'].get(stored_target, 0) + 1
        family = 'other'
        for suffix, fixed in (('/windows/system32/config/regback', 'windows_registry_regback'),
                              ('/windows/system32/config/txr', 'windows_registry_txr'),
                              ('/windows/system32/config', 'windows_registry_config')):
            if suffix + '/' in decoded_name or decoded_name.endswith(suffix):
                family = fixed
                break
        summary['path_families'][family] = summary['path_families'].get(family, 0) + 1
        components = stored_name.lstrip('/').split('/')
        if len(components) > 1 and components[0] == 'uploads':
            candidate = components[1].casefold()
            accessor = candidate if candidate in {'auto', 'ntfs', 'file', 'sparse', 'data', 'mft', 'vss'} else 'other'
        if archive is not None:
            try:
                info = archive.getinfo(stored_name.lstrip('/'))
            except KeyError:
                pass
            else:
                summary['archive_member_present'] += 1
                summary['archive_directories'] += info.is_dir()
                summary['archive_bytes'] += info.file_size
                summary['nonzero_archive_member'] += info.file_size > 0
    summary['accessors'][accessor] = summary['accessors'].get(accessor, 0) + 1
    target_type = upload_target_type(source)
    summary['target_types'][target_type] = summary['target_types'].get(target_type, 0) + 1
    logical_size = upload.get('Size', 0)
    if isinstance(logical_size, int) and not isinstance(logical_size, bool) and logical_size > 0:
        summary['logical_size_positive'] += 1
        summary['logical_bytes'] += logical_size
    summary['stored_name_present'] += bool(upload.get('StoredName'))
    size = upload.get('StoredSize', 0)
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        summary['stored_bytes'] += size
        summary['nonzero_stored_size'] += size > 0
    else:
        summary['malformed_stored_size'] += 1


def is_empty_directory_read_error(upload, archive):
    """Recognize only Windows error 1 on an actual empty directory member.

    Adaptive TryToDownload uses stat without IsDir filtering. The auto accessor
    documents Incorrect function on directories; Container.Upload appends '/' iff
    stat.Mode.IsDir(). Such entries have no file content to acquire. A regular
    file, any copied byte, or any other error remains fatal.
    """
    error = upload.get('Error')
    if not isinstance(error, str):
        return False
    native = native_error_category(error)
    message = normalize_system_message(error)
    exact_error_one = message == 'incorrect function' or message.endswith(': incorrect function')
    if native != 'win32_error_1' and not exact_error_one:
        return False
    size = upload.get('StoredSize', 0)
    if not isinstance(size, int) or isinstance(size, bool) or size != 0:
        return False
    name = upload.get('StoredName')
    if not isinstance(name, str) or not name.lstrip('/').startswith('uploads/'):
        return False
    try:
        info = archive.getinfo(name.lstrip('/'))
    except KeyError:
        return False
    return info.is_dir() and info.file_size == 0


def validate(path):
    """Return a payload-free summary, or raise InvalidCollection."""
    with zipfile.ZipFile(path) as archive:
        context, names, log_rows, warning_rows = _shared.validate_container(
            archive, 'windows', (TRIAGE, AUTORUNS), 'Windows')
        unique_names = set(names)

        triage_rows = autoruns_rows = result_rows = successful_uploads = 0
        upload_errors = {}
        skipped_directory_errors = {}
        skipped_directory_uploads = 0
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
                    if errored and is_empty_directory_read_error(upload, archive):
                        skipped_directory_uploads += 1
                        record_upload_error(skipped_directory_errors, upload, row.get('SourceFile'), archive, row)
                        continue
                    if errored:
                        record_upload_error(upload_errors, upload, row.get('SourceFile'), archive, row)
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
                    if not errored and not info.is_dir() and stored_size == actual_size and actual_size > 0 and row.get('SourceFile'):
                        successful_uploads += 1

        diagnostics = {
            'upload_errors': upload_errors, 'upload_sizes': sizes,
            'upload_references': reference_errors, 'result_rows': result_rows,
            'triage_rows': triage_rows, 'autoruns_entries': autoruns_rows,
            'verified_triage_uploads': successful_uploads,
            'skipped_directory_uploads': skipped_directory_uploads,
            'skipped_directory_diagnostics': skipped_directory_errors}
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
                'log_rows': log_rows, 'warning_rows': warning_rows,
                'skipped_directory_uploads': skipped_directory_uploads,
                'skipped_directory_diagnostics': skipped_directory_errors}


def main():
    return _shared.run_cli(validate, __doc__)


if __name__ == '__main__':
    sys.exit(main())
