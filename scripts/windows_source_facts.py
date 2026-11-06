#!/usr/bin/env python3
"""Record private same-runner metadata for failed Windows collection sources."""
import argparse
import ctypes
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path, PureWindowsPath
import re
import sys
from urllib.parse import unquote
import zipfile

# Reuse the validator's purely lexical guard, including DOS-device rejection.
_spec = spec_from_file_location('windows_source_eligibility', Path(__file__).with_name('validate_windows_collection.py'))
_eligibility = module_from_spec(_spec)
_spec.loader.exec_module(_eligibility)


def ordinary_drive_path(path):
    if not isinstance(path, str) or '\x00' in path or len(path) > 32767:
        return False
    if any(part in ('.', '..') for part in re.split(r'[\\/]', path)):
        return False
    parsed = PureWindowsPath(path)
    return (bool(re.fullmatch(r'[a-zA-Z]:', parsed.drive)) and parsed.root == '\\' and
            all(':' not in part for part in parsed.parts[1:]))


def describe_source(path):
    # Raw NTFS, VSS, UNC and device names must not become false Win32 misses.
    if not ordinary_drive_path(path) or _eligibility.windows_temp_scope(path) is None:
        return {'source_type': 'unsupported_path'}
    try:
        info = os.lstat(path)
    except OSError as error:
        winerror = getattr(error, 'winerror', None)
        return {'source_type': 'missing' if winerror in (2, 3) else 'other',
                'source_winerror': winerror}
    return {'source_type': 'existing', 'source_size': info.st_size}


def gather_facts(collection):
    sources = {}
    with zipfile.ZipFile(collection) as archive:
        for name in archive.namelist():
            if unquote(name) != 'results/Windows.Triage.Targets/Uploads.json':
                continue
            with archive.open(name) as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        continue
                    source = row.get('SourceFile')
                    upload = row.get('Upload')
                    if (isinstance(upload, dict) and upload.get('Error') and
                            isinstance(source, str) and source not in sources):
                        sources[source] = describe_source(source)
    with collection.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'collection_sha256': digest, 'sources': sources}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if (sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            not ctypes.windll.shell32.IsUserAnAdmin()):
        parser.error('source checks require Administrator on a hosted Windows runner')
    if args.output.parent.resolve() != args.collection.parent.resolve():
        parser.error('source facts must remain beside the private collection')
    try:
        facts = gather_facts(args.collection)
        with args.output.open('x', encoding='utf-8') as stream:
            json.dump(facts, stream)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, EOFError):
        print('Could not record Windows source metadata.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
