"""Validate the parser/MOTW contract on the disposable Windows CI image.

Only fixed source names, counts and qualification booleans leave the runner.
The optional seed manifest contains synthetic paths and stays on that runner.
"""
import hashlib
from datetime import datetime
import re
from urllib.parse import unquote

PARSERS = (
    'Windows.Forensics.SRUM', 'Windows.Forensics.Bam',
    'Windows.Registry.UserAssist', 'Windows.Registry.AppCompatCache',
    'Windows.Forensics.Amcache',
)
MOTW = 'Generic.Collectors.File'
SOURCE_FIELDS = {
    PARSERS[0] + '/Execution Stats': ('App', 'TimeStamp'),
    PARSERS[0] + '/Application Resource Usage': ('App', 'TimeStamp'),
    PARSERS[0] + '/Network Connections': ('App', 'TimeStamp'),
    PARSERS[0] + '/Network Usage': ('App', 'TimeStamp', 'BytesSent', 'BytesRecvd'),
    PARSERS[0] + '/SruDbIdMapTable': (),
    PARSERS[1]: ('Binary', 'Bam_time', 'SID'),
    PARSERS[2]: ('Name', 'User', 'LastExecution', 'NumberOfExecutions'),
    PARSERS[3]: ('Path', 'ModificationTime'),
}
for _source in ('File', 'Programs', 'Generic', 'InventoryDriverBinary',
                'InventoryApplication', 'InventoryDeviceContainer',
                'InventoryDriverPackage', 'InventoryApplicationFile',
                'InventoryDevicePnp', 'InventoryApplicationShortcut'):
    SOURCE_FIELDS[PARSERS[4] + '/' + _source] = ()
SOURCE_FIELDS.update({PARSERS[4] + '/' + source: fields for source, fields in {
    'File': ('FullPath', 'SHA1'), 'Programs': ('Name', 'Publisher'),
    'Generic': ('SHA1', 'LastModifiedKey'),
    'InventoryApplication': ('Name', 'Timestamp'),
    'InventoryApplicationFile': ('FullPath', 'Timestamp'),
    'InventoryApplicationShortcut': ('ShortcutPath', 'Timestamp'),
}.items()})


def source_path(value):
    value = str(value).replace('\\', '/').casefold()
    return re.sub(r'^//[.?]/(?=[a-z]:/)', '', value)


def digest(archive, name):
    result = hashlib.sha256()
    with archive.open(name) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def validate(archive, context, names, rows, require, seed_manifest=None):
    requested = context['request']['artifacts']
    require(set(PARSERS + (MOTW,)).issubset(requested),
            'Windows parser/MOTW artifacts were not requested')
    counts = dict.fromkeys(SOURCE_FIELDS, 0)
    meaningful = dict.fromkeys(PARSERS, 0)
    metadata, uploads = {}, {}
    for member in names:
        if not member.startswith('results/') or not member.endswith('.json'):
            continue
        source = unquote(member[len('results/'):-len('.json')])
        if source in counts:
            for row in rows(archive, member):
                require(all(field in row for field in SOURCE_FIELDS[source]),
                        'Windows parser result schema is incomplete')
                if source.endswith('/Network Usage'):
                    require(all(type(row[key]) is int and row[key] >= 0
                                for key in ('BytesSent', 'BytesRecvd')),
                            'SRUM network counters are malformed')
                time_field = ('TimeStamp' if source.startswith(PARSERS[0] + '/') else
                              'Bam_time' if source == PARSERS[1] else
                              'LastExecution' if source == PARSERS[2] else
                              'ModificationTime' if source == PARSERS[3] else
                              'Timestamp' if 'Timestamp' in row else None)
                if time_field and not (source == PARSERS[2] and row[time_field] == ''):
                    try:
                        valid_time = (isinstance(row[time_field], str) and
                                      datetime.fromisoformat(row[time_field]) is not None)
                    except ValueError:
                        valid_time = False
                    require(valid_time, 'Windows parser timestamp is malformed')
                if source == PARSERS[2]:
                    require(type(row['NumberOfExecutions']) is int and row['NumberOfExecutions'] >= 0,
                            'UserAssist execution count is malformed')
                counts[source] += 1
                artifact = source.split('/')[0]
                identity = {PARSERS[0]: ('App',), PARSERS[1]: ('Binary',),
                            PARSERS[2]: ('Name',), PARSERS[3]: ('Path',),
                            PARSERS[4]: ('FullPath', 'Name', 'SHA1', 'ShortcutPath')}[artifact]
                meaningful[artifact] += any(isinstance(row.get(key), str) and row[key]
                                            for key in identity)
        elif source in (MOTW + '/All Matches Metadata', MOTW + '/Uploads'):
            target = metadata if source.endswith('Metadata') else uploads
            for row in rows(archive, member):
                path = row.get('SourceFile')
                require(isinstance(path, str) and path and
                        path.casefold().endswith(':zone.identifier'),
                        'MOTW source path is malformed')
                key = source_path(path)
                require(key not in target, 'duplicate MOTW source result')
                target[key] = row

    totals = {name: sum(value for source, value in counts.items()
                        if source == name or source.startswith(name + '/'))
              for name in PARSERS}
    # This is CI-image qualification, not a requirement for arbitrary endpoints.
    require(all(meaningful.values()), 'Windows CI image produced no meaningful results for a selected parser')
    require(metadata.keys() == uploads.keys(), 'MOTW metadata/upload sources differ')
    archive_paths = {}
    for name in names:
        decoded = unquote(name)
        require(decoded not in archive_paths, 'ambiguous escaped ZIP member')
        archive_paths[decoded] = name
    stored = {}
    for item in rows(archive, 'uploads.json'):
        components = item.get('_Components')
        if (item.get('Type') or not isinstance(components, list) or len(components) < 3 or
                components[:2] != ['uploads', 'ntfs']):
            continue
        path = item.get('vfs_path')
        if isinstance(path, str) and source_path(path) in uploads:
            key = source_path(path)
            require(key not in stored and all(isinstance(part, str) for part in components),
                    'duplicate or malformed MOTW upload metadata')
            stored[key] = (item, archive_paths.get('/'.join(components).lstrip('/')))
    verified = {}
    destinations = set()
    for key, row in uploads.items():
        destination = row.get('DestinationFile')
        require(isinstance(destination, str) and destination,
                'MOTW upload has no destination')
        # Generic.Collectors.File exposes Upload.Path (the source), not
        # Upload.StoredName. Resolve through the container's uploads.json.
        require(source_path(destination) == key, 'MOTW upload source differs from metadata')
        record, destination = stored.get(key, ({}, None))
        require(destination is not None and not archive.getinfo(destination).is_dir(),
                'MOTW upload references missing evidence')
        require(destination not in destinations, 'MOTW uploads share an evidence member')
        destinations.add(destination)
        size = metadata[key].get('Size')
        require(type(size) is int and size >= 0 and
                type(row.get('FileSize')) is int and
                type(record.get('file_size')) is int and type(record.get('uploaded_size')) is int and
                row.get('FileSize') == size and record.get('file_size') == size and
                record.get('uploaded_size') == size and archive.getinfo(destination).file_size == size,
                'MOTW evidence size differs from matched stream')
        sha = row.get('SourceFileSha256')
        require(isinstance(sha, str) and re.fullmatch('[a-fA-F0-9]{64}', sha),
                'MOTW stream hash is absent or malformed')
        actual = digest(archive, destination)
        require(actual == sha.lower(), 'MOTW evidence hash differs from upload result')
        for field in ('Created', 'Changed', 'Modified', 'LastAccessed'):
            require(field in row and field in metadata[key] and
                    row[field] == metadata[key][field], 'MOTW source timestamps differ')
        verified[key] = (size, actual)

    seed_counts = {'included': 0, 'excluded': 0}
    if seed_manifest is not None:
        require(isinstance(seed_manifest, dict) and seed_manifest.get('version') == 1 and
                isinstance(seed_manifest.get('streams'), list) and seed_manifest['streams'],
                'MOTW seed manifest is malformed')
        expected = set()
        for item in seed_manifest['streams']:
            require(isinstance(item, dict) and isinstance(item.get('path'), str) and
                    type(item.get('include')) is bool and type(item.get('size')) is int and
                    item['size'] >= 0 and isinstance(item.get('sha256'), str) and
                    re.fullmatch('[a-f0-9]{64}', item['sha256']),
                    'MOTW seed record is malformed')
            key = source_path(item['path'])
            require(key not in expected, 'duplicate MOTW seed')
            expected.add(key)
            if item['include']:
                require(verified.get(key) == (item['size'], item['sha256']),
                        'expected MOTW seed evidence was not preserved')
                if 'modified' in item:
                    try:
                        equal = (datetime.fromisoformat(metadata[key]['Modified']) ==
                                 datetime.fromisoformat(item['modified']))
                    except (TypeError, ValueError):
                        equal = False
                    require(equal, 'MOTW seed modification timestamp differs')
                seed_counts['included'] += 1
            else:
                require(key not in metadata and key not in uploads,
                        'out-of-scope MOTW seed was collected')
                seed_counts['excluded'] += 1
        require(seed_counts['included'] > 0 and seed_counts['excluded'] > 0,
                'MOTW seed manifest lacks positive or negative controls')

    return {'parser_rows': totals, 'parser_meaningful_rows': meaningful, 'parser_source_rows': counts,
            'srum_network_usage_rows': counts[PARSERS[0] + '/Network Usage'],
            'verified_motw_streams': len(verified),
            'verified_motw_bytes': sum(item[0] for item in verified.values()),
            'motw_seed_counts': seed_counts,
            'motw_seeded': seed_manifest is not None}
