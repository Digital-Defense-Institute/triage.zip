"""Keep the complete baseline spec and add exactly the proposed five parsers."""
import json
from pathlib import Path

from benchmark_collection_metrics import PARSERS


def main():
    metadata = json.loads(Path('data/velociraptor-version.json').read_text())
    if metadata['velociraptor_version'] != '0.77.3' or metadata['triage_targets_sha256'] != '71e36f9cc06ae3bab0414988189e856ddd89c258501e006ac9d8f1bd01621492':
        raise ValueError('upstream inputs differ from the production baseline under comparison')
    source = Path('config/spec.yaml').read_text()
    if source.count('Artifacts:\n') != 1 or any(name in source for name in PARSERS):
        raise ValueError('baseline spec does not match expected unmodified collector')
    additions = ''.join(' ' + name + ': {}\n' for name in PARSERS)
    # Append in the same order as the proposed production spec. With artifact
    # concurrency enabled, prepending parsers would change scheduling too.
    boundary = '# Can be ZIP, GCS, S3, Azure, SMBShare, SFTP'
    if source.count(boundary) != 1:
        raise ValueError('cannot locate the end of baseline artifact selection')
    derived = source.replace(boundary, additions + '\n' + boundary, 1)
    original = 'OptCollectorTemplate: "Velociraptor_Triage_Collector.exe"'
    if derived.count(original) != 1:
        raise ValueError('baseline collector filename does not match expected spec')
    derived = derived.replace(original, 'OptCollectorTemplate: "Velociraptor_Triage_Collector_Parsers.exe"', 1)
    Path('config/spec_benchmark_parsers.yaml').write_text(derived)


if __name__ == '__main__':
    main()
