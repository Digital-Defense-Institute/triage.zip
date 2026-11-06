"""Extract only fixed artifact counts and byte totals from disposable evidence."""
import argparse
import json
from pathlib import Path
from urllib.parse import unquote
import zipfile

BASELINE = ('Windows.Triage.Targets', 'Windows.Sysinternals.Autoruns')
PARSERS = ('Windows.Forensics.SRUM', 'Windows.Forensics.Bam',
           'Windows.Registry.UserAssist', 'Windows.Registry.AppCompatCache',
           'Windows.Forensics.Amcache')


def summarize(path, variant):
    with zipfile.ZipFile(path) as archive:
        context = json.loads(archive.read('collection_context.json'))
        expected = set(BASELINE + (PARSERS if variant == 'parsers' else ()))
        if set(context['request']['artifacts']) != expected:
            raise ValueError('benchmark artifact selection differs from expected variant')
        counts = dict.fromkeys(PARSERS, 0)
        sizes = dict.fromkeys(PARSERS, 0)
        for info in archive.infolist():
            if not info.filename.startswith('results/') or not info.filename.endswith('.json'):
                continue
            artifact = unquote(info.filename[len('results/'):-len('.json')]).split('/')[0]
            if artifact not in counts:
                continue
            sizes[artifact] += info.file_size
            with archive.open(info) as stream:
                for line in stream:
                    if line.strip():
                        if not isinstance(json.loads(line), dict):
                            raise ValueError('non-object parser result')
                        counts[artifact] += 1
        return {'variant': variant, 'zip_bytes': Path(path).stat().st_size,
                'parser_rows': counts, 'parser_result_bytes': sizes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('--variant', choices=('baseline', 'parsers'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = summarize(args.collection, args.variant)
    except (KeyError, ValueError, OSError, zipfile.BadZipFile):
        result = {'valid': False, 'error': 'cannot summarize expected benchmark collection'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    return 1 if result.get('valid') is False else 0


if __name__ == '__main__':
    raise SystemExit(main())
