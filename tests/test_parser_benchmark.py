"""Synthetic-only tests for payload-free parser benchmark reporting."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('benchmark_metrics', ROOT / 'scripts/benchmark_collection_metrics.py')
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)


class BenchmarkTests(unittest.TestCase):
    def test_workflow_is_manual_read_only_and_cannot_publish(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('  workflow_dispatch:', workflow)
        self.assertIn('  contents: read', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('gh release', workflow)
        self.assertNotIn('git push', workflow)
        self.assertNotIn('\n  publish:', workflow)
        self.assertNotIn('\n  push:', workflow)

    def summary(self, variant, artifacts, payload):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('collection_context.json', json.dumps({'request': {'artifacts': artifacts}}))
                archive.writestr('results/Windows.Forensics.SRUM%2FNetwork Usage.json', payload)
            return metrics.summarize(path, variant)

    def test_fixed_counts_do_not_expose_result_content(self):
        result = self.summary('parsers', metrics.BASELINE + metrics.PARSERS,
                              json.dumps({'SECRET': 'PRIVATE EVIDENCE'}) + '\n')
        self.assertEqual(result['parser_rows']['Windows.Forensics.SRUM'], 1)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_wrong_selection_is_rejected(self):
        for variant in ('baseline', 'parsers'):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                self.summary(variant, metrics.BASELINE + ('Generic.Collectors.File',), '')

    def test_missing_parser_rows_remain_explicitly_zero(self):
        result = self.summary('parsers', metrics.BASELINE + metrics.PARSERS, '')
        self.assertEqual(set(result['parser_rows'].values()), {0})


if __name__ == '__main__':
    unittest.main()
