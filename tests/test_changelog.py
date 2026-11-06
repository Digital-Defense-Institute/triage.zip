"""Check the shared changelog's rendered views and source-backed chronology."""
from html.parser import HTMLParser
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_changelog", ROOT / "site/render_changelog.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.local_files, self.fragments = [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        target = attrs.get("href", attrs.get("src", ""))
        if target.startswith("#"):
            self.fragments.append(target[1:])
        elif target and ":" not in target:
            self.local_files.append(target)


class ChangelogTests(unittest.TestCase):
    def test_generated_outputs_are_current(self):
        data = renderer.load_entries()
        self.assertEqual((ROOT / "changelog.html").read_text(), renderer.render_html(data))
        self.assertEqual((ROOT / "CHANGELOG.md").read_text(), renderer.render_markdown(data))

    def test_static_page_has_valid_anchors_and_local_resources(self):
        parser = PageParser()
        parser.feed((ROOT / "changelog.html").read_text())
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for fragment in parser.fragments:
            self.assertIn(fragment, parser.ids)
        for name in parser.local_files:
            self.assertTrue((ROOT / name).is_file(), name)
        for entry in renderer.load_entries()["entries"]:
            self.assertIn(entry["id"], parser.ids)
            for text in entry["changes"]:
                self.assertIn(renderer.escape(text), (ROOT / "changelog.html").read_text())

    def test_historical_sources_are_in_reviewed_main_history(self):
        # Sources must be in this checkout's history, not experimental branches.
        baseline = "HEAD"
        for entry in renderer.load_entries()["entries"]:
            if not entry["date"]:
                continue
            for source in entry["sources"]:
                revision = source.get("commit")
                if revision:
                    result = subprocess.run(["git", "merge-base", "--is-ancestor", revision, baseline],
                                            cwd=ROOT, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, f"Unverified historical source: {revision}")
                    if entry["date"] <= "2026-10-06":
                        timestamp = subprocess.check_output(
                            ["git", "show", "-s", "--format=%cI", revision], cwd=ROOT, text=True).strip()
                        merged = datetime.fromisoformat(timestamp).astimezone(timezone.utc).date()
                        self.assertEqual(str(merged), entry["date"], revision)

    def test_html_escapes_source_content(self):
        sample = {"id": "escape-test", "date": None, "kind": "Proposed",
                  "title": "<script>bad()</script>", "platforms": ["Windows"],
                  "changes": ['<img src=x onerror="bad()">'],
                  "sources": [{"label": "<unsafe>", "url": "https://github.com/test/test"}]}
        html = renderer.html_entry(sample)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img", html)
        self.assertIn("&lt;unsafe&gt;", html)


if __name__ == "__main__":
    unittest.main()
