"""Run the production publication policy against real temporary Git history."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PublicationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.commit('README.md')
        self.before = self.git('rev-parse', 'HEAD').strip()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo, text=True)

    def commit(self, path):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(target.read_text() + '\nchange' if target.exists() else 'new')
        self.git('add', '.')
        self.git('commit', '-qm', 'Test change')

    def policy(self, event='push', ref='refs/heads/main', before=None, **flags):
        env = dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REF=ref,
                   GITHUB_SHA=self.git('rev-parse', 'HEAD').strip(),
                   PUSH_BEFORE=self.before if before is None else before,
                   VELO_VERSION_CHANGED='false', TRIAGE_TARGETS_CHANGED='false',
                   LINUX_TRIAGE_TARGETS_CHANGED='false')
        env.update(flags)
        return subprocess.run(['bash', str(ROOT / 'scripts/ci_policy.sh')],
                              cwd=self.repo, env=env, text=True, capture_output=True)

    def assert_policy(self, build, publish, **kwargs):
        result = self.policy(**kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f'build={str(build).lower()}\npublish={str(publish).lower()}\n')

    def test_docs_site_tests_and_metadata_push_only_validates(self):
        for path in ('README.md', 'index.html', 'AGENTS.md', 'tests/test_example.py',
                     'data/velociraptor-version.json'):
            self.commit(path)
        self.assert_policy(True, False)

    def test_collector_inputs_publish_including_earlier_commit_in_push(self):
        for path in ('config/spec.yaml', 'lib/collector_common.sh', 'build_collector.sh',
                     'build_collector_macos.sh', 'scripts/ci_policy.sh', '.github/workflows/ci.yml'):
            with self.subTest(path=path):
                self.before = self.git('rev-parse', 'HEAD').strip()
                self.commit(path)
                self.commit('README.md')
                self.assert_policy(True, True)

    def test_deletions_and_renames_out_of_config_publish(self):
        self.commit('config/spec.yaml')
        self.before = self.git('rev-parse', 'HEAD').strip()
        self.git('mv', 'config/spec.yaml', 'old-spec.yaml')
        self.git('commit', '-qm', 'Move spec')
        self.assert_policy(True, True)
        self.commit('config/another.yaml')
        self.before = self.git('rev-parse', 'HEAD').strip()
        self.git('rm', '-q', 'config/another.yaml')
        self.git('commit', '-qm', 'Remove spec')
        self.assert_policy(True, True)

    def test_each_upstream_change_publishes_on_main(self):
        for flag in ('VELO_VERSION_CHANGED', 'TRIAGE_TARGETS_CHANGED', 'LINUX_TRIAGE_TARGETS_CHANGED'):
            for event in ('push', 'schedule'):
                with self.subTest(flag=flag, event=event):
                    self.assert_policy(True, True, event=event, **{flag: 'true'})

    def test_unchanged_schedule_skips_both(self):
        self.assert_policy(False, False, event='schedule')

    def test_manual_dispatch_forces_main_publication_only(self):
        self.assert_policy(True, True, event='workflow_dispatch')
        self.assert_policy(True, False, event='workflow_dispatch', ref='refs/heads/feature')

    def test_pull_requests_never_publish_even_with_changes(self):
        for ref in ('refs/pull/19/merge', 'refs/heads/main'):
            self.assert_policy(True, False, event='pull_request', ref=ref, VELO_VERSION_CHANGED='true')

    def test_non_main_push_never_publishes(self):
        self.assert_policy(True, False, ref='refs/heads/feature', VELO_VERSION_CHANGED='true')

    def test_new_branch_compares_against_empty_tree(self):
        self.assert_policy(True, False, before='0' * 40)
        self.commit('config/spec.yaml')
        self.assert_policy(True, True, before='0' * 40)

    def test_missing_history_fails_without_publication_output(self):
        result = self.policy(before='1' * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('unable to compare', result.stderr)

    def test_all_release_mutations_use_prebuild_policy(self):
        # Wiring guard; the event/path behavior is exercised above using Git.
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('fetch-depth: 0', workflow)
        # Once policy approves a build, CI must not enable an independent skip.
        self.assertNotIn('SKIP_IF_VERSION_UNCHANGED:', workflow)
        self.assertIn('run: bash scripts/ci_policy.sh >> "$GITHUB_OUTPUT"', workflow)
        for step in ('Commit version metadata', 'Delete existing latest release',
                     'Delete old latest tag', 'Create Latest Release'):
            self.assertIn(f"- name: {step}\n        if: steps.policy.outputs.publish == 'true'", workflow)
        self.assertLess(workflow.index('id: policy'), workflow.index('- name: Run build script'))
        self.assertLess(workflow.index('- name: Create Latest Release'),
                        workflow.index('- name: Commit version metadata'))
        for script in ('build_collector.sh', 'build_collector_macos.sh'):
            self.assertNotIn('VELO_VERSION_CHANGED=', (ROOT / script).read_text())
