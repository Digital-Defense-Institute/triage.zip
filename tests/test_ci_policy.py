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

    def workflow_jobs(self):
        # No YAML dependency: job keys are the workflow's two-space mapping.
        import re
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        matches = list(re.finditer(r'^  ([a-z_]+):\n', workflow[workflow.index('jobs:'):], re.M))
        jobs = workflow[workflow.index('jobs:'):]
        return {match.group(1): jobs[match.start():matches[i + 1].start() if i + 1 < len(matches) else len(jobs)]
                for i, match in enumerate(matches)}

    def test_publication_requires_policy_and_successful_windows_validation(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        jobs = self.workflow_jobs()
        self.assertEqual(set(jobs), {'build', 'windows_validate', 'publish'})
        build, windows, publish = (jobs[name] for name in ('build', 'windows_validate', 'publish'))
        self.assertIn('fetch-depth: 0', build)
        self.assertNotIn('SKIP_IF_VERSION_UNCHANGED:', workflow)
        self.assertIn('run: bash scripts/ci_policy.sh >> "$GITHUB_OUTPUT"', build)
        self.assertIn('build: ${{ steps.policy.outputs.build }}', build)
        self.assertIn('publish: ${{ steps.policy.outputs.publish }}', build)
        self.assertIn('needs: build', windows)
        self.assertIn("if: needs.build.outputs.build == 'true'", windows)
        self.assertIn('runs-on: windows-2022', windows)
        self.assertIn('needs: [build, windows_validate]', publish)
        self.assertIn("if: needs.build.outputs.publish == 'true' && needs.windows_validate.result == 'success'", publish)
        # A failed/timed out/cancelled/skipped Windows job cannot enter publish.
        self.assertNotIn('always()', publish)
        self.assertLess(build.index('id: policy'), build.index('- name: Run build script'))
        for step in ('Commit version metadata', 'Delete existing latest release',
                     'Delete old latest tag', 'Create Latest Release'):
            self.assertIn(f'- name: {step}', publish)
            self.assertNotIn(f'- name: {step}', build + windows)
        self.assertLess(publish.index('- name: Verify tested payloads'),
                        publish.index('- name: Delete existing latest release'))
        self.assertLess(publish.index('- name: Create Latest Release'),
                        publish.index('- name: Commit version metadata'))
        for script in ('build_collector.sh', 'build_collector_macos.sh'):
            self.assertNotIn('VELO_VERSION_CHANGED=', (ROOT / script).read_text())

    def test_same_immutable_build_payloads_are_validated_and_published(self):
        jobs = self.workflow_jobs()
        build, windows, publish = (jobs[name] for name in ('build', 'windows_validate', 'publish'))
        self.assertIn('artifact_id: ${{ steps.package.outputs.artifact-id }}', build)
        for consumer in (windows, publish):
            self.assertIn('artifact-ids: ${{ needs.build.outputs.artifact_id }}', consumer)
            self.assertNotIn('bash build_collector.sh', consumer)
        self.assertIn('> SHA256SUMS', build)
        self.assertIn('Get-Content release-inputs/SHA256SUMS', windows)
        self.assertIn('sha256sum --check --strict SHA256SUMS', publish)
        self.assertIn('VALIDATED_SHA256: ${{ needs.windows_validate.outputs.collector_sha256 }}', publish)
        self.assertIn('test "${ACTUAL_SHA256%% *}" = "$VALIDATED_SHA256"', publish)
        self.assertIn('test "$(git rev-parse origin/main)" = "$GITHUB_SHA"', publish)
        self.assertIn('cp release-inputs/data/velociraptor-version.json data/velociraptor-version.json', publish)
        self.assertIn('--target "$GITHUB_SHA"', publish)
        for output in ('Velociraptor_Triage_Collector.exe', 'Velociraptor_Triage_Collector_Linux',
                       'Velociraptor_Triage_Collector_macOS', 'Velociraptor_Triage_Collector_macOS_ARM'):
            self.assertIn('./release-inputs/' + output, publish)
        self.assertNotIn('./datastore/', publish)

    def test_collector_execution_is_bounded_and_evidence_is_not_uploaded(self):
        jobs = self.workflow_jobs()
        build, windows, publish = (jobs[name] for name in ('build', 'windows_validate', 'publish'))
        self.assertIn('timeout-minutes: 55', windows)
        self.assertIn('-TimeoutSeconds 2700', windows)
        self.assertIn('./scripts/run_windows_collection.ps1 -Collector $collector', windows)
        self.assertIn('-OutputDirectory "$env:RUNNER_TEMP/windows-collection"', windows)
        self.assertIn('if ($LASTEXITCODE -ne 0)', windows)
        self.assertIn('$report.valid -ne $true -or $report.collector_sha256 -ne $before', windows)
        self.assertIn('if ($before -ne $after)', windows)
        self.assertIn("python -B -m unittest discover -s tests -p 'test_windows*.py' -v", windows)
        self.assertIn('path: windows-validation/validation-report.json', windows)
        self.assertIn('retention-days: 3', windows)
        self.assertNotIn('path: datastore', build)
        self.assertNotIn('path: windows-collection', windows)
        self.assertNotIn('path: windows-validation/', windows.replace('path: windows-validation/validation-report.json', ''))
        # Read-only tokens on jobs that execute freshly downloaded tools/data.
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertIn('permissions:\n      contents: write', publish)
        self.assertNotIn('contents: write', build + windows)
        self.assertIn('persist-credentials: false', build)
        self.assertIn('persist-credentials: false', windows)
