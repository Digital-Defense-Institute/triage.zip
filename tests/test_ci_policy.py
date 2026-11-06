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

    def test_publication_requires_policy_and_both_successful_collections(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        jobs = self.workflow_jobs()
        self.assertEqual(set(jobs), {'build', 'windows_validate', 'linux_validate', 'publish'})
        build, windows, linux, publish = (jobs[name] for name in ('build', 'windows_validate', 'linux_validate', 'publish'))
        self.assertIn('fetch-depth: 0', build)
        self.assertNotIn('SKIP_IF_VERSION_UNCHANGED:', workflow)
        self.assertIn('run: bash scripts/ci_policy.sh >> "$GITHUB_OUTPUT"', build)
        self.assertIn('build: ${{ steps.policy.outputs.build }}', build)
        self.assertIn('publish: ${{ steps.policy.outputs.publish }}', build)
        self.assertIn('needs: build', windows)
        self.assertIn("if: needs.build.outputs.build == 'true'", windows)
        self.assertIn('runs-on: windows-2022', windows)
        self.assertIn('needs: build', linux)
        self.assertIn("if: needs.build.outputs.build == 'true'", linux)
        self.assertIn('runs-on: ubuntu-24.04', linux)
        self.assertIn('needs: [build, windows_validate, linux_validate]', publish)
        self.assertIn("if: needs.build.outputs.publish == 'true' && needs.windows_validate.result == 'success' && needs.linux_validate.result == 'success'", publish)
        # Either failed/timed out/cancelled/skipped collection job blocks publication.
        self.assertNotIn('always()', publish)
        self.assertIn('concurrency:\n      group: triage-latest-publication\n      cancel-in-progress: false', publish)
        self.assertNotIn('concurrency:', build + windows + linux)
        self.assertLess(build.index('id: policy'), build.index('- name: Run build script'))
        for step in ('Commit version metadata', 'Delete existing latest release',
                     'Delete old latest tag', 'Create Latest Release'):
            self.assertIn(f'- name: {step}', publish)
            self.assertNotIn(f'- name: {step}', build + windows + linux)
        self.assertLess(publish.index('- name: Verify tested payloads'),
                        publish.index('- name: Delete existing latest release'))
        self.assertLess(publish.index('- name: Create Latest Release'),
                        publish.index('- name: Commit version metadata'))
        for script in ('build_collector.sh', 'build_collector_macos.sh'):
            self.assertNotIn('VELO_VERSION_CHANGED=', (ROOT / script).read_text())

    def test_metadata_push_works_without_checkout_branch_upstream(self):
        # SHA checkout + switch -C creates main without tracking configuration.
        # Exercise the actual metadata-push command against an empty local remote.
        import shlex
        publish = self.workflow_jobs()['publish']
        metadata_step = publish.split('      - name: Commit version metadata\n', 1)[1]
        pushes = [line.strip() for line in metadata_step.splitlines()
                  if line.strip().startswith('git push')]
        self.assertEqual(pushes, ['git push origin HEAD:refs/heads/main'])
        with tempfile.TemporaryDirectory() as remote_dir:
            subprocess.check_call(['git', 'init', '--bare', '-q', remote_dir])
            self.git('remote', 'add', 'origin', remote_dir)
            sha = self.git('rev-parse', 'HEAD').strip()
            self.git('switch', '--detach', '-q', sha)
            self.git('switch', '-C', 'main', '-q', sha)
            upstream = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'main@{upstream}'],
                                      cwd=self.repo, capture_output=True, text=True)
            self.assertNotEqual(upstream.returncode, 0)
            self.git(*shlex.split(pushes[0])[1:])
            published_sha = subprocess.check_output(
                ['git', '--git-dir', remote_dir, 'rev-parse', 'refs/heads/main'], text=True).strip()
            self.assertEqual(published_sha, sha)

    def test_same_immutable_build_payloads_are_validated_and_published(self):
        jobs = self.workflow_jobs()
        build, windows, linux, publish = (jobs[name] for name in ('build', 'windows_validate', 'linux_validate', 'publish'))
        self.assertIn('artifact_id: ${{ steps.package.outputs.artifact-id }}', build)
        for consumer in (windows, linux, publish):
            self.assertIn('artifact-ids: ${{ needs.build.outputs.artifact_id }}', consumer)
            self.assertNotIn('bash build_collector.sh', consumer)
        self.assertIn('> SHA256SUMS', build)
        self.assertIn('Get-Content release-inputs/SHA256SUMS', windows)
        self.assertIn('sha256sum --check --strict SHA256SUMS', publish)
        self.assertIn('sha256sum --check --strict SHA256SUMS', linux)
        for platform in ('WINDOWS', 'LINUX'):
            self.assertIn(f'VALIDATED_{platform}_SHA256: ${{{{ needs.{platform.lower()}_validate.outputs.collector_sha256 }}}}', publish)
            self.assertIn(f'test "${{{platform}_SHA256%% *}}" = "$VALIDATED_{platform}_SHA256"', publish)
        self.assertIn('test "$(git rev-parse origin/main)" = "$GITHUB_SHA"', publish)
        self.assertIn('cp release-inputs/data/velociraptor-version.json data/velociraptor-version.json', publish)
        self.assertIn('--target "$GITHUB_SHA"', publish)
        for output in ('Velociraptor_Triage_Collector.exe', 'Velociraptor_Triage_Collector_Linux',
                       'Velociraptor_Triage_Collector_macOS', 'Velociraptor_Triage_Collector_macOS_ARM'):
            self.assertIn('./release-inputs/' + output, publish)
        self.assertNotIn('./datastore/', publish)

    def test_collector_execution_is_bounded_and_evidence_is_not_uploaded(self):
        jobs = self.workflow_jobs()
        build, windows, linux, publish = (jobs[name] for name in ('build', 'windows_validate', 'linux_validate', 'publish'))
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
        self.assertNotIn('contents: write', build + windows + linux)
        self.assertIn('persist-credentials: false', build)
        self.assertIn('persist-credentials: false', windows)

    def test_linux_collection_is_bounded_root_execution_and_only_report_is_uploaded(self):
        linux = self.workflow_jobs()['linux_validate']
        self.assertIn('timeout-minutes: 55', linux)
        self.assertIn('--timeout-seconds 2700', linux)
        self.assertIn('chmod +x "$COLLECTOR"', linux)
        self.assertIn('sudo --preserve-env=GITHUB_ACTIONS,RUNNER_ENVIRONMENT "$(command -v python)"', linux)
        self.assertIn('scripts/run_linux_collection.py --collector "$COLLECTOR"', linux)
        self.assertIn('--output-directory "$RUNNER_TEMP/linux-collection"', linux)
        self.assertIn('set -euo pipefail', linux)
        self.assertIn("report.get('valid') is not True or report.get('collector_sha256') != sys.argv[1]", linux)
        self.assertIn('test "$BEFORE" = "$AFTER"', linux)
        self.assertIn("python -B -m unittest discover -s tests -p 'test_linux*.py' -v", linux)
        self.assertIn('path: linux-validation/validation-report.json', linux)
        self.assertIn('retention-days: 3', linux)
        self.assertIn('persist-credentials: false', linux)
        self.assertNotIn('path: datastore', linux)
        self.assertNotIn('path: linux-collection', linux)
        self.assertNotIn('path: linux-validation/', linux.replace('path: linux-validation/validation-report.json', ''))
        self.assertNotIn('GITHUB_TOKEN:', linux)

    def test_linux_validation_step_rejects_failed_reports_and_changed_bytes(self):
        # Run the workflow's actual shell with a harmless fake collector runner.
        # This catches errors masked by subsequent successful shell commands.
        import hashlib
        import json
        import shutil
        import sys
        import textwrap
        if not shutil.which('sha256sum') or not shutil.which('realpath'):
            self.skipTest('Workflow checksum/path commands unavailable')
        linux = self.workflow_jobs()['linux_validate']
        step = linux.split('      - name: Run and validate Linux collection\n', 1)[1]
        shell = step.split('        run: |\n', 1)[1].split('      # Never upload', 1)[0]
        shell = textwrap.dedent(shell)
        for mode in ('success', 'invalid_report', 'wrong_hash', 'exit_failure', 'mutated', 'corrupt_payload'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                payloads = work / 'release-inputs'
                payloads.mkdir()
                collector = payloads / 'Velociraptor_Triage_Collector_Linux'
                collector.write_bytes(b'harmless test payload')
                checksum = hashlib.sha256(collector.read_bytes()).hexdigest()
                (payloads / 'SHA256SUMS').write_text(f'{checksum}  {collector.name}\n')
                if mode == 'corrupt_payload':
                    collector.write_bytes(b'changed after build')
                scripts = work / 'scripts'
                scripts.mkdir()
                fake_runner = scripts / 'run_linux_collection.py'
                fake_runner.write_text(textwrap.dedent("""
                    import hashlib
                    import json
                    import os
                    from pathlib import Path
                    import sys
                    args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
                    Path('runner-called').touch()
                    mode = os.environ['TEST_MODE']
                    if mode == 'exit_failure':
                        raise SystemExit(7)
                    collector = Path(args['--collector'])
                    digest = hashlib.sha256(collector.read_bytes()).hexdigest()
                    report = {'valid': mode != 'invalid_report',
                              'collector_sha256': '0' * 64 if mode == 'wrong_hash' else digest}
                    destination = Path(args['--report-directory'])
                    destination.mkdir()
                    (destination / 'validation-report.json').write_text(json.dumps(report))
                    if mode == 'mutated':
                        collector.write_bytes(b'changed during execution')
                    """))
                commands = work / 'bin'
                commands.mkdir()
                (commands / 'python').symlink_to(sys.executable)
                sudo = commands / 'sudo'
                sudo.write_text('#!/bin/sh\nshift\nexec "$@"\n')
                sudo.chmod(0o700)
                output = work / 'job-output'
                env = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                           GITHUB_WORKSPACE=str(work), RUNNER_TEMP=str(work / 'runner-temp'),
                           GITHUB_OUTPUT=str(output), TEST_MODE=mode)
                result = subprocess.run(['bash', '-c', shell], cwd=work, env=env,
                                        capture_output=True, text=True)
                if mode == 'success':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(output.read_text(), f'collector_sha256={checksum}\n')
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(output.exists(), 'failed validation emitted publication hash')
                self.assertEqual((work / 'runner-called').exists(), mode != 'corrupt_payload')
