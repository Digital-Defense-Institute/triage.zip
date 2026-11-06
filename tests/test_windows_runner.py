"""Exercise process failure and timeout handling without running a collector."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PWSH = shutil.which('pwsh')


@unittest.skipUnless(PWSH, 'PowerShell is unavailable')
class WindowsRunnerTests(unittest.TestCase):
    def test_script_parses(self):
        result = subprocess.run([PWSH, '-NoProfile', '-Command',
            f"$tokens=$null; $errors=$null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{ROOT}/scripts/run_windows_collection.ps1', "
            "[ref]$tokens, [ref]$errors) | Out-Null; if ($errors) { $errors; exit 1 }"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipIf(__import__('sys').platform == 'win32', 'Unix fake executables')
    def test_completion_failure_and_timeout(self):
        with tempfile.TemporaryDirectory() as folder:
            work = pathlib.Path(folder)
            for body, success, message in (
                    ('exit 0', True, ''), ('exit 7', False, 'code 7'),
                    ('sleep 30', False, 'execution timeout')):
                with self.subTest(body=body):
                    fake = work / 'fake-collector'
                    fake.write_text('#!/bin/sh\n' + body + '\n')
                    fake.chmod(0o700)
                    command = (
                        f". '{ROOT}/scripts/run_windows_collection.ps1'; "
                        f"Invoke-CollectorProcess -Executable '{fake}' -WorkingDirectory '{work}' "
                        f"-Timeout 1 -Stdout '{work}/stdout' -Stderr '{work}/stderr'")
                    result = subprocess.run([PWSH, '-NoProfile', '-Command', command],
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                    if message:
                        self.assertIn(message, result.stderr)

    @unittest.skipIf(__import__('sys').platform == 'win32', 'Non-Windows guard')
    def test_refuses_collection_on_developer_host(self):
        result = subprocess.run([PWSH, '-NoProfile', '-File',
                                 str(ROOT / 'scripts/run_windows_collection.ps1')],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('disposable GitHub-hosted Windows runner', result.stderr)


if __name__ == '__main__':
    unittest.main()
