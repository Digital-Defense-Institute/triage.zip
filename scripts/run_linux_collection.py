#!/usr/bin/env python3
"""Run the production collector only on a disposable hosted Linux runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys


class RunnerFailure(RuntimeError):
    pass


def collector_environment():
    # The collection does not need CI tokens or setup credentials in its env.
    environment = {'PATH': os.environ.get('PATH', os.defpath),
                   'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    if 'HOME' in os.environ:
        environment['HOME'] = os.environ['HOME']
    return environment


def run_collector(executable, directory, timeout):
    """Bound execution and terminate its process group, including external tools."""
    with (directory / 'process.stdout.log').open('wb') as stdout, \
         (directory / 'process.stderr.log').open('wb') as stderr:
        process = subprocess.Popen([str(executable)], cwd=directory,
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env=collector_environment(), start_new_session=True)
        try:
            try:
                result = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                raise RunnerFailure('execution_timeout') from None
            if result != 0:
                raise RunnerFailure('collector_nonzero_exit')
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collector', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    parser.add_argument('--report-directory', required=True, type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=2700)
    args = parser.parse_args()
    if (sys.platform != 'linux' or os.geteuid() != 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        parser.error('collection requires root on a disposable GitHub-hosted Linux runner')
    if not 1 <= args.timeout_seconds <= 7200:
        parser.error('timeout must be between 1 and 7200 seconds')
    output = args.output_directory.resolve()
    reports = args.report_directory.resolve()
    if output.exists():
        parser.error('output directory must be new to exclude stale collections')
    if reports == output or output in reports.parents:
        parser.error('report directory must be outside the collection directory')
    collector = args.collector.resolve(strict=True)
    reports.mkdir(parents=True, exist_ok=True)
    report_path = reports / 'validation-report.json'
    report = {'valid': False, 'platform': 'linux', 'stage': 'starting'}
    result = 1
    created = False
    try:
        output.mkdir(mode=0o700)
        created = True
        digest = sha256(collector)
        report['collector_sha256'] = digest
        executable = output / 'Velociraptor_Triage_Collector_Linux'
        shutil.copyfile(collector, executable)
        executable.chmod(0o700)
        if sha256(executable) != digest:
            raise RunnerFailure('collector_copy_mismatch')
        report['stage'] = 'execution'
        run_collector(executable, output, args.timeout_seconds)
        if sha256(executable) != digest or sha256(collector) != digest:
            raise RunnerFailure('collector_bytes_changed')
        report['stage'] = 'container-validation'
        collections = list(output.glob('Triage-*.zip'))
        if len(collections) != 1 or not collections[0].is_file():
            raise RunnerFailure('expected_one_collection_zip')
        validator = Path(__file__).with_name('validate_linux_collection.py')
        # Only the validator's fixed diagnostic JSON is retained, never raw logs.
        validation = subprocess.run([sys.executable, '-B', str(validator), str(collections[0]),
                                     '--report', str(report_path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=collector_environment())
        if not report_path.is_file():
            raise RunnerFailure('validator_report_missing')
        payload = json.loads(report_path.read_text(encoding='utf-8'))
        if not isinstance(payload, dict):
            raise RunnerFailure('validator_report_malformed')
        report = payload
        report.update(collector_sha256=digest, platform='linux', stage='container-validation')
        if validation.returncode != 0 or report.get('valid') is not True:
            raise RunnerFailure('container_validation_failed')
        report['stage'] = 'complete'
        result = 0
    except RunnerFailure as error:
        report.update(valid=False, failure_reason=str(error))
    except (OSError, ValueError):
        report.update(valid=False, failure_reason='validation_runner_failed')
    finally:
        if created:
            shutil.rmtree(output)
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, sort_keys=True))
    return result


if __name__ == '__main__':
    sys.exit(main())
