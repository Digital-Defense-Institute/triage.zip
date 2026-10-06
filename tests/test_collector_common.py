"""Exercise actual Bash helpers with local synthetic release/executable fixtures."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "lib/collector_common.sh"


def shell(code, *args, cwd=None):
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", '. "$1"; shift; ' + code,
         "test", str(HELPERS), *map(str, args)], text=True, capture_output=True, cwd=cwd)


def asset(name):
    return {"name": name, "browser_download_url": "https://example.invalid/" + name,
            "size": 123, "digest": "sha256:" + "a" * 64}


class SelectionTests(unittest.TestCase):
    def select(self, names, arch="linux-amd64", version=""):
        result = shell('select_velociraptor_asset "$1" "$2" "$3"',
                       json.dumps({"tag_name": "v0.76", "assets": [asset(n) for n in names]}),
                       arch, version)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_numeric_latest_and_exact_suffix(self):
        selected = self.select([
            "velociraptor-v0.77.9-linux-amd64.gz",
            "velociraptor-v0.77.10-linux-amd64.gz",
            "velociraptor-v0.99.0-linux-amd64-musl.gz",
            "velociraptor-v0.99.0-linux-amd64-sumo.gz",
            "velociraptor-v0.99.0-linux-arm64.gz",
            "velociraptor-v0.99.0-linux-amd64.sig",
            "velociraptor-v0.99.0-linux-amd64.gz.sig",
            "other-velociraptor-v0.99.0-linux-amd64.gz",
            "velociraptor-v0.99.0-rc1-linux-amd64.gz"])
        self.assertEqual(selected["version"], "0.77.10")
        self.assertEqual(selected["size"], 123)
        self.assertEqual(selected["digest"], "sha256:" + "a" * 64)

    def test_raw_release(self):
        self.assertEqual(self.select(["velociraptor-v0.76.5-linux-amd64"])["version"], "0.76.5")

    def test_gzip_tie_preference_is_order_independent(self):
        names = ["velociraptor-v0.77.3-linux-amd64.gz", "velociraptor-v0.77.3-linux-amd64"]
        for candidates in (names, names[::-1]):
            self.assertTrue(self.select(candidates)["name"].endswith(".gz"))

    def test_exact_darwin_parity_for_both_formats(self):
        for suffix in ("", ".gz"):
            names = [f"velociraptor-v{v}-darwin-arm64{suffix}" for v in ("0.77.2", "0.77.3", "0.77.4")]
            selected = self.select(names, "darwin-arm64", "0.77.3")
            self.assertEqual(selected["name"], "velociraptor-v0.77.3-darwin-arm64" + suffix)
            self.assertIsNone(self.select(names, "darwin-arm64", "0.77.5")["url"])

    def test_missing_architecture_and_empty_release(self):
        self.assertIsNone(self.select(["velociraptor-v0.77.3-darwin-amd64.gz"])["url"])
        self.assertIsNone(self.select([])["version"])


# Minimal headers recognized by the real `file` command. These are synthetic
# parser fixtures, never executed and never claimed to be real Velociraptor.
ELF = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
MACH_X64 = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 0, 0, 0, 0)
MACH_ARM = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.output = self.directory / "velociraptor"
        self.output.write_bytes(b"previous validated binary")

    def download(self, payload, name="velociraptor-v0.77.3-linux-amd64.gz", updates=None,
                 downloader='cp "$1" "$2"'):
        source = self.directory / "source"
        source.write_bytes(payload)
        metadata = {"name": name, "url": str(source), "size": len(payload),
                    "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
        metadata.update(updates or {})
        # Replace only the transport; selection, verification, decompression,
        # chmod and publication all run the real production implementation.
        result = shell('download_with_retry() { ' + downloader + '; }; '
                       'download_velociraptor_asset "$1" "$2"',
                       json.dumps(metadata), self.output)
        self.assertEqual(list(self.directory.glob("*.download.*")), [], "temporary data leaked")
        return result

    def assert_failure(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.output.read_bytes(), b"previous validated binary")

    def test_raw_and_gzip_all_build_architectures(self):
        for arch, binary in (("linux-amd64", ELF), ("darwin-amd64", MACH_X64), ("darwin-arm64", MACH_ARM)):
            for compressed in (False, True):
                with self.subTest(arch=arch, compressed=compressed):
                    payload = gzip.compress(binary) if compressed else binary
                    name = "velociraptor-v0.77.3-" + arch + (".gz" if compressed else "")
                    result = self.download(payload, name)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.output.read_bytes(), binary)
                    self.assertTrue(os.access(self.output, os.X_OK))

    def test_old_release_without_size_or_digest(self):
        result = self.download(ELF, "velociraptor-v0.76.5-linux-amd64", {"size": None, "digest": None})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_size_and_digest_mismatch(self):
        for updates in ({"size": 999999}, {"digest": "sha256:" + "0" * 64}, {"digest": "md5:unsupported"}):
            with self.subTest(updates=updates):
                self.assert_failure(self.download(gzip.compress(ELF), updates=updates))

    def test_corrupt_and_truncated_gzip(self):
        for payload in (b"not gzip", gzip.compress(ELF)[:-5]):
            self.assert_failure(self.download(payload))

    def test_empty_and_html_and_wrong_architecture(self):
        for payload in (b"", gzip.compress(b""), gzip.compress(b"<html>error</html>"), gzip.compress(MACH_ARM)):
            self.assert_failure(self.download(payload))

    def test_failed_download_cleans_partial_file(self):
        self.assert_failure(self.download(gzip.compress(ELF), downloader='printf partial > "$2"; return 1'))

    def test_missing_asset_fails_without_publishing(self):
        self.assert_failure(self.download(gzip.compress(ELF), updates={"name": None, "url": None}))


class ArtifactVerificationTests(unittest.TestCase):
    def test_old_and_new_verifier_flags_and_error_propagation(self):
        for modern, exit_code in ((False, 0), (True, 0), (True, 1)):
            with self.subTest(modern=modern, exit_code=exit_code), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                for platform, name in (("Windows", "Windows.Triage.Targets"), ("Linux", "Linux.Triage.UAC")):
                    artifact = root / f"datastore/artifact_definitions/{platform}/Triage/{name}.yaml"
                    artifact.parent.mkdir(parents=True)
                    artifact.write_text("name: " + name)
                binary = root / "verifier"
                binary.write_text("#!/bin/bash\n"
                                  'if [[ "$*" == *--help* ]]; then\n'
                                  + ("echo '--[no-]nowall'\n" if modern else "echo legacy-verifier\n")
                                  + 'exit 0\nfi\nprintf "%s\\n" "$@" > args\n'
                                  + f"exit {exit_code}\n")
                binary.chmod(0o755)
                result = shell('verify_triage_artifacts "$1"', binary, cwd=d)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                args = (root / "args").read_text().splitlines()
                self.assertEqual("--nowall" in args, modern)
                self.assertIn("--builtin", args)
                self.assertEqual(sum(a.endswith(".yaml") for a in args), 2)

    def test_missing_bundle_fails_before_verification(self):
        with tempfile.TemporaryDirectory() as d:
            result = shell('verify_triage_artifacts /does/not/exist', cwd=d)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing Windows or Linux", result.stderr)


class BuildContractTests(unittest.TestCase):
    def test_four_platform_matrix_and_no_x86_spec(self):
        self.assertFalse((ROOT / "config/spec_x86.yaml").exists())
        expected = {"spec.yaml", "spec_linux.yaml", "spec_macos.yaml", "spec_macos_arm.yaml"}
        self.assertEqual({p.name for p in (ROOT / "config").glob("spec*.yaml")}, expected)
        for script in ("build_collector.sh", "build_collector_macos.sh"):
            contents = (ROOT / script).read_text()
            self.assertEqual(set(re.findall(r'collector --datastore ./datastore/ ./config/(\S+)', contents)), expected)
            self.assertNotIn("spec_x86", contents)
            self.assertNotIn("Collector_x86", contents)
            # ARM host selection must not change the x64 embedded tool input.
            self.assertIn('--download ./velociraptor_darwin_amd64', contents)
            self.assertIn('--download ./velociraptor_darwin_arm64', contents)
        for spec in (ROOT / "config").glob("*.yaml"):
            self.assertNotIn("Windows_x86", spec.read_text())

    def test_macos_native_host_selection(self):
        script = (ROOT / "build_collector_macos.sh").read_text()
        case = script[script.index('case "$(uname -m)"'):script.index("esac") + 4]
        for machine, expected in (("arm64", "darwin-arm64"), ("x86_64", "darwin-amd64")):
            result = shell('uname() { printf "%s" ' + machine + '; }; '
                           + case + '; printf "%s" "$host_arch"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected)
        result = shell('uname() { echo unsupported; }; ' + case)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('select_velociraptor_asset "$response" "$host_arch"', script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
