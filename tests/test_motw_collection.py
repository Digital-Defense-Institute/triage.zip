"""Exercise the production MOTW spec against an isolated upstream NTFS image.

Set VELOCIRAPTOR_BINARY and VELOCIRAPTOR_NTFS_FIXTURE to run. The fixture is
artifacts/testdata/files/test.ntfs.dd from Velocidex/velociraptor v0.77.3.
Only a temporary copy of that image is modified; no host NTFS volume is read.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SHA256 = "4efccac3f92a14da89ae9bca7231644ba25c65c09772c1f06b4e490e691f28ca"
BINARY = os.environ.get("VELOCIRAPTOR_BINARY")
FIXTURE = os.environ.get("VELOCIRAPTOR_NTFS_FIXTURE")
CONTENT = (b"[ZoneTransfer]\r\nZoneId=3\r\n"
           b"HostUrl=https://example.test/payload.hta\r\n"
           b"ReferrerUrl=https://example.test/\r\n")


def stream_fixture(original, content, stream_name="Zone.Identifier"):
    """Replace the last resident ADS in upstream's known 1 KiB MFT record."""
    if hashlib.sha256(original).hexdigest() != FIXTURE_SHA256:
        raise ValueError("unexpected upstream NTFS fixture digest")
    data = bytearray(original)
    base, offset, old_end = 3542016, 384, 456
    record = bytearray(data[base:base + 1024])
    assert record[:4] == b"FILE"
    assert struct.unpack_from("<I", record, old_end)[0] == 0xffffffff
    assert record[offset + 24:offset + 46] == "goodbye.txt".encode("utf-16le")
    usa, count = struct.unpack_from("<HH", record, 4)
    sequence = record[usa:usa + 2]
    for sector in range(1, count):
        end = sector * 512 - 2
        assert record[end:end + 2] == sequence
        record[end:end + 2] = record[usa + sector * 2:usa + sector * 2 + 2]
    name = stream_name.encode("utf-16le")
    content_offset = (24 + len(name) + 7) // 8 * 8
    size = (content_offset + len(content) + 7) // 8 * 8
    assert offset + size + 8 <= len(record)
    attribute = bytearray(record[offset:offset + 24])
    struct.pack_into("<I", attribute, 4, size)
    attribute[9] = len(stream_name)
    struct.pack_into("<I", attribute, 16, len(content))
    struct.pack_into("<H", attribute, 20, content_offset)
    attribute += name
    attribute += bytes(content_offset - len(attribute))
    attribute += content
    attribute += bytes(size - len(attribute))
    record[offset:] = attribute + b"\xff\xff\xff\xff" + bytes(4) + bytes(1024 - offset - size - 8)
    struct.pack_into("<I", record, 24, offset + size + 8)
    for sector in range(1, count):
        end = sector * 512 - 2
        record[usa + sector * 2:usa + sector * 2 + 2] = record[end:end + 2]
        record[end:end + 2] = sequence
    data[base:base + 1024] = record
    return data


@unittest.skipUnless(BINARY and FIXTURE, "set VELOCIRAPTOR_BINARY and VELOCIRAPTOR_NTFS_FIXTURE")
class MotwCollectionTests(unittest.TestCase):
    def collect(self, content=CONTENT, stream_name="Zone.Identifier", profile=True, cap=None):
        with tempfile.TemporaryDirectory(prefix="triage-motw-test-") as directory:
            root = Path(directory)
            image = root / "fixture.dd"
            image.write_bytes(stream_fixture(Path(FIXTURE).read_bytes(), content, stream_name))
            remap = root / "remap.json"
            remap.write_text(json.dumps({"remappings": [{
                "type": "mount",
                "from": {"accessor": "raw_ntfs", "prefix": json.dumps({
                    "DelegateAccessor": "file", "DelegatePath": str(image), "Path": "/Folder A"})},
                "on": {"accessor": "ntfs", "path_type": "ntfs",
                       "prefix": "C:/Users/alice" if profile else "C:/Windows/Fixture"}
            }]}))
            # Materialize CSV in the caller's scope, just as collector argument
            # compilation does. The artifact receives the actual production spec.
            query = '''
LET Spec <= parse_yaml(filename=SpecFile)
LET Args <= Spec.Artifacts.`Generic.Collectors.File`
LET Globs <= SELECT * FROM parse_csv(filename=Args.collectionSpec, accessor="data")
LET _ <= remap(config=read_file(filename=Remap), clear=TRUE)
SELECT * FROM Artifact.Generic.Collectors.File(
  collectionSpec=Globs, Root=Args.Root, Accessor=Args.Accessor,
  MaxFileSize=if(condition=Override, then=Cap, else=Args.MaxFileSize))
'''
            result = subprocess.run([
                str(Path(BINARY).resolve()), "-v", "query", "--dump_dir", str(root / "uploads"),
                "--env", "SpecFile=" + str(ROOT / "config/spec.yaml"),
                "--env", "Remap=" + str(remap), "--env", "Override=" + ("Y" if cap else ""),
                "--env", "Cap=" + str(cap or 0), query,
            ], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("[ERROR]", result.stderr)
            rows = json.loads(result.stdout or "[]")
            uploads = [row for row in rows if row.get("_Source") == "Generic.Collectors.File/Uploads"]
            preserved = [Path(row["DestinationFile"]).read_bytes() for row in uploads]
            return rows, uploads, preserved

    def test_exact_stream_bytes_hash_and_timestamps_without_parent_upload(self):
        rows, uploads, preserved = self.collect()
        self.assertEqual(len(rows), 2)
        self.assertEqual(preserved, [CONTENT])
        self.assertEqual(uploads[0]["SourceFileSha256"], hashlib.sha256(CONTENT).hexdigest())
        self.assertTrue(uploads[0]["SourceFile"].endswith(":Zone.Identifier"))
        for field in ("Created", "Changed", "Modified", "LastAccessed"):
            self.assertTrue(uploads[0][field])

    def test_per_file_cap_inclusive_boundary(self):
        self.assertEqual(self.collect(cap=len(CONTENT) - 1)[1], [])
        self.assertEqual(self.collect(cap=len(CONTENT))[2], [CONTENT])

    def test_other_streams_and_nonprofile_paths_are_not_collected(self):
        self.assertEqual(self.collect(stream_name="UnrelatedStream")[1], [])
        self.assertEqual(self.collect(profile=False)[1], [])

    def test_all_zones_binary_content_and_empty_stream_are_preserved(self):
        for content in (CONTENT.replace(b"ZoneId=3", b"ZoneId=1"), b"binary\x00\xff\xfe", b""):
            with self.subTest(content=content):
                self.assertEqual(self.collect(content=content)[2], [content])


if __name__ == "__main__":
    unittest.main()
