#!/usr/bin/env python3
"""Focused tests for RPM digest validation and archive metadata mapping."""

import importlib.util
import io
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("packaging_check", Path(__file__).with_name("check-service-packaging.py"))
packaging_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging_check)


class RpmExtractionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = Path(self.directory.name) / "example.rpm"
        self.package.write_bytes(b"test package")

    def archive(self, mode=0o644):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            member = tarfile.TarInfo("./usr/share/doc/rustnet/SERVICE.md")
            member.mode = mode
            member.size = 5
            archive.addfile(member, io.BytesIO(b"guide"))
        return buffer.getvalue()

    def test_extracts_archive_using_rpm_metadata_modes(self):
        mode = stat.S_IFREG | 0o644
        listing = f"/usr/share/doc/rustnet/SERVICE.md\t{mode}\n".encode()
        with patch.object(subprocess, "check_output", side_effect=[b"digests OK", listing, self.archive()]) as command:
            self.assertEqual(
                packaging_check.rpm_members(self.package),
                {"/usr/share/doc/rustnet/SERVICE.md": (mode, b"guide")},
            )
        self.assertEqual(command.call_args_list[0].args[0], ("rpm", "--checksig", str(self.package)))
        self.assertEqual(command.call_args_list[2].args[0], ["rpm2archive", "-n", "-"])

    def test_failed_digest_check_stops_before_extraction(self):
        error = subprocess.CalledProcessError(1, ["rpm", "--checksig", str(self.package)])
        with patch.object(subprocess, "check_output", side_effect=error) as command:
            with self.assertRaises(subprocess.CalledProcessError):
                packaging_check.rpm_members(self.package)
        self.assertEqual(command.call_count, 1)

    def test_rejects_archive_mode_mismatch(self):
        listing = f"/usr/share/doc/rustnet/SERVICE.md\t{stat.S_IFREG | 0o644}\n".encode()
        with patch.object(subprocess, "check_output", side_effect=[b"digests OK", listing, self.archive(0o600)]):
            with self.assertRaisesRegex(ValueError, "RPM mode mismatch"):
                packaging_check.rpm_members(self.package)


if __name__ == "__main__":
    unittest.main()
