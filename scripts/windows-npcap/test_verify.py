"""Portable tests of the runtime validator's pass/fail decisions."""

import json
from pathlib import Path
import tempfile
import unittest

from verify import DLLS, pe_machine, validate_result


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.expected = {name: str(Path("system") / "Npcap" / name) for name in DLLS}
        self.result = {
            "label": "test",
            "marker_executed": False,
            "modules": set(self.expected.values()),
            "returncode": 0,
            "stdout": json.dumps({"type": "snapshot", "runtime": {
                "status": "stopped", "capture_status": "healthy",
            }}),
            "stderr": "",
        }

    def validate(self, state="installed", arguments=("--headless",)):
        validate_result(self.result, self.expected, state, arguments)

    def test_healthy_capture_accepts_both_system_modules(self):
        self.validate()

    def test_either_module_from_another_directory_fails(self):
        for name in DLLS:
            with self.subTest(name=name):
                self.result["modules"] = set(self.expected.values()) | {
                    str(Path("app") / name),
                }
                with self.assertRaisesRegex(RuntimeError, "unexpected"):
                    self.validate()

    def test_marker_fails_even_if_module_was_unloaded(self):
        self.result["marker_executed"] = True
        with self.assertRaisesRegex(RuntimeError, "marker DLL executed"):
            self.validate()

    def test_missing_module_observations_fail_closed(self):
        for name in DLLS:
            with self.subTest(name=name):
                self.result["modules"] = set(self.expected.values()) - {self.expected[name]}
                with self.assertRaisesRegex(RuntimeError, "both modules were not observed"):
                    self.validate()

    def test_failed_startup_rejects_dependency_resolution_failure(self):
        self.result["returncode"] = 0xC0000139
        with self.assertRaisesRegex(RuntimeError, "capture failed"):
            self.validate()

    def test_unhealthy_or_unfinished_snapshot_fails(self):
        for runtime in ({"status": "stopping", "capture_status": "healthy"},
                        {"status": "stopped", "capture_status": "failed"}):
            with self.subTest(runtime=runtime):
                self.result["stdout"] = json.dumps({"type": "snapshot", "runtime": runtime})
                with self.assertRaisesRegex(RuntimeError, "completed headless snapshot"):
                    self.validate()

    def test_absent_runtime_requires_missing_dependency_diagnostic(self):
        self.result.update(modules=set(), returncode=1, stderr="Npcap is not installed")
        self.validate("absent")
        self.result["stderr"] = "unexpected crash"
        with self.assertRaisesRegex(RuntimeError, "missing Npcap diagnostic"):
            self.validate("absent")

    def test_absent_runtime_rejects_success_or_loaded_module(self):
        self.result.update(modules=set(), returncode=0, stderr="Npcap is not installed")
        with self.assertRaisesRegex(RuntimeError, "missing Npcap diagnostic"):
            self.validate("absent")
        self.result.update(returncode=1, modules={self.expected["Packet.dll"]})
        with self.assertRaisesRegex(RuntimeError, "loaded on the absent"):
            self.validate("absent")

    def test_help_and_version_require_success_without_npcap(self):
        for flag in ("--help", "--version"):
            with self.subTest(flag=flag):
                self.result.update(modules=set(), returncode=0)
                self.validate(arguments=(flag,))
                self.result["modules"] = set(self.expected.values())
                with self.assertRaisesRegex(RuntimeError, "help/version failed or loaded"):
                    self.validate(arguments=(flag,))
                self.result.update(modules=set(), returncode=1)
                with self.assertRaisesRegex(RuntimeError, "help/version failed or loaded"):
                    self.validate(arguments=(flag,))

    def test_pe_machine_reads_architecture_and_rejects_non_pe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.exe"
            for architecture in (0x14C, 0x8664):
                data = bytearray(128)
                data[:2] = b"MZ"
                data[0x3C:0x40] = (64).to_bytes(4, "little")
                data[64:68] = b"PE\0\0"
                data[68:70] = architecture.to_bytes(2, "little")
                path.write_bytes(data)
                self.assertEqual(pe_machine(path), architecture)
            path.write_bytes(b"invalid")
            with self.assertRaisesRegex(RuntimeError, "Not a PE image"):
                pe_machine(path)


if __name__ == "__main__":
    unittest.main()
