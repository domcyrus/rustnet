"""Regression cases for the Windows import-table check."""

import unittest

from verify_windows_imports import verify_imports


def imports(eager=(), delayed=()):
    return "\n".join(
        [
            "Dump of file rustnet.exe",
            "  Section contains the following imports:",
            *[f"    {name}" for name in eager],
            "  Section contains the following delay load imports:",
            *[f"    {name}" for name in delayed],
            "  Summary",
        ]
    )


class ImportChecks(unittest.TestCase):
    def test_capture_can_omit_packet_dll_after_native_address_enumeration(self):
        verify_imports(imports(eager=("KERNEL32.dll",), delayed=("wpcap.dll",)))

    def test_both_npcap_libraries_can_be_delayed(self):
        verify_imports(imports(delayed=("Packet.dll", "wpcap.dll")))

    def test_import_names_are_case_insensitive(self):
        verify_imports(imports(delayed=("PACKET.DLL", "WPCAP.DLL")))

    def test_eager_packet_dll_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "packet.dll is not a delay"):
            verify_imports(imports(eager=("Packet.dll",), delayed=("wpcap.dll",)))

    def test_eager_capture_import_is_rejected_even_if_also_delayed(self):
        with self.assertRaisesRegex(ValueError, "wpcap.dll is not a delay"):
            verify_imports(imports(eager=("wpcap.dll",), delayed=("wpcap.dll",)))

    def test_capture_import_is_required(self):
        with self.assertRaisesRegex(ValueError, "wpcap.dll is missing"):
            verify_imports(imports(delayed=("Packet.dll",)))

    def test_import_symbol_text_does_not_count_as_a_dll_entry(self):
        with self.assertRaisesRegex(ValueError, "wpcap.dll is missing"):
            verify_imports(imports(delayed=("123 symbol_containing_wpcap.dll",)))

    def test_unknown_section_does_not_hide_eager_imports(self):
        with self.assertRaisesRegex(ValueError, "wpcap.dll is not a delay"):
            verify_imports("wpcap.dll")


if __name__ == "__main__":
    unittest.main()
