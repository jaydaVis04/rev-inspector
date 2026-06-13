import tempfile
import unittest
from pathlib import Path

from revinspector.strings import categorize_strings, extract_strings


class StringTests(unittest.TestCase):
    def test_extract_and_categorize_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.bin"
            sample.write_bytes(
                b"\x00http://example.invalid/a\x00"
                b"CreateRemoteThread\x00"
                b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
                b"C:\\Users\\Public\\drop.exe\x00"
            )

            categorized = categorize_strings(extract_strings(sample))

            self.assertEqual(categorized["urls"], ["http://example.invalid/a"])
            self.assertEqual(categorized["suspicious_apis"], ["CreateRemoteThread"])
            self.assertEqual(categorized["registry_keys"], ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"])
            self.assertEqual(categorized["windows_paths"], ["C:\\Users\\Public\\drop.exe"])


if __name__ == "__main__":
    unittest.main()
