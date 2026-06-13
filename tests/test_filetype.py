import tempfile
import unittest
from pathlib import Path

from revinspector.filetype import detect_file_type


class FileTypeTests(unittest.TestCase):
    def test_detect_script_from_shebang(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample"
            sample.write_bytes(b"#!/usr/bin/env sh\necho hello\n")

            self.assertEqual(detect_file_type(sample), "script")

    def test_detect_pe_magic(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.exe"
            sample.write_bytes(b"MZ" + b"\x00" * 64)

            self.assertEqual(detect_file_type(sample), "PE")

    def test_detect_elf_magic(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample"
            sample.write_bytes(b"\x7fELF" + b"\x00" * 64)

            self.assertEqual(detect_file_type(sample), "ELF")


if __name__ == "__main__":
    unittest.main()
