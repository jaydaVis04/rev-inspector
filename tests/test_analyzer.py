import tempfile
import unittest
from pathlib import Path

from revinspector.analyzer import analyze_file


class AnalyzerFacadeTests(unittest.TestCase):
    def test_analyzer_returns_gui_friendly_report(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.sh"
            sample.write_text("#!/usr/bin/env sh\ncurl https://example.invalid\n", encoding="utf-8")

            report = analyze_file(sample)

            self.assertEqual(report["file_type"], "script")
            self.assertEqual(report["size_bytes"], sample.stat().st_size)
            self.assertTrue(report["sha256"])
            self.assertIn("network access", report["indicators"])
            self.assertIn("findings", report)
            self.assertIn("hex_preview", report)
            self.assertEqual(report["hex_preview"][0]["offset"], "00000000")


if __name__ == "__main__":
    unittest.main()
