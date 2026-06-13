import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_cli_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.sh"
            sample.write_text("#!/usr/bin/env sh\ncurl https://example.invalid\n", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, "-m", "revinspector", str(sample), "--json"],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertIn('"type": "script"', result.stdout)
            self.assertIn("network access", result.stdout)

    def test_cli_writes_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "sample.sh"
            report = Path(tempdir) / "report.html"
            sample.write_text("#!/usr/bin/env sh\ncurl https://example.invalid\n", encoding="utf-8")

            subprocess.run(
                [sys.executable, "-m", "revinspector", str(sample), "--html-out", str(report)],
                check=True,
                capture_output=True,
                text=True,
            )

            html = report.read_text(encoding="utf-8")
            self.assertIn("<!doctype html>", html)
            self.assertIn("Static analysis only", html)
            self.assertIn("network access", html)


if __name__ == "__main__":
    unittest.main()
