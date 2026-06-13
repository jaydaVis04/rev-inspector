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


if __name__ == "__main__":
    unittest.main()
