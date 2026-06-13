import unittest

try:
    from fastapi.testclient import TestClient
except (ImportError, RuntimeError):
    TestClient = None


@unittest.skipIf(TestClient is None, "FastAPI is not installed")
class WebGuiTests(unittest.TestCase):
    def test_index_page(self) -> None:
        from web.app import app

        client = TestClient(app)
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Rev Inspector", response.text)
        self.assertIn("Static analysis only", response.text)

    def test_upload_report_page(self) -> None:
        from web.app import app

        client = TestClient(app)
        response = client.post(
            "/analyze",
            files={"file": ("sample.sh", b"#!/usr/bin/env sh\ncurl https://example.invalid\n")},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Analysis Report", response.text)
        self.assertIn("network access", response.text)


if __name__ == "__main__":
    unittest.main()
