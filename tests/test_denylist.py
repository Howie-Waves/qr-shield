import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services import denylist


class DenylistEvidenceTests(unittest.TestCase):
    def test_matching_hash_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "denylist.json"
            path.write_text(
                json.dumps(
                    {
                        "version": "test-v1",
                        "entries": [
                            {
                                "hostname_sha256": denylist.hostname_hash("listed.test"),
                                "reason_code": "TEST_MATCH",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with patch.object(denylist, "DENYLIST_PATH", path):
                result = denylist.check_denylist("https://listed.test/path")
        self.assertEqual(result["status"], "failed")
        self.assertIn("DENYLIST_MATCH", result["reason_codes"])
        self.assertEqual(result["details"]["version"], "test-v1")

    def test_unavailable_denylist_is_incomplete(self) -> None:
        with patch.object(denylist, "DENYLIST_PATH", Path("/missing/denylist.json")):
            result = denylist.check_denylist("https://example.com")
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("DENYLIST_UNAVAILABLE", result["reason_codes"])
