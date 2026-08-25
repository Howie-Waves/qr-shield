import json
import unittest
from pathlib import Path

from app.services.block_inspection import inspect_blocks


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "data" / "test_images" / "e2_us1_tampering"


class TamperingDatasetTests(unittest.TestCase):
    def test_manifest_is_labelled_and_tampered_cases_never_pass(self) -> None:
        manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest["records"]), 10)
        for record in manifest["records"]:
            result = inspect_blocks((FIXTURES / record["file"]).read_bytes())
            if record["label"] == "tampered":
                self.assertIn(result["status"], {"warning", "incomplete"}, record["file"])

    def test_clean_fixture_false_positive_rate_is_within_approved_limit(self) -> None:
        manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
        clean = [item for item in manifest["records"] if item["label"] == "clean"]
        false_positives = sum(
            inspect_blocks((FIXTURES / item["file"]).read_bytes())["status"] != "passed"
            for item in clean
        )
        self.assertLessEqual(false_positives / len(clean), 0.25)
