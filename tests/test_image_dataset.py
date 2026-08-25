import json
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "test_images"


def url_vet_level_result(level: str) -> tuple[dict, dict]:
    scores = {"low": 5.0, "medium": 45.0, "high": 80.0}
    verdicts = {"low": "Safe", "medium": "Suspicious", "high": "Malicious"}
    score = scores[level]
    verdict = verdicts[level]
    return (
        {
            "check_id": "url_vet",
            "status": "passed",
            "summary": "url.vet URL risk analysis completed.",
            "reason_codes": [f"URL_VET_VERDICT_{verdict.upper()}"],
            "details": {"version": "urlvet-test-v1"},
        },
        {
            "score": score,
            "level": level.title(),
            "reasons": ["Deterministic url.vet fixture evidence."],
            "model_name": "url.vet",
            "model_version": "urlvet-test-v1",
            "trust_score": 100.0 - score,
            "verdict": verdict,
        },
    )


class TestImageDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)
        cls.manifest = json.loads(
            (DATASET / "manifest.json").read_text(encoding="utf-8")
        )

    def test_manifest_covers_every_user_story_with_image_specific_cases(self) -> None:
        stories = {record["user_story"] for record in self.manifest["records"]}
        self.assertTrue(
            {
                "e1_us1_upload",
                "e1_us2_risk",
                "e1_us3_content",
                "e2_us2_payment",
                "e2_us3_isolation",
                "e3_us1_evidence",
            }.issubset(stories)
        )
        self.assertTrue((DATASET / "e2_us1_tampering" / "manifest.json").is_file())

    def test_every_manifest_record_exists_inside_the_dataset(self) -> None:
        dataset_root = DATASET.resolve()
        for record in self.manifest["records"]:
            with self.subTest(record=record["file"]):
                path = (DATASET / record["file"]).resolve()
                self.assertTrue(path.is_relative_to(dataset_root))
                self.assertTrue(path.is_file())

    def test_low_medium_and_high_examples_match_documented_thresholds(self) -> None:
        for level in ("low", "medium", "high"):
            path = DATASET / "e1_us2_risk" / f"{level}.png"
            with patch("app.main.analyze_url", return_value=url_vet_level_result(level)):
                response = self.client.post(
                    "/api/v1/analyze",
                    files={"file": (path.name, path.read_bytes(), "image/png")},
                )
            with self.subTest(level=level):
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["analysis"]["level"].casefold(), level)

    def test_rejected_upload_examples_return_the_documented_status(self) -> None:
        rejected = DATASET / "e1_us1_upload" / "rejected"
        cases = {
            "empty.png": ("image/png", 400),
            "damaged.png": ("image/png", 400),
            "unsupported.gif": ("image/gif", 400),
            "over_5_mib.png": ("image/png", 413),
            "over_25_megapixels.png": ("image/png", 400),
        }
        for filename, (mime_type, expected_status) in cases.items():
            path = rejected / filename
            response = self.client.post(
                "/api/v1/analyze",
                files={"file": (filename, path.read_bytes(), mime_type)},
            )
            with self.subTest(filename=filename):
                self.assertEqual(response.status_code, expected_status)
