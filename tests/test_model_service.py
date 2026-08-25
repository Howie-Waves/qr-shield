import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from app.services import model_service


HTTPS_EXAMPLE = "https://example.com"


class ModelServiceTests(unittest.TestCase):
    # E1-US2 中文：结果必须来自已校验版本的本地模型。
    # E1-US2 EN: Results must come from a verified local model version.
    def test_loads_existing_model(self) -> None:
        self.assertTrue(model_service.MODEL_PATH.is_file())
        self.assertTrue(model_service.METADATA_PATH.is_file())

        model, metadata = model_service._load_artifacts()

        self.assertIsNotNone(model)
        self.assertTrue(metadata.get("model_name"))

    def test_prediction_result_contract(self) -> None:
        result = model_service.predict_url_risk(HTTPS_EXAMPLE)

        self.assertIsInstance(result, dict)
        self.assertGreaterEqual(result["score"], 0)
        self.assertLessEqual(result["score"], 100)
        self.assertIn(result["level"], {"Low", "Medium", "High"})
        self.assertIsInstance(result["is_phishing"], bool)
        self.assertIsInstance(result["reasons"], list)
        self.assertGreaterEqual(len(result["reasons"]), 1)
        self.assertLessEqual(len(result["reasons"]), 3)
        self.assertTrue(result["model_name"])
        self.assertEqual(result["model_version"], "url-risk-lr-2026.07.29")

    def test_prediction_has_no_feature_name_warning(self) -> None:
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            result = model_service.predict_url_risk(HTTPS_EXAMPLE)

        self.assertIsInstance(result, dict)
        feature_name_warnings = [
            warning
            for warning in caught_warnings
            if "valid feature names" in str(warning.message)
        ]
        self.assertEqual(feature_name_warnings, [])

    def test_missing_model_has_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing_model = Path(temporary_directory) / "missing.joblib"
            with patch.object(model_service, "MODEL_PATH", missing_model):
                with self.assertRaisesRegex(
                    model_service.ModelUnavailableError,
                    "missing required file",
                ):
                    model_service.predict_url_risk(HTTPS_EXAMPLE)


if __name__ == "__main__":
    unittest.main()
