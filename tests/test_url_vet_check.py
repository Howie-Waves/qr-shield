# AI-assisted implementation: written with AI assistance and reviewed by the
# project author.
import unittest
from unittest.mock import patch

from app.services.url_vet_check import analyze_url
from app.services.url_vet_client import UrlVetUnavailableError


def response(
    risk_score=5,
    trust_score=100,
    verdict="Safe",
    reasons=None,
    incomplete=False,
):
    if reasons is None:
        reasons = {
            "good_reasons": ["Long-standing domain history."],
            "bad_reasons": None,
            "neutral_reasons": ["Standard domain extension."],
        }
    return {
        "result": {
            "risk_score": risk_score,
            "trust_score": trust_score,
            "verdict": verdict,
            "reasons": reasons,
        },
        "incomplete": incomplete,
    }


class UrlVetCheckTests(unittest.TestCase):
    def test_successful_safe_response_returns_check_and_analysis(self) -> None:
        with (
            patch("app.services.url_vet_check.scan", return_value=response()),
            patch.dict("os.environ", {"QR_URLVET_VERSION": "urlvet-test-v1"}),
        ):
            check, analysis = analyze_url("https://example.com")

        self.assertEqual(check["check_id"], "url_vet")
        self.assertEqual(check["status"], "passed")
        self.assertEqual(check["details"]["version"], "urlvet-test-v1")
        self.assertEqual(analysis["score"], 5.0)
        self.assertEqual(analysis["level"], "Low")
        self.assertEqual(analysis["model_name"], "url.vet")
        self.assertEqual(analysis["model_version"], "urlvet-test-v1")
        self.assertEqual(analysis["trust_score"], 100.0)
        self.assertEqual(analysis["verdict"], "Safe")
        self.assertEqual(
            analysis["reasons"],
            ["Long-standing domain history.", "Standard domain extension."],
        )

    def test_medium_and_high_levels_follow_existing_thresholds(self) -> None:
        with patch("app.services.url_vet_check.scan", return_value=response(risk_score=40)):
            _, medium = analyze_url("https://example.com")
        with patch("app.services.url_vet_check.scan", return_value=response(risk_score=70)):
            _, high = analyze_url("https://example.com")

        self.assertEqual(medium["level"], "Medium")
        self.assertEqual(high["level"], "High")

    def test_reasons_are_capped_and_null_groups_are_ignored(self) -> None:
        raw_reasons = {
            "bad_reasons": ["bad one", "bad two"],
            "neutral_reasons": None,
            "good_reasons": ["good one", "good two"],
        }
        with patch(
            "app.services.url_vet_check.scan",
            return_value=response(risk_score=75, verdict="Malicious", reasons=raw_reasons),
        ):
            _, analysis = analyze_url("https://example.com")

        self.assertEqual(analysis["reasons"], ["bad one", "bad two", "good one"])

    def test_empty_verdict_is_preserved_without_marking_low_by_default(self) -> None:
        with patch(
            "app.services.url_vet_check.scan",
            return_value=response(risk_score=0, trust_score=0, verdict=""),
        ):
            check, analysis = analyze_url("http://1.2.3.4/login")

        self.assertEqual(check["status"], "passed")
        self.assertIsNone(analysis["verdict"])
        self.assertEqual(analysis["score"], 0.0)

    def test_unavailable_client_returns_incomplete_check_and_no_analysis(self) -> None:
        with patch(
            "app.services.url_vet_check.scan",
            side_effect=UrlVetUnavailableError("down"),
        ):
            check, analysis = analyze_url("https://example.com")

        self.assertEqual(check["check_id"], "url_vet")
        self.assertEqual(check["status"], "incomplete")
        self.assertIn("URL_VET_UNAVAILABLE", check["reason_codes"])
        self.assertIsNone(analysis)

    def test_incomplete_response_with_score_preserves_partial_analysis(self) -> None:
        with patch(
            "app.services.url_vet_check.scan",
            return_value=response(incomplete=True),
        ):
            check, analysis = analyze_url("https://example.com")

        self.assertEqual(check["status"], "warning")
        self.assertIn("URL_VET_PARTIAL", check["reason_codes"])
        self.assertEqual(check["details"]["risk_score"], 5.0)
        self.assertEqual(check["details"]["risk_level"], "Low")
        self.assertEqual(check["details"]["trust_score"], 100.0)
        self.assertEqual(check["details"]["verdict"], "Safe")
        self.assertEqual(
            check["details"]["reasons"],
            ["Long-standing domain history.", "Standard domain extension."],
        )
        self.assertEqual(analysis["score"], 5.0)
        self.assertEqual(analysis["risk_score"], 5.0)
        self.assertEqual(analysis["model_name"], "url.vet")
        self.assertTrue(analysis["url_vet_partial"])

    def test_incomplete_response_without_score_stays_incomplete(self) -> None:
        raw = {
            "result": {"trust_score": 100, "verdict": "Safe"},
            "incomplete": True,
            "errors": ["content check did not complete"],
        }
        with patch("app.services.url_vet_check.scan", return_value=raw):
            check, analysis = analyze_url("https://example.com")

        self.assertEqual(check["status"], "incomplete")
        self.assertIn("URL_VET_INCOMPLETE", check["reason_codes"])
        self.assertIsNone(analysis)

    def test_missing_result_fields_return_incomplete_check_and_no_analysis(self) -> None:
        cases = (
            {},
            {"result": None, "incomplete": False},
            {"result": {"trust_score": 100}, "incomplete": False},
            {"result": {"risk_score": "not a number"}, "incomplete": False},
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with patch("app.services.url_vet_check.scan", return_value=raw):
                    check, analysis = analyze_url("https://example.com")

                self.assertEqual(check["status"], "incomplete")
                self.assertIn("URL_VET_RESULT_INVALID", check["reason_codes"])
                self.assertIsNone(analysis)


if __name__ == "__main__":
    unittest.main()
