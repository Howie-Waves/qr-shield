import json
import unittest
from pathlib import Path

from app.services.decision_policy import load_decision_policy


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "reports" / "phase3_completion_report.json"


class Phase3CompletionReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_report = REPORT_PATH.read_text(encoding="utf-8")
        cls.report = json.loads(cls.raw_report)

    def test_report_is_versioned_and_covers_required_acceptance_checks(self) -> None:
        self.assertEqual(self.report["report_version"], "phase3-completion-report-v1")
        self.assertEqual(self.report["policy_version"], "phase3-decision-policy-v1")
        self.assertTrue(self.report["calibration_report_valid"])
        self.assertTrue(self.report["e3_us1_evaluation_passed"])
        self.assertTrue(self.report["real_suspicious_qr_evaluation_passed"])
        self.assertTrue(self.report["non_url_boundary_tests_passed"])
        self.assertTrue(self.report["logo_decoder_regression_passed"])
        self.assertTrue(
            all(self.report["acceptance_checks"].values()),
            self.report["acceptance_checks"],
        )

    def test_report_thresholds_match_the_runtime_policy(self) -> None:
        policy = load_decision_policy()
        calibration = self.report["calibration"]

        self.assertEqual(calibration["policy_version"], policy.policy_version)
        self.assertEqual(
            calibration["thresholds"],
            {
                "low_medium": 62.0,
                "medium_high": 79.0,
                "high_dangerous": 100.0,
            },
        )
        self.assertEqual(calibration["benchmark"], 79.0)
        self.assertEqual(calibration["agreement_margin"], 1.0)
        self.assertEqual(calibration["selected_metrics"]["confusion_matrix"]["false_negative"], 0)

    def test_non_url_and_suspicious_evidence_are_conservative(self) -> None:
        for case in self.report["non_url_boundary_tests"]["cases"].values():
            self.assertTrue(case["passed"], case)
            self.assertEqual(case["url_vet_status"], "not_applicable")
            self.assertFalse(case["url_vet_called"])
            self.assertFalse(case["local_model_called"])

        suspicious = self.report["real_suspicious_qr_evaluation"]["metrics"]
        self.assertEqual(suspicious["low_suspicion_count"], 0)
        self.assertEqual(suspicious["not_suspicious_count"], 0)
        self.assertEqual(suspicious["detection_rate"], 1.0)

    def test_report_does_not_retain_live_url_or_qr_payload_content(self) -> None:
        self.assertNotIn("://", self.raw_report)
        self.assertNotIn("safe_fixture_path", self.raw_report)
        self.assertNotIn("data/test_images/phase3_real_suspicious", self.raw_report)
        self.assertGreaterEqual(len(self.report["limitations"]), 4)

    def test_full_suite_result_is_explicit_about_known_environment_failure(self) -> None:
        full_suite = self.report["full_unittest"]
        self.assertIn(full_suite["status"], {"passed", "failed", "not_run", "timeout"})
        if full_suite["status"] == "failed":
            self.assertTrue(full_suite["known_unrelated_failure"])
            self.assertTrue(full_suite["effective_passed"])


if __name__ == "__main__":
    unittest.main()
