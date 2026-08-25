import json
import unittest

from scripts.evaluate_e3_us1 import MANIFEST_PATH, evaluate


class E3US1EvaluationTests(unittest.TestCase):
    def test_locked_evaluation_is_reproducible_and_cautious(self) -> None:
        report = evaluate()
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        self.assertEqual(report["dataset_version"], manifest["version"])
        self.assertEqual(report["passed_scenarios"], report["scenario_count"])
        self.assertGreaterEqual(report["latency_ms"]["p95"], report["latency_ms"]["p50"])
        outcomes = {case["id"]: case["actual_outcome"] for case in report["scenario_effectiveness"]}
        self.assertEqual(outcomes["model_unavailable"], "Incomplete")
        self.assertEqual(outcomes["denylist_unavailable"], "Incomplete")
        self.assertEqual(outcomes["denylist_match"], "Review required")
        self.assertEqual(outcomes["suspicious_lexical_url"], "Review required")
        suspicious = next(
            case
            for case in report["scenario_effectiveness"]
            if case["id"] == "suspicious_lexical_url"
        )
        self.assertEqual(suspicious["decision"]["conclusion"], "Suspicious")
        self.assertNotEqual(suspicious["decision"]["suspicion_level"], "Low suspicion")

    def test_report_contains_calibration_and_traceability_evidence(self) -> None:
        report = evaluate()
        self.assertEqual(len(report["calibration"]["bins"]), 3)
        normal = next(case for case in report["scenario_effectiveness"] if case["id"] == "normal_url")
        self.assertIn("url_vet", normal["source_versions"])
        self.assertIn("local_denylist", normal["source_versions"])
        self.assertIn("decision_policy", normal["source_versions"])
        self.assertEqual(normal["decision"]["policy_version"], "phase3-decision-policy-v1")
