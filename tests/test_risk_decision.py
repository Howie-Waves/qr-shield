import unittest

from app.services.decision_policy import load_decision_policy
from app.services.risk_decision import (
    decide_single_source,
    decide_url_risk,
    not_applicable_decision,
)


class RiskDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_decision_policy()

    def decide(self, risk: float | None, judgement: float | None, verdict: str = "Safe") -> dict:
        return decide_url_risk(risk, judgement, verdict, policy=self.policy)

    def test_exact_threshold_boundaries_have_no_gaps_or_overlaps(self) -> None:
        cases = (
            (0.0, "Low suspicion"),
            (61.99, "Low suspicion"),
            (62.0, "Medium suspicion"),
            (78.99, "Medium suspicion"),
            (79.0, "High suspicion"),
            (99.99, "High suspicion"),
            (100.0, "Dangerous"),
        )
        for score, expected_level in cases:
            with self.subTest(score=score):
                decision = self.decide(score, score)
                self.assertEqual(decision["risk_score_level"], expected_level)
                self.assertEqual(decision["judgement_score_level"], expected_level)
                self.assertEqual(decision["suspicion_level"], expected_level)

    def test_agreeing_below_benchmark_is_not_suspicious_with_high_confidence(self) -> None:
        decision = self.decide(60, 60)

        self.assertEqual(decision["conclusion"], "Not suspicious")
        self.assertEqual(decision["suspicion_level"], "Low suspicion")
        self.assertEqual(decision["confidence_level"], "High")
        self.assertTrue(decision["risk_vote_suspicious"] is False)
        self.assertTrue(decision["judgement_vote_suspicious"] is False)

    def test_agreeing_above_benchmark_is_suspicious(self) -> None:
        decision = self.decide(90, 90)

        self.assertEqual(decision["conclusion"], "Suspicious")
        self.assertEqual(decision["suspicion_level"], "High suspicion")
        self.assertEqual(decision["confidence_level"], "High")
        self.assertTrue(decision["risk_vote_suspicious"])
        self.assertTrue(decision["judgement_vote_suspicious"])

    def test_agreeing_scores_close_to_benchmark_have_medium_confidence(self) -> None:
        decision = self.decide(80, 80)

        self.assertEqual(decision["conclusion"], "Suspicious")
        self.assertEqual(decision["confidence_level"], "Medium")
        self.assertIn("close to the benchmark", decision["confidence_reason"])

    def test_high_risk_score_and_low_judgement_is_partially_suspicious(self) -> None:
        decision = self.decide(90, 20)

        self.assertEqual(decision["conclusion"], "Partially suspicious")
        self.assertEqual(decision["suspicion_level"], "High suspicion")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertIn("disagree", decision["confidence_reason"])

    def test_low_risk_score_and_high_judgement_is_partially_suspicious(self) -> None:
        decision = self.decide(20, 90)

        self.assertEqual(decision["conclusion"], "Partially suspicious")
        self.assertEqual(decision["suspicion_level"], "High suspicion")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertTrue(
            any("Local judgement score 90 reached" in item for item in decision["decision_reasons"])
        )

    def test_malicious_verdict_cannot_be_hidden_by_low_scores(self) -> None:
        decision = self.decide(5, 5, "Malicious")

        self.assertEqual(decision["conclusion"], "Suspicious")
        self.assertEqual(decision["suspicion_level"], "Dangerous")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertEqual(decision["adverse_verdict"], "Malicious")
        self.assertTrue(any("minimum level of Dangerous" in item for item in decision["decision_reasons"]))

    def test_risky_verdict_uses_the_policy_dangerous_floor(self) -> None:
        decision = self.decide(5, 5, "Risky")

        self.assertEqual(decision["conclusion"], "Suspicious")
        self.assertEqual(decision["suspicion_level"], "Dangerous")
        self.assertEqual(decision["adverse_verdict"], "Risky")

    def test_suspicious_verdict_keeps_a_high_suspicion_floor(self) -> None:
        decision = self.decide(5, 5, "Suspicious")

        self.assertEqual(decision["conclusion"], "Partially suspicious")
        self.assertEqual(decision["suspicion_level"], "High suspicion")
        self.assertEqual(decision["confidence_level"], "Low")

    def test_one_available_score_gets_a_partial_level_and_low_confidence(self) -> None:
        decision = self.decide(None, 90)

        self.assertEqual(decision["conclusion"], "Partially suspicious")
        self.assertEqual(decision["suspicion_level"], "High suspicion")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertIsNone(decision["risk_score_level"])
        self.assertEqual(decision["judgement_score_level"], "High suspicion")
        self.assertIn("missing source", decision["confidence_reason"])

    def test_both_missing_scores_remain_incomplete(self) -> None:
        decision = self.decide(None, None)

        self.assertEqual(decision["conclusion"], "Incomplete")
        self.assertIsNone(decision["suspicion_level"])
        self.assertEqual(decision["confidence_level"], "Unavailable")
        self.assertIn("url.vet risk score", decision["confidence_reason"])

    def test_non_web_content_has_no_fabricated_score_or_confidence(self) -> None:
        decision = not_applicable_decision("WiFi content is outside URL analysis.")

        self.assertEqual(decision["conclusion"], "Not applicable")
        self.assertEqual(decision["suspicion_level"], "Not applicable")
        self.assertEqual(decision["confidence_level"], "Not applicable")
        self.assertIsNone(decision["policy_version"])

    def test_single_local_score_is_partial_but_not_incomplete(self) -> None:
        decision = decide_single_source(
            58.99,
            "local judgement",
            policy=self.policy,
        )

        self.assertEqual(decision["conclusion"], "Partially assessed")
        self.assertEqual(decision["suspicion_level"], "Low suspicion")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertIsNone(decision["risk_score_level"])
        self.assertEqual(decision["judgement_score_level"], "Low suspicion")
        self.assertIn("missing source", decision["confidence_reason"])

    def test_partial_url_vet_evidence_keeps_both_scores_but_lowers_confidence(self) -> None:
        decision = decide_url_risk(
            30,
            58.99,
            "Safe",
            policy=self.policy,
            partial_source="url.vet",
        )

        self.assertEqual(decision["conclusion"], "Partially assessed")
        self.assertEqual(decision["confidence_level"], "Low")
        self.assertIn("partial evidence", decision["confidence_reason"])


if __name__ == "__main__":
    unittest.main()
