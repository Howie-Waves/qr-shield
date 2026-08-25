import unittest

from app.schemas import RiskAnalysis, RiskDecision


class SchemaTests(unittest.TestCase):
    def test_risk_analysis_accepts_url_vet_fields(self) -> None:
        analysis = RiskAnalysis(
            score=5,
            risk_score=5,
            level="Low",
            reasons=["Long-standing domain history."],
            model_name="url.vet",
            model_version="urlvet-test-v1",
            trust_score=100,
            verdict="Safe",
            judgement_score=12.5,
            judgement_reasons=["No configured high-risk lexical signals were found."],
            judgement_model_name="LogisticRegression",
            judgement_model_version="url-risk-lr-test-v1",
            url_vet_partial=True,
        )

        self.assertEqual(analysis.risk_score, 5)
        self.assertEqual(analysis.trust_score, 100)
        self.assertEqual(analysis.verdict, "Safe")
        self.assertEqual(analysis.judgement_score, 12.5)
        self.assertEqual(analysis.judgement_model_version, "url-risk-lr-test-v1")
        self.assertTrue(analysis.url_vet_partial)

    def test_risk_analysis_keeps_url_vet_fields_optional(self) -> None:
        analysis = RiskAnalysis(
            score=5,
            level="Low",
            reasons=["No configured high-risk lexical signals were found."],
            model_name="LogisticRegression",
            model_version="url-risk-lr-2026.07.29",
        )

        self.assertIsNone(analysis.trust_score)
        self.assertIsNone(analysis.verdict)
        self.assertIsNone(analysis.judgement_score)
        self.assertEqual(analysis.judgement_reasons, [])

    def test_risk_decision_keeps_policy_and_confidence_distinct(self) -> None:
        decision = RiskDecision(
            policy_version="phase3-decision-policy-v1",
            policy_status="provisional",
            benchmark=79,
            agreement_margin=1,
            thresholds={"low_medium": 62, "medium_high": 79, "high_dangerous": 100},
            suspicion_level="High suspicion",
            conclusion="Partially suspicious",
            confidence_level="Low",
            confidence_reason="The two scores disagree around the benchmark.",
            decision_reasons=["Local judgement score reached B=79."],
            risk_score_level="Low suspicion",
            judgement_score_level="High suspicion",
            risk_vote_suspicious=False,
            judgement_vote_suspicious=True,
        )

        self.assertEqual(decision.conclusion, "Partially suspicious")
        self.assertEqual(decision.confidence_level, "Low")
        self.assertEqual(decision.benchmark, 79)

    def test_non_url_decision_has_explicit_not_applicable_state(self) -> None:
        decision = RiskDecision(
            suspicion_level="Not applicable",
            conclusion="Not applicable",
            confidence_level="Not applicable",
            confidence_reason="URL analysis does not apply to this QR content.",
        )

        self.assertEqual(decision.suspicion_level, "Not applicable")
        self.assertEqual(decision.confidence_level, "Not applicable")


if __name__ == "__main__":
    unittest.main()
