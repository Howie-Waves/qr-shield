import unittest

from app.services.checks import aggregate_outcome, make_check


class E2US3CheckContractTests(unittest.TestCase):
    def test_incomplete_check_requires_incomplete_assessment(self) -> None:
        result = aggregate_outcome(
            [make_check("url_model", "incomplete", "Model unavailable.")]
        )
        self.assertEqual(result, ("Incomplete", "Incomplete", ["url_model"]))

    def test_warning_requires_review_without_claiming_low_risk(self) -> None:
        outcome, status, failed = aggregate_outcome(
            [make_check("block_inspection", "warning", "Anomaly found.")]
        )
        self.assertEqual(outcome, "Review required")
        self.assertEqual(status, "Complete")
        self.assertEqual(failed, [])
