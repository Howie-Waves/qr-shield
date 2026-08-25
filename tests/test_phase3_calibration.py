import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app.services.decision_policy import (
    CalibrationDataset,
    CalibrationObservations,
    CalibrationReport,
    DecisionPolicy,
    load_calibration_manifest,
)
from scripts.calibrate_phase3_policy import (
    ROOT,
    _normalise_tranco_domain,
    _selection_priority,
    _load_cache,
    _write_cache,
    calculate_metrics,
    derive_agreement_margin,
    derive_thresholds,
    select_benchmark,
)


CALIBRATION_ROOT = ROOT / "data" / "evaluation" / "phase3_calibration"
DATASET_PATH = CALIBRATION_ROOT / "calibration_dataset.json"
OBSERVATIONS_PATH = CALIBRATION_ROOT / "calibration_observations.json"
POLICY_PATH = CALIBRATION_ROOT / "decision_policy.json"
REPORT_PATH = ROOT / "reports" / "phase3_calibration_report.json"


def observation(
    label: str,
    risk: float | None,
    judgement: float | None,
    verdict: str | None = None,
):
    return SimpleNamespace(
        label=label,
        risk_score=risk,
        judgement_score=judgement,
        verdict=verdict,
    )


class Phase3CalibrationAlgorithmTests(unittest.TestCase):
    def test_score_cache_is_bound_to_url_vet_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache_path = Path(directory) / "cache.json"
            with patch(
                "scripts.calibrate_phase3_policy.CACHE_PATH",
                cache_path,
            ):
                _write_cache({"payload-hash": {"risk_score": 10}}, "urlvet-v1")

                self.assertEqual(
                    _load_cache("urlvet-v1"),
                    {"payload-hash": {"risk_score": 10}},
                )
                self.assertEqual(_load_cache("urlvet-v2"), {})

    def test_selection_priority_and_tranco_normalisation_are_deterministic(self) -> None:
        first = _selection_priority("tranco_top_1m", 123, "https://example.com/")
        second = _selection_priority("tranco_top_1m", 123, "https://example.com/")

        self.assertEqual(first, second)
        self.assertEqual(_normalise_tranco_domain("Example.COM."), "https://example.com/")
        self.assertIsNone(_normalise_tranco_domain("not a domain"))

    def test_benchmark_prioritises_no_false_negatives_then_fewer_false_positives(self) -> None:
        records = [
            observation("presumed_benign", 5, 15),
            observation("presumed_benign", 10, 35),
            observation("suspicious", 75, 80),
            observation("suspicious", 90, 95),
        ]

        benchmark, candidate_count, metrics = select_benchmark(records)

        self.assertEqual(candidate_count, 99)
        self.assertEqual(benchmark, 57)
        self.assertEqual(metrics.confusion_matrix.false_negative, 0)
        self.assertEqual(metrics.confusion_matrix.false_positive, 0)

    def test_missing_score_pair_is_incomplete_not_low_risk(self) -> None:
        records = [
            observation("presumed_benign", 5, 10),
            observation("suspicious", None, 95),
        ]

        metrics = calculate_metrics(records, 50)

        self.assertEqual(metrics.completed_count, 1)
        self.assertEqual(metrics.incomplete_count, 1)
        self.assertEqual(metrics.confusion_matrix.false_negative, 0)

    def test_adverse_verdict_is_not_hidden_by_low_numeric_scores(self) -> None:
        records = [
            observation("presumed_benign", 5, 10, verdict="Suspicious"),
            observation("suspicious", 5, 10, verdict="Risky"),
        ]

        metrics = calculate_metrics(records, 50)

        self.assertEqual(metrics.confusion_matrix.false_positive, 1)
        self.assertEqual(metrics.confusion_matrix.true_positive, 1)
        self.assertEqual(metrics.confusion_matrix.false_negative, 0)

    def test_agreement_margin_uses_first_quartile_absolute_score_difference(self) -> None:
        records = [
            observation("presumed_benign", 10, 20),
            observation("presumed_benign", 20, 40),
            observation("suspicious", 80, 100),
        ]

        self.assertEqual(derive_agreement_margin(records), 15)

    def test_four_thresholds_have_distinct_distribution_evidence(self) -> None:
        records = [
            observation("presumed_benign", 10, 20),
            observation("presumed_benign", 20, 30),
            observation("presumed_benign", 30, 40),
            observation("presumed_benign", 40, 50),
            observation("suspicious", 80, 90),
            observation("suspicious", 90, 95),
            observation("suspicious", 95, 100),
            observation("suspicious", 100, 100),
        ]

        thresholds, margin, evidence = derive_thresholds(records, 70)

        self.assertEqual(thresholds, {
            "low_medium": 43.0,
            "medium_high": 70,
            "high_dangerous": 94.0,
        })
        self.assertEqual(margin, 5)
        self.assertEqual(evidence["combined_score_rule"], "max(risk_score, judgement_score)")


class CommittedPhase3CalibrationEvidenceTests(unittest.TestCase):
    def test_committed_generated_evidence_is_valid_and_consistent(self) -> None:
        dataset = CalibrationDataset.model_validate_json(DATASET_PATH.read_text(encoding="utf-8"))
        observations = CalibrationObservations.model_validate_json(
            OBSERVATIONS_PATH.read_text(encoding="utf-8")
        )
        policy = DecisionPolicy.model_validate_json(POLICY_PATH.read_text(encoding="utf-8"))
        report = CalibrationReport.model_validate_json(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(dataset.dataset_version, observations.dataset_version)
        self.assertEqual(dataset.dataset_version, policy.dataset_version)
        self.assertEqual(dataset.dataset_version, report.dataset_version)
        self.assertEqual(len(dataset.records), len(observations.records))
        self.assertEqual(
            {record.sample_id: record.payload_sha256 for record in dataset.records},
            {record.sample_id: record.payload_sha256 for record in observations.records},
        )
        self.assertEqual(policy.status, "provisional")
        self.assertEqual(policy.thresholds.medium_high, policy.suspicious_benchmark)
        self.assertLess(policy.thresholds.low_medium, policy.suspicious_benchmark)
        self.assertGreater(policy.thresholds.high_dangerous, policy.suspicious_benchmark)
        self.assertEqual(report.selected_policy, policy)

        source_labels = {
            source.source_id: source.label for source in load_calibration_manifest().sources
        }
        self.assertEqual(
            {record.source_id for record in dataset.records},
            set(source_labels),
        )
        for record in dataset.records:
            self.assertEqual(record.label, source_labels[record.source_id])

    def test_committed_calibration_evidence_contains_no_raw_urls(self) -> None:
        for path in (DATASET_PATH, OBSERVATIONS_PATH, POLICY_PATH, REPORT_PATH):
            text = path.read_text(encoding="utf-8").casefold()
            self.assertNotIn("http://", text, path.name)
            self.assertNotIn("https://", text, path.name)
            self.assertNotIn('"url"', text, path.name)

    def test_report_metrics_can_be_recalculated_from_committed_observations(self) -> None:
        observations = CalibrationObservations.model_validate_json(
            OBSERVATIONS_PATH.read_text(encoding="utf-8")
        )
        report = CalibrationReport.model_validate_json(REPORT_PATH.read_text(encoding="utf-8"))
        benchmark = report.selected_policy.suspicious_benchmark

        calibration = calculate_metrics(
            [record for record in observations.records if record.split == "calibration"],
            benchmark,
        )
        validation = calculate_metrics(
            [record for record in observations.records if record.split == "validation"],
            benchmark,
        )

        self.assertEqual(calibration, report.selected_policy.metrics)
        self.assertEqual(validation, report.validation_metrics)

    def test_generated_json_files_have_no_unknown_top_level_fields(self) -> None:
        expected = {
            DATASET_PATH: set(CalibrationDataset.model_fields),
            OBSERVATIONS_PATH: set(CalibrationObservations.model_fields),
            POLICY_PATH: set(DecisionPolicy.model_fields),
            REPORT_PATH: set(CalibrationReport.model_fields),
        }
        for path, fields in expected.items():
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(set(raw), fields, path.name)


if __name__ == "__main__":
    unittest.main()
