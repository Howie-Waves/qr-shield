import unittest
from copy import deepcopy

from pydantic import ValidationError

from app.services.decision_policy import (
    CalibrationDataset,
    CalibrationManifest,
    CalibrationReport,
    DecisionPolicy,
    load_calibration_manifest,
    verify_local_raw_files,
)


def valid_dataset() -> dict:
    records = []
    cases = (
        ("calibration", "presumed_benign", "tranco_top_1m"),
        ("calibration", "suspicious", "phishtank_online_valid"),
        ("validation", "presumed_benign", "tranco_top_1m"),
        ("validation", "suspicious", "phishtank_online_valid"),
    )
    for index, (split, label, source_id) in enumerate(cases, start=1):
        records.append(
            {
                "sample_id": f"sample-{index}",
                "source_id": source_id,
                "source_row_number": index,
                "source_record_id": str(index),
                "payload_sha256": f"{index:064x}",
                "label": label,
                "split": split,
                "inclusion_reason": "Deterministic contract fixture.",
            }
        )
    return {
        "schema_version": "1.0",
        "dataset_version": "phase3-calibration-test-v1",
        "source_manifest_version": "phase3-calibration-sources-v1",
        "random_seed": 5238,
        "selection_method": "Deterministic contract fixture.",
        "records": records,
    }


def valid_policy() -> dict:
    return {
        "schema_version": "1.0",
        "policy_version": "phase3-policy-test-v1",
        "status": "provisional",
        "dataset_version": "phase3-calibration-sources-v1",
        "generated_at": "2026-08-12T00:00:00Z",
        "risk_score_source": "url.vet result.risk_score",
        "judgement_score_source": "local LR phishing probability",
        "thresholds": {
            "low_medium": 20,
            "medium_high": 50,
            "high_dangerous": 80,
        },
        "suspicious_benchmark": 50,
        "agreement_margin": 10,
        "verdict_floors": {
            "suspicious": "High suspicion",
            "risky": "Dangerous",
            "malicious": "Dangerous",
        },
        "selection_priority": (
            "minimise_false_negatives_then_maximise_recall_then_minimise_false_positives"
        ),
        "metrics": {
            "sample_count": 100,
            "presumed_benign_count": 50,
            "suspicious_count": 50,
            "completed_count": 90,
            "incomplete_count": 10,
            "confusion_matrix": {
                "true_positive": 40,
                "true_negative": 42,
                "false_positive": 3,
                "false_negative": 5,
            },
            "precision": 0.9302,
            "recall": 0.8889,
            "false_negative_rate": 0.1111,
            "false_positive_rate": 0.0667,
        },
        "limitations": ["Synthetic contract fixture; not an approved policy."],
    }


class DecisionPolicyContractTests(unittest.TestCase):
    def test_committed_source_manifest_is_valid_and_labelled(self) -> None:
        manifest = load_calibration_manifest()

        self.assertEqual(manifest.dataset_version, "phase3-calibration-sources-v1")
        self.assertFalse(manifest.raw_data_committed)
        self.assertTrue(manifest.contains_potentially_live_urls)
        self.assertEqual(
            {source.label for source in manifest.sources},
            {"presumed_benign", "suspicious"},
        )
        self.assertEqual(
            {source.source_id: source.record_count for source in manifest.sources},
            {"tranco_top_1m": 1_000_000, "phishtank_online_valid": 71_464},
        )

    def test_local_raw_files_match_manifest_when_available(self) -> None:
        results = verify_local_raw_files(load_calibration_manifest())

        self.assertNotIn("mismatch", results.values())
        self.assertTrue(
            set(results.values()).issubset({"matched", "not_available"})
        )

    def test_source_manifest_rejects_missing_label_class(self) -> None:
        manifest = load_calibration_manifest().model_dump(mode="json")
        manifest["sources"][1]["label"] = "presumed_benign"

        with self.assertRaisesRegex(ValidationError, "both calibration labels"):
            CalibrationManifest.model_validate(manifest)

    def test_sampled_dataset_requires_both_labels_in_both_splits(self) -> None:
        dataset = CalibrationDataset.model_validate(valid_dataset())

        self.assertEqual(len(dataset.records), 4)
        self.assertNotIn("url", dataset.records[0].model_fields_set)

        payload = valid_dataset()
        payload["records"][3]["label"] = "presumed_benign"
        with self.assertRaisesRegex(ValidationError, "each split"):
            CalibrationDataset.model_validate(payload)

    def test_decision_policy_accepts_ordered_evidence_backed_contract(self) -> None:
        policy = DecisionPolicy.model_validate(valid_policy())

        self.assertLess(
            policy.thresholds.low_medium,
            policy.thresholds.medium_high,
        )
        self.assertEqual(policy.suspicious_benchmark, 50)
        self.assertEqual(policy.metrics.confusion_matrix.false_negative, 5)

    def test_decision_policy_rejects_unordered_thresholds(self) -> None:
        payload = valid_policy()
        payload["thresholds"] = {
            "low_medium": 50,
            "medium_high": 20,
            "high_dangerous": 80,
        }

        with self.assertRaisesRegex(ValidationError, "strictly increasing"):
            DecisionPolicy.model_validate(payload)

    def test_decision_policy_rejects_inconsistent_metric_counts(self) -> None:
        payload = valid_policy()
        payload["metrics"]["completed_count"] = 89

        with self.assertRaisesRegex(ValidationError, "completion counts"):
            DecisionPolicy.model_validate(payload)

    def test_decision_policy_rejects_metrics_that_do_not_match_matrix(self) -> None:
        payload = valid_policy()
        payload["metrics"]["recall"] = 1.0

        with self.assertRaisesRegex(ValidationError, "recall must match"):
            DecisionPolicy.model_validate(payload)

    def test_calibration_report_requires_matching_dataset_and_source_hashes(self) -> None:
        policy = valid_policy()
        report = CalibrationReport.model_validate(
            {
                "schema_version": "1.0",
                "report_version": "phase3-report-test-v1",
                "dataset_version": "phase3-calibration-sources-v1",
                "generated_at": "2026-08-12T00:00:00Z",
                "candidate_policy_count": 10,
                "source_hashes": {
                    "tranco_top_1m": "a" * 64,
                    "phishtank_online_valid": "b" * 64,
                },
                "analysis_versions": {
                    "url_vet": "urlvet-test-v1",
                    "local_judgement_model": "lr-test-v1",
                },
                "selected_policy": policy,
                "validation_metrics": policy["metrics"],
                "observation_count": 200,
                "score_pair_count": 180,
                "url_vet_status_counts": {
                    "complete": 180,
                    "partial": 10,
                    "unavailable": 10,
                },
                "verdict_counts": {"Safe": 100, "Suspicious": 100},
                "threshold_evidence": {
                    "combined_score_rule": "max(risk_score, judgement_score)",
                    "low_medium_method": "Synthetic fixture.",
                    "presumed_benign_distribution": {
                        "count": 4,
                        "minimum": 10,
                        "first_quartile": 20,
                        "median": 30,
                        "third_quartile": 40,
                        "maximum": 50,
                    },
                    "presumed_benign_upper_quartile": 40,
                    "medium_high_method": "Synthetic fixture.",
                    "high_dangerous_method": "Synthetic fixture.",
                    "suspicious_distribution": {
                        "count": 4,
                        "minimum": 60,
                        "first_quartile": 70,
                        "median": 80,
                        "third_quartile": 90,
                        "maximum": 100,
                    },
                    "agreement_margin_method": "Synthetic fixture.",
                    "absolute_score_difference_distribution": {
                        "count": 4,
                        "minimum": 1,
                        "first_quartile": 2,
                        "median": 3,
                        "third_quartile": 4,
                        "maximum": 5,
                    },
                    "adverse_verdicts": ["Suspicious", "Risky", "Malicious"],
                },
                "methodology": ["Synthetic contract fixture."],
                "justification": "Contract fixture only.",
            }
        )

        self.assertEqual(report.selected_policy.policy_version, policy["policy_version"])

        bad_report = deepcopy(report.model_dump(mode="json"))
        bad_report["dataset_version"] = "other-dataset"
        with self.assertRaisesRegex(ValidationError, "same dataset"):
            CalibrationReport.model_validate(bad_report)


if __name__ == "__main__":
    unittest.main()
