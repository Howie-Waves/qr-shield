import json
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from app.services.decision_policy import (
    load_calibration_manifest,
    verify_local_raw_files,
)
from app.services.qr_decoder import decode_qr_image
from scripts.evaluate_phase3_real_qr import (
    MANIFEST_PATH,
    REPORT_PATH,
    RealQrEvaluationReport,
    ReadyRecord,
    _encode_qr,
    _cross_checked_evidence,
    evaluate,
    load_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


class Phase3RealQrEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest()
        cls.ready = [
            record for record in cls.manifest.records if isinstance(record, ReadyRecord)
        ]

    def test_manifest_selects_every_complete_suspicious_validation_observation(self) -> None:
        linked, observations = _cross_checked_evidence(self.manifest)

        self.assertEqual(set(linked), {record.sample_id for record in self.ready})
        self.assertEqual(len(self.ready), 3)
        self.assertEqual(observations.url_vet_version, "urlvet-556c7aa3f5bb")
        self.assertEqual(
            {record.source_record_id for record in self.ready},
            {"9206118", "9413269", "9245521"},
        )

    def test_safe_reproductions_are_hash_locked_decodable_in_memory_and_inert(self) -> None:
        for record in self.ready:
            with self.subTest(sample=record.sample_id):
                decoded = decode_qr_image(
                    _encode_qr(record.fixture.payload),
                    "in-memory-safe-reproduction.png",
                )
                self.assertEqual(decoded["decoded_text"], record.fixture.payload)
                self.assertEqual(decoded["content_type"], "url")
                self.assertTrue(
                    (urlsplit(decoded["decoded_text"]).hostname or "").endswith(".invalid")
                )
                self.assertNotEqual(
                    record.fixture.payload_sha256,
                    record.original_payload_sha256,
                )

    def test_suspicious_sources_are_never_low_or_not_suspicious(self) -> None:
        report = evaluate(require_raw=False)

        self.assertEqual(report.metrics.low_suspicion_count, 0)
        self.assertEqual(report.metrics.not_suspicious_count, 0)
        self.assertEqual(report.metrics.safety_pass_rate, 1.0)
        self.assertEqual(report.metrics.detection_rate, 1.0)
        self.assertEqual(report.metrics.passed_case_count, report.ready_case_count)
        for case in report.case_results:
            with self.subTest(sample=case.sample_id):
                self.assertFalse(case.forbidden_low_outcome)
                self.assertTrue(case.detection_pass)
                self.assertIn(
                    case.decision.suspicion_level,
                    {"High suspicion", "Dangerous"},
                )
                self.assertIn(
                    case.decision.conclusion,
                    {"Partially suspicious", "Suspicious"},
                )

    def test_supervisor_sample_remains_named_pending_evidence(self) -> None:
        pending = [record for record in self.manifest.records if record.status == "pending"]

        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].sample_id, "supervisor-australia-fraud-qr")
        self.assertFalse(pending[0].source_received)
        self.assertEqual(pending[0].redistribution_permission, "undetermined")

    def test_committed_report_is_valid_redacted_and_matches_current_decisions(self) -> None:
        committed = RealQrEvaluationReport.model_validate_json(
            REPORT_PATH.read_text(encoding="utf-8")
        )
        current = evaluate(require_raw=False)

        self.assertEqual(committed.dataset_version, self.manifest.dataset_version)
        self.assertEqual(committed.metrics.low_suspicion_count, 0)
        self.assertEqual(committed.metrics.not_suspicious_count, 0)
        self.assertEqual(committed.metrics.passed_case_count, committed.ready_case_count)
        self.assertNotIn("://", REPORT_PATH.read_text(encoding="utf-8"))
        current_by_id = {case.sample_id: case for case in current.case_results}
        for case in committed.case_results:
            self.assertEqual(case.decision, current_by_id[case.sample_id].decision)
            self.assertEqual(case.risk_score, current_by_id[case.sample_id].risk_score)
            self.assertEqual(
                case.judgement_score,
                current_by_id[case.sample_id].judgement_score,
            )
            self.assertEqual(
                case.safe_reproduction_payload_sha256,
                current_by_id[case.sample_id].safe_reproduction_payload_sha256,
            )

    def test_manifest_contains_only_safe_or_provider_reference_urls(self) -> None:
        raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

        def strings(value):
            if isinstance(value, str):
                yield value
            elif isinstance(value, dict):
                for child in value.values():
                    yield from strings(child)
            elif isinstance(value, list):
                for child in value:
                    yield from strings(child)

        urls = [value for value in strings(raw) if "://" in value]
        self.assertGreaterEqual(len(urls), len(self.ready) + 1)
        for value in urls:
            hostname = (urlsplit(value).hostname or "").casefold()
            self.assertTrue(
                hostname == "phishtank.org" or hostname.endswith(".invalid"),
                value,
            )

    def test_evaluation_has_no_committed_binary_fixture_dependency(self) -> None:
        manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
        report_text = REPORT_PATH.read_text(encoding="utf-8")

        self.assertNotIn("data/test_images/phase3_real_suspicious", manifest_text)
        self.assertNotIn("data/test_images/phase3_real_suspicious", report_text)
        self.assertNotIn("safe_fixture_path", report_text)
        self.assertNotIn("safe_fixture_sha256", report_text)
        self.assertIn("safe_reproduction_decode_status", report_text)
        self.assertNotIn("safe_fixture_decode_success_count", report_text)

    def test_locked_local_source_reproduces_original_qr_audit_when_available(self) -> None:
        source_status = verify_local_raw_files(
            load_calibration_manifest()
        ).get("phishtank_online_valid")
        if source_status != "matched":
            self.skipTest("Ignored locked PhishTank snapshot is not available")

        report = evaluate(require_raw=True)

        self.assertEqual(report.source_audit_mode, "locked_local_snapshot")
        self.assertEqual(
            report.metrics.source_qr_decode_success_count,
            report.ready_case_count,
        )
        for case in report.case_results:
            self.assertEqual(case.source_qr_decode_status, "passed")
            self.assertTrue(case.local_score_reproduced)


if __name__ == "__main__":
    unittest.main()
