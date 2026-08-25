import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app.services import review_store


class E3US2ReviewStoreTests(unittest.TestCase):
    def test_review_case_retains_only_hashes_and_requires_authorisation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "QR_REVIEW_DB_PATH": str(Path(directory) / "review.db"),
                "QR_SHIELD_REVIEWERS": "reviewer-a",
            },
        ):
            case_id = review_store.create_review_case(
                "https://private.example/path", "private.example", "Review required", "v1", ["TEST"], True
            )
            row = review_store.list_review_cases()[0]
            self.assertEqual(row["case_id"], case_id)
            self.assertNotIn("private.example", str(row))
            self.assertTrue(row["consented_at"])
            self.assertEqual(row["policy_version"], review_store.RETENTION_POLICY_VERSION)
            with self.assertRaises(PermissionError):
                review_store.decide_case(case_id, "not-authorised", "approved")
            review_store.decide_case(case_id, "reviewer-a", "approved")
            self.assertEqual(review_store.list_review_cases()[0]["status"], "resolved")

    def test_release_audit_never_modifies_model_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "QR_REVIEW_DB_PATH": str(Path(directory) / "review.db"),
                "QR_SHIELD_REVIEWERS": "reviewer-a",
            },
        ):
            metrics = Path(directory) / "metrics.json"
            metrics.write_text(
                '{"scenario_count": 2, "passed_scenarios": 2}', encoding="utf-8"
            )
            before = metrics.read_bytes()
            release_id = review_store.record_model_release(
                "v1", metrics, "reviewer-a", "approved", "v0", "test"
            )
            self.assertTrue(release_id)
            self.assertEqual(metrics.read_bytes(), before)

    def test_retention_cleanup_removes_expired_pending_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"QR_REVIEW_DB_PATH": str(Path(directory) / "review.db")}
        ):
            review_store.create_review_case("payload", None, "Incomplete", None, [], True)
            old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
            with sqlite3.connect(Path(directory) / "review.db") as connection:
                connection.execute("UPDATE review_cases SET created_at=?", (old,))
            self.assertEqual(review_store.cleanup_expired(), 1)
            self.assertEqual(review_store.list_review_cases(), [])

    def test_consent_and_release_gate_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "QR_REVIEW_DB_PATH": str(Path(directory) / "review.db"),
                "QR_SHIELD_REVIEWERS": "reviewer-a",
            },
        ):
            with self.assertRaises(PermissionError):
                review_store.create_review_case("payload", None, "Incomplete", None, [], False)
            evidence = Path(directory) / "failed.json"
            evidence.write_text('{"scenario_count": 2, "passed_scenarios": 1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "passing evaluation"):
                review_store.record_model_release(
                    "v2", evidence, "reviewer-a", "approved", "v1", None
                )
            evidence.write_text('{"scenario_count": 2, "passed_scenarios": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "rollback target"):
                review_store.record_model_release(
                    "v2", evidence, "reviewer-a", "approved", None, None
                )
