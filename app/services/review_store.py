"""Redacted local SQLite storage for explicit review cases and model releases."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "review_queue.db"
RETENTION_POLICY_VERSION = "e3-us2-redaction-v1"
RETAINED_FIELDS = (
    "payload_sha256", "hostname_sha256", "outcome", "model_version",
    "reason_codes", "status", "consented_at", "policy_version",
)


def _db_path() -> Path:
    return Path(os.getenv("QR_REVIEW_DB_PATH", str(DEFAULT_DB_PATH)))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: str) -> str:
    return hashlib.sha256(value.casefold().strip().encode("utf-8")).hexdigest()


def _connection() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS review_cases (
            case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, resolved_at TEXT,
            payload_sha256 TEXT NOT NULL, hostname_sha256 TEXT, outcome TEXT NOT NULL,
            model_version TEXT, reason_codes TEXT NOT NULL, status TEXT NOT NULL,
            reviewer_id TEXT, reviewer_decision TEXT, consented_at TEXT NOT NULL,
            policy_version TEXT NOT NULL
        )"""
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(review_cases)")}
    if "consented_at" not in columns:
        connection.execute("ALTER TABLE review_cases ADD COLUMN consented_at TEXT")
    if "policy_version" not in columns:
        connection.execute("ALTER TABLE review_cases ADD COLUMN policy_version TEXT")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS model_releases (
            release_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, model_version TEXT NOT NULL,
            metrics_sha256 TEXT NOT NULL, reviewer_id TEXT NOT NULL, decision TEXT NOT NULL,
            rollback_target TEXT, notes TEXT
        )"""
    )
    return connection


def create_review_case(
    payload: str,
    hostname: str | None,
    outcome: str,
    model_version: str | None,
    reason_codes: list[str],
    consent: bool,
) -> str:
    """Queue an explicit review request, retaining hashes only."""
    if not consent:
        raise PermissionError("Explicit retention consent is required.")
    case_id = str(uuid.uuid4())
    with _connection() as connection:
        connection.execute(
            """INSERT INTO review_cases (
                case_id, created_at, resolved_at, payload_sha256, hostname_sha256,
                outcome, model_version, reason_codes, status, reviewer_id,
                reviewer_decision, consented_at, policy_version
            ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)""",
            (
                case_id, _now(), _digest(payload), _digest(hostname) if hostname else None,
                outcome, model_version, ",".join(sorted(set(reason_codes))), _now(),
                RETENTION_POLICY_VERSION,
            ),
        )
    return case_id


def _allowed_reviewer(reviewer_id: str) -> bool:
    allowed = {
        item.strip()
        for item in os.getenv("QR_SHIELD_REVIEWERS", "").split(",")
        if item.strip()
    }
    return reviewer_id in allowed


def list_review_cases() -> list[dict[str, str | None]]:
    with _connection() as connection:
        rows = connection.execute("SELECT * FROM review_cases ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]


def decide_case(case_id: str, reviewer_id: str, decision: str) -> None:
    if decision not in {"approved", "rejected", "closed"}:
        raise ValueError("Decision must be approved, rejected, or closed.")
    if not _allowed_reviewer(reviewer_id):
        raise PermissionError("Reviewer is not in QR_SHIELD_REVIEWERS.")
    with _connection() as connection:
        result = connection.execute(
            "UPDATE review_cases SET status=?, reviewer_id=?, reviewer_decision=?, resolved_at=? WHERE case_id=?",
            ("resolved", reviewer_id, decision, _now(), case_id),
        )
        if result.rowcount != 1:
            raise ValueError("Review case was not found.")


def record_model_release(
    model_version: str,
    metrics_path: Path,
    reviewer_id: str,
    decision: str,
    rollback_target: str | None,
    notes: str | None,
) -> str:
    """Record a governed release decision without changing a model artifact."""
    if not _allowed_reviewer(reviewer_id):
        raise PermissionError("Reviewer is not in QR_SHIELD_REVIEWERS.")
    if decision not in {"approved", "rejected", "rolled_back"}:
        raise ValueError("Invalid model release decision.")
    if not model_version.strip():
        raise ValueError("A versioned model release is required.")
    if decision in {"approved", "rolled_back"} and not rollback_target:
        raise ValueError("A rollback target is required for approved or rolled-back releases.")
    try:
        evidence = json.loads(metrics_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("Evaluation evidence must be a readable JSON report.") from exc
    if decision == "approved" and (
        not isinstance(evidence, dict)
        or evidence.get("passed_scenarios") != evidence.get("scenario_count")
    ):
        raise ValueError("Approved releases require a passing evaluation report.")
    digest = hashlib.sha256(metrics_path.read_bytes()).hexdigest()
    release_id = str(uuid.uuid4())
    with _connection() as connection:
        connection.execute(
            "INSERT INTO model_releases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (release_id, _now(), model_version, digest, reviewer_id, decision, rollback_target, notes),
        )
    return release_id


def cleanup_expired() -> int:
    """Delete pending cases after 30 days and resolved cases after 90 days."""
    now = datetime.now(timezone.utc)
    pending_cutoff = (now - timedelta(days=30)).isoformat()
    resolved_cutoff = (now - timedelta(days=90)).isoformat()
    with _connection() as connection:
        result = connection.execute(
            "DELETE FROM review_cases WHERE (status='pending' AND created_at < ?) OR "
            "(status='resolved' AND resolved_at < ?)",
            (pending_cutoff, resolved_cutoff),
        )
    return result.rowcount
