"""Common local-check contract and cautious assessment outcome policy."""

from __future__ import annotations

from typing import Any


COMPLETE_STATUSES = frozenset({"passed", "not_applicable"})
REVIEW_STATUSES = frozenset({"warning", "failed", "unverifiable"})


def make_check(
    check_id: str,
    status: str,
    summary: str,
    reason_codes: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a result object for a local assessment check."""
    return {
        "check_id": check_id,
        "status": status,
        "summary": summary,
        "reason_codes": reason_codes or [],
        "details": details or {},
    }


def adapt_check(result: dict[str, Any]) -> dict[str, Any]:
    """Convert an existing service result to the common check contract."""
    return make_check(
        str(result["id"]),
        str(result["status"]),
        str(result["summary"]),
        list(result.get("reason_codes") or []),
        dict(result.get("evidence") or {}),
    )


def aggregate_outcome(checks: list[dict[str, Any]]) -> tuple[str, str, list[str]]:
    """Return assessment outcome, display status, and incomplete check IDs."""
    incomplete = [item["check_id"] for item in checks if item["status"] == "incomplete"]
    if incomplete:
        return "Incomplete", "Incomplete", incomplete
    if any(item["status"] in REVIEW_STATUSES for item in checks):
        return "Review required", "Complete", []
    if all(item["status"] == "not_applicable" for item in checks):
        return "Not applicable", "Not scored", []
    return "Risk assessed", "Complete", []
