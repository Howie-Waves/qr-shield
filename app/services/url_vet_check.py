"""Adapter from url.vet responses to QR Shield checks and analysis."""

from __future__ import annotations

import math
import os
from typing import Any

from app.services.checks import make_check
from app.services.url_vet_client import UrlVetUnavailableError, scan


DEFAULT_URL_VET_VERSION = "urlvet-local"
RISK_LEVEL_THRESHOLDS = {"low_max_exclusive": 40, "medium_max_exclusive": 70}


def get_url_vet_version() -> str:
    return os.getenv("QR_URLVET_VERSION", DEFAULT_URL_VET_VERSION).strip() or DEFAULT_URL_VET_VERSION


def _risk_level(score: float) -> str:
    if score < RISK_LEVEL_THRESHOLDS["low_max_exclusive"]:
        return "Low"
    if score < RISK_LEVEL_THRESHOLDS["medium_max_exclusive"]:
        return "Medium"
    return "High"


def _finite_score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score):
        return None
    return min(max(score, 0.0), 100.0)


def _reasons(raw_reasons: Any) -> list[str]:
    if not isinstance(raw_reasons, dict):
        return []
    messages: list[str] = []
    for group in ("bad_reasons", "good_reasons", "neutral_reasons"):
        values = raw_reasons.get(group)
        if not isinstance(values, list):
            continue
        for value in values:
            text = str(value).strip()
            if text:
                messages.append(text)
            if len(messages) == 3:
                return messages
    return messages


def _result_details(result: Any, version: str) -> dict[str, Any]:
    details: dict[str, Any] = {"version": version}
    if not isinstance(result, dict):
        return details

    score = _finite_score(result.get("risk_score"))
    if score is not None:
        details["risk_score"] = score
        details["risk_level"] = _risk_level(score)

    trust_score = _finite_score(result.get("trust_score"))
    if trust_score is not None:
        details["trust_score"] = trust_score

    verdict = str(result.get("verdict") or "").strip()
    if verdict:
        details["verdict"] = verdict

    reasons = _reasons(result.get("reasons"))
    if reasons:
        details["reasons"] = reasons

    return details


def _incomplete(
    summary: str,
    reason_code: str,
    details: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], None]:
    check_details = details or {"version": get_url_vet_version()}
    return (
        make_check(
            "url_vet",
            "incomplete",
            summary,
            [reason_code],
            check_details,
        ),
        None,
    )


def _analysis_from_details(details: dict[str, Any]) -> dict[str, Any] | None:
    score = _finite_score(details.get("risk_score"))
    if score is None:
        return None
    return {
        "score": score,
        "risk_score": score,
        "level": details.get("risk_level") or _risk_level(score),
        "reasons": list(details.get("reasons") or []),
        "model_name": "url.vet",
        "model_version": details.get("version") or get_url_vet_version(),
        "trust_score": details.get("trust_score"),
        "verdict": details.get("verdict"),
    }


def _partial(
    summary: str,
    details: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    analysis = _analysis_from_details(details)
    if analysis is None:
        raise ValueError("partial url.vet evidence requires a numeric risk score")
    analysis["url_vet_partial"] = True
    return (
        make_check(
            "url_vet",
            "warning",
            summary,
            ["URL_VET_PARTIAL"],
            details,
        ),
        analysis,
    )


def analyze_url(url: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return the url.vet check plus RiskAnalysis-compatible data."""
    version = get_url_vet_version()
    try:
        raw = scan(url)
    except UrlVetUnavailableError:
        return _incomplete("url.vet is unavailable.", "URL_VET_UNAVAILABLE")

    result = raw.get("result")
    if raw.get("incomplete") is True:
        details = _result_details(result, version)
        errors = raw.get("errors")
        if isinstance(errors, list):
            details["errors"] = [str(error) for error in errors[:3]]
        if _analysis_from_details(details) is not None:
            return _partial(
                "url.vet returned partial analysis; available risk evidence is shown.",
                details,
            )
        return _incomplete(
            "url.vet reported an incomplete analysis.",
            "URL_VET_INCOMPLETE",
            details,
        )

    if not isinstance(result, dict):
        return _incomplete("url.vet returned invalid result data.", "URL_VET_RESULT_INVALID")

    score = _finite_score(result.get("risk_score"))
    if score is None:
        return _incomplete("url.vet returned invalid risk score data.", "URL_VET_RESULT_INVALID")

    trust_score = _finite_score(result.get("trust_score"))
    verdict = str(result.get("verdict") or "").strip() or None
    reasons = _reasons(result.get("reasons"))

    analysis = {
        "score": score,
        "risk_score": score,
        "level": _risk_level(score),
        "reasons": reasons,
        "model_name": "url.vet",
        "model_version": version,
        "trust_score": trust_score,
        "verdict": verdict,
    }
    check = make_check(
        "url_vet",
        "passed",
        "url.vet URL risk analysis completed.",
        [f"URL_VET_VERDICT_{verdict.upper()}"] if verdict else [],
        {
            "version": version,
            "risk_score": score,
            "trust_score": trust_score,
            "verdict": verdict,
            "risk_level_thresholds": RISK_LEVEL_THRESHOLDS,
        },
    )
    return check, analysis
