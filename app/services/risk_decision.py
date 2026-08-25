"""Apply the versioned Phase 3 policy to two independent URL scores."""

from __future__ import annotations

import math
from typing import Any

from app.services.decision_policy import DecisionPolicy, load_decision_policy


LEVEL_RANK = {
    "Low suspicion": 0,
    "Medium suspicion": 1,
    "High suspicion": 2,
    "Dangerous": 3,
}


class DecisionPolicyUnavailableError(RuntimeError):
    """Raised when the committed policy cannot be loaded for a URL decision."""


def _valid_score(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or not 0 <= score <= 100:
        return None
    return score


def _score_level(score: float, policy: DecisionPolicy) -> str:
    thresholds = policy.thresholds
    if score < thresholds.low_medium:
        return "Low suspicion"
    if score < thresholds.medium_high:
        return "Medium suspicion"
    if score < thresholds.high_dangerous:
        return "High suspicion"
    return "Dangerous"


def _base_result(policy: DecisionPolicy | None) -> dict[str, Any]:
    if policy is None:
        return {
            "policy_version": None,
            "policy_status": None,
            "benchmark": None,
            "agreement_margin": None,
            "thresholds": None,
        }
    return {
        "policy_version": policy.policy_version,
        "policy_status": policy.status,
        "benchmark": policy.suspicious_benchmark,
        "agreement_margin": policy.agreement_margin,
        "thresholds": policy.thresholds.model_dump(mode="json"),
    }


def not_applicable_decision(reason: str) -> dict[str, Any]:
    """Return an explicit no-score result for non-web QR content."""
    return {
        **_base_result(None),
        "suspicion_level": "Not applicable",
        "conclusion": "Not applicable",
        "confidence_level": "Not applicable",
        "confidence_reason": reason,
        "decision_reasons": [],
        "risk_score_level": None,
        "judgement_score_level": None,
        "risk_vote_suspicious": None,
        "judgement_vote_suspicious": None,
        "adverse_verdict": None,
    }


def policy_unavailable_decision(reason: str) -> dict[str, Any]:
    """Return an incomplete result rather than applying guessed thresholds."""
    return {
        **_base_result(None),
        "suspicion_level": None,
        "conclusion": "Incomplete",
        "confidence_level": "Unavailable",
        "confidence_reason": reason,
        "decision_reasons": [],
        "risk_score_level": None,
        "judgement_score_level": None,
        "risk_vote_suspicious": None,
        "judgement_vote_suspicious": None,
        "adverse_verdict": None,
    }


def _incomplete_decision(
    policy: DecisionPolicy,
    risk_score: float | None,
    judgement_score: float | None,
) -> dict[str, Any]:
    missing_sources: list[str] = []
    if risk_score is None:
        missing_sources.append("url.vet risk score")
    if judgement_score is None:
        missing_sources.append("local judgement score")
    missing_text = " and ".join(missing_sources)
    return {
        **_base_result(policy),
        "suspicion_level": None,
        "conclusion": "Incomplete",
        "confidence_level": "Unavailable",
        "confidence_reason": (
            f"{missing_text} is unavailable, so no final suspicion level was assigned."
        ),
        "decision_reasons": [
            "Both score sources are mandatory for a completed Phase 3 URL decision."
        ],
        "risk_score_level": _score_level(risk_score, policy) if risk_score is not None else None,
        "judgement_score_level": (
            _score_level(judgement_score, policy)
            if judgement_score is not None
            else None
        ),
        "risk_vote_suspicious": (
            risk_score >= policy.suspicious_benchmark if risk_score is not None else None
        ),
        "judgement_vote_suspicious": (
            judgement_score >= policy.suspicious_benchmark
            if judgement_score is not None
            else None
        ),
        "adverse_verdict": None,
    }


def _load_policy(policy: DecisionPolicy | None) -> DecisionPolicy:
    if policy is not None:
        return policy
    try:
        return load_decision_policy()
    except Exception as exc:
        raise DecisionPolicyUnavailableError(
            "The versioned decision policy is unavailable."
        ) from exc


def decide_url_risk(
    risk_score: Any,
    judgement_score: Any,
    verdict: Any = None,
    *,
    policy: DecisionPolicy | None = None,
    partial_source: str | None = None,
) -> dict[str, Any]:
    """Combine url.vet and local scores using the checked-in policy."""
    selected_policy = _load_policy(policy)
    risk = _valid_score(risk_score)
    judgement = _valid_score(judgement_score)
    if risk is None or judgement is None:
        if risk is not None:
            return decide_single_source(
                risk,
                "url.vet",
                verdict,
                policy=selected_policy,
            )
        if judgement is not None:
            return decide_single_source(
                judgement,
                "local judgement",
                verdict,
                policy=selected_policy,
            )
        return _incomplete_decision(selected_policy, risk, judgement)

    risk_level = _score_level(risk, selected_policy)
    judgement_level = _score_level(judgement, selected_policy)
    risk_vote = risk >= selected_policy.suspicious_benchmark
    judgement_vote = judgement >= selected_policy.suspicious_benchmark

    normalized_verdict = str(verdict or "").strip().casefold()
    verdict_floors = {
        "suspicious": selected_policy.verdict_floors.suspicious,
        "risky": selected_policy.verdict_floors.risky,
        "malicious": selected_policy.verdict_floors.malicious,
    }
    verdict_floor = verdict_floors.get(normalized_verdict)
    final_level = max((risk_level, judgement_level), key=LEVEL_RANK.__getitem__)
    if verdict_floor and LEVEL_RANK[verdict_floor] > LEVEL_RANK[final_level]:
        final_level = verdict_floor

    adverse_verdict = normalized_verdict.title() if verdict_floor else None
    if final_level == "Dangerous":
        conclusion = "Suspicious"
    elif risk_vote and judgement_vote:
        conclusion = "Suspicious"
    elif risk_vote or judgement_vote or adverse_verdict:
        conclusion = "Partially suspicious"
    else:
        conclusion = "Not suspicious"

    if partial_source and conclusion == "Not suspicious":
        conclusion = "Partially assessed"

    score_difference = abs(risk - judgement)
    near_benchmark = (
        abs(risk - selected_policy.suspicious_benchmark) <= selected_policy.agreement_margin
        or abs(judgement - selected_policy.suspicious_benchmark)
        <= selected_policy.agreement_margin
    )
    if risk_vote != judgement_vote:
        confidence_level = "Low"
        confidence_reason = (
            "The url.vet risk score and local judgement score disagree around the "
            f"benchmark B={selected_policy.suspicious_benchmark:g}; the more cautious "
            "suspicious conclusion was retained."
        )
    elif adverse_verdict and not (risk_vote and judgement_vote):
        confidence_level = "Low"
        confidence_reason = (
            f"The url.vet {adverse_verdict} verdict conflicts with one or both "
            "below-benchmark score votes, so the adverse verdict was retained cautiously."
        )
    elif (
        score_difference <= selected_policy.agreement_margin
        and not near_benchmark
    ):
        confidence_level = "High"
        direction = "above" if risk_vote else "below"
        confidence_reason = (
            f"Both scores agree {direction} B={selected_policy.suspicious_benchmark:g}, "
            f"differ by no more than D={selected_policy.agreement_margin:g}, and are not "
            "close to the benchmark."
        )
    else:
        confidence_level = "Medium"
        qualifiers: list[str] = []
        if near_benchmark:
            qualifiers.append("at least one score is close to the benchmark")
        if score_difference > selected_policy.agreement_margin:
            qualifiers.append("the score difference exceeds the agreement margin")
        confidence_reason = (
            "Both scores make the same benchmark decision, but "
            + " and ".join(qualifiers)
            + "."
        )

    if partial_source:
        confidence_level = "Low"
        confidence_reason = (
            confidence_reason.rstrip(".")
            + f" The {partial_source} source also returned partial evidence, so this "
            "is not a fully completed two-source analysis."
        )

    decision_reasons = [
        (
            f"url.vet risk score {risk:g} "
            f"{'reached' if risk_vote else 'stayed below'} B={selected_policy.suspicious_benchmark:g}."
        ),
        (
            f"Local judgement score {judgement:g} "
            f"{'reached' if judgement_vote else 'stayed below'} B={selected_policy.suspicious_benchmark:g}."
        ),
        f"The more cautious score-derived level is {max((risk_level, judgement_level), key=LEVEL_RANK.__getitem__)}.",
    ]
    if adverse_verdict:
        decision_reasons.append(
            f"url.vet verdict {adverse_verdict} sets a minimum level of {verdict_floor}."
        )
    if final_level != max((risk_level, judgement_level), key=LEVEL_RANK.__getitem__):
        decision_reasons.append(f"Final level was raised to {final_level} by the verdict floor.")

    return {
        **_base_result(selected_policy),
        "suspicion_level": final_level,
        "conclusion": conclusion,
        "confidence_level": confidence_level,
        "confidence_reason": confidence_reason,
        "decision_reasons": decision_reasons,
        "risk_score_level": risk_level,
        "judgement_score_level": judgement_level,
        "risk_vote_suspicious": risk_vote,
        "judgement_vote_suspicious": judgement_vote,
        "adverse_verdict": adverse_verdict,
    }


def decide_single_source(
    score: Any,
    source: str,
    verdict: Any = None,
    *,
    policy: DecisionPolicy | None = None,
) -> dict[str, Any]:
    """Provide a clearly partial decision when only one score is available."""
    selected_policy = _load_policy(policy)
    usable_score = _valid_score(score)
    if usable_score is None:
        return _incomplete_decision(selected_policy, None, None)
    if source not in {"url.vet", "local judgement"}:
        raise ValueError("source must be url.vet or local judgement")

    level = _score_level(usable_score, selected_policy)
    vote_suspicious = usable_score >= selected_policy.suspicious_benchmark
    normalized_verdict = str(verdict or "").strip().casefold()
    verdict_floors = {
        "suspicious": selected_policy.verdict_floors.suspicious,
        "risky": selected_policy.verdict_floors.risky,
        "malicious": selected_policy.verdict_floors.malicious,
    }
    verdict_floor = verdict_floors.get(normalized_verdict)
    final_level = level
    if verdict_floor and LEVEL_RANK[verdict_floor] > LEVEL_RANK[final_level]:
        final_level = verdict_floor
    adverse_verdict = normalized_verdict.title() if verdict_floor else None

    conclusion = (
        "Partially suspicious"
        if vote_suspicious or adverse_verdict or final_level == "Dangerous"
        else "Partially assessed"
    )
    source_label = "url.vet risk score" if source == "url.vet" else "local judgement score"
    decision_reasons = [
        f"Only the {source_label} was available: {usable_score:g}.",
        f"The available score maps to {final_level} under the versioned policy.",
        "A second score source was unavailable, so this is not a completed two-source decision.",
    ]
    if adverse_verdict:
        decision_reasons.append(
            f"url.vet verdict {adverse_verdict} sets a minimum level of {verdict_floor}."
        )

    return {
        **_base_result(selected_policy),
        "suspicion_level": final_level,
        "conclusion": conclusion,
        "confidence_level": "Low",
        "confidence_reason": (
            f"Only the {source_label} was available; the missing source prevents a "
            "full two-score conclusion, so confidence is Low."
        ),
        "decision_reasons": decision_reasons,
        "risk_score_level": level if source == "url.vet" else None,
        "judgement_score_level": level if source == "local judgement" else None,
        "risk_vote_suspicious": vote_suspicious if source == "url.vet" else None,
        "judgement_vote_suspicious": vote_suspicious if source == "local judgement" else None,
        "adverse_verdict": adverse_verdict,
    }
