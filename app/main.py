"""FastAPI endpoints for safe, in-memory QR image decoding."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, HTTPException, UploadFile, status

from app.schemas import AnalyzeResponse, HealthResponse, ReviewCaseRequest, ReviewCaseResponse
from app.services.model_service import ModelUnavailableError, predict_url_risk
from app.services.block_inspection import inspect_blocks
from app.services.checks import adapt_check, aggregate_outcome, make_check
from app.services.denylist import check_denylist
from app.services.payment_verification import verify_payment
from app.services.qr_decoder import MAX_IMAGE_SIZE, QRDecodeError, decode_qr_image
from app.services.risk_decision import (
    DecisionPolicyUnavailableError,
    decide_url_risk,
    decide_single_source,
    not_applicable_decision,
    policy_unavailable_decision,
)
from app.services.url_vet_check import analyze_url
from app.services.url_features import extract_hostname
from app.services import review_store


app = FastAPI(title="QR Shield E1-US1")


def _is_structured_non_web_payload(text: str) -> bool:
    low = text.strip().casefold()
    return low.startswith("wifi:") or "wifimasterkey://" in low or text.strip().startswith("BEGIN:VCARD")


def _run_local_judgement(url: str) -> tuple[dict, dict | None]:
    """Score a valid URL locally without changing the primary url.vet result."""
    try:
        result = predict_url_risk(url)
    except ModelUnavailableError:
        return (
            make_check(
                "local_judgement",
                "incomplete",
                "The local URL judgement model is unavailable.",
                ["LOCAL_JUDGEMENT_UNAVAILABLE"],
            ),
            None,
        )
    except Exception:
        return (
            make_check(
                "local_judgement",
                "incomplete",
                "The local URL judgement model could not complete.",
                ["LOCAL_JUDGEMENT_INVALID"],
            ),
            None,
        )

    judgement = {
        "judgement_score": result["score"],
        "judgement_level": result["level"],
        "judgement_reasons": list(result.get("reasons") or [])[:3],
        "judgement_model_name": result["model_name"],
        "judgement_model_version": result["model_version"],
    }
    return (
        make_check(
            "local_judgement",
            "passed",
            "Local lexical URL judgement completed.",
            [],
            {
                "judgement_score": judgement["judgement_score"],
                "level": judgement["judgement_level"],
                "reasons": judgement["judgement_reasons"],
                "model_name": judgement["judgement_model_name"],
                "model_version": judgement["judgement_model_version"],
            },
        ),
        judgement,
    )


def _local_only_analysis(judgement: dict) -> dict:
    """Expose the local score without presenting it as url.vet evidence."""
    return {
        "score": judgement["judgement_score"],
        "level": judgement["judgement_level"],
        "reasons": judgement["judgement_reasons"],
        "model_name": judgement["judgement_model_name"],
        "model_version": judgement["judgement_model_version"],
        "risk_score": None,
        "trust_score": None,
        "verdict": None,
        "judgement_score": judgement["judgement_score"],
        "judgement_reasons": judgement["judgement_reasons"],
        "judgement_model_name": judgement["judgement_model_name"],
        "judgement_model_version": judgement["judgement_model_version"],
    }


@app.get("/health", response_model=HealthResponse)
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/review-cases", response_model=ReviewCaseResponse)
def report_for_review(request: ReviewCaseRequest) -> dict:
    """Store an explicit review request as redacted local metadata only."""
    try:
        case_id = review_store.create_review_case(
            request.payload,
            request.hostname,
            request.assessment_outcome,
            request.model_version,
            request.reason_codes,
            request.consent,
        )
    except PermissionError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    return {"case_id": case_id}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(file: UploadFile = File(...)) -> dict:
    """Validate and decode one QR image without opening its destination."""
    try:
        image_bytes = await file.read(MAX_IMAGE_SIZE + 1)
    except Exception:
        raise HTTPException(500, "The uploaded file could not be read.") from None
    finally:
        await file.close()

    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "Image file exceeds the 5 MiB size limit.",
        )

    try:
        decoded = decode_qr_image(image_bytes, Path(file.filename or "").name)
    except QRDecodeError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except Exception:
        raise HTTPException(500, "An internal error occurred while decoding.") from None

    analysis = None
    decision = not_applicable_decision(
        "This QR code does not contain a supported web URL for two-score analysis."
    )
    hostname = None
    checks = [adapt_check(inspect_blocks(image_bytes))]
    assessment_outcome = "Not applicable"
    analysis_status = "Not scored"
    failed_check_ids: list[str] = []
    message = "Decoded locally. The destination was not opened."
    if decoded["content_type"] == "url":
        hostname = extract_hostname(decoded["decoded_text"])
        if not hostname:
            checks.append(check_denylist(decoded["decoded_text"]))
            checks.append(
                make_check(
                    "url_vet", "not_applicable", "url.vet does not apply to a malformed URL."
                )
            )
            message = (
                "URL risk scoring was not performed because the URL is malformed. "
                "The destination was not opened."
            )
            decision = not_applicable_decision(
                "The QR code does not contain a valid web URL for two-score analysis."
            )
        else:
            checks.append(check_denylist(decoded["decoded_text"]))
            url_vet_check: dict | None = None
            url_vet_partial = False
            try:
                url_vet_check, analysis = analyze_url(decoded["decoded_text"])
            except Exception:
                checks.append(
                    make_check(
                        "url_vet", "incomplete", "url.vet URL risk analysis could not complete.",
                        ["URL_VET_RESULT_INVALID"],
                    )
                )
                message = (
                    "url.vet was unavailable. A local URL judgement will be shown "
                    "if it completes; the destination was not opened."
                )
            else:
                checks.append(url_vet_check)
                url_vet_partial = url_vet_check.get("status") == "warning"
                if analysis is None:
                    message = (
                        "url.vet did not return a usable score. A local URL judgement "
                        "will be shown if it completes; the destination was not opened."
                    )
                elif url_vet_partial:
                    message = (
                        "url.vet returned partial evidence. The available score and "
                        "local judgement are shown for review; the destination was not opened."
                    )
                else:
                    analysis["risk_score"] = analysis["score"]
                    message = "Decoded and checked with url.vet. The destination was not opened."

            local_judgement_check, local_judgement = _run_local_judgement(
                decoded["decoded_text"]
            )
            checks.append(local_judgement_check)
            if analysis is not None and local_judgement is not None:
                analysis.update(local_judgement)
            try:
                if analysis is not None and local_judgement is not None:
                    decision = decide_url_risk(
                        analysis.get("risk_score"),
                        local_judgement.get("judgement_score"),
                        analysis.get("verdict"),
                        partial_source="url.vet" if url_vet_partial else None,
                    )
                elif analysis is not None:
                    decision = decide_single_source(
                        analysis.get("risk_score"),
                        "url.vet",
                        analysis.get("verdict"),
                    )
                elif local_judgement is not None:
                    analysis = _local_only_analysis(local_judgement)
                    decision = decide_single_source(
                        local_judgement.get("judgement_score"),
                        "local judgement",
                    )
                else:
                    decision = decide_url_risk(None, None)
            except DecisionPolicyUnavailableError:
                checks.append(
                    make_check(
                        "decision_policy",
                        "incomplete",
                        "The versioned risk decision policy is unavailable.",
                        ["DECISION_POLICY_UNAVAILABLE"],
                    )
                )
                decision = policy_unavailable_decision(
                    "The versioned decision policy is unavailable, so no final suspicion level was assigned."
                )
    else:
        checks.append(
            make_check(
                "local_denylist", "not_applicable",
                "Denylist does not apply to non-URL QR content.",
            )
        )
        decoded_text = decoded["decoded_text"]
        uri_scheme = urlsplit(decoded_text).scheme
        if decoded["content_type"] == "payment":
            url_vet_summary = "url.vet does not apply to payment QR content."
            message = (
                "URL risk scoring was not performed because this QR code contains "
                "payment content."
            )
        elif _is_structured_non_web_payload(decoded_text):
            url_vet_summary = "url.vet does not apply to structured non-web QR content."
            message = (
                "URL risk scoring was not performed because this QR code contains "
                "structured non-web content."
            )
        elif uri_scheme:
            url_vet_summary = (
                "url.vet does not apply to unsupported URI scheme: "
                f"{uri_scheme.casefold()}."
            )
            message = (
                "URL risk scoring was not performed because this QR code uses an "
                "unsupported URI scheme."
            )
        else:
            url_vet_summary = "url.vet does not apply to plain-text QR content."
            message = (
                "URL risk scoring was not performed because this QR code contains "
                "plain text."
            )
        checks.append(make_check("url_vet", "not_applicable", url_vet_summary))
        decision = not_applicable_decision(url_vet_summary)
    payment = verify_payment(decoded["decoded_text"])
    checks.append(adapt_check(payment))
    if decoded["content_type"] == "payment":
        message = "Payment fields were checked locally. No payment was initiated."

    assessment_outcome, analysis_status, failed_check_ids = aggregate_outcome(checks)
    score_source_failures_only = bool(failed_check_ids) and set(failed_check_ids).issubset(
        {"url_vet", "local_judgement"}
    )
    missing_score_source = any(
        item["check_id"] in {"url_vet", "local_judgement"}
        and item["status"] == "incomplete"
        for item in checks
    )
    partial_url_vet = any(
        item["check_id"] == "url_vet" and item["status"] == "warning"
        for item in checks
    )

    if decision["conclusion"] == "Incomplete":
        # Missing policy, both score sources, or another mandatory check must
        # remain visibly incomplete; no fallback is allowed without evidence.
        assessment_outcome = "Incomplete"
        analysis_status = "Incomplete"
    elif analysis is not None and (missing_score_source or partial_url_vet):
        # A usable single score or partial url.vet response is useful evidence,
        # but it is never represented as a completed two-source assessment.
        if analysis_status != "Incomplete" or score_source_failures_only:
            assessment_outcome = "Review required"
            analysis_status = "Partial"
    elif (
        decision["conclusion"] in {"Partially suspicious", "Suspicious"}
        and analysis_status != "Incomplete"
    ):
        assessment_outcome = "Review required"
    if analysis is None and analysis_status == "Complete":
        analysis_status = "Not scored"
        assessment_outcome = (
            "Review required" if assessment_outcome == "Review required" else "Not applicable"
        )

    source_versions = {
        item["check_id"]: item["details"].get("version")
        or item["details"].get("model_version")
        for item in checks
        if item["details"].get("version") or item["details"].get("model_version")
    }
    if decision["policy_version"]:
        source_versions["decision_policy"] = decision["policy_version"]

    return {
        "filename": Path(file.filename or "").name,
        "decoded_text": decoded["decoded_text"],
        "content_type": decoded["content_type"],
        "hostname": hostname,
        "image": {"width": decoded["image_width"], "height": decoded["image_height"]},
        "block_inspection": inspect_blocks(image_bytes),
        "payment": payment,
        "analysis": analysis,
        "decision": decision,
        "analysis_status": analysis_status,
        "failed_check_ids": failed_check_ids,
        "assessment_outcome": assessment_outcome,
        "checks": checks,
        "source_versions": source_versions,
        "principal_signals": [
            code for item in checks for code in item["reason_codes"]
        ][:3],
        "message": message,
    }
