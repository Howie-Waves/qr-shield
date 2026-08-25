"""Plain-English presentation rules for the student interface."""

from urllib.parse import urlsplit


NON_URL_GUIDANCE = (
    "This is not a valid URL. Review the decoded content before deciding whether to trust it."
)


def _whole_number_text(value: object) -> str | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return f"{number:.0f}"


def _number_text(value: object) -> str | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number.is_integer():
        return f"{number:.0f}"
    return f"{number:.2f}".rstrip("0").rstrip(".")


def _score_text(value: object) -> str:
    text = _number_text(value)
    return f"{text} / 100" if text is not None else "Not available"


def _check_details(result: dict, check_id: str) -> tuple[dict, str]:
    for check in result.get("checks") or []:
        if check.get("check_id") != check_id:
            continue
        details = check.get("details")
        return (details if isinstance(details, dict) else {}, str(check.get("status") or "unknown"))
    return {}, "not_available"


def _decision_threshold_ranges(thresholds: object) -> list[tuple[str, str]]:
    if not isinstance(thresholds, dict):
        return []
    low_medium = _number_text(thresholds.get("low_medium"))
    medium_high = _number_text(thresholds.get("medium_high"))
    high_dangerous = _number_text(thresholds.get("high_dangerous"))
    if not low_medium or not medium_high or not high_dangerous:
        return []
    return [
        ("Low suspicion", f"0 to below {low_medium}"),
        ("Medium suspicion", f"{low_medium} to below {medium_high}"),
        ("High suspicion", f"{medium_high} to below {high_dangerous}"),
        ("Dangerous", f"{high_dangerous} to 100"),
    ]


def _vote_text(value: object) -> str:
    if value is True:
        return "Reached suspicious benchmark"
    if value is False:
        return "Below suspicious benchmark"
    return "Not available"


def get_decision_display(result: dict) -> dict[str, object]:
    """Format the API's versioned decision without recalculating it in the UI."""
    decision = result.get("decision")
    if not isinstance(decision, dict):
        return {
            "available": False,
            "final_level": "Not scored",
            "conclusion": "Not available",
            "confidence_level": "Unavailable",
            "confidence_reason": "No versioned decision was returned.",
            "decision_reasons": [],
            "benchmark": "Not available",
            "agreement_margin": "Not available",
            "threshold_ranges": [],
            "policy": "Not available",
            "risk_score_level": "Not available",
            "judgement_score_level": "Not available",
            "risk_vote": "Not available",
            "judgement_vote": "Not available",
            "adverse_verdict": "Not available",
            "has_score_conflict": False,
            "has_verdict_conflict": False,
        }

    risk_vote = decision.get("risk_vote_suspicious")
    judgement_vote = decision.get("judgement_vote_suspicious")
    adverse_verdict = str(decision.get("adverse_verdict") or "").strip()
    has_score_conflict = (
        isinstance(risk_vote, bool)
        and isinstance(judgement_vote, bool)
        and risk_vote != judgement_vote
    )
    has_verdict_conflict = bool(adverse_verdict) and not (risk_vote is True and judgement_vote is True)
    policy_version = str(decision.get("policy_version") or "Not available")
    policy_status = str(decision.get("policy_status") or "")
    policy = policy_version if not policy_status else f"{policy_version} ({policy_status})"

    conclusion = str(decision.get("conclusion") or "Not available")
    final_level = str(decision.get("suspicion_level") or "Not scored")
    confidence_level = str(decision.get("confidence_level") or "Unavailable")
    if conclusion == "Not applicable":
        final_level = "Not applicable"
        if confidence_level == "Unavailable":
            confidence_level = "Not applicable"

    return {
        "available": True,
        "final_level": final_level,
        "conclusion": conclusion,
        "confidence_level": confidence_level,
        "confidence_reason": str(
            decision.get("confidence_reason") or "No confidence explanation was returned."
        ),
        "decision_reasons": [
            str(reason)
            for reason in (decision.get("decision_reasons") or [])
            if str(reason).strip()
        ][:4],
        "benchmark": _score_text(decision.get("benchmark")),
        "agreement_margin": _number_text(decision.get("agreement_margin")) or "Not available",
        "threshold_ranges": _decision_threshold_ranges(decision.get("thresholds")),
        "policy": policy,
        "risk_score_level": str(decision.get("risk_score_level") or "Not available"),
        "judgement_score_level": str(
            decision.get("judgement_score_level") or "Not available"
        ),
        "risk_vote": _vote_text(risk_vote),
        "judgement_vote": _vote_text(judgement_vote),
        "adverse_verdict": adverse_verdict or "Not available",
        "has_score_conflict": has_score_conflict,
        "has_verdict_conflict": has_verdict_conflict,
    }


def get_score_evidence_display(result: dict) -> dict[str, object]:
    """Collect independently labelled url.vet and local-score evidence for display."""
    analysis = result.get("analysis")
    analysis = analysis if isinstance(analysis, dict) else {}
    url_vet_details, url_vet_status = _check_details(result, "url_vet")
    judgement_details, judgement_status = _check_details(result, "local_judgement")
    if analysis and url_vet_status == "not_available":
        url_vet_status = "complete"
    if analysis.get("judgement_score") is not None and judgement_status == "not_available":
        judgement_status = "complete"
    decision = get_decision_display(result)

    risk_score = analysis.get("risk_score", analysis.get("score"))
    if risk_score is None:
        risk_score = url_vet_details.get("risk_score")
    judgement_score = analysis.get("judgement_score")
    if judgement_score is None:
        judgement_score = judgement_details.get("judgement_score")
    trust_score = analysis.get("trust_score", url_vet_details.get("trust_score"))
    verdict = str(analysis.get("verdict") or url_vet_details.get("verdict") or "Not available")
    url_vet_reasons = analysis.get("reasons") or url_vet_details.get("reasons") or []
    judgement_reasons = analysis.get("judgement_reasons") or judgement_details.get("reasons") or []

    risk_label = (
        "url.vet risk signal"
        if url_vet_status == "incomplete"
        else "url.vet partial risk score"
        if url_vet_status == "warning"
        else "url.vet risk score"
    )
    risk_context = (
        "Partial signal; it was not treated as a completed url.vet result."
        if url_vet_status in {"incomplete", "warning"}
        else f"{decision['risk_score_level']}. {decision['risk_vote']}."
    )
    judgement_context = f"{decision['judgement_score_level']}. {decision['judgement_vote']}."

    return {
        "risk_label": risk_label,
        "risk_score": _score_text(risk_score),
        "risk_context": risk_context,
        "judgement_score": _score_text(judgement_score),
        "judgement_context": judgement_context,
        "trust_score": _score_text(trust_score),
        "verdict": verdict,
        "risk_level": str(decision["risk_score_level"]),
        "judgement_level": str(decision["judgement_score_level"]),
        "risk_vote": str(decision["risk_vote"]),
        "judgement_vote": str(decision["judgement_vote"]),
        "url_vet_reasons": [str(reason) for reason in url_vet_reasons if str(reason).strip()][:3],
        "judgement_reasons": [
            str(reason) for reason in judgement_reasons if str(reason).strip()
        ][:3],
        "url_vet_status": url_vet_status,
        "judgement_status": judgement_status,
        "has_any_evidence": any(
            (
                risk_score is not None,
                judgement_score is not None,
                trust_score is not None,
                verdict != "Not available",
            )
        ),
    }


def _preview(text: str, limit: int = 90) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3].rstrip() + "..."


def _url_components(text: str) -> tuple[str, str]:
    """Return normalised URL parts without letting a malformed URI break the UI."""
    try:
        parsed = urlsplit(text)
        return parsed.scheme.casefold(), (parsed.hostname or "").casefold()
    except ValueError:
        return "", ""


def _is_valid_web_url(scheme: str, hostname: str) -> bool:
    return scheme in {"http", "https"} and bool(hostname)


def _content_display(
    label: str,
    summary: str,
    fields: list[tuple[str, str]],
    *,
    non_url: bool = False,
) -> dict[str, object]:
    return {
        "label": label,
        "summary": summary,
        "fields": fields,
        "guidance": NON_URL_GUIDANCE if non_url else None,
        "is_non_url": non_url,
    }


def _parse_wifi_fields(text: str) -> list[tuple[str, str]]:
    low = text.casefold()
    if "wifimasterkey://" in low:
        return [
            ("Format", "WiFiMasterKey share"),
            ("SSID", "Not disclosed"),
            ("Password", "Not disclosed"),
        ]

    payload = text.strip()[5:] if text.strip().casefold().startswith("wifi:") else ""
    values: dict[str, str] = {}
    for part in payload.split(";"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        values[key.strip().upper()] = value.strip()

    fields = [
        ("SSID", values.get("S") or "Not disclosed"),
        ("Security", values.get("T") or "Not specified"),
        ("Password", values.get("P") or "Not included"),
    ]
    return fields


def _vcard_value(text: str, key: str) -> str | None:
    key = key.upper()
    for line in text.splitlines():
        if ":" not in line:
            continue
        left, value = line.split(":", 1)
        name = left.split(";", 1)[0].upper()
        if name == key and value.strip():
            return " ".join(value.replace(";", " ").split())
    return None


def _parse_vcard_fields(text: str) -> list[tuple[str, str]]:
    candidates = (
        ("Name", _vcard_value(text, "FN") or _vcard_value(text, "N")),
        ("Organisation", _vcard_value(text, "ORG")),
        ("Phone", _vcard_value(text, "TEL")),
        ("Email", _vcard_value(text, "EMAIL")),
        ("Website", _vcard_value(text, "URL")),
    )
    return [(label, value) for label, value in candidates if value]


def _payment_fields(result: dict) -> list[tuple[str, str]]:
    payment = result.get("payment") or {}
    evidence = payment.get("evidence") or {}
    fields = [("Status", str(payment.get("status", "unknown")).replace("_", " ").title())]
    if evidence.get("merchant_id"):
        fields.append(("Merchant", str(evidence["merchant_id"])))
    if evidence.get("payee_masked"):
        fields.append(("Payee", str(evidence["payee_masked"])))
    amount = str(evidence.get("amount") or "").strip()
    currency = str(evidence.get("currency") or "").strip()
    if amount or currency:
        fields.append(("Amount", f"{currency} {amount}".strip()))
    return fields


def get_qr_content_display(result: dict) -> dict[str, object]:
    text = str(result.get("decoded_text") or "").strip()
    low = text.casefold()
    content_type = str(result.get("content_type") or "").casefold()
    hostname = str(result.get("hostname") or "").strip()
    scheme, parsed_hostname = _url_components(text)
    host = (hostname or parsed_hostname).casefold()

    if content_type == "payment" or low.startswith("qrshield-pay:"):
        if _is_valid_web_url(scheme, parsed_hostname):
            return _content_display(
                "Payment link QR",
                "This web payment link was classified as payment content and was not sent to url.vet. No payment was started.",
                [
                    ("Provider", "Alipay" if host == "qr.alipay.com" else "Payment provider"),
                    ("Hostname", hostname or parsed_hostname),
                ],
            )
        return _content_display(
            "Payment QR",
            "Payment details were parsed locally. No payment was started.",
            _payment_fields(result),
            non_url=True,
        )
    if low.startswith("wifi:") or "wifimasterkey://" in low:
        return _content_display(
            "WiFi network QR",
            "WiFi setup content was parsed locally and was not sent to url.vet.",
            _parse_wifi_fields(text),
            non_url=True,
        )
    if text.strip().startswith("BEGIN:VCARD"):
        return _content_display(
            "Contact card QR",
            "Contact-card content was parsed locally and was not sent to url.vet.",
            _parse_vcard_fields(text),
            non_url=True,
        )
    if "qr.alipay.com" in host or low.startswith("https://qr.alipay.com/"):
        return _content_display(
            "Payment link QR",
            "Alipay payment-link content is a web URL and may be checked with url.vet.",
            [("Provider", "Alipay"), ("Hostname", hostname or parsed_hostname or "Unknown")],
        )
    if "wechat.com" in host:
        return _content_display(
            "WeChat QR",
            "WeChat link content is a web URL and may be checked with url.vet.",
            [("Provider", "WeChat"), ("Hostname", hostname or parsed_hostname or "Unknown")],
        )
    if content_type == "url":
        if _is_valid_web_url(scheme, parsed_hostname):
            return _content_display(
                "Web URL QR",
                "Supported web URL content may be checked with url.vet.",
                [("Hostname", hostname or parsed_hostname)],
            )
        return _content_display(
            "Malformed web URL QR",
            "This web address could not be validated and was not sent to url.vet.",
            [],
            non_url=True,
        )
    if scheme:
        return _content_display(
            "Unsupported URI QR",
            "This URI scheme is outside url.vet and was not URL-risk scored.",
            [("Scheme", scheme)],
            non_url=True,
        )
    return _content_display(
        "Plain text QR",
        "Text content was decoded locally and was not sent to url.vet.",
        [("Preview", _preview(text))] if text else [],
        non_url=True,
    )


def get_api_error_message(status_code: int) -> str:
    messages = {
        400: "No readable QR code was found. Try a clearer image with the full QR code visible.",
        413: "The image exceeds the 5 MiB limit. Compress it or upload a smaller image.",
        422: "The upload request is invalid. Upload a PNG, JPG or JPEG image.",
        503: "The risk model is temporarily unavailable. No safe conclusion was produced.",
        500: "The image could not be processed. Try another image or try again later.",
    }
    return messages.get(
        status_code,
        "QR Shield could not connect to its local analysis service. Start the API and try again.",
    )


def get_display_explanation(analysis: dict) -> dict:
    """Return exactly the API model version and no more than three reasons."""
    return {
        "model_version": str(analysis.get("model_version", "Unknown")),
        "reasons": list(analysis.get("reasons") or [])[:3],
    }


def get_url_vet_display(analysis: dict) -> str | None:
    if str(analysis.get("model_name", "")).casefold() != "url.vet":
        return None
    verdict = str(analysis.get("verdict") or "").strip()
    trust_score = analysis.get("trust_score")
    trust_text = "Unknown"
    if isinstance(trust_score, (int, float)):
        trust_text = f"{float(trust_score):.0f}/100"
    if verdict and trust_text != "Unknown":
        return f"url.vet verdict: {verdict}; trust score: {trust_text}."
    if verdict:
        return f"url.vet verdict: {verdict}."
    if trust_text != "Unknown":
        return f"url.vet trust score: {trust_text}."
    return "url.vet analysis completed."


def get_url_vet_evidence_display(result: dict) -> dict[str, object] | None:
    analysis = result.get("analysis") or {}
    details: dict = {}
    status = "complete"

    if str(analysis.get("model_name", "")).casefold() == "url.vet":
        details = analysis
        is_partial = bool(analysis.get("url_vet_partial"))
        status = "warning" if is_partial else "complete"
        title = "Partial url.vet evidence" if is_partial else "url.vet analysis"
        notice = (
            "url.vet returned partial evidence. The available score is shown, but "
            "the URL inspection is incomplete. Do not treat this as a safe conclusion."
            if is_partial
            else "url.vet completed URL inspection."
        )
    else:
        for check in result.get("checks") or []:
            if check.get("check_id") == "url_vet" and isinstance(check.get("details"), dict):
                details = check["details"]
                status = str(check.get("status", "unknown"))
                break
        if not details:
            return None
        title = "Partial url.vet evidence"
        notice = (
            "url.vet returned partial evidence. The available score is shown, but "
            "the URL inspection is incomplete. Do not treat this as a safe conclusion."
        )

    score_text = _whole_number_text(details.get("score", details.get("risk_score")))
    trust_text = _whole_number_text(details.get("trust_score"))
    verdict = str(details.get("verdict") or "Not available")
    risk_level = str(details.get("level") or details.get("risk_level") or "Not available")
    reasons = list(details.get("reasons") or [])[:3]

    if not score_text and not trust_text and verdict == "Not available" and not reasons:
        return None

    return {
        "title": title,
        "status": status,
        "risk_score": f"{score_text} / 100" if score_text else "Not available",
        "risk_level": risk_level,
        "verdict": verdict,
        "trust_score": f"{trust_text} / 100" if trust_text else "Not available",
        "notice": notice,
        "reasons": reasons,
    }


def get_unverifiable_payment_message() -> str:
    return "Unverifiable — confirm the payee and amount directly with the merchant before paying."


def get_result_presentation(result: dict) -> dict[str, str]:
    """Map technical outcomes to a clear student-facing decision and action."""
    outcome = str(result.get("assessment_outcome", ""))
    status = str(result.get("analysis_status", ""))
    analysis = result.get("analysis") or {}
    decision = result.get("decision") or {}
    conclusion = str(decision.get("conclusion") or "")
    suspicion_level = str(decision.get("suspicion_level") or "")

    if status == "Incomplete" or outcome == "Incomplete":
        return {
            "tone": "info",
            "title": "Unable to complete all checks",
            "summary": "No safe conclusion was produced. Do not treat this result as low risk.",
            "action": "Try a clearer image. If checks remain incomplete, verify the QR code through an official source.",
        }
    if status == "Partial":
        if conclusion == "Partially suspicious":
            return {
                "tone": "warning",
                "title": "Partial suspicious URL assessment",
                "summary": "A suspicious signal is available, but one URL evidence source did not complete. Treat the result conservatively.",
                "action": "Do not use this QR code yet. Verify the destination through an official source.",
            }
        return {
            "tone": "warning",
            "title": "Partial URL assessment",
            "summary": "A URL score is available, but url.vet did not complete. This is an advisory result, not a safety guarantee.",
            "action": "Use the displayed score as a warning only and verify the destination through an official source before continuing.",
        }
    if conclusion == "Suspicious":
        title = (
            "Dangerous URL signals detected"
            if suspicion_level == "Dangerous"
            else "Suspicious URL signals detected"
        )
        return {
            "tone": "error",
            "title": title,
            "summary": "The versioned decision policy retained suspicious evidence from the available sources.",
            "action": "Do not use this QR code yet. Verify the request through an official website or a trusted phone number.",
        }
    if conclusion == "Partially suspicious":
        return {
            "tone": "warning",
            "title": "Conflicting suspicious signals",
            "summary": "At least one source reached the suspicious benchmark or returned an adverse verdict.",
            "action": "Do not use this QR code yet. Verify the destination and request through an official source.",
        }
    if conclusion == "Partially assessed":
        return {
            "tone": "warning",
            "title": "Partial URL assessment",
            "summary": "A local score is available, but url.vet did not complete. Treat this as an advisory result, not a safety guarantee.",
            "action": "Use the displayed score as a warning only and verify the destination through an official source before continuing.",
        }
    if outcome == "Review required":
        return {
            "tone": "error",
            "title": "Review required",
            "summary": "One or more checks found conflicting or adverse evidence.",
            "action": "Do not use this QR code yet. Verify the request through the organisation's official website or a trusted phone number.",
        }
    if not analysis:
        return {
            "tone": "info",
            "title": "URL risk scoring was not performed",
            "summary": "This QR code does not contain a supported, valid web destination.",
            "action": "Review the decoded content in Technical evidence before deciding what to do.",
        }

    if conclusion == "Not suspicious" and suspicion_level == "Medium suspicion":
        return {
            "tone": "warning",
            "title": "Below the suspicious benchmark, but use caution",
            "summary": "Both score sources remained below the benchmark, but the QR code still has medium-level signals.",
            "action": "Verify the hostname and request through an official source before continuing.",
        }
    if conclusion == "Not suspicious" and suspicion_level == "Low suspicion":
        return {
            "tone": "success",
            "title": "No major suspicious signals found",
            "summary": "The available score sources stayed below the suspicious benchmark. This is not a safety guarantee.",
            "action": "Confirm the hostname is the one you expected. For sensitive accounts or payments, open the official site yourself.",
        }

    level = str(analysis.get("level", "High"))
    if level == "Low":
        return {
            "tone": "success",
            "title": "No major risk signals found",
            "summary": "The configured checks completed without a major warning. This is not a safety guarantee.",
            "action": "Confirm the hostname is the one you expected. For sensitive accounts or payments, open the official site yourself.",
        }
    if level == "Medium":
        return {
            "tone": "warning",
            "title": "Use caution",
            "summary": "The QR code contains signals that deserve closer inspection.",
            "action": "Do not continue until you have verified the hostname and request through an official source.",
        }
    return {
        "tone": "error",
        "title": "High risk detected",
        "summary": "Strong risk signals were found in this QR code.",
        "action": "Do not open the destination or make a payment. Contact the organisation using trusted contact details.",
    }
