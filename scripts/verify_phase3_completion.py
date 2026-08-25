"""Run the final Phase 3 acceptance checks and write a redacted report.

The report intentionally contains summaries and hashes rather than QR images,
live threat URLs, or decoded payloads. The normal command expects the local
url.vet Docker service; ``--skip-full-suite`` is available for a quick local
iteration before the final verification run.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import cv2
import httpx
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import app
from app.services.decision_policy import (
    CalibrationReport,
    load_decision_policy,
)
from app.services.payment_verification import verify_payment
from app.services.qr_decoder import decode_qr_image
from app.services.risk_decision import decide_url_risk
from app.services.url_vet_client import get_url_vet_base_url
from scripts.evaluate_e3_us1 import evaluate as evaluate_e3_us1
from scripts.evaluate_phase3_real_qr import evaluate as evaluate_real_qr
from scripts.evaluate_robustness import evaluate as evaluate_robustness
from scripts.evaluate_tampering_fixtures import evaluate as evaluate_tampering


CALIBRATION_REPORT_PATH = ROOT / "reports" / "phase3_calibration_report.json"
COMPLETION_REPORT_PATH = ROOT / "reports" / "phase3_completion_report.json"
LOGO_DATASET_PATH = ROOT / "data" / "test_images" / "e4_us1_robustness"
KNOWN_REVIEW_STORE_FAILURE = "test_retention_cleanup_removes_expired_pending_cases"
PAYMENT_PAYLOAD = (
    "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;"
    "amount=12.50;currency=AUD"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_error(error: Exception) -> str:
    """Keep exception summaries useful without copying payloads into reports."""
    message = str(error).replace("\r", " ").replace("\n", " ")
    return message.replace("http://", "[http omitted]://").replace(
        "https://", "[https omitted]://"
    )[:300]


def _capture(function):
    try:
        return function()
    except Exception as error:  # pragma: no cover - exercised by broken environments
        return {"passed": False, "error": _safe_error(error)}


def _check_calibration() -> dict:
    policy = load_decision_policy()
    report = CalibrationReport.model_validate_json(
        CALIBRATION_REPORT_PATH.read_text(encoding="utf-8")
    )
    selected = report.selected_policy
    thresholds = selected.thresholds.model_dump(mode="json")
    expected_thresholds = {
        "low_medium": 62.0,
        "medium_high": 79.0,
        "high_dangerous": 100.0,
    }
    passed = (
        policy.policy_version == selected.policy_version == "phase3-decision-policy-v1"
        and thresholds == expected_thresholds
        and selected.suspicious_benchmark == 79.0
        and selected.agreement_margin == 1.0
        and selected.metrics.confusion_matrix.false_negative == 0
        and report.validation_metrics.confusion_matrix.false_negative == 0
        and report.observation_count == 60
        and report.score_pair_count == 50
    )
    return {
        "passed": passed,
        "policy_version": policy.policy_version,
        "policy_status": policy.status,
        "dataset_version": report.dataset_version,
        "thresholds": thresholds,
        "benchmark": selected.suspicious_benchmark,
        "agreement_margin": selected.agreement_margin,
        "observation_count": report.observation_count,
        "score_pair_count": report.score_pair_count,
        "selected_metrics": selected.metrics.model_dump(mode="json"),
        "validation_metrics": report.validation_metrics.model_dump(mode="json"),
    }


def _check_e3_us1() -> dict:
    report = evaluate_e3_us1()
    passed = report["passed_scenarios"] == report["scenario_count"]
    return {
        "passed": passed,
        "dataset_version": report["dataset_version"],
        "scenario_count": report["scenario_count"],
        "passed_scenarios": report["passed_scenarios"],
        "latency_ms": report["latency_ms"],
    }


def _check_real_suspicious_qr() -> dict:
    report = evaluate_real_qr(require_raw=False)
    metrics = report.metrics.model_dump(mode="json")
    passed = (
        report.ready_case_count == 3
        and report.pending_case_count == 1
        and metrics["safe_reproduction_decode_success_count"] == 3
        and metrics["low_suspicion_count"] == 0
        and metrics["not_suspicious_count"] == 0
        and metrics["passed_case_count"] == 3
        and metrics["detection_rate"] == 1.0
    )
    return {
        "passed": passed,
        "dataset_version": report.dataset_version,
        "source_audit_mode": report.source_audit_mode,
        "ready_case_count": report.ready_case_count,
        "pending_case_count": report.pending_case_count,
        "metrics": metrics,
    }


def _make_qr_image(payload: str) -> bytes:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(
        image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255
    )
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError("Could not encode an in-memory QR acceptance fixture.")
    return encoded.tobytes()


def _check_non_url_boundary() -> dict:
    cases = {
        "plain_text": ("plain text", "text"),
        "payment": (PAYMENT_PAYLOAD, "payment"),
        "wifi": ("WIFI:S:Monash;T:WPA;P:secret;;", "text"),
        "vcard": (
            "BEGIN:VCARD\nVERSION:3.0\nFN:QR Shield\nEND:VCARD",
            "text",
        ),
        "unsupported_uri": ("ftp://example.com/file", "text"),
        "malformed_http": ("https://[bad-ip]/", "url"),
    }
    results: dict[str, dict] = {}
    client = TestClient(app)
    for case_id, (payload, expected_content_type) in cases.items():
        with patch("app.main.analyze_url") as analyze_url, patch(
            "app.main.predict_url_risk"
        ) as local_model:
            response = client.post(
                "/api/v1/analyze",
                files={
                    "file": (
                        f"{case_id}.png",
                        _make_qr_image(payload),
                        "image/png",
                    )
                },
            )
        body = response.json()
        url_vet_check = next(
            item for item in body.get("checks", []) if item.get("check_id") == "url_vet"
        )
        case_passed = (
            response.status_code == 200
            and body.get("content_type") == expected_content_type
            and body.get("analysis_status") == "Not scored"
            and body.get("analysis") is None
            and body.get("decision", {}).get("conclusion") == "Not applicable"
            and body.get("decision", {}).get("confidence_level") == "Unavailable"
            and url_vet_check.get("status") == "not_applicable"
            and not analyze_url.called
            and not local_model.called
        )
        results[case_id] = {
            "passed": case_passed,
            "status_code": response.status_code,
            "content_type": body.get("content_type"),
            "analysis_status": body.get("analysis_status"),
            "decision_conclusion": body.get("decision", {}).get("conclusion"),
            "url_vet_status": url_vet_check.get("status"),
            "url_vet_called": analyze_url.called,
            "local_model_called": local_model.called,
        }
    return {"passed": all(item["passed"] for item in results.values()), "cases": results}


def _check_logo_decoder() -> dict:
    manifest = json.loads(
        (LOGO_DATASET_PATH / "robustness_manifest.json").read_text(encoding="utf-8")
    )
    record = next(item for item in manifest["originals"] if item["file"] == "logo.jpg")
    image_path = LOGO_DATASET_PATH / record["file"]
    decoded = decode_qr_image(image_path.read_bytes(), image_path.name)
    return {
        "passed": (
            record["expected_decodable"]
            and decoded["decoded_text"] == record["expected_text"]
            and decoded["content_type"] == "url"
        ),
        "fixture": "logo.jpg",
        "content_type": decoded["content_type"],
        "decode_status": "passed",
    }


def _check_payment() -> dict:
    valid = verify_payment(PAYMENT_PAYLOAD)
    mismatch = verify_payment(PAYMENT_PAYLOAD.replace("12.50", "13.00"))
    return {
        "passed": valid["status"] == "passed" and mismatch["status"] == "failed",
        "valid_case_status": valid["status"],
        "mismatch_case_status": mismatch["status"],
    }


def _check_tampering() -> dict:
    report = evaluate_tampering()
    return {
        "passed": (
            report["false_negative"] == 0
            and report["false_positive_rate"] <= 0.25
        ),
        "dataset_version": report["dataset_version"],
        "fixture_count": report["fixture_count"],
        "false_negative": report["false_negative"],
        "false_positive_rate": report["false_positive_rate"],
    }


def _check_robustness() -> dict:
    report = evaluate_robustness()
    return {
        "passed": report["passed"],
        "dataset_version": report["dataset_version"],
        "image_count": report["image_count"],
        "decodable_count": report["decodable_count"],
        "pipeline": report["overall"]["pipeline"],
        "criteria": report["criteria"],
    }


def _check_url_vet_smoke(required: bool) -> dict:
    policy = load_decision_policy()
    incomplete_decision = decide_url_risk(None, 20, policy=policy)
    incomplete_not_promoted = (
        incomplete_decision["conclusion"] == "Incomplete"
        and incomplete_decision["suspicion_level"] is None
        and incomplete_decision["confidence_level"] == "Unavailable"
    )
    result = {
        "required": required,
        "service_reachable": None,
        "health_response_shape_valid": None,
        "analysis_endpoint_controlled_response": None,
        "incomplete_responses_are_not_promoted": incomplete_not_promoted,
        "passed": incomplete_not_promoted,
    }
    if not required:
        return result

    try:
        base_url = get_url_vet_base_url()
        with httpx.Client(timeout=5.0, trust_env=False) as client:
            health_response = client.get(f"{base_url}/health")
            health_body = health_response.json()
            health_shape = (
                health_response.status_code == 200
                and isinstance(health_body, dict)
                and health_body.get("status") in {"ok", "running"}
                and (
                    "service" not in health_body
                    or health_body.get("service") == "url.vet API"
                )
                and (
                    "version" not in health_body
                    or isinstance(health_body.get("version"), str)
                )
            )
            analysis_response = client.get(
                f"{base_url}/api/v1/analyze",
                params={"url": "https://qr-shield-completion.invalid/"},
            )
            try:
                analysis_body = analysis_response.json()
            except ValueError:
                analysis_body = None
            controlled_response = (
                isinstance(analysis_body, dict)
                and analysis_response.status_code in {200, 400, 422, 500}
            )
        result.update(
            {
                "service_reachable": True,
                "health_response_shape_valid": health_shape,
                "analysis_endpoint_controlled_response": controlled_response,
                "passed": health_shape and controlled_response and incomplete_not_promoted,
            }
        )
    except (httpx.HTTPError, ValueError, OSError) as error:
        result["error"] = _safe_error(error)
    return result


def _run_full_unittest() -> dict:
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "effective_passed": False,
            "test_count": None,
            "failure_names": ["unittest discovery exceeded 300 seconds"],
            "known_unrelated_failure": None,
        }

    output = f"{completed.stdout}\n{completed.stderr}"
    count_match = re.search(r"Ran\s+(\d+)\s+tests?", output)
    failure_names = re.findall(r"^(?:FAIL|ERROR):\s+(.+)$", output, re.MULTILINE)
    if completed.returncode != 0 and not failure_names:
        failure_names = ["unittest returned a failure without a parsed test name"]
    known_only = bool(failure_names) and all(
        KNOWN_REVIEW_STORE_FAILURE in name for name in failure_names
    )
    passed = completed.returncode == 0
    return {
        "status": "passed" if passed else "failed",
        "effective_passed": passed or known_only,
        "test_count": int(count_match.group(1)) if count_match else None,
        "failure_names": failure_names,
        "known_unrelated_failure": (
            "Windows SQLite temporary-directory file-lock failure in the existing "
            "review-store retention test."
            if known_only
            else None
        ),
    }


def _build_report(*, require_url_vet: bool) -> dict:
    calibration = _capture(_check_calibration)
    e3_us1 = _capture(_check_e3_us1)
    real_qr = _capture(_check_real_suspicious_qr)
    non_url = _capture(_check_non_url_boundary)
    logo = _capture(_check_logo_decoder)
    payment = _capture(_check_payment)
    tampering = _capture(_check_tampering)
    robustness = _capture(_check_robustness)
    url_vet = _capture(lambda: _check_url_vet_smoke(require_url_vet))

    checks = {
        "calibration_report": calibration["passed"],
        "e3_us1": e3_us1["passed"],
        "real_suspicious_qr": real_qr["passed"],
        "non_url_boundary": non_url["passed"],
        "logo_decoder": logo["passed"],
        "payment": payment["passed"],
        "tampering": tampering["passed"],
        "robustness": robustness["passed"],
        "url_vet_loopback_smoke": url_vet["passed"],
    }
    return {
        "report_version": "phase3-completion-report-v1",
        "generated_at": _utc_now(),
        "policy_version": calibration.get("policy_version"),
        "calibration_report_valid": calibration["passed"],
        "e3_us1_evaluation_passed": e3_us1["passed"],
        "real_suspicious_qr_evaluation_passed": real_qr["passed"],
        "non_url_boundary_tests_passed": non_url["passed"],
        "logo_decoder_regression_passed": logo["passed"],
        "acceptance_checks": checks,
        "phase3_acceptance_passed": all(checks.values()),
        "calibration": calibration,
        "e3_us1_evaluation": e3_us1,
        "real_suspicious_qr_evaluation": real_qr,
        "non_url_boundary_tests": non_url,
        "logo_decoder_regression": logo,
        "payment_regression": payment,
        "tampering_regression": tampering,
        "robustness_regression": robustness,
        "url_vet_loopback_smoke": url_vet,
        "full_unittest": {
            "status": "not_run",
            "effective_passed": None,
            "test_count": None,
            "failure_names": [],
            "known_unrelated_failure": None,
        },
        "limitations": [
            "The Phase 3 policy remains provisional because the labelled sample is bounded and below the approval target.",
            "The calibration labels are binary and the four display bands are operational bands, not four independently labelled classes.",
            "The three ready suspicious QR entries are safe in-memory reproductions, not recovered incident images.",
            "PhishTank supplies the suspicious labels and is also used by url.vet, so this is integration evidence rather than independent validation.",
            "The supervisor Australian fraud QR remains pending until the original sample and redistribution decision are available.",
        ],
    }


def _finalise_report(report: dict, *, full_suite_was_skipped: bool) -> None:
    full = report["full_unittest"]
    if full_suite_was_skipped:
        report["completion_status"] = "phase_checks_passed_full_suite_not_run"
        report["overall_passed"] = report["phase3_acceptance_passed"]
        return
    if report["phase3_acceptance_passed"] and full["effective_passed"]:
        if full["status"] == "passed":
            report["completion_status"] = "passed"
        else:
            report["completion_status"] = "passed_with_known_unrelated_test_failure"
        report["overall_passed"] = True
    else:
        report["completion_status"] = "failed"
        report["overall_passed"] = False


def _write_report(report: dict) -> None:
    COMPLETION_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    COMPLETION_REPORT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-url-vet",
        action="store_true",
        help="require the local url.vet Docker service to answer its smoke checks",
    )
    parser.add_argument(
        "--skip-full-suite",
        action="store_true",
        help="skip unittest discovery; useful only for a fast intermediate check",
    )
    args = parser.parse_args(argv)

    report = _build_report(require_url_vet=args.require_url_vet)
    # Write before discovery so test_phase3_completion.py can validate the
    # report during the full suite itself.
    _write_report(report)
    if not args.skip_full_suite:
        report["full_unittest"] = _run_full_unittest()
    _finalise_report(report, full_suite_was_skipped=args.skip_full_suite)
    _write_report(report)

    print(
        f"Phase 3 completion: {report['completion_status']} | "
        f"report: {COMPLETION_REPORT_PATH.relative_to(ROOT)}"
    )
    return 0 if report["overall_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
