# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
"""Generate a reproducible local E3-US1 evidence-evaluation report."""

from __future__ import annotations

import json
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

import cv2
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import app
from app.services.checks import make_check
from app.services.model_service import ModelUnavailableError


MANIFEST_PATH = ROOT / "data" / "evaluation" / "e3_us1" / "manifest.json"
REPORT_PATH = ROOT / "reports" / "e3_us1_evaluation.json"


def make_qr_image(payload: str) -> bytes:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=14, fy=14, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError("Could not encode locked evaluation QR image.")
    return encoded.tobytes()


def _override_context(name: str | None):
    if name == "model_unavailable":
        return patch(
            "app.main.predict_url_risk",
            side_effect=ModelUnavailableError("Locked evaluation model failure."),
        )
    if name == "denylist_unavailable":
        return patch(
            "app.main.check_denylist",
            return_value=make_check(
                "local_denylist", "incomplete", "Locked evaluation source failure.",
                ["DENYLIST_UNAVAILABLE"],
            ),
        )
    if name == "denylist_match":
        return patch(
            "app.main.check_denylist",
            return_value=make_check(
                "local_denylist", "failed", "Locked evaluation denylist match.",
                ["DENYLIST_MATCH"], {"version": "locked-test-v1"},
            ),
        )
    return nullcontext()


def _url_vet_double(record: dict) -> tuple[dict, dict | None]:
    if record.get("override") == "model_unavailable":
        return (
            make_check(
                "url_vet", "incomplete", "Locked evaluation url.vet failure.",
                ["URL_VET_UNAVAILABLE"], {"version": "locked-urlvet-v1"},
            ),
            None,
        )
    score = 80.0 if record.get("label") == 1 else 5.0
    verdict = "Suspicious" if score >= 40 else "Safe"
    return (
        make_check(
            "url_vet", "passed", "Locked evaluation url.vet analysis completed.",
            [f"URL_VET_VERDICT_{verdict.upper()}"],
            {"version": "locked-urlvet-v1"},
        ),
        {
            "score": score,
            "level": "High" if score >= 70 else "Low",
            "reasons": ["Locked deterministic url.vet evidence."],
            "model_name": "url.vet",
            "model_version": "locked-urlvet-v1",
            "trust_score": 20.0 if score >= 70 else 100.0,
            "verdict": verdict,
        },
    )


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[round((len(ordered) - 1) * fraction)], 3)


def evaluate() -> dict:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    client = TestClient(app)
    cases = []
    scores: list[tuple[float, int]] = []
    latencies = []
    for record in manifest["records"]:
        start = time.perf_counter()
        with (
            _override_context(record.get("override")),
            patch("app.main.analyze_url", return_value=_url_vet_double(record)),
        ):
            response = client.post(
                "/api/v1/analyze",
                files={"file": (f"{record['id']}.png", make_qr_image(record["payload"]), "image/png")},
            )
        latency_ms = (time.perf_counter() - start) * 1000
        body = response.json()
        latencies.append(latency_ms)
        actual = body.get("assessment_outcome")
        analysis = body.get("analysis") or {}
        if record.get("label") is not None and analysis:
            scores.append((float(analysis["score"]), int(record["label"])))
        cases.append(
            {
                "id": record["id"],
                "expected_outcome": record["expected_outcome"],
                "actual_outcome": actual,
                "passed": response.status_code == 200 and actual == record["expected_outcome"],
                "analysis_status": body.get("analysis_status"),
                "decision": body.get("decision"),
                "failed_check_ids": body.get("failed_check_ids"),
                "source_versions": body.get("source_versions"),
                "principal_signals": body.get("principal_signals"),
                "latency_ms": round(latency_ms, 3),
            }
        )

    bins = []
    for low, high in ((0, 40), (40, 70), (70, 101)):
        values = [(score, label) for score, label in scores if low <= score < high]
        bins.append(
            {
                "score_range": f"{low}-{high - 1}",
                "count": len(values),
                "mean_score": round(sum(score for score, _ in values) / len(values), 3) if values else None,
                "observed_positive_rate": round(sum(label for _, label in values) / len(values), 3) if values else None,
            }
        )
    return {
        "dataset": manifest["dataset"],
        "dataset_version": manifest["version"],
        "scenario_count": len(cases),
        "passed_scenarios": sum(case["passed"] for case in cases),
        "scenario_effectiveness": cases,
        "calibration": {"bins": bins, "method": "locked-scenario score bins"},
        "latency_ms": {"p50": _percentile(latencies, 0.50), "p95": _percentile(latencies, 0.95)},
        "failure_behaviour": [
            case for case in cases if case["actual_outcome"] in {"Incomplete", "Review required"}
        ],
    }


def main() -> None:
    report = evaluate()
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {REPORT_PATH.relative_to(ROOT)}")
    if report["passed_scenarios"] != report["scenario_count"]:
        raise SystemExit("Locked E3-US1 evaluation did not meet its expected outcomes.")


if __name__ == "__main__":
    main()
