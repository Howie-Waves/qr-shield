# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
"""Evaluate E2-US1 fixtures and write false-positive/false-negative metrics."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.block_inspection import inspect_blocks

FIXTURES = ROOT / "data" / "test_images" / "e2_us1_tampering"
REPORT = ROOT / "reports" / "tampering_metrics.json"


def evaluate() -> dict:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    for record in manifest["records"]:
        result = inspect_blocks((FIXTURES / record["file"]).read_bytes())
        flagged = result["status"] in {"warning", "incomplete"}
        if record["label"] == "tampered":
            counts["true_positive" if flagged else "false_negative"] += 1
        else:
            counts["false_positive" if flagged else "true_negative"] += 1
    tampered = counts["true_positive"] + counts["false_negative"]
    clean = counts["true_negative"] + counts["false_positive"]
    report = {
        "dataset_version": manifest["version"],
        "fixture_count": len(manifest["records"]),
        "thresholds": manifest["thresholds"],
        **counts,
        "true_positive_rate": counts["true_positive"] / tampered if tampered else 0,
        "false_negative_rate": counts["false_negative"] / tampered if tampered else 0,
        "false_positive_rate": counts["false_positive"] / clean if clean else 0,
    }
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
