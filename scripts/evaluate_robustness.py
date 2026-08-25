# AI-assisted implementation: written with AI assistance and reviewed by the
# project author.
"""Evaluate E4-US1 decoder robustness/generalization and write a report.

Dataset:
  * originals under data/test_images/e4_us1_robustness/*.png|jpg
  * controlled perturbations under .../perturbed/{rotation,perspective,noise}/
    (produced by generate_robustness_perturbations.py)

Ground truth lives in robustness_manifest.json (one entry per original with the
true payload and whether it is decodable at all). On first run this manifest is
bootstrapped by decoding each original, so PLEASE review expected_text against a
real phone scan before trusting the numbers.

For every image we score three decoders against ground truth:
  * cv2      - OpenCV QRCodeDetector only
  * pyzxing  - ZXing only
  * pipeline - decode_qr_image (pyzxing first, cv2 fallback) = the real product

Each decode falls into one of three outcomes:
  * correct - decoded text equals the true payload
              (for non-decodable codes: correctly produced nothing)
  * miss    - produced nothing (safe but unusable)
  * wrong   - produced something that is NOT the true payload (dangerous)

Pass criteria (agreed):
  1. pipeline correct-count >= max(cv2, pyzxing)   (upgrade must not regress)
  2. pipeline correct-rate on the decodable set >= TARGET_RATE
  3. zero wrong decodes for the pipeline            (security floor)
  4. every non-decodable code is cleanly rejected
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import cv2
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services import qr_decoder  # noqa: E402
from app.services.qr_decoder import decode_qr_image, QRDecodeError  # noqa: E402

BASE = ROOT / "data" / "test_images" / "e4_us1_robustness"
MANIFEST = BASE / "robustness_manifest.json"
PERTURB_INDEX = BASE / "perturbed" / "perturbations_index.json"
REPORT = ROOT / "reports" / "robustness_metrics.json"

IMG_EXTS = {".png", ".jpg", ".jpeg"}
# Proprietary / non-standard codes that no open decoder can read.
NON_DECODABLE = {"小程序.png"}
TARGET_RATE = 0.85


def _ndarray(path: Path) -> np.ndarray | None:
    """Decode file bytes to BGR exactly as the app does (cv2.imdecode)."""
    data = np.frombuffer(path.read_bytes(), dtype=np.uint8)
    return cv2.imdecode(data, cv2.IMREAD_COLOR)


def _classify(text: str | None) -> str:
    if text is None:
        return "proprietary"
    low = text.strip().casefold()
    if low.startswith("wifi:") or "wifimasterkey://" in low:
        return "wifi"
    if text.strip().startswith("BEGIN:VCARD"):
        return "vcard"
    if low.startswith(("mailto:", "matmsg", "smtp:")):
        return "email"
    if "wechat.com" in low or low.startswith(("wxp://", "weixin://")):
        return "wechat"
    if "alipay.com" in low:
        return "alipay"
    if low.startswith(("http://", "https://")):
        return "url"
    return "text"


def build_manifest() -> dict:
    """Bootstrap ground truth by decoding each original (for later review)."""
    originals = sorted(
        p for p in BASE.glob("*") if p.is_file() and p.suffix.lower() in IMG_EXTS
    )
    entries = []
    for path in originals:
        if path.name in NON_DECODABLE:
            entries.append({
                "file": path.name, "content_type": "proprietary",
                "expected_decodable": False, "expected_text": "",
            })
            continue
        image = _ndarray(path)
        text = qr_decoder._decode_with_pyzxing(image) if image is not None else None
        entries.append({
            "file": path.name,
            "content_type": _classify(text),
            "expected_decodable": True,
            "expected_text": text or "",
        })
    manifest = {
        "version": "1.0",
        "note": "expected_text was bootstrapped by decoding; verify with a real "
                "phone scan before trusting the metrics.",
        "originals": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def _decode_pipeline(path: Path) -> str | None:
    """Run the real product path; return decoded text or None on rejection."""
    try:
        return decode_qr_image(path.read_bytes(), path.name)["decoded_text"]
    except QRDecodeError:
        return None
    except Exception:
        return None


def _outcome(decoded: str | None, expected_text: str, decodable: bool) -> str:
    if not decodable:
        return "correct" if not decoded else "wrong"
    if not decoded:
        return "miss"
    return "correct" if decoded == expected_text else "wrong"


def _blank() -> dict:
    return {"correct": 0, "miss": 0, "wrong": 0, "n": 0}


def _tally(bucket: dict, decoder: str, outcome: str) -> None:
    bucket[decoder][outcome] += 1
    bucket[decoder]["n"] += 1


def evaluate() -> dict:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.is_file() else build_manifest()
    truth = {e["file"]: e for e in manifest["originals"]}

    # Assemble the full work list: originals + perturbations.
    items: list[dict] = []
    for entry in manifest["originals"]:
        items.append({"path": BASE / entry["file"], "group": "original",
                      "content_type": entry["content_type"], "source": entry["file"]})
    if PERTURB_INDEX.is_file():
        index = json.loads(PERTURB_INDEX.read_text(encoding="utf-8"))
        for rec in index["records"]:
            src = truth.get(rec["source"])
            if src is None:
                continue
            items.append({"path": BASE / "perturbed" / rec["file"], "group": rec["perturbation"],
                          "content_type": src["content_type"], "source": rec["source"]})

    decoders = ("cv2", "pyzxing", "pipeline")
    overall = {d: _blank() for d in decoders}
    by_group: dict[str, dict] = defaultdict(lambda: {d: _blank() for d in decoders})
    by_ctype: dict[str, dict] = defaultdict(lambda: {d: _blank() for d in decoders})
    details: list[dict] = []

    for item in items:
        src = truth[item["source"]]
        expected, decodable = src["expected_text"], src["expected_decodable"]
        image = _ndarray(item["path"])
        results = {
            "cv2": qr_decoder._decode_with_cv2(image) if image is not None else None,
            "pyzxing": qr_decoder._decode_with_pyzxing(image) if image is not None else None,
            "pipeline": _decode_pipeline(item["path"]),
        }
        row = {"file": item["path"].relative_to(BASE).as_posix(), "group": item["group"],
               "content_type": item["content_type"], "expected_decodable": decodable}
        for decoder, decoded in results.items():
            outcome = _outcome(decoded, expected, decodable)
            row[decoder] = outcome
            _tally(overall, decoder, outcome)
            _tally(by_group[item["group"]], decoder, outcome)
            _tally(by_ctype[item["content_type"]], decoder, outcome)
        details.append(row)

    decodable_total = sum(1 for it in items if truth[it["source"]]["expected_decodable"])

    def rate(bucket: dict) -> float:
        return round(bucket["correct"] / decodable_total, 4) if decodable_total else 0.0

    criteria = {
        "pipeline_ge_best_single": overall["pipeline"]["correct"] >= max(
            overall["cv2"]["correct"], overall["pyzxing"]["correct"]),
        "pipeline_meets_target": rate(overall["pipeline"]) >= TARGET_RATE,
        "zero_wrong_pipeline": overall["pipeline"]["wrong"] == 0,
        "non_decodable_rejected": all(
            r["pipeline"] == "correct" for r in details if not r["expected_decodable"]),
        "target_rate": TARGET_RATE,
    }
    passed = (criteria["pipeline_ge_best_single"] and criteria["zero_wrong_pipeline"]
              and criteria["non_decodable_rejected"] and criteria["pipeline_meets_target"])

    report = {
        "dataset_version": manifest["version"],
        "image_count": len(items),
        "decodable_count": decodable_total,
        "non_decodable_count": len(items) - decodable_total,
        "pyzxing_available": qr_decoder.PYZXING_AVAILABLE,
        "passed": passed,
        "criteria": criteria,
        "overall": {d: {**overall[d], "correct_rate": rate(overall[d])} for d in decoders},
        "by_group": {g: {d: b[d] for d in decoders} for g, b in sorted(by_group.items())},
        "by_content_type": {c: {d: b[d] for d in decoders} for c, b in sorted(by_ctype.items())},
        "details": sorted(details, key=lambda r: r["file"]),
    }
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _print_summary(report: dict) -> None:
    print(f"pyzxing available: {report['pyzxing_available']} | "
          f"images: {report['image_count']} (decodable {report['decodable_count']}, "
          f"non-decodable {report['non_decodable_count']})")
    print(f"\n{'decoder':<10}{'correct':<9}{'miss':<7}{'wrong':<7}{'rate(decodable)':<16}")
    for decoder, stat in report["overall"].items():
        print(f"{decoder:<10}{stat['correct']:<9}{stat['miss']:<7}{stat['wrong']:<7}{stat['correct_rate']:<16}")
    print("\nby perturbation group (correct / n, pipeline):")
    for group, buckets in report["by_group"].items():
        pl = buckets["pipeline"]
        print(f"  {group:<12} cv2 {buckets['cv2']['correct']}/{buckets['cv2']['n']:<4} "
              f"pyzxing {buckets['pyzxing']['correct']}/{buckets['pyzxing']['n']:<4} "
              f"pipeline {pl['correct']}/{pl['n']}")
    print(f"\ncriteria: {json.dumps(report['criteria'], ensure_ascii=False)}")
    print("RESULT:", "PASS ✅" if report["passed"] else "FAIL ❌")


if __name__ == "__main__":
    _print_summary(evaluate())
