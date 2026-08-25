# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
"""Generate deterministic, labelled E2-US1 QR tampering fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import cv2
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "test_images" / "e2_us1_tampering"
PAYLOAD = "https://example.com/qr-shield-demo"


def _qr(payload: str = PAYLOAD, scale: int = 8) -> np.ndarray:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST)
    return cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)


def _save(path: Path, image: np.ndarray) -> None:
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError(f"Could not encode {path.name}")
    path.write_bytes(encoded.tobytes())


def _overlay(image: np.ndarray, region: str) -> np.ndarray:
    result = image.copy()
    found, points = cv2.QRCodeDetector().detect(result)
    if not found or points is None:
        raise RuntimeError("Could not locate generated QR image.")
    box = np.asarray(points).reshape(4, 2)
    left, top = np.floor(box.min(axis=0)).astype(int)
    right, bottom = np.ceil(box.max(axis=0)).astype(int)
    cell_x, cell_y = (right - left) // 3, (bottom - top) // 3
    positions = {
        "center": (left + cell_x, top + cell_y, left + cell_x * 2, top + cell_y * 2),
        "top_left": (left, top, left + cell_x, top + cell_y),
        "top_right": (right - cell_x, top, right, top + cell_y),
        "bottom_left": (left, bottom - cell_y, left + cell_x, bottom),
        "bottom_right": (right - cell_x, bottom - cell_y, right, bottom),
    }
    x1, y1, x2, y2 = positions[region]
    cv2.rectangle(result, (x1, y1), (x2, y2), 255, -1)
    return result


def generate(output: Path = OUTPUT) -> list[dict]:
    clean_dir, tampered_dir = output / "clean", output / "tampered"
    clean_dir.mkdir(parents=True, exist_ok=True)
    tampered_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []

    for index, scale in enumerate((7, 8, 9, 10), start=1):
        name = f"clean_{index:02d}.png"
        _save(clean_dir / name, _qr(scale=scale))
        records.append({"file": f"clean/{name}", "label": "clean", "scenario": "clean", "tampered_regions": []})

    base = _qr()
    for region in ("center", "top_left", "top_right", "bottom_left", "bottom_right"):
        name = f"{region}_overlay.png"
        _save(tampered_dir / name, _overlay(base, region))
        records.append({"file": f"tampered/{name}", "label": "tampered", "scenario": "white_overlay", "tampered_regions": [region]})

    for index, region in enumerate(("center", "top_left", "bottom_right"), start=1):
        image = _overlay(_qr(scale=9), region)
        name = f"{region}_overlay_variant_{index}.png"
        _save(tampered_dir / name, image)
        records.append({"file": f"tampered/{name}", "label": "tampered", "scenario": "white_overlay_variant", "tampered_regions": [region]})

    first, second = _qr("https://one.example"), _qr("https://two.example")
    combined = np.hstack((first, np.full((first.shape[0], 80), 255, dtype=np.uint8), second))
    _save(tampered_dir / "multiple_qr.png", combined)
    records.append({"file": "tampered/multiple_qr.png", "label": "tampered", "scenario": "multiple_qr", "tampered_regions": []})

    manifest = {
        "dataset": "QR Shield E2-US1 synthetic tampering fixtures",
        "version": "1.0",
        "thresholds": {"min_black_ratio": 0.05, "max_black_ratio": 0.95},
        "records": records,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return records


if __name__ == "__main__":
    print(f"Generated {len(generate())} labelled fixtures in {OUTPUT}")
