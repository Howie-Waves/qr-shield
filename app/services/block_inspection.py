"""Inspect five QR regions for obvious local tampering."""

from __future__ import annotations

import cv2
import numpy as np


GRID_SIZE = 360
MIN_BLACK = 0.05
MAX_BLACK = 0.95
BLOCK_INSPECTION_VERSION = "five-region-v1"
REGIONS = {
    "top_left": (0, 0),
    "top_right": (0, 2),
    "center": (1, 1),
    "bottom_left": (2, 0),
    "bottom_right": (2, 2),
}


def _order_pts(pts: np.ndarray) -> np.ndarray:
    box = np.asarray(pts, dtype=np.float32).reshape(4, 2)
    sums = box.sum(axis=1)
    diffs = np.diff(box, axis=1).ravel()
    return np.array(
        [
            box[np.argmin(sums)],
            box[np.argmin(diffs)],
            box[np.argmax(sums)],
            box[np.argmax(diffs)],
        ],
        dtype=np.float32,
    )


def _warp(img: np.ndarray, pts: np.ndarray) -> np.ndarray:
    src = _order_pts(pts)
    end = float(GRID_SIZE - 1)
    dst = np.array([[0, 0], [end, 0], [end, end], [0, end]], dtype=np.float32)
    mat = cv2.getPerspectiveTransform(src, dst)
    return cv2.warpPerspective(img, mat, (GRID_SIZE, GRID_SIZE))


def _region_stats(img: np.ndarray, name: str, row: int, col: int) -> dict:
    cell = GRID_SIZE // 3
    roi = img[row * cell : (row + 1) * cell, col * cell : (col + 1) * cell]
    gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
    _, bits = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    ratio = float(np.mean(bits == 0))
    text, _, _ = cv2.QRCodeDetector().detectAndDecode(roi)
    state = "passed" if MIN_BLACK <= ratio <= MAX_BLACK and not text else "warning"
    return {
        "region": name,
        "status": state,
        "black_ratio": round(ratio, 4),
        "nested_qr": bool(text),
    }


# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
def inspect_blocks(raw: bytes) -> dict:
    """Return five-region evidence without saving the image."""
    # E2-US1 中文：透视校正后检查中心和四角，结果保留区域证据。
    # E2-US1 EN: Inspect the centre and corners after perspective correction.
    buf = np.frombuffer(raw, dtype=np.uint8)
    img = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    if img is None:
        return {
            "id": "block_inspection",
            "status": "incomplete",
            "summary": "The image could not be inspected.",
            "reason_codes": ["IMAGE_UNREADABLE"],
            "evidence": {"version": BLOCK_INSPECTION_VERSION, "qr_count": 0, "regions": []},
        }

    det = cv2.QRCodeDetector()
    try:
        multi, texts, pts, _ = det.detectAndDecodeMulti(img)
        qr_count = len(pts) if multi and pts is not None else 0
        qr_pts = pts[0] if qr_count else None
        if qr_pts is None:
            found, pts = det.detect(img)
            qr_pts = pts if found else None
            qr_count = 1 if found else 0
    except cv2.error:
        qr_pts = None
        qr_count = 0

    if qr_pts is None:
        return {
            "id": "block_inspection",
            "status": "incomplete",
            "summary": "QR regions could not be localized.",
            "reason_codes": ["QR_NOT_LOCALIZED"],
            "evidence": {"version": BLOCK_INSPECTION_VERSION, "qr_count": 0, "regions": []},
        }

    grid = _warp(img, qr_pts)
    regions = [
        _region_stats(grid, name, row, col)
        for name, (row, col) in REGIONS.items()
    ]
    codes = []
    if qr_count > 1:
        codes.append("MULTIPLE_QR_CODES")
    if any(item["status"] == "warning" for item in regions):
        codes.append("REGION_ANOMALY")
    state = "warning" if codes else "passed"
    summary = (
        "QR region anomalies need review."
        if codes
        else "Five QR regions passed local inspection."
    )
    return {
        "id": "block_inspection",
        "status": state,
        "summary": summary,
        "reason_codes": codes,
        "evidence": {
            "version": BLOCK_INSPECTION_VERSION,
            "black_ratio_limits": {"minimum": MIN_BLACK, "maximum": MAX_BLACK},
            "qr_count": qr_count,
            "regions": regions,
        },
    }
