# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
"""Generate the complete, deterministic QR Shield test-image pack."""

from __future__ import annotations

import json
from pathlib import Path

import cv2
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "test_images"
MAX_IMAGE_SIZE = 5 * 1024 * 1024


QR_CASES = (
    # E1-US1: supported upload formats and an independent valid retry image.
    ("e1_us1_upload/valid/url_png.png", "https://example.com", "Risk assessed", ".png"),
    ("e1_us1_upload/valid/url_jpg.jpg", "https://example.com", "Risk assessed", ".jpg"),
    ("e1_us1_upload/valid/url_jpeg.jpeg", "https://example.com", "Risk assessed", ".jpeg"),
    ("e1_us1_upload/valid/retry_after_failure.png", "plain text", "Not scored", ".png"),
    # E1-US2: stable examples on both sides of the documented thresholds.
    ("e1_us2_risk/low.png", "https://www.monash.edu", "Low (<40)", ".png"),
    ("e1_us2_risk/medium.png", "https://a.b.c.example.com/login", "Medium (40-<70)", ".png"),
    ("e1_us2_risk/high.png", "http://secure-account-verify.test/login?payment=confirm", "High (>=70)", ".png"),
    # E1-US3: URL, plain-text and malformed-URL presentation.
    ("e1_us3_content/valid_url.png", "https://student.monash.edu/help", "Risk assessed", ".png"),
    ("e1_us3_content/plain_text.png", "QR Shield demonstration text", "Not scored", ".png"),
    ("e1_us3_content/malformed_url.png", "https://[bad-ip]/", "Not scored", ".png"),
    # E2-US2: trusted, mismatched and missing merchant references.
    ("e2_us2_payment/trusted_match.png", "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;amount=12.50;currency=AUD", "Passed", ".png"),
    ("e2_us2_payment/amount_mismatch.png", "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;amount=99.00;currency=AUD", "Review required", ".png"),
    ("e2_us2_payment/unknown_reference.png", "QRSHIELD-PAY:v1;merchant_id=unknown;payee_id=payee-9999;amount=10.00;currency=AUD", "Unverifiable", ".png"),
    # E2-US3: content must remain untrusted text and never trigger networking.
    ("e2_us3_isolation/private_address.png", "http://127.0.0.1:8080/admin", "No network access", ".png"),
    ("e2_us3_isolation/script_like_url.png", "https://example.test/download?next=javascript:alert(1)", "No browser/script action", ".png"),
    ("e2_us3_isolation/redirect_chain_text.png", "https://redirect.example.test/r/1?next=/r/2", "No redirect followed", ".png"),
    # E3-US1: locked evidence-fusion scenarios represented as uploadable images.
    ("e3_us1_evidence/normal_url.png", "https://example.com", "Risk assessed", ".png"),
    ("e3_us1_evidence/suspicious_lexical_url.png", "http://192.0.2.1/secure-login?account=verify", "Risk assessed", ".png"),
    ("e3_us1_evidence/denylist_match.png", "https://listed.test/login", "Review required", ".png"),
    ("e3_us1_evidence/denylist_unavailable.png", "https://example.com/again", "Requires test override", ".png"),
    ("e3_us1_evidence/model_unavailable.png", "https://example.com/model", "Requires test override", ".png"),
    ("e3_us1_evidence/payment_mismatch.png", "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;amount=99.00;currency=AUD", "Review required", ".png"),
)


def _encode_qr(payload: str, extension: str) -> bytes:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(image, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, encoded = cv2.imencode(extension, image)
    if not ok:
        raise RuntimeError(f"OpenCV could not encode {extension} fixture.")
    return encoded.tobytes()


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def generate(output: Path = OUTPUT) -> dict:
    records: list[dict] = []
    for relative, payload, expected, extension in QR_CASES:
        _write(output / relative, _encode_qr(payload, extension))
        records.append(
            {
                "file": relative,
                "user_story": relative.split("/", 1)[0],
                "kind": "qr_image",
                "payload": payload,
                "expected": expected,
            }
        )

    rejected = (
        ("e1_us1_upload/rejected/empty.png", b"", "400: empty file"),
        ("e1_us1_upload/rejected/damaged.png", b"not an image", "400: damaged image"),
        ("e1_us1_upload/rejected/unsupported.gif", b"GIF89a", "400: unsupported format"),
        ("e1_us1_upload/rejected/over_5_mib.png", b"x" * (MAX_IMAGE_SIZE + 1), "413: over 5 MiB"),
    )
    for relative, content, expected in rejected:
        _write(output / relative, content)
        records.append(
            {
                "file": relative,
                "user_story": "e1_us1_upload",
                "kind": "rejected_upload",
                "expected": expected,
            }
        )

    oversized_pixels = np.full((5001, 5000), 255, dtype=np.uint8)
    ok, encoded = cv2.imencode(".png", oversized_pixels)
    if not ok:
        raise RuntimeError("OpenCV could not encode the 25 MP boundary fixture.")
    pixel_path = "e1_us1_upload/rejected/over_25_megapixels.png"
    _write(output / pixel_path, encoded.tobytes())
    records.append(
        {
            "file": pixel_path,
            "user_story": "e1_us1_upload",
            "kind": "rejected_upload",
            "expected": "400: over 25 megapixels",
        }
    )

    manifest = {
        "dataset": "QR Shield complete test-image pack",
        "version": "1.0",
        "generated_locally": True,
        "network_access_required": False,
        "records": records,
        "notes": {
            "e2_us1_tampering": "See e2_us1_tampering/manifest.json.",
            "e3_us2_privacy": "Reuses ordinary images; verify memory-only processing and consent in API tests.",
        },
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    result = generate()
    print(f"Generated {len(result['records'])} fixtures in {OUTPUT}")
