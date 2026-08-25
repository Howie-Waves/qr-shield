"""Generate safe, local QR images for the product demonstration."""

from __future__ import annotations

from pathlib import Path

import cv2


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ASSET_DIR = PROJECT_ROOT / "data" / "test_images" / "manual_demo"
DEMO_PAYLOADS = {
    "normal_url.png": "https://www.monash.edu",
    "suspicious_url.png": (
        "http://secure-account-verify.test/login?payment=confirm"
    ),
    "plain_text.png": "QR Shield demonstration text",
}


def _encode_qr(payload: str) -> bytes:
    qr_code = cv2.QRCodeEncoder_create().encode(payload)
    qr_code = cv2.resize(
        qr_code,
        None,
        fx=10,
        fy=10,
        interpolation=cv2.INTER_NEAREST,
    )
    qr_code = cv2.copyMakeBorder(
        qr_code,
        40,
        40,
        40,
        40,
        cv2.BORDER_CONSTANT,
        value=255,
    )
    success, encoded = cv2.imencode(".png", qr_code)
    if not success:
        raise RuntimeError("OpenCV could not encode a demo QR image.")
    return encoded.tobytes()


def generate_demo_qr_assets(
    output_directory: Path = DEMO_ASSET_DIR,
) -> dict[str, str]:
    output_directory.mkdir(parents=True, exist_ok=True)
    for filename, payload in DEMO_PAYLOADS.items():
        destination = output_directory / filename
        temporary = output_directory / f".{filename}.tmp"
        temporary.write_bytes(_encode_qr(payload))
        temporary.replace(destination)
        print(f"{filename}: {payload}")
    return DEMO_PAYLOADS.copy()


if __name__ == "__main__":
    generate_demo_qr_assets()
