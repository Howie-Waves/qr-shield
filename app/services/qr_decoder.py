"""In-memory QR code decoding for PNG and JPEG images."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import cv2
import numpy as np
from PIL import Image, UnidentifiedImageError


'''
E4: pyzxing (ZXing) is the primary decoder for robustness (rotated, blurry,
logo-in-centre codes and more symbologies)
'''
PYZXING_AVAILABLE = False
try:
    import os

    import jdk4py

    os.environ.setdefault("JAVA_HOME", str(jdk4py.JAVA_HOME))
    _JAVA_BIN = str(jdk4py.JAVA.parent)
    if _JAVA_BIN not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _JAVA_BIN + os.pathsep + os.environ.get("PATH", "")

    from pyzxing import BarCodeReader

    PYZXING_AVAILABLE = True
except Exception:
    BarCodeReader = None
    PYZXING_AVAILABLE = False

_PYZXING_READER = None

# This is a QR-code tool, so only accept QR-family 2D formats from ZXing. Under
# heavy distortion ZXing can false-positive a 1D barcode (e.g. UPC_E) inside a
# QR's texture and return a bogus payload; rejecting non-QR formats avoids that.
_ACCEPTED_QR_FORMATS = frozenset({"QR_CODE", "MICRO_QR_CODE", "RMQR_CODE"})


MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 25_000_000
SUPPORTED_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg"})
SUPPORTED_FORMATS = frozenset({"PNG", "JPEG"})

# Define standard prefixes for real-world payment QR codes
PAYMENT_PREFIXES = (
    "wxp://",                  # WeChat Pay
    "https://qr.alipay.com/",  # Alipay
    "000201",                  # UnionPay / EMVCo international standard
    "upi://pay",               # Indian UPI
    "QRSHIELD-PAY:",           # Legacy internal test identifier
)
class QRDecodeError(ValueError):
    """Raised when an uploaded image cannot produce a QR payload."""


def _check_image(raw: bytes) -> None:
    # E1-US1 中文：先读图片头和尺寸，伪装文件不能进入 OpenCV 解码。
    # E1-US1 EN: Check the image header and size before OpenCV decodes it.
    try:
        with Image.open(BytesIO(raw)) as img:
            if img.format not in SUPPORTED_FORMATS:
                raise QRDecodeError(
                    "Image content must be a valid PNG or JPEG file."
                )
            width, height = img.size
            if width < 1 or height < 1:
                raise QRDecodeError("Image dimensions are invalid.")
            if width * height > MAX_IMAGE_PIXELS:
                raise QRDecodeError("Image exceeds the 25 megapixel limit.")
            img.verify()
    except QRDecodeError:
        raise
    except (OSError, UnidentifiedImageError, ValueError):
        raise QRDecodeError(
            "Image is damaged or is not a valid PNG/JPEG file."
        ) from None


def _get_pyzxing_reader():
    """Lazily build one ZXing reader."""
    global _PYZXING_READER
    if not PYZXING_AVAILABLE:
        return None
    if _PYZXING_READER is None:
        try:
            _PYZXING_READER = BarCodeReader()
        except Exception:
            return None
    return _PYZXING_READER


def _decode_with_pyzxing(image: np.ndarray) -> str | None:
    """Decode with ZXing; return the raw payload text or None if undecodable."""
    reader = _get_pyzxing_reader()
    if reader is None:
        return None
    try:
        results = reader.decode_array(image)
    except Exception:
        return None
    for record in results or []:
        fmt = record.get("format")
        if isinstance(fmt, bytes):
            fmt = fmt.decode("ascii", "replace")
        if fmt not in _ACCEPTED_QR_FORMATS:
            continue  # ignore 1D-barcode false positives and other symbologies
        text = record.get("text") or record.get("parsed_text")
        if text:
            return str(text)
        for key in ("raw", "parsed"):
            value = record.get(key)
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            if value:
                return value
    return None


def _decode_with_cv2(image: np.ndarray) -> str | None:
    """Decode with OpenCV's detector; return the payload text or None."""
    try:
        decoded_text, points, _ = cv2.QRCodeDetector().detectAndDecode(image)
    except cv2.error:
        return None
    if not decoded_text or points is None:
        return None
    return decoded_text


# AI-assisted implementation: This function was implemented with assistance
# from OpenAI Codex and reviewed by the project author.
def decode_qr_image(image_bytes: bytes, filename: str) -> dict:
    """Decode one QR code without writing files or accessing its content."""
    extension = Path(filename or "").suffix.casefold()
    if extension not in SUPPORTED_EXTENSIONS:
        raise QRDecodeError("Unsupported image format; use PNG, JPG, or JPEG.")
    if not isinstance(image_bytes, bytes):
        raise QRDecodeError("Image data must be provided as bytes.")
    if not image_bytes:
        raise QRDecodeError("Image file is empty.")
    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise QRDecodeError("Image file exceeds the 5 MiB size limit.")

    _check_image(image_bytes)
    try:
        encoded_image = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(encoded_image, cv2.IMREAD_COLOR)
    except (cv2.error, ValueError):
        image = None

    if image is None or image.size == 0:
        raise QRDecodeError("Image is damaged or is not a valid PNG/JPEG file.")

    image_height, image_width = image.shape[:2]
    # pyzxing first for robustness; OpenCV as a silent fallback.
    decoded_text = _decode_with_pyzxing(image)
    if not decoded_text:
        decoded_text = _decode_with_cv2(image)
    if not decoded_text:
        raise QRDecodeError("No QR code was detected in the image.")

    if decoded_text.startswith(PAYMENT_PREFIXES):
        content_type = "payment"
    elif decoded_text.casefold().startswith(("http://", "https://")):
        content_type = "url"
    else:
        content_type = "text"
    return {
        "decoded_text": decoded_text,
        "content_type": content_type,
        "image_width": int(image_width),
        "image_height": int(image_height),
    }
