import json
import socket
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

import cv2
import numpy as np

from app.services import qr_decoder
from app.services.qr_decoder import (
    MAX_IMAGE_SIZE,
    QRDecodeError,
    decode_qr_image,
)


URL_PAYLOAD = "https://example.com"
TEXT_PAYLOAD = "plain text"
ROOT = Path(__file__).resolve().parents[1]


def make_qr_image(payload: str, extension: str) -> bytes:
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
    parameters = (
        [cv2.IMWRITE_JPEG_QUALITY, 100]
        if extension.casefold() in {".jpg", ".jpeg"}
        else []
    )
    success, encoded = cv2.imencode(extension, qr_code, parameters)
    if not success:
        raise RuntimeError("OpenCV could not encode the in-memory test image.")
    return encoded.tobytes()


class QRDecoderTests(unittest.TestCase):
    # E1-US1 中文：图片只在内存中校验和解码，不触发外部连接。
    # E1-US1 EN: Validate and decode in memory without external connections.
    def test_png_qr_code_decodes(self) -> None:
        image_bytes = make_qr_image(URL_PAYLOAD, ".png")

        result = decode_qr_image(image_bytes, "code.png")

        self.assertEqual(result["decoded_text"], URL_PAYLOAD)
        self.assertEqual(result["content_type"], "url")
        self.assertGreater(result["image_width"], 0)
        self.assertGreater(result["image_height"], 0)

    def test_jpeg_qr_code_decodes(self) -> None:
        image_bytes = make_qr_image(URL_PAYLOAD, ".jpg")

        result = decode_qr_image(image_bytes, "code.jpeg")

        self.assertEqual(result["decoded_text"], URL_PAYLOAD)
        self.assertEqual(result["content_type"], "url")

    def test_logo_centre_fixture_decodes_to_manifest_payload(self) -> None:
        dataset = ROOT / "data" / "test_images" / "e4_us1_robustness"
        manifest = json.loads(
            (dataset / "robustness_manifest.json").read_text(encoding="utf-8")
        )
        record = next(
            item for item in manifest["originals"] if item["file"] == "logo.jpg"
        )
        image_path = dataset / record["file"]

        result = decode_qr_image(image_path.read_bytes(), image_path.name)

        self.assertTrue(record["expected_decodable"])
        self.assertEqual(result["decoded_text"], record["expected_text"])
        self.assertEqual(result["content_type"], "url")

    def test_plain_text_qr_code(self) -> None:
        image_bytes = make_qr_image(TEXT_PAYLOAD, ".png")

        result = decode_qr_image(image_bytes, "text.png")

        self.assertEqual(result["decoded_text"], TEXT_PAYLOAD)
        self.assertEqual(result["content_type"], "text")

    def test_empty_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(QRDecodeError, "empty"):
            decode_qr_image(b"", "empty.png")

    def test_file_over_five_mib_is_rejected(self) -> None:
        oversized = b"\x00" * (MAX_IMAGE_SIZE + 1)

        with self.assertRaisesRegex(QRDecodeError, "5 MiB"):
            decode_qr_image(oversized, "large.jpg")

    def test_unsupported_extension_is_rejected(self) -> None:
        with self.assertRaisesRegex(QRDecodeError, "Unsupported image format"):
            decode_qr_image(b"image", "code.gif")

    def test_damaged_image_is_rejected(self) -> None:
        with self.assertRaisesRegex(QRDecodeError, "damaged"):
            decode_qr_image(b"not an image", "broken.png")

    def test_renamed_gif_is_rejected(self) -> None:
        gif = (
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
            b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )

        with self.assertRaisesRegex(QRDecodeError, "PNG or JPEG"):
            decode_qr_image(gif, "renamed.png")

    def test_large_pixel_count_is_rejected(self) -> None:
        image_bytes = make_qr_image(URL_PAYLOAD, ".png")

        with patch.object(qr_decoder, "MAX_IMAGE_PIXELS", 100):
            with self.assertRaisesRegex(QRDecodeError, "megapixel"):
                decode_qr_image(image_bytes, "large-pixels.png")

    def test_image_without_qr_code_is_rejected(self) -> None:
        ordinary_image = np.full((200, 300, 3), 255, dtype=np.uint8)
        success, encoded = cv2.imencode(".png", ordinary_image)
        self.assertTrue(success)

        with self.assertRaisesRegex(QRDecodeError, "No QR code"):
            decode_qr_image(encoded.tobytes(), "ordinary.png")

    def test_url_decoding_does_not_make_network_requests(self) -> None:
        image_bytes = make_qr_image(URL_PAYLOAD, ".png")

        with (
            patch.object(urllib.request, "urlopen") as urlopen,
            patch.object(socket, "create_connection") as create_connection,
        ):
            result = decode_qr_image(image_bytes, "network-check.png")

        self.assertEqual(result["decoded_text"], URL_PAYLOAD)
        urlopen.assert_not_called()
        create_connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
