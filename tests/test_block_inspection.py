import unittest

import cv2
import numpy as np

from app.services.block_inspection import inspect_blocks


def qr_bytes(text: str = "https://example.com") -> bytes:
    qr = cv2.QRCodeEncoder_create().encode(text)
    qr = cv2.resize(qr, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    qr = cv2.copyMakeBorder(qr, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    ok, buf = cv2.imencode(".png", qr)
    if not ok:
        raise RuntimeError("Could not create the test QR image.")
    return buf.tobytes()


class BlockInspectionTests(unittest.TestCase):
    # E2-US1 中文：五区检查必须返回可复核的区域证据。
    # E2-US1 EN: Five-region inspection must return reviewable evidence.
    def test_clean_qr_returns_five_regions(self) -> None:
        result = inspect_blocks(qr_bytes())

        self.assertEqual(result["id"], "block_inspection")
        self.assertIn(result["status"], {"passed", "warning"})
        self.assertEqual(len(result["evidence"]["regions"]), 5)
        self.assertEqual(
            {row["region"] for row in result["evidence"]["regions"]},
            {
                "top_left",
                "top_right",
                "center",
                "bottom_left",
                "bottom_right",
            },
        )

    def test_center_cover_returns_warning(self) -> None:
        img = cv2.imdecode(
            np.frombuffer(qr_bytes(), dtype=np.uint8),
            cv2.IMREAD_COLOR,
        )
        height, width = img.shape[:2]
        cv2.rectangle(
            img,
            (width * 2 // 5, height * 2 // 5),
            (width * 3 // 5, height * 3 // 5),
            (255, 255, 255),
            -1,
        )
        ok, buf = cv2.imencode(".png", img)
        self.assertTrue(ok)

        result = inspect_blocks(buf.tobytes())

        self.assertEqual(result["status"], "warning")
        self.assertIn("REGION_ANOMALY", result["reason_codes"])

    # E2-US1 中文：四角被明显覆盖时不能返回通过。
    # E2-US1 EN: Obvious cover over any corner must never return passed.
    def test_corner_covers_do_not_pass(self) -> None:
        src = cv2.imdecode(
            np.frombuffer(qr_bytes(), dtype=np.uint8),
            cv2.IMREAD_COLOR,
        )
        found, pts = cv2.QRCodeDetector().detect(src)
        self.assertTrue(found)
        box = np.asarray(pts).reshape(4, 2)
        x1, y1 = np.floor(box.min(axis=0)).astype(int)
        x2, y2 = np.ceil(box.max(axis=0)).astype(int)
        cell = min(x2 - x1, y2 - y1) // 3
        boxes = (
            (x1, y1, x1 + cell, y1 + cell),
            (x2 - cell, y1, x2, y1 + cell),
            (x1, y2 - cell, x1 + cell, y2),
            (x2 - cell, y2 - cell, x2, y2),
        )

        for box in boxes:
            with self.subTest(box=box):
                img = src.copy()
                x1, y1, x2, y2 = box
                cv2.rectangle(img, (x1, y1), (x2, y2), (255, 255, 255), -1)
                ok, buf = cv2.imencode(".png", img)
                self.assertTrue(ok)

                result = inspect_blocks(buf.tobytes())

                self.assertIn(result["status"], {"warning", "incomplete"})

    def test_plain_image_is_incomplete(self) -> None:
        img = np.full((240, 240, 3), 255, dtype=np.uint8)
        ok, buf = cv2.imencode(".png", img)
        self.assertTrue(ok)

        result = inspect_blocks(buf.tobytes())

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["reason_codes"], ["QR_NOT_LOCALIZED"])

    def test_multiple_qr_codes_return_warning(self) -> None:
        first = cv2.imdecode(
            np.frombuffer(qr_bytes("https://one.example"), dtype=np.uint8),
            cv2.IMREAD_COLOR,
        )
        second = cv2.imdecode(
            np.frombuffer(qr_bytes("https://two.example"), dtype=np.uint8),
            cv2.IMREAD_COLOR,
        )
        gap = np.full((first.shape[0], 80, 3), 255, dtype=np.uint8)
        img = np.hstack((first, gap, second))
        ok, buf = cv2.imencode(".png", img)
        self.assertTrue(ok)

        result = inspect_blocks(buf.tobytes())

        self.assertEqual(result["status"], "warning")
        self.assertGreaterEqual(result["evidence"]["qr_count"], 2)
        self.assertIn("MULTIPLE_QR_CODES", result["reason_codes"])


if __name__ == "__main__":
    unittest.main()
