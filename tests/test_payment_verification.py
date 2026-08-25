import unittest

from app.services.payment_verification import (
    PaymentError,
    parse_payment,
    verify_payment,
)


VALID = (
    "QRSHIELD-PAY:v1;merchant_id=uni-cafe;payee_id=payee-4821;"
    "amount=12.50;currency=AUD"
)


class PaymentTests(unittest.TestCase):
    # E2-US2 中文：支付核验只比较本地合成基准，响应不泄露完整收款号。
    # E2-US2 EN: Compare local demo data and never expose a full payee ID.
    def test_valid_payment_passes(self) -> None:
        result = verify_payment(VALID)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["evidence"]["payee_masked"], "***4821")
        self.assertNotIn("payee-4821", str(result))

    def test_non_payment_is_not_applicable(self) -> None:
        result = verify_payment("https://example.com")

        self.assertEqual(result["status"], "not_applicable")

    def test_missing_field_is_rejected(self) -> None:
        text = VALID.replace(";currency=AUD", "")

        with self.assertRaises(PaymentError) as ctx:
            parse_payment(text)

        self.assertEqual(ctx.exception.code, "FIELD_MISSING")

    def test_duplicate_field_is_rejected(self) -> None:
        text = VALID + ";amount=10.00"

        with self.assertRaises(PaymentError) as ctx:
            parse_payment(text)

        self.assertEqual(ctx.exception.code, "FIELD_DUPLICATE")

    def test_unknown_field_is_rejected(self) -> None:
        text = VALID + ";note=test"

        with self.assertRaises(PaymentError) as ctx:
            parse_payment(text)

        self.assertEqual(ctx.exception.code, "FIELD_UNKNOWN")

    def test_bad_amount_is_rejected(self) -> None:
        for amount in ("0", "-1.00", "12.345", "NaN"):
            with self.subTest(amount=amount):
                text = VALID.replace("12.50", amount)
                with self.assertRaises(PaymentError) as ctx:
                    parse_payment(text)
                self.assertEqual(ctx.exception.code, "AMOUNT_INVALID")

    def test_field_mismatches_are_reported(self) -> None:
        text = VALID.replace("payee-4821", "payee-9999").replace(
            "12.50",
            "13.00",
        )

        result = verify_payment(text)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(
            result["reason_codes"],
            ["PAYEE_MISMATCH", "AMOUNT_MISMATCH"],
        )
        self.assertNotIn("payee-9999", str(result))

    def test_merchant_and_currency_mismatches_are_reported(self) -> None:
        unknown = VALID.replace("uni-cafe", "other-cafe")
        wrong_currency = VALID.replace("currency=AUD", "currency=USD")

        merchant = verify_payment(unknown)
        currency = verify_payment(wrong_currency)

        self.assertEqual(merchant["status"], "unverifiable")
        self.assertEqual(merchant["reason_codes"], ["MERCHANT_UNKNOWN"])
        self.assertIn("Confirm the payee and amount", merchant["summary"])
        self.assertEqual(currency["reason_codes"], ["CURRENCY_MISMATCH"])

    def test_currency_format_is_strict(self) -> None:
        for code in ("aud", "AU", "AUDD"):
            with self.subTest(code=code):
                text = VALID.replace("currency=AUD", f"currency={code}")
                with self.assertRaises(PaymentError) as ctx:
                    parse_payment(text)
                self.assertEqual(ctx.exception.code, "CURRENCY_INVALID")


if __name__ == "__main__":
    unittest.main()
