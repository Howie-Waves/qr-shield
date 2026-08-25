"""Validate local demonstration payment payloads."""

from __future__ import annotations

import csv
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REF_PATH = ROOT / "data" / "processed" / "merchant_references.csv"
PREFIX = "QRSHIELD-PAY:v1"
PAYMENT_CHECK_VERSION = "payment-reference-v1"
FIELDS = {"merchant_id", "payee_id", "amount", "currency"}
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
AMOUNT_RE = re.compile(r"^(?:0|[1-9]\d*)(?:\.\d{1,2})?$")
CURRENCY_RE = re.compile(r"^[A-Z]{3}$")


class PaymentError(ValueError):
    """A payment payload error with a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _mask(payee: str) -> str:
    tail = payee[-4:] if len(payee) >= 4 else payee
    return f"***{tail}"


def parse_payment(text: str) -> dict:
    # E2-US2 中文：支付字段必须完整且唯一，金额只用 Decimal 处理。
    # E2-US2 EN: Require unique payment fields and parse money with Decimal.
    parts = text.split(";")
    if not parts or parts[0] != PREFIX:
        raise PaymentError("PREFIX_INVALID", "Payment prefix is invalid.")

    values: dict[str, str] = {}
    for part in parts[1:]:
        if part.count("=") != 1:
            raise PaymentError("FIELD_INVALID", "A payment field is invalid.")
        key, value = part.split("=", 1)
        if key not in FIELDS:
            raise PaymentError("FIELD_UNKNOWN", f"Unknown payment field: {key}")
        if key in values:
            raise PaymentError("FIELD_DUPLICATE", f"Duplicate payment field: {key}")
        if not value:
            raise PaymentError("FIELD_EMPTY", f"Empty payment field: {key}")
        values[key] = value

    missing = FIELDS - values.keys()
    if missing:
        names = ", ".join(sorted(missing))
        raise PaymentError("FIELD_MISSING", f"Missing payment field(s): {names}")
    if not ID_RE.fullmatch(values["merchant_id"]):
        raise PaymentError("MERCHANT_INVALID", "Merchant ID is invalid.")
    if not ID_RE.fullmatch(values["payee_id"]):
        raise PaymentError("PAYEE_INVALID", "Payee ID is invalid.")
    if not AMOUNT_RE.fullmatch(values["amount"]):
        raise PaymentError("AMOUNT_INVALID", "Amount must have at most two decimals.")
    if not CURRENCY_RE.fullmatch(values["currency"]):
        raise PaymentError("CURRENCY_INVALID", "Currency must be three uppercase letters.")

    try:
        amount = Decimal(values["amount"])
    except InvalidOperation:
        raise PaymentError("AMOUNT_INVALID", "Amount is invalid.") from None
    if not amount.is_finite() or amount <= 0:
        raise PaymentError("AMOUNT_INVALID", "Amount must be greater than zero.")
    return {**values, "amount": amount}


def _load_refs(path: Path) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8", newline="") as file:
            return list(csv.DictReader(file))
    except (OSError, csv.Error):
        return []


def verify_payment(text: str, path: Path = REF_PATH) -> dict:
    """Compare a demonstration payload with a local merchant reference."""
    if not text.startswith("QRSHIELD-PAY:"):
        return {
            "id": "payment",
            "status": "not_applicable",
            "summary": "The QR code is not a demonstration payment.",
            "reason_codes": [],
            "evidence": {"version": PAYMENT_CHECK_VERSION},
        }
    try:
        pay = parse_payment(text)
    except PaymentError as exc:
        return {
            "id": "payment",
            "status": "failed",
            "summary": str(exc),
            "reason_codes": [exc.code],
            "evidence": {"version": PAYMENT_CHECK_VERSION},
        }

    refs = _load_refs(path)
    ref = next(
        (row for row in refs if row.get("merchant_id") == pay["merchant_id"]),
        None,
    )
    evidence = {
        "version": PAYMENT_CHECK_VERSION,
        "merchant_id": pay["merchant_id"],
        "payee_masked": _mask(pay["payee_id"]),
        "amount": f"{pay['amount']:.2f}",
        "currency": pay["currency"],
    }
    if ref is None:
        return {
            "id": "payment",
            "status": "unverifiable",
            "summary": (
                "Unverifiable: no trusted merchant reference was found. "
                "Confirm the payee and amount before paying."
            ),
            "reason_codes": ["MERCHANT_UNKNOWN"],
            "evidence": evidence,
        }

    codes = []
    if pay["payee_id"] != ref.get("payee_id"):
        codes.append("PAYEE_MISMATCH")
    try:
        ref_amount = Decimal(str(ref.get("amount", "")))
    except InvalidOperation:
        ref_amount = Decimal("-1")
    if pay["amount"] != ref_amount:
        codes.append("AMOUNT_MISMATCH")
    if pay["currency"] != ref.get("currency"):
        codes.append("CURRENCY_MISMATCH")
    return {
        "id": "payment",
        "status": "failed" if codes else "passed",
        "summary": (
            "Payment fields do not match the local reference."
            if codes
            else "Payment fields match the local reference."
        ),
        "reason_codes": codes,
        "evidence": evidence,
    }
