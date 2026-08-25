"""Lexical URL feature extraction with no network access."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from urllib.parse import SplitResult, urlsplit


FEATURE_NAMES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "digit_ratio",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "subdomain_count",
    "url_entropy",
    "has_ip_address",
    "uses_https",
    "has_at_symbol",
    "suspicious_keyword_count",
    "uses_shortener",
)

SUSPICIOUS_KEYWORDS = (
    "account",
    "bank",
    "confirm",
    "credential",
    "invoice",
    "login",
    "password",
    "payment",
    "paypal",
    "secure",
    "signin",
    "suspend",
    "update",
    "verify",
    "wallet",
)

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "buff.ly",
        "cutt.ly",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }
)


def _safe_split(url: str) -> SplitResult:
    """Parse a URL-like string without resolving or requesting it."""
    if not url:
        return SplitResult("", "", "", "", "")

    try:
        parsed = urlsplit(url)
        if not parsed.netloc and "://" not in url:
            parsed = urlsplit(f"//{url}")
        return parsed
    except (TypeError, ValueError):
        return SplitResult("", "", "", "", "")


def _safe_hostname(parsed: SplitResult) -> str:
    try:
        return (parsed.hostname or "").rstrip(".").casefold()
    except ValueError:
        return ""


def _is_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(text).values()
    )


def _uses_shortener(hostname: str) -> bool:
    return any(
        hostname == shortener or hostname.endswith(f".{shortener}")
        for shortener in URL_SHORTENERS
    )


def extract_hostname(url: str) -> str:
    """Return a normalized hostname without resolving it."""
    # E1-US3 中文：域名只从字符串提取，不做 DNS 查询。
    # E1-US3 EN: Read the hostname from text only; never perform DNS lookup.
    text = url.strip() if isinstance(url, str) else ""
    return _safe_hostname(_safe_split(text))


def extract_url_features(url: str) -> dict[str, float]:
    """Extract stable lexical features without accessing the URL."""
    text = url if isinstance(url, str) else ""
    stripped = text.strip()
    parsed = _safe_split(stripped)
    hostname = extract_hostname(stripped)
    is_ip = _is_ip_address(hostname)
    hostname_labels = [label for label in hostname.split(".") if label]
    subdomain_count = 0 if is_ip else max(len(hostname_labels) - 2, 0)
    lowered = stripped.casefold()
    digit_count = sum(character.isdigit() for character in stripped)
    special_count = sum(not character.isalnum() for character in stripped)

    values = {
        "url_length": float(len(stripped)),
        "hostname_length": float(len(hostname)),
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "digit_ratio": float(digit_count / len(stripped)) if stripped else 0.0,
        "special_char_count": float(special_count),
        "dot_count": float(stripped.count(".")),
        "hyphen_count": float(stripped.count("-")),
        "subdomain_count": float(subdomain_count),
        "url_entropy": float(_entropy(stripped)),
        "has_ip_address": float(is_ip),
        "uses_https": float(parsed.scheme.casefold() == "https"),
        "has_at_symbol": float("@" in stripped),
        "suspicious_keyword_count": float(
            sum(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)
        ),
        "uses_shortener": float(_uses_shortener(hostname)),
    }
    return {name: values[name] for name in FEATURE_NAMES}
