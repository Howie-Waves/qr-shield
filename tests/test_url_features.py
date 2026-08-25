import unittest
from unittest.mock import patch

from app.services import url_features
from app.services.url_features import (
    FEATURE_NAMES,
    extract_hostname,
    extract_url_features,
)


HTTPS_EXAMPLE = "https://example.com"
HTTPS_MONASH = "https://monash.edu"
IP_LOGIN = "http://192.0.2.1/login"
SUSPICIOUS_LOGIN = "http://secure-account-verify.test/login"


class UrlFeaturesTests(unittest.TestCase):
    # E1-US3 中文：显示规范域名，但绝不解析或连接它。
    # E1-US3 EN: Show the normalized host without resolving or connecting.
    def test_extract_hostname(self) -> None:
        host = extract_hostname("HTTPS://User:Pass@Sub.Example.COM.:443/path")

        self.assertEqual(host, "sub.example.com")

    def test_invalid_hostname_is_empty(self) -> None:
        self.assertEqual(extract_hostname("https://[bad-ip]/"), "")

    def test_https_url(self) -> None:
        features = extract_url_features(HTTPS_EXAMPLE)

        self.assertEqual(features["uses_https"], 1.0)
        self.assertEqual(features["has_ip_address"], 0.0)
        self.assertEqual(features["hostname_length"], float(len("example.com")))

    def test_url_without_scheme(self) -> None:
        no_scheme_url = HTTPS_EXAMPLE.removeprefix("https://")
        features = extract_url_features(no_scheme_url)

        self.assertEqual(features["hostname_length"], float(len("example.com")))
        self.assertEqual(features["uses_https"], 0.0)

    def test_ip_address_url(self) -> None:
        features = extract_url_features(IP_LOGIN)

        self.assertEqual(features["has_ip_address"], 1.0)
        self.assertGreaterEqual(features["suspicious_keyword_count"], 1.0)

    def test_at_symbol(self) -> None:
        features = extract_url_features("@")

        self.assertEqual(features["has_at_symbol"], 1.0)

    def test_url_shortener(self) -> None:
        with patch.object(
            url_features,
            "URL_SHORTENERS",
            frozenset({"example.com"}),
        ):
            features = extract_url_features(HTTPS_EXAMPLE)

        self.assertEqual(features["uses_shortener"], 1.0)

    def test_suspicious_keywords(self) -> None:
        features = extract_url_features(SUSPICIOUS_LOGIN)

        self.assertGreaterEqual(features["suspicious_keyword_count"], 3.0)

    def test_empty_string_has_safe_zero_features(self) -> None:
        features = extract_url_features("")

        self.assertEqual(tuple(features), FEATURE_NAMES)
        self.assertTrue(all(value == 0.0 for value in features.values()))

    def test_chinese_characters_do_not_raise(self) -> None:
        features = extract_url_features("中文字符")

        self.assertEqual(features["url_length"], 4.0)
        self.assertEqual(tuple(features), FEATURE_NAMES)

    def test_feature_fields_and_order_are_stable(self) -> None:
        first = extract_url_features(HTTPS_EXAMPLE)
        second = extract_url_features(HTTPS_MONASH)

        self.assertEqual(tuple(first), FEATURE_NAMES)
        self.assertEqual(tuple(second), FEATURE_NAMES)
        self.assertTrue(all(isinstance(value, float) for value in first.values()))


if __name__ == "__main__":
    unittest.main()
