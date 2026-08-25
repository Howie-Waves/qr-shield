# AI-assisted implementation: written with AI assistance and reviewed by the
# project author.

import unittest
from unittest.mock import Mock, patch

import httpx

from app.services.url_vet_client import (
    UrlVetUnavailableError,
    _base_url,
    get_url_vet_base_url,
    scan,
)


class UrlVetClientTests(unittest.TestCase):
    def test_rejects_non_loopback_base_url(self) -> None:
        with self.assertRaises(ValueError):
            _base_url("http://example.com:8080")

    def test_uses_default_loopback_base_url(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(get_url_vet_base_url(), "http://127.0.0.1:8080")

    def test_scan_returns_response_json_with_proxy_bypass(self) -> None:
        response = Mock()
        response.is_success = True
        response.json.return_value = {"result": {"risk_score": 5}, "incomplete": False}

        client = Mock()
        client.get.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=None)

        with patch("app.services.url_vet_client.httpx.Client", return_value=client) as client_cls:
            result = scan("https://example.com")

        self.assertEqual(result["result"]["risk_score"], 5)
        client_cls.assert_called_once_with(timeout=10.0, trust_env=False)
        client.get.assert_called_once_with(
            "http://127.0.0.1:8080/api/v1/analyze",
            params={"url": "https://example.com"},
        )

    def test_scan_raises_unavailable_for_timeout(self) -> None:
        client = Mock()
        client.get.side_effect = httpx.TimeoutException("timed out")
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=None)

        with patch("app.services.url_vet_client.httpx.Client", return_value=client):
            with self.assertRaises(UrlVetUnavailableError):
                scan("https://example.com")

    def test_scan_raises_unavailable_for_non_success_status(self) -> None:
        response = Mock()
        response.is_success = False
        response.status_code = 500

        client = Mock()
        client.get.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=None)

        with patch("app.services.url_vet_client.httpx.Client", return_value=client):
            with self.assertRaises(UrlVetUnavailableError):
                scan("https://example.com")

    def test_scan_raises_unavailable_for_invalid_json(self) -> None:
        response = Mock()
        response.is_success = True
        response.json.side_effect = ValueError("invalid")

        client = Mock()
        client.get.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=None)

        with patch("app.services.url_vet_client.httpx.Client", return_value=client):
            with self.assertRaises(UrlVetUnavailableError):
                scan("https://example.com")

    def test_scan_raises_unavailable_for_non_object_json(self) -> None:
        response = Mock()
        response.is_success = True
        response.json.return_value = ["not", "an", "object"]

        client = Mock()
        client.get.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=None)

        with patch("app.services.url_vet_client.httpx.Client", return_value=client):
            with self.assertRaises(UrlVetUnavailableError):
                scan("https://example.com")


if __name__ == "__main__":
    unittest.main()
