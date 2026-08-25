"""HTTP client for the local self-hosted url.vet service."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx


DEFAULT_URL_VET_BASE_URL = "http://127.0.0.1:8080"
REQUEST_TIMEOUT_SECONDS = 10.0
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class UrlVetUnavailableError(RuntimeError):
    """Raised when url.vet cannot provide a usable response."""


def get_url_vet_base_url() -> str:
    """Return the configured url.vet base URL, falling back to loopback."""
    raw = os.getenv("QR_URLVET_BASE_URL", DEFAULT_URL_VET_BASE_URL)
    try:
        return _base_url(raw)
    except ValueError:
        return DEFAULT_URL_VET_BASE_URL


def _base_url(base_url: str) -> str:
    """Validate that url.vet is reached only through loopback HTTP."""
    url = (base_url or DEFAULT_URL_VET_BASE_URL).rstrip("/")
    parts = urlsplit(url)
    if (
        parts.scheme != "http"
        or parts.hostname not in LOOPBACK_HOSTS
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise ValueError("url.vet base URL must use a loopback HTTP address.")
    return url


def _create_client() -> httpx.Client:
    return httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False)


def scan(url: str) -> dict[str, Any]:
    """Analyze a URL with local url.vet without trusting proxies."""
    base_url = get_url_vet_base_url()
    try:
        with _create_client() as client:
            response = client.get(
                f"{base_url}/api/v1/analyze",
                params={"url": url},
            )
    except httpx.HTTPError as exc:
        raise UrlVetUnavailableError("url.vet is unavailable.") from exc

    if not response.is_success:
        raise UrlVetUnavailableError(
            f"url.vet returned HTTP {response.status_code}."
        )

    try:
        result = response.json()
    except ValueError as exc:
        raise UrlVetUnavailableError("url.vet returned invalid JSON.") from exc
    if not isinstance(result, dict):
        raise UrlVetUnavailableError("url.vet returned an invalid response.")
    return result
