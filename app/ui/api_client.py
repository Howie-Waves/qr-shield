"""HTTP client functions used by the Streamlit UI."""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx


DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"
REQUEST_TIMEOUT_SECONDS = 30.0
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class APIClientError(RuntimeError):
    """A safe API error for presentation by the UI."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def get_api_base_url() -> str:
    raw = os.getenv("QR_API_BASE_URL", DEFAULT_API_BASE_URL)
    try:
        return _base_url(raw)
    except ValueError:
        return DEFAULT_API_BASE_URL


def _base_url(base_url: str) -> str:
    url = (base_url or DEFAULT_API_BASE_URL).rstrip("/")
    parts = urlsplit(url)
    # E1-US1: The UI only calls the local API; decoded URLs remain inert text.
    if (
        parts.scheme != "http"
        or parts.hostname not in LOOPBACK_HOSTS
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise ValueError("QR API base URL must use a loopback HTTP address.")
    return url


def _create_client() -> httpx.Client:
    # The UI only ever calls the loopback API (see _base_url), so it must ignore any
    # system/HTTP(S) proxy. On machines with a system proxy enabled, routing a
    # 127.0.0.1 request through the proxy makes the local call fail.
    return httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, trust_env=False)


def check_api_health(base_url: str) -> bool:
    """Return whether the FastAPI health endpoint reports an OK state."""
    try:
        url = _base_url(base_url)
        with _create_client() as client:
            response = client.get(f"{url}/health")
            return (
                response.status_code == 200
                and response.json().get("status") == "ok"
            )
    except (httpx.HTTPError, ValueError):
        return False


def analyze_qr(
    base_url: str,
    filename: str,
    content: bytes,
    mime_type: str,
) -> dict:
    """Send an image to the API without interpreting or opening its payload."""
    try:
        url = _base_url(base_url)
        with _create_client() as client:
            response = client.post(
                f"{url}/api/v1/analyze",
                files={"file": (filename, content, mime_type)},
            )
    except (httpx.HTTPError, ValueError) as exc:
        raise APIClientError("Unable to connect to the API.") from exc

    if not response.is_success:
        raise APIClientError(
            "The API could not analyze the uploaded image.",
            status_code=response.status_code,
        )
    try:
        result: Any = response.json()
    except ValueError as exc:
        raise APIClientError("The API returned an invalid response.") from exc
    if not isinstance(result, dict):
        raise APIClientError("The API returned an invalid response.")
    return result


def create_review_case(base_url: str, result: dict, consent: bool) -> str:
    """Submit only an explicit review request to the local API."""
    analysis = result.get("analysis") or {}
    payload = {
        "payload": str(result.get("decoded_text", "")),
        "hostname": result.get("hostname"),
        "assessment_outcome": str(result.get("assessment_outcome", "Incomplete")),
        "model_version": analysis.get("model_version"),
        "reason_codes": [
            code for item in result.get("checks", []) for code in item.get("reason_codes", [])
        ],
        "consent": consent,
    }
    try:
        url = _base_url(base_url)
        with _create_client() as client:
            response = client.post(f"{url}/api/v1/review-cases", json=payload)
            response.raise_for_status()
            return str(response.json()["case_id"])
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise APIClientError("Unable to create a review case.") from exc
