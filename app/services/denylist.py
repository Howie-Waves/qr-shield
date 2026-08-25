"""Versioned offline hostname denylist evidence source."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.services.checks import make_check
from app.services.url_features import extract_hostname


DENYLIST_PATH = Path(__file__).resolve().parents[2] / "data" / "processed" / "local_denylist.json"


def hostname_hash(hostname: str) -> str:
    """Hash a normalized hostname so this source stores no plain hostnames."""
    return hashlib.sha256(hostname.casefold().strip().encode("utf-8")).hexdigest()


def check_denylist(url: str) -> dict:
    """Return local denylist evidence without resolving or requesting the URL."""
    hostname = extract_hostname(url)
    if not hostname:
        return make_check(
            "local_denylist", "not_applicable", "No valid hostname is available for denylist lookup."
        )
    try:
        data = json.loads(DENYLIST_PATH.read_text(encoding="utf-8"))
        version = str(data["version"])
        entries = data["entries"]
        if not isinstance(entries, list):
            raise ValueError("entries must be a list")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return make_check(
            "local_denylist", "incomplete", "The local denylist is unavailable.", ["DENYLIST_UNAVAILABLE"]
        )

    digest = hostname_hash(hostname)
    for entry in entries:
        if isinstance(entry, dict) and entry.get("hostname_sha256") == digest:
            return make_check(
                "local_denylist", "failed", "Hostname matches the local denylist.",
                ["DENYLIST_MATCH", str(entry.get("reason_code", "LISTED"))],
                {"version": version},
            )
    return make_check(
        "local_denylist", "passed", "No local denylist match.", [], {"version": version}
    )
