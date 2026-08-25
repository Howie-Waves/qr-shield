"""Local URL risk inference using lexical URL features only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.services.url_features import FEATURE_NAMES, extract_url_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "url_risk_model.joblib"
METADATA_PATH = PROJECT_ROOT / "models" / "model_metadata.json"


class ModelUnavailableError(RuntimeError):
    """Raised when the trained local model or metadata is unavailable."""


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_artifacts() -> tuple[Any, dict[str, Any]]:
    missing = [str(path) for path in (MODEL_PATH, METADATA_PATH) if not path.is_file()]
    if missing:
        raise ModelUnavailableError(
            "URL risk model is unavailable; missing required file(s): "
            + ", ".join(missing)
        )

    try:
        model = joblib.load(MODEL_PATH)
        metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ModelUnavailableError(
            f"URL risk model could not be loaded: {exc}"
        ) from exc

    if metadata.get("feature_order") != list(FEATURE_NAMES):
        raise ModelUnavailableError(
            "Model metadata feature order does not match the application."
        )
    if not metadata.get("model_version"):
        raise ModelUnavailableError("Model metadata has no version.")
    if metadata.get("artifact_sha256") != _file_hash(MODEL_PATH):
        raise ModelUnavailableError("Model artifact hash does not match metadata.")
    return model, metadata


def _phishing_probability(model: Any, feature_vector: pd.DataFrame) -> float:
    if not hasattr(model, "predict_proba"):
        raise ModelUnavailableError("URL risk model does not support probabilities.")

    probabilities = np.asarray(model.predict_proba(feature_vector), dtype=float)
    if probabilities.ndim != 2 or probabilities.shape[0] != 1:
        raise ModelUnavailableError("URL risk model returned invalid probabilities.")

    classes = list(getattr(model, "classes_", []))
    if classes:
        try:
            phishing_index = classes.index(1)
        except ValueError as exc:
            raise ModelUnavailableError(
                "URL risk model has no phishing class (label 1)."
            ) from exc
    elif probabilities.shape[1] == 2:
        phishing_index = 1
    else:
        raise ModelUnavailableError("URL risk model class order is unavailable.")

    probability = float(probabilities[0, phishing_index])
    if not np.isfinite(probability):
        raise ModelUnavailableError("URL risk model returned an invalid probability.")
    return min(max(probability, 0.0), 1.0)


def _risk_level(score: float) -> str:
    if score < 40:
        return "Low"
    if score < 70:
        return "Medium"
    return "High"


def _reasons(features: dict[str, float]) -> list[str]:
    candidates = (
        (
            features["has_ip_address"] == 1.0,
            "The URL uses an IP address instead of a domain name.",
        ),
        (
            features["has_at_symbol"] == 1.0,
            "The URL contains an @ symbol that can obscure its destination.",
        ),
        (
            features["uses_shortener"] == 1.0,
            "The URL uses a shortening service that hides the destination.",
        ),
        (
            features["suspicious_keyword_count"] > 0,
            "The URL contains words commonly associated with phishing.",
        ),
        (
            features["subdomain_count"] >= 3,
            "The hostname contains an unusually deep subdomain structure.",
        ),
        (features["url_length"] >= 100, "The URL is unusually long."),
        (
            features["uses_https"] == 0.0 and features["url_length"] > 0,
            "The URL does not explicitly use HTTPS.",
        ),
    )
    reasons = [message for condition, message in candidates if condition][:3]
    return reasons or ["No configured high-risk lexical signals were found."]


def predict_url_risk(url: str) -> dict:
    """Predict phishing risk locally without opening or requesting the URL."""
    # E1-US2 中文：版本和哈希绑定模型结果，不能用占位分数代替推理。
    # E1-US2 EN: Bind results to a model version and hash; never fake a score.
    model, metadata = _load_artifacts()
    features = extract_url_features(url)
    feature_order = metadata["feature_order"]
    feature_vector = pd.DataFrame(
        [[features[name] for name in feature_order]],
        columns=feature_order,
        dtype=float,
    )
    probability = _phishing_probability(model, feature_vector)
    risk_score = round(probability * 100.0, 2)
    threshold = float(metadata.get("threshold", 0.5))

    return {
        "score": risk_score,
        "level": _risk_level(risk_score),
        "is_phishing": probability >= threshold,
        "reasons": _reasons(features),
        "model_name": str(metadata.get("model_name") or type(model).__name__),
        "model_version": str(metadata["model_version"]),
        "threshold": threshold,
        "risk_level_thresholds": {"low_max_exclusive": 40, "medium_max_exclusive": 70},
    }
