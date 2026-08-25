"""Build a redacted, evidence-backed provisional Phase 3 decision policy."""

from __future__ import annotations

import argparse
import csv
import hashlib
import heapq
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.decision_policy import (
    CALIBRATION_DATASET_PATH,
    CALIBRATION_OBSERVATIONS_PATH,
    DECISION_POLICY_PATH,
    CalibrationDataset,
    CalibrationManifest,
    CalibrationMetrics,
    CalibrationObservations,
    CalibrationReport,
    DecisionPolicy,
    load_calibration_manifest,
    verify_local_raw_files,
)
from app.services.model_service import ModelUnavailableError, predict_url_risk
from app.services.url_vet_check import get_url_vet_version
from app.services.url_vet_client import UrlVetUnavailableError, scan


REPORT_PATH = ROOT / "reports" / "phase3_calibration_report.json"
CACHE_PATH = ROOT / "data" / "processed" / "phase3_calibration_cache.json"
DATASET_VERSION = "phase3-labelled-url-calibration-v1"
OBSERVATION_VERSION = "phase3-score-observations-v1"
POLICY_VERSION = "phase3-decision-policy-v1"
REPORT_VERSION = "phase3-calibration-report-v1"
RANDOM_SEED = 5238
SAMPLE_COUNTS = {"calibration": 20, "validation": 10}
MIN_APPROVAL_SAMPLE_COUNT = 200
SELECTION_METHOD = (
    "For each source, select the smallest SHA-256 priorities produced from the "
    "fixed seed, source ID, source row number, and payload. Assign the first 20 "
    "eligible records to calibration and the next 10 to validation. Tranco "
    "domains are normalised to an HTTPS root URL; PhishTank URLs are retained "
    "only in ignored local memory/cache reconstruction, never committed."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _payload_sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _selection_priority(source_id: str, row_number: int, payload: str) -> int:
    value = f"{RANDOM_SEED}:{source_id}:{row_number}:{payload}"
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16)


def _normalise_tranco_domain(domain: str) -> str | None:
    domain = domain.strip().lower().rstrip(".")
    if not domain or any(char.isspace() for char in domain):
        return None
    payload = f"https://{domain}/"
    return payload if urlsplit(payload).hostname else None


def _valid_web_url(value: str) -> str | None:
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme.casefold() not in {"http", "https"} or not parts.hostname:
        return None
    return value


def _source_rows(source: Any) -> Iterable[tuple[int, str, str]]:
    path = ROOT / Path(source.raw_path)
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        if source.source_id == "tranco_top_1m":
            for row_number, row in enumerate(csv.reader(file), start=1):
                if len(row) < 2:
                    continue
                payload = _normalise_tranco_domain(row[1])
                if payload:
                    yield row_number, row[0].strip(), payload
            return

        reader = csv.DictReader(file)
        for row_number, row in enumerate(reader, start=2):
            payload = _valid_web_url(str(row.get("url") or ""))
            if payload:
                yield row_number, str(row.get("phish_id") or row_number), payload


def _smallest_priority_rows(source: Any, count: int) -> list[tuple[int, str, str]]:
    heap: list[tuple[int, int, str, str]] = []
    seen_hashes: set[str] = set()
    for row_number, source_record_id, payload in _source_rows(source):
        payload_hash = _payload_sha256(payload)
        if payload_hash in seen_hashes:
            continue
        seen_hashes.add(payload_hash)
        priority = _selection_priority(source.source_id, row_number, payload)
        item = (-priority, row_number, source_record_id, payload)
        if len(heap) < count:
            heapq.heappush(heap, item)
        elif priority < -heap[0][0]:
            heapq.heapreplace(heap, item)
    if len(heap) != count:
        raise RuntimeError(f"{source.source_id} has fewer than {count} eligible rows")
    return [
        (row_number, source_record_id, payload)
        for _, row_number, source_record_id, payload in sorted(heap, reverse=True)
    ]


def build_dataset(
    manifest: CalibrationManifest,
) -> tuple[CalibrationDataset, dict[str, str]]:
    total_per_source = sum(SAMPLE_COUNTS.values())
    records: list[dict[str, Any]] = []
    private_payloads: dict[str, str] = {}
    for source in manifest.sources:
        selected = _smallest_priority_rows(source, total_per_source)
        offset = 0
        for split, split_count in SAMPLE_COUNTS.items():
            for index, (row_number, source_record_id, payload) in enumerate(
                selected[offset : offset + split_count], start=1
            ):
                payload_hash = _payload_sha256(payload)
                sample_id = f"{source.source_id}-{split}-{index:03d}"
                private_payloads[sample_id] = payload
                records.append(
                    {
                        "sample_id": sample_id,
                        "source_id": source.source_id,
                        "source_row_number": row_number,
                        "source_record_id": source_record_id,
                        "payload_sha256": payload_hash,
                        "label": source.label,
                        "split": split,
                        "inclusion_reason": (
                            "Deterministic fixed-seed sample from an eligible valid "
                            "HTTP/HTTPS source record."
                        ),
                    }
                )
            offset += split_count

    dataset = CalibrationDataset.model_validate(
        {
            "schema_version": "1.0",
            "dataset_version": DATASET_VERSION,
            "source_manifest_version": manifest.dataset_version,
            "random_seed": RANDOM_SEED,
            "selection_method": SELECTION_METHOD,
            "records": records,
        }
    )
    return dataset, private_payloads


def _load_cache(url_vet_version: str) -> dict[str, dict[str, Any]]:
    if not CACHE_PATH.is_file():
        return {}
    raw = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    if (
        not isinstance(raw, dict)
        or raw.get("schema_version") != "1.0"
        or raw.get("url_vet_version") != url_vet_version
    ):
        return {}
    records = raw.get("records")
    return records if isinstance(records, dict) else {}


def _write_cache(records: dict[str, dict[str, Any]], url_vet_version: str) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "url_vet_version": url_vet_version,
        "records": records,
    }
    CACHE_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _finite_score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score):
        return None
    return round(min(max(score, 0.0), 100.0), 4)


def collect_observations(
    dataset: CalibrationDataset,
    private_payloads: dict[str, str],
    *,
    refresh: bool = False,
    retry_unavailable: bool = False,
) -> CalibrationObservations:
    url_vet_version = get_url_vet_version()
    cache = {} if refresh else _load_cache(url_vet_version)
    observations: list[dict[str, Any]] = []
    local_model_version = "unavailable"
    for index, record in enumerate(dataset.records, start=1):
        payload = private_payloads[record.sample_id]
        try:
            local = predict_url_risk(payload)
            judgement_score = _finite_score(local.get("score"))
            local_model_status = "complete" if judgement_score is not None else "unavailable"
            local_model_version = str(local.get("model_version") or local_model_version)
        except ModelUnavailableError:
            judgement_score = None
            local_model_status = "unavailable"

        cached = cache.get(record.payload_sha256)
        if retry_unavailable and cached is not None:
            if cached.get("url_vet_status") == "unavailable":
                cached = None
        if cached is None:
            print(f"Collecting score evidence {index}/{len(dataset.records)}: {record.sample_id}")
            try:
                raw = scan(payload)
            except UrlVetUnavailableError:
                risk_score = None
                verdict = None
                url_vet_status = "unavailable"
                error_count = 1
            else:
                result = raw.get("result") if isinstance(raw, dict) else None
                result = result if isinstance(result, dict) else {}
                risk_score = _finite_score(result.get("risk_score"))
                verdict_text = str(result.get("verdict") or "").strip()
                verdict = verdict_text or None
                errors = raw.get("errors") if isinstance(raw, dict) else None
                error_count = len(errors) if isinstance(errors, list) else 0
                if risk_score is None:
                    url_vet_status = "unavailable"
                elif raw.get("incomplete") is True:
                    url_vet_status = "partial"
                else:
                    url_vet_status = "complete"

            cached = {
                "payload_sha256": record.payload_sha256,
                "risk_score": risk_score,
                "verdict": verdict,
                "url_vet_status": url_vet_status,
                "url_vet_error_count": error_count,
            }
            cache[record.payload_sha256] = cached
            _write_cache(cache, url_vet_version)

        observations.append(
            {
                "sample_id": record.sample_id,
                "payload_sha256": record.payload_sha256,
                "label": record.label,
                "split": record.split,
                "risk_score": cached.get("risk_score"),
                "judgement_score": judgement_score,
                "verdict": cached.get("verdict"),
                "url_vet_status": cached.get("url_vet_status", "unavailable"),
                "url_vet_error_count": cached.get("url_vet_error_count", 0),
                "local_model_status": local_model_status,
            }
        )

    return CalibrationObservations.model_validate(
        {
            "schema_version": "1.0",
            "observation_version": OBSERVATION_VERSION,
            "dataset_version": dataset.dataset_version,
            "generated_at": _utc_now(),
            "url_vet_version": url_vet_version,
            "local_model_version": local_model_version,
            "records": observations,
        }
    )


def _usable_score(record: Any) -> float | None:
    if record.risk_score is None or record.judgement_score is None:
        return None
    return max(record.risk_score, record.judgement_score)


ADVERSE_VERDICTS = frozenset({"suspicious", "risky", "malicious"})


def _has_adverse_verdict(record: Any) -> bool:
    return str(getattr(record, "verdict", None) or "").strip().casefold() in ADVERSE_VERDICTS


def calculate_metrics(records: list[Any], benchmark: float) -> CalibrationMetrics:
    matrix = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    incomplete = 0
    for record in records:
        score = _usable_score(record)
        if score is None:
            incomplete += 1
            continue
        actual_positive = record.label == "suspicious"
        predicted_positive = score >= benchmark or _has_adverse_verdict(record)
        if actual_positive and predicted_positive:
            matrix["true_positive"] += 1
        elif actual_positive:
            matrix["false_negative"] += 1
        elif predicted_positive:
            matrix["false_positive"] += 1
        else:
            matrix["true_negative"] += 1

    tp = matrix["true_positive"]
    tn = matrix["true_negative"]
    fp = matrix["false_positive"]
    fn = matrix["false_negative"]
    ratio = lambda numerator, denominator: numerator / denominator if denominator else 0.0
    return CalibrationMetrics.model_validate(
        {
            "sample_count": len(records),
            "presumed_benign_count": sum(r.label == "presumed_benign" for r in records),
            "suspicious_count": sum(r.label == "suspicious" for r in records),
            "completed_count": len(records) - incomplete,
            "incomplete_count": incomplete,
            "confusion_matrix": matrix,
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_negative_rate": ratio(fn, tp + fn),
            "false_positive_rate": ratio(fp, tn + fp),
        }
    )


def select_benchmark(records: list[Any]) -> tuple[float, int, CalibrationMetrics]:
    usable_scores = [score for record in records if (score := _usable_score(record)) is not None]
    if not usable_scores:
        raise RuntimeError("No complete score pairs are available for calibration")

    candidates: list[tuple[tuple[float, ...], float, CalibrationMetrics]] = []
    for benchmark in range(1, 100):
        metrics = calculate_metrics(records, float(benchmark))
        nearest_margin = min(abs(score - benchmark) for score in usable_scores)
        matrix = metrics.confusion_matrix
        ordering = (
            float(matrix.false_negative),
            -metrics.recall,
            float(matrix.false_positive),
            -nearest_margin,
            abs(benchmark - 50.0),
            float(benchmark),
        )
        candidates.append((ordering, float(benchmark), metrics))
    _, benchmark, metrics = min(candidates, key=lambda item: item[0])
    return benchmark, len(candidates), metrics


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        raise RuntimeError("Cannot calculate a percentile from no values")
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return float(ordered[lower] * (1.0 - weight) + ordered[upper] * weight)


def _distribution(values: list[float]) -> dict[str, float | int]:
    return {
        "count": len(values),
        "minimum": round(min(values), 4),
        "first_quartile": round(_percentile(values, 0.25), 4),
        "median": round(_percentile(values, 0.50), 4),
        "third_quartile": round(_percentile(values, 0.75), 4),
        "maximum": round(max(values), 4),
    }


def derive_agreement_margin(records: list[Any]) -> float:
    differences = [
        abs(record.risk_score - record.judgement_score)
        for record in records
        if record.risk_score is not None and record.judgement_score is not None
    ]
    if not differences:
        raise RuntimeError("No score pairs are available to derive agreement margin")
    empirical = math.floor(_percentile(differences, 0.25) + 0.5)
    return float(min(max(empirical, 1), 100))


def derive_thresholds(
    records: list[Any], benchmark: float
) -> tuple[dict[str, float], float, dict[str, Any]]:
    presumed_benign = [
        score
        for record in records
        if record.label == "presumed_benign"
        and (score := _usable_score(record)) is not None
    ]
    suspicious = [
        score
        for record in records
        if record.label == "suspicious"
        and (score := _usable_score(record)) is not None
    ]
    differences = [
        abs(record.risk_score - record.judgement_score)
        for record in records
        if record.risk_score is not None and record.judgement_score is not None
    ]
    if not presumed_benign or not suspicious or not differences:
        raise RuntimeError("Both labelled score distributions are required")

    benign_distribution = _distribution(presumed_benign)
    benign_upper_quartile = benign_distribution["third_quartile"]
    low_medium = float(math.ceil(min(benign_upper_quartile, benchmark - 1.0)))

    suspicious_distribution = _distribution(suspicious)
    high_dangerous = float(
        max(math.ceil(suspicious_distribution["first_quartile"]), benchmark + 1.0)
    )
    high_dangerous = min(high_dangerous, 100.0)
    if not 0 <= low_medium < benchmark < high_dangerous <= 100:
        raise RuntimeError("Observed distributions cannot produce four ordered levels")

    agreement_margin = derive_agreement_margin(records)
    evidence = {
        "combined_score_rule": "max(risk_score, judgement_score)",
        "low_medium_method": (
            "T1 is the ceiling of the presumed-benign calibration third "
            "quartile Q3, capped below B. The upper quarter of presumed-benign "
            "scores is therefore not displayed as Low."
        ),
        "presumed_benign_distribution": benign_distribution,
        "presumed_benign_upper_quartile": round(benign_upper_quartile, 4),
        "medium_high_method": (
            "T2 equals the selected suspicious benchmark B, so High begins "
            "where the labelled calibration decision changes to suspicious."
        ),
        "high_dangerous_method": (
            "T3 is the ceiling of the suspicious calibration first quartile, "
            "with Risky/Malicious verdict floors independently forcing Dangerous."
        ),
        "suspicious_distribution": suspicious_distribution,
        "agreement_margin_method": (
            "D is the rounded first quartile of absolute risk/judgement score "
            "differences, with a minimum of 1. It is a strict empirical "
            "agreement tolerance, not a risk-level boundary."
        ),
        "absolute_score_difference_distribution": _distribution(differences),
        "adverse_verdicts": ["Suspicious", "Risky", "Malicious"],
    }
    return (
        {
            "low_medium": low_medium,
            "medium_high": benchmark,
            "high_dangerous": high_dangerous,
        },
        agreement_margin,
        evidence,
    )


def build_report(
    manifest: CalibrationManifest,
    dataset: CalibrationDataset,
    observations: CalibrationObservations,
) -> tuple[DecisionPolicy, CalibrationReport]:
    calibration_records = [r for r in observations.records if r.split == "calibration"]
    validation_records = [r for r in observations.records if r.split == "validation"]
    benchmark, candidate_count, calibration_metrics = select_benchmark(calibration_records)
    thresholds, agreement_margin, threshold_evidence = derive_thresholds(
        calibration_records, benchmark
    )
    validation_metrics = calculate_metrics(validation_records, benchmark)
    status_counts = Counter(record.url_vet_status for record in observations.records)
    verdict_counts = Counter(record.verdict or "Not available" for record in observations.records)
    score_pair_count = sum(_usable_score(record) is not None for record in observations.records)

    limitations = [
        "Tranco popularity is a presumed-benign proxy, not proof that every sampled destination is safe.",
        "PhishTank online status and url.vet evidence are time-sensitive retrieval snapshots.",
        "The retained local LR model has no committed training-source manifest, so overlap with this calibration sample cannot be excluded.",
        "url.vet includes a PhishTank threat-intelligence check, so PhishTank-labelled calibration is not an independent external validation of url.vet.",
        "Binary labels support the suspicious benchmark directly; the four display levels are provisional operational bands derived from presumed-benign Q3, benchmark B, and suspicious Q1 rather than four independently labelled ground-truth classes.",
    ]
    if len(observations.records) < MIN_APPROVAL_SAMPLE_COUNT:
        limitations.append(
            f"The {len(observations.records)}-record bounded sample is below the {MIN_APPROVAL_SAMPLE_COUNT}-record approval target."
        )
    if status_counts["partial"] or status_counts["unavailable"]:
        limitations.append(
            "Some url.vet analyses were partial or unavailable; usable numeric scores are retained, but full network-backed completion is reported separately."
        )
    validation_negative_count = (
        validation_metrics.confusion_matrix.true_negative
        + validation_metrics.confusion_matrix.false_positive
    )
    if validation_metrics.false_positive_rate > 0.20:
        limitations.append(
            "The validation false-positive rate is "
            f"{validation_metrics.false_positive_rate:.1%} across "
            f"{validation_negative_count} completed presumed-benign records; "
            "the safety-first policy over-warns and requires more representative "
            "calibration before approval."
        )

    generated_at = _utc_now()
    policy = DecisionPolicy.model_validate(
        {
            "schema_version": "1.0",
            "policy_version": POLICY_VERSION,
            "status": "provisional",
            "dataset_version": dataset.dataset_version,
            "generated_at": generated_at,
            "risk_score_source": "url.vet result.risk_score",
            "judgement_score_source": "local LR phishing probability",
            "thresholds": thresholds,
            "suspicious_benchmark": benchmark,
            "agreement_margin": agreement_margin,
            "verdict_floors": {
                "suspicious": "High suspicion",
                "risky": "Dangerous",
                "malicious": "Dangerous",
            },
            "selection_priority": (
                "minimise_false_negatives_then_maximise_recall_then_minimise_false_positives"
            ),
            "metrics": calibration_metrics.model_dump(mode="json"),
            "limitations": limitations,
        }
    )
    report = CalibrationReport.model_validate(
        {
            "schema_version": "1.0",
            "report_version": REPORT_VERSION,
            "dataset_version": dataset.dataset_version,
            "generated_at": generated_at,
            "candidate_policy_count": candidate_count,
            "source_hashes": {source.source_id: source.sha256 for source in manifest.sources},
            "analysis_versions": {
                "url_vet": observations.url_vet_version,
                "local_judgement_model": observations.local_model_version,
            },
            "selected_policy": policy.model_dump(mode="json"),
            "validation_metrics": validation_metrics.model_dump(mode="json"),
            "observation_count": len(observations.records),
            "score_pair_count": score_pair_count,
            "url_vet_status_counts": {
                status: status_counts[status]
                for status in ("complete", "partial", "unavailable")
            },
            "verdict_counts": dict(sorted(verdict_counts.items())),
            "threshold_evidence": threshold_evidence,
            "methodology": [
                "Use max(risk_score, judgement_score) for conservative benchmark evaluation so one high score cannot be averaged away; Suspicious, Risky, and Malicious verdicts are also adverse predictions.",
                "Evaluate integer benchmark candidates B=1..99 on the calibration split; minimise false negatives, then maximise recall, then minimise false positives, then maximise distance to the nearest observed score.",
                "Derive T1 from the presumed-benign score distribution, set T2=B, derive T3 from the suspicious score distribution, and derive D separately from observed two-score disagreement.",
                "Freeze all selected values before evaluating the separate validation split.",
                "Treat missing score pairs as incomplete rather than as zero or low-risk predictions; report partial url.vet analyses separately from score availability.",
            ],
            "justification": (
                f"Selected B={benchmark:g} after evaluating {candidate_count} candidates on "
                f"{len(calibration_records)} calibration records. T1={thresholds['low_medium']:g} "
                "is the presumed-benign upper-quartile boundary, T2 equals B, "
                f"T3={thresholds['high_dangerous']:g} is the suspicious lower-quartile "
                f"boundary, and D={agreement_margin:g} is the strict empirical agreement "
                "tolerance. The resulting four levels "
                "are provisional because the labels are binary, the bounded sample is small, "
                "and url.vet completion limitations remain visible in this report."
            ),
        }
    )
    return policy, report


def _write_model(path: Path, model: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")


def run(
    *, refresh: bool = False, retry_unavailable: bool = False
) -> CalibrationReport:
    manifest = load_calibration_manifest()
    verification = verify_local_raw_files(manifest)
    mismatches = [source_id for source_id, result in verification.items() if result != "matched"]
    if mismatches:
        raise RuntimeError("Required raw calibration files did not match: " + ", ".join(mismatches))

    dataset, private_payloads = build_dataset(manifest)
    observations = collect_observations(
        dataset,
        private_payloads,
        refresh=refresh,
        retry_unavailable=retry_unavailable,
    )
    policy, report = build_report(manifest, dataset, observations)
    _write_model(CALIBRATION_DATASET_PATH, dataset)
    _write_model(CALIBRATION_OBSERVATIONS_PATH, observations)
    _write_model(DECISION_POLICY_PATH, policy)
    _write_model(REPORT_PATH, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore the ignored local score cache and rescan every selected URL.",
    )
    parser.add_argument(
        "--retry-unavailable",
        action="store_true",
        help="Rescan only locally cached records whose url.vet score was unavailable.",
    )
    args = parser.parse_args(argv)
    report = run(
        refresh=args.refresh,
        retry_unavailable=args.retry_unavailable,
    )
    policy = report.selected_policy
    print(
        f"Wrote provisional {policy.policy_version}: "
        f"T1={policy.thresholds.low_medium:g}, "
        f"T2/B={policy.suspicious_benchmark:g}, "
        f"T3={policy.thresholds.high_dangerous:g}, "
        f"D={policy.agreement_margin:g}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
