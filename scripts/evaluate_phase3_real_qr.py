"""Evaluate reviewed suspicious-source QR reproductions without storing live URLs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal
from urllib.parse import urlsplit

import cv2
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.schemas import RiskDecision
from app.services.decision_policy import (
    CalibrationObservation,
    CalibrationObservations,
    CalibrationRecord,
    load_calibration_dataset,
    load_calibration_manifest,
    load_calibration_observations,
    sha256_file,
)
from app.services.model_service import predict_url_risk
from app.services.qr_decoder import QRDecodeError, decode_qr_image
from app.services.risk_decision import decide_url_risk


EVALUATION_ROOT = ROOT / "data" / "evaluation" / "phase3_real_qr"
MANIFEST_PATH = EVALUATION_ROOT / "manifest.json"
REPORT_PATH = ROOT / "reports" / "phase3_real_qr_evaluation.json"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceReference(StrictModel):
    source_id: Literal["phishtank_online_valid"]
    source_name: str = Field(min_length=1)
    provider: Literal["PhishTank"]
    landing_page: str = Field(pattern=r"^https://phishtank\.org/")
    source_manifest_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    source_snapshot_retrieved_at: date
    raw_path: str
    label_definition: str = Field(min_length=1)

    @field_validator("raw_path")
    @classmethod
    def raw_path_is_the_ignored_phishtank_snapshot(cls, value: str) -> str:
        path = PurePosixPath(value)
        expected = PurePosixPath(
            "data/raw/phase3_calibration/suspicious/phishtank_online_valid.csv"
        )
        if path != expected:
            raise ValueError("raw_path must reference the locked PhishTank snapshot")
        return value


class SafeFixture(StrictModel):
    payload: str = Field(min_length=1)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    generation: Literal["in_memory"]

    @model_validator(mode="after")
    def payload_is_inert_and_hash_locked(self) -> "SafeFixture":
        parsed = urlsplit(self.payload)
        hostname = (parsed.hostname or "").casefold()
        if parsed.scheme != "https" or not hostname.endswith(".invalid"):
            raise ValueError("safe fixture payloads must use HTTPS and the .invalid TLD")
        if _sha256_text(self.payload) != self.payload_sha256:
            raise ValueError("fixture payload hash does not match its payload")
        return self


class ReadyRecord(StrictModel):
    status: Literal["ready"]
    sample_id: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_category: Literal["public_threat_intelligence"]
    calibration_sample_id: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_record_id: str = Field(pattern=r"^[0-9]+$")
    source_row_number: int = Field(gt=1)
    source_submission_at: datetime
    source_verified_at: datetime
    source_verified: Literal[True]
    source_online_at_snapshot: Literal[True]
    target_category: str = Field(min_length=1)
    expected_label: Literal["suspicious"]
    expected_payload_behaviour: str = Field(min_length=1)
    acquired_at: date
    original_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    original_incident_qr_available: Literal[False]
    original_payload_committed: Literal[False]
    fixture_kind: Literal["safe_reproduction"]
    fixture_is_malicious: Literal[False]
    fixture: SafeFixture
    reviewer: str = Field(min_length=1)
    reviewed_at: date
    review_scope: str = Field(min_length=1)
    redistribution_permission: Literal["safe_reproduction_payload_only"]

    @model_validator(mode="after")
    def safe_fixture_is_not_the_original_payload(self) -> "ReadyRecord":
        if self.original_payload_sha256 == self.fixture.payload_sha256:
            raise ValueError("safe fixture must not reproduce the original source payload")
        return self


class PendingRecord(StrictModel):
    status: Literal["pending"]
    sample_id: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_category: Literal["supervisor_provided_incident"]
    expected_label: Literal["suspicious"]
    expected_payload_behaviour: str = Field(min_length=1)
    source_received: Literal[False]
    pending_reason: str = Field(min_length=1)
    review_owner: str = Field(min_length=1)
    redistribution_permission: Literal["undetermined"]


EvaluationRecord = Annotated[ReadyRecord | PendingRecord, Field(discriminator="status")]


class RealQrManifest(StrictModel):
    schema_version: Literal["1.0"]
    dataset_name: str = Field(min_length=1)
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    description: str = Field(min_length=1)
    selection_method: str = Field(min_length=1)
    original_payloads_committed: Literal[False]
    contains_potentially_live_payloads: Literal[False]
    source: SourceReference
    safety_rules: list[str] = Field(min_length=3)
    limitations: list[str] = Field(min_length=3)
    records: list[EvaluationRecord] = Field(min_length=2)

    @model_validator(mode="after")
    def records_are_unique_and_include_pending_evidence(self) -> "RealQrManifest":
        sample_ids = [record.sample_id for record in self.records]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("evaluation sample IDs must be unique")
        ready = [record for record in self.records if isinstance(record, ReadyRecord)]
        pending = [record for record in self.records if isinstance(record, PendingRecord)]
        if not ready or not pending:
            raise ValueError("manifest must contain ready and pending evidence")
        source_ids = [record.source_record_id for record in ready]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("ready source record IDs must be unique")
        return self


class EvaluationCaseResult(StrictModel):
    sample_id: str
    source_record_id: str
    target_category: str
    expected_label: Literal["suspicious"]
    evidence_subject: Literal["original_source_payload"]
    original_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    provenance_status: Literal["matched"]
    safe_reproduction_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    safe_reproduction_decode_status: Literal["passed", "failed"]
    source_qr_decode_status: Literal["passed", "failed", "not_available"]
    local_score_reproduced: bool | None
    risk_score: float = Field(ge=0, le=100)
    judgement_score: float = Field(ge=0, le=100)
    verdict: str
    url_vet_observation_status: Literal["complete"]
    decision: RiskDecision
    forbidden_low_outcome: bool
    detection_pass: bool
    passed: bool


class EffectivenessMetrics(StrictModel):
    suspicious_case_count: int = Field(gt=0)
    safe_reproduction_decode_success_count: int = Field(ge=0)
    source_qr_decode_success_count: int = Field(ge=0)
    detected_suspicious_count: int = Field(ge=0)
    low_suspicion_count: int = Field(ge=0)
    not_suspicious_count: int = Field(ge=0)
    passed_case_count: int = Field(ge=0)
    safety_pass_rate: float = Field(ge=0, le=1)
    detection_rate: float = Field(ge=0, le=1)


class RealQrEvaluationReport(StrictModel):
    schema_version: Literal["1.0"]
    report_version: Literal["phase3-real-qr-report-v1"]
    dataset_version: str
    generated_at: datetime
    source_snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    source_evidence_generated_at: datetime
    analysis_versions: dict[Literal["url_vet", "local_judgement_model"], str]
    decision_policy_version: str
    selection_method: str
    source_audit_mode: Literal[
        "locked_local_snapshot", "not_available", "partial"
    ]
    ready_case_count: int = Field(gt=0)
    pending_case_count: int = Field(gt=0)
    metrics: EffectivenessMetrics
    case_results: list[EvaluationCaseResult] = Field(min_length=1)
    pending_evidence: list[PendingRecord] = Field(min_length=1)
    methodology: list[str] = Field(min_length=3)
    limitations: list[str] = Field(min_length=3)

    @model_validator(mode="after")
    def counts_match_case_results(self) -> "RealQrEvaluationReport":
        metrics = self.metrics
        if self.ready_case_count != len(self.case_results):
            raise ValueError("ready_case_count must match case_results")
        if self.pending_case_count != len(self.pending_evidence):
            raise ValueError("pending_case_count must match pending_evidence")
        if metrics.suspicious_case_count != self.ready_case_count:
            raise ValueError("all ready cases must be counted as suspicious")
        expected_counts = {
            "safe_reproduction_decode_success_count": sum(
                case.safe_reproduction_decode_status == "passed"
                for case in self.case_results
            ),
            "source_qr_decode_success_count": sum(
                case.source_qr_decode_status == "passed" for case in self.case_results
            ),
            "detected_suspicious_count": sum(
                case.detection_pass for case in self.case_results
            ),
            "low_suspicion_count": sum(
                case.decision.suspicion_level == "Low suspicion"
                for case in self.case_results
            ),
            "not_suspicious_count": sum(
                case.decision.conclusion == "Not suspicious"
                for case in self.case_results
            ),
            "passed_case_count": sum(case.passed for case in self.case_results),
        }
        for field, expected in expected_counts.items():
            if getattr(metrics, field) != expected:
                raise ValueError(f"{field} must match case_results")
        expected_safety_rate = 1.0 - (
            sum(case.forbidden_low_outcome for case in self.case_results)
            / self.ready_case_count
        )
        expected_detection_rate = (
            metrics.detected_suspicious_count / self.ready_case_count
        )
        if abs(metrics.safety_pass_rate - expected_safety_rate) > 0.0001:
            raise ValueError("safety_pass_rate must match case_results")
        if abs(metrics.detection_rate - expected_detection_rate) > 0.0001:
            raise ValueError("detection_rate must match case_results")
        return self


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _encode_qr(payload: str) -> bytes:
    image = cv2.QRCodeEncoder_create().encode(payload)
    image = cv2.resize(image, None, fx=10, fy=10, interpolation=cv2.INTER_NEAREST)
    image = cv2.copyMakeBorder(
        image,
        40,
        40,
        40,
        40,
        cv2.BORDER_CONSTANT,
        value=255,
    )
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError("OpenCV could not encode a Phase 3 QR fixture")
    return encoded.tobytes()


def load_manifest(path: Path = MANIFEST_PATH) -> RealQrManifest:
    return RealQrManifest.model_validate_json(path.read_text(encoding="utf-8"))


def _ready_records(manifest: RealQrManifest) -> list[ReadyRecord]:
    return [record for record in manifest.records if isinstance(record, ReadyRecord)]


def _pending_records(manifest: RealQrManifest) -> list[PendingRecord]:
    return [record for record in manifest.records if isinstance(record, PendingRecord)]


def _cross_checked_evidence(
    manifest: RealQrManifest,
) -> tuple[
    dict[str, tuple[CalibrationRecord, CalibrationObservation]],
    CalibrationObservations,
]:
    source_manifest = load_calibration_manifest()
    source = next(
        (item for item in source_manifest.sources if item.source_id == manifest.source.source_id),
        None,
    )
    if source is None:
        raise RuntimeError("The referenced PhishTank source is not in the source manifest")
    if source_manifest.dataset_version != manifest.source.source_manifest_version:
        raise RuntimeError("Source manifest version does not match the evaluation manifest")
    if source.sha256 != manifest.source.source_snapshot_sha256:
        raise RuntimeError("Source snapshot hash does not match the evaluation manifest")
    if source.retrieved_at != manifest.source.source_snapshot_retrieved_at:
        raise RuntimeError("Source retrieval date does not match the evaluation manifest")
    if source.raw_path != manifest.source.raw_path:
        raise RuntimeError("Source raw path does not match the evaluation manifest")

    dataset = load_calibration_dataset()
    observations = load_calibration_observations()
    dataset_by_id = {record.sample_id: record for record in dataset.records}
    observations_by_id = {record.sample_id: record for record in observations.records}
    eligible_ids = {
        record.sample_id
        for record in dataset.records
        if record.source_id == source.source_id
        and record.split == "validation"
        and record.label == "suspicious"
        and observations_by_id[record.sample_id].url_vet_status == "complete"
    }
    selected_ids = {record.calibration_sample_id for record in _ready_records(manifest)}
    if selected_ids != eligible_ids:
        raise RuntimeError(
            "Ready cases must be every complete suspicious PhishTank validation observation"
        )

    linked: dict[str, tuple[CalibrationRecord, CalibrationObservation]] = {}
    for record in _ready_records(manifest):
        dataset_record = dataset_by_id.get(record.calibration_sample_id)
        observation = observations_by_id.get(record.calibration_sample_id)
        if dataset_record is None or observation is None:
            raise RuntimeError(f"Missing frozen evidence for {record.sample_id}")
        expected = (
            dataset_record.source_id == source.source_id
            and dataset_record.source_record_id == record.source_record_id
            and dataset_record.source_row_number == record.source_row_number
            and dataset_record.payload_sha256 == record.original_payload_sha256
            and dataset_record.label == "suspicious"
            and dataset_record.split == "validation"
            and observation.payload_sha256 == record.original_payload_sha256
            and observation.label == "suspicious"
            and observation.split == "validation"
            and observation.url_vet_status == "complete"
            and observation.risk_score is not None
            and observation.judgement_score is not None
        )
        if not expected:
            raise RuntimeError(f"Frozen evidence mismatch for {record.sample_id}")
        linked[record.sample_id] = (dataset_record, observation)
    return linked, observations


def _decode_safe_reproduction(record: ReadyRecord) -> str:
    try:
        decoded = decode_qr_image(
            _encode_qr(record.fixture.payload),
            "in-memory-safe-reproduction.png",
        )
    except (QRDecodeError, cv2.error, ValueError):
        return "failed"
    return (
        "passed"
        if decoded["decoded_text"] == record.fixture.payload
        and decoded["content_type"] == "url"
        else "failed"
    )


def _audit_original_sources(
    manifest: RealQrManifest,
    linked: dict[str, tuple[CalibrationRecord, CalibrationObservation]],
    local_model_version: str,
    *,
    require_raw: bool,
) -> dict[str, tuple[str, bool | None]]:
    source_path = ROOT / PurePosixPath(manifest.source.raw_path)
    if not source_path.is_file():
        if require_raw:
            raise RuntimeError(
                "The ignored PhishTank source snapshot is required for the original-QR audit"
            )
        return {record.sample_id: ("not_available", None) for record in _ready_records(manifest)}
    if sha256_file(source_path) != manifest.source.source_snapshot_sha256:
        raise RuntimeError("The local PhishTank source snapshot hash does not match")

    by_source_id = {record.source_record_id: record for record in _ready_records(manifest)}
    results: dict[str, tuple[str, bool | None]] = {}
    with source_path.open("r", encoding="utf-8-sig", newline="") as file:
        for row_number, row in enumerate(csv.DictReader(file), start=2):
            record = by_source_id.get(str(row.get("phish_id") or ""))
            if record is None:
                continue
            payload = str(row.get("url") or "")
            metadata_matches = (
                row_number == record.source_row_number
                and str(row.get("verified") or "").casefold() == "yes"
                and str(row.get("online") or "").casefold() == "yes"
                and str(row.get("target") or "") == record.target_category
                and _sha256_text(payload) == record.original_payload_sha256
                and datetime.fromisoformat(str(row.get("submission_time")))
                == record.source_submission_at
                and datetime.fromisoformat(str(row.get("verification_time")))
                == record.source_verified_at
            )
            if not metadata_matches:
                raise RuntimeError(f"Raw source metadata mismatch for {record.sample_id}")

            try:
                qr_bytes = _encode_qr(payload)
                decoded = decode_qr_image(qr_bytes, "source-audit.png")
                qr_matches = (
                    _sha256_text(decoded["decoded_text"]) == record.original_payload_sha256
                    and decoded["content_type"] == "url"
                )
            except (QRDecodeError, cv2.error, ValueError):
                qr_matches = False

            observation = linked[record.sample_id][1]
            local_result = predict_url_risk(payload)
            local_matches = (
                local_result["model_version"]
                == local_model_version
                and abs(float(local_result["score"]) - float(observation.judgement_score))
                <= 0.001
            )
            results[record.sample_id] = (
                "passed" if qr_matches else "failed",
                local_matches,
            )

    missing = set(by_source_id) - {
        record.source_record_id
        for record in _ready_records(manifest)
        if record.sample_id in results
    }
    if missing:
        raise RuntimeError("Selected PhishTank records are missing from the locked source")
    return results


def evaluate(*, require_raw: bool = False) -> RealQrEvaluationReport:
    manifest = load_manifest()
    linked, observations = _cross_checked_evidence(manifest)
    audits = _audit_original_sources(
        manifest,
        linked,
        observations.local_model_version,
        require_raw=require_raw,
    )
    cases: list[EvaluationCaseResult] = []

    for record in _ready_records(manifest):
        observation = linked[record.sample_id][1]
        decision = RiskDecision.model_validate(
            decide_url_risk(
                observation.risk_score,
                observation.judgement_score,
                observation.verdict,
            )
        )
        reproduction_status = _decode_safe_reproduction(record)
        source_qr_status, local_score_reproduced = audits[record.sample_id]
        forbidden_low = (
            decision.suspicion_level == "Low suspicion"
            or decision.conclusion == "Not suspicious"
        )
        detection_pass = (
            decision.suspicion_level in {"High suspicion", "Dangerous"}
            and decision.conclusion in {"Partially suspicious", "Suspicious"}
        )
        source_audit_pass = source_qr_status != "failed" and local_score_reproduced is not False
        cases.append(
            EvaluationCaseResult(
                sample_id=record.sample_id,
                source_record_id=record.source_record_id,
                target_category=record.target_category,
                expected_label=record.expected_label,
                evidence_subject="original_source_payload",
                original_payload_sha256=record.original_payload_sha256,
                provenance_status="matched",
                safe_reproduction_payload_sha256=record.fixture.payload_sha256,
                safe_reproduction_decode_status=reproduction_status,
                source_qr_decode_status=source_qr_status,
                local_score_reproduced=local_score_reproduced,
                risk_score=float(observation.risk_score),
                judgement_score=float(observation.judgement_score),
                verdict=str(observation.verdict or "Not available"),
                url_vet_observation_status="complete",
                decision=decision,
                forbidden_low_outcome=forbidden_low,
                detection_pass=detection_pass,
                passed=(
                    reproduction_status == "passed"
                    and source_audit_pass
                    and not forbidden_low
                    and detection_pass
                ),
            )
        )

    ready_count = len(cases)
    source_statuses = {case.source_qr_decode_status for case in cases}
    if source_statuses == {"passed"}:
        audit_mode = "locked_local_snapshot"
    elif source_statuses == {"not_available"}:
        audit_mode = "not_available"
    else:
        audit_mode = "partial"
    metrics = EffectivenessMetrics(
        suspicious_case_count=ready_count,
        safe_reproduction_decode_success_count=sum(
            case.safe_reproduction_decode_status == "passed" for case in cases
        ),
        source_qr_decode_success_count=sum(
            case.source_qr_decode_status == "passed" for case in cases
        ),
        detected_suspicious_count=sum(case.detection_pass for case in cases),
        low_suspicion_count=sum(
            case.decision.suspicion_level == "Low suspicion" for case in cases
        ),
        not_suspicious_count=sum(
            case.decision.conclusion == "Not suspicious" for case in cases
        ),
        passed_case_count=sum(case.passed for case in cases),
        safety_pass_rate=round(
            1.0 - (sum(case.forbidden_low_outcome for case in cases) / ready_count),
            6,
        ),
        detection_rate=round(sum(case.detection_pass for case in cases) / ready_count, 6),
    )
    extra_limitations = []
    if audit_mode != "locked_local_snapshot":
        extra_limitations.append(
            "The ignored raw PhishTank snapshot was unavailable, so original-payload QR decoding and local-score reproduction were not re-audited in this run."
        )
    return RealQrEvaluationReport(
        schema_version="1.0",
        report_version="phase3-real-qr-report-v1",
        dataset_version=manifest.dataset_version,
        generated_at=datetime.now(timezone.utc),
        source_snapshot_sha256=manifest.source.source_snapshot_sha256,
        source_evidence_generated_at=observations.generated_at,
        analysis_versions={
            "url_vet": observations.url_vet_version,
            "local_judgement_model": observations.local_model_version,
        },
        decision_policy_version=cases[0].decision.policy_version or "unavailable",
        selection_method=manifest.selection_method,
        source_audit_mode=audit_mode,
        ready_case_count=ready_count,
        pending_case_count=len(_pending_records(manifest)),
        metrics=metrics,
        case_results=cases,
        pending_evidence=_pending_records(manifest),
        methodology=[
            "Select all complete PhishTank suspicious records in the previously frozen validation split without consulting their scores or final decisions.",
            "Verify the redacted manifest against the locked source manifest, sampled-record hashes, and frozen url.vet/local-model observations.",
            "Generate each redacted .invalid safe reproduction in memory and decode it; when the ignored raw snapshot is available, render each original source URL to an in-memory QR and compare only its SHA-256 after decoding.",
            "Apply the committed Phase 3 decision policy to the original source payload's frozen scores and verdict, never to invented fixture scores.",
            "Fail a suspicious case if it becomes Low suspicion or Not suspicious; separately require a High/Dangerous suspicious conclusion for detection_pass.",
        ],
        limitations=[*manifest.limitations, *extra_limitations],
    )


def _write_report(report: RealQrEvaluationReport) -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-raw",
        action="store_true",
        help="Evaluate in-memory safe reproductions when the ignored PhishTank snapshot is absent.",
    )
    args = parser.parse_args(argv)
    report = evaluate(require_raw=not args.allow_missing_raw)
    _write_report(report)
    print(
        f"Wrote {REPORT_PATH.relative_to(ROOT)}: "
        f"{report.metrics.passed_case_count}/{report.ready_case_count} ready cases passed."
    )
    if report.metrics.passed_case_count != report.ready_case_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
