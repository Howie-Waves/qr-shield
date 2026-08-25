"""Versioned contracts for Phase 3 calibration and decision policies."""

from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ROOT = Path(__file__).resolve().parents[2]
CALIBRATION_MANIFEST_PATH = (
    ROOT / "data" / "evaluation" / "phase3_calibration" / "source_manifest.json"
)
CALIBRATION_DATASET_PATH = (
    ROOT / "data" / "evaluation" / "phase3_calibration" / "calibration_dataset.json"
)
CALIBRATION_OBSERVATIONS_PATH = (
    ROOT / "data" / "evaluation" / "phase3_calibration" / "calibration_observations.json"
)
DECISION_POLICY_PATH = (
    ROOT / "data" / "evaluation" / "phase3_calibration" / "decision_policy.json"
)
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


class CalibrationSource(StrictModel):
    source_id: str = Field(pattern=r"^[a-z0-9_]+$")
    source_name: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    landing_page: str = Field(pattern=r"^https://")
    source_version: str = Field(min_length=1)
    label: Literal["presumed_benign", "suspicious"]
    label_definition: str = Field(min_length=1)
    retrieved_at: date
    retrieval_date_basis: str = Field(min_length=1)
    raw_path: str
    raw_format: Literal["csv"]
    has_header: bool
    columns: list[str] = Field(min_length=2)
    record_count: int = Field(gt=0)
    file_size_bytes: int = Field(gt=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    observed_properties: dict[str, str | int | bool]

    @field_validator("raw_path")
    @classmethod
    def raw_path_stays_in_ignored_calibration_root(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.parts[:3] != ("data", "raw", "phase3_calibration")
        ):
            raise ValueError("raw_path must stay under data/raw/phase3_calibration")
        return value


class CalibrationManifest(StrictModel):
    schema_version: Literal["1.0"]
    dataset_name: str = Field(min_length=1)
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    description: str = Field(min_length=1)
    raw_data_committed: Literal[False]
    contains_potentially_live_urls: Literal[True]
    sources: list[CalibrationSource] = Field(min_length=2)

    @model_validator(mode="after")
    def sources_are_unique_and_cover_both_labels(self) -> "CalibrationManifest":
        source_ids = [source.source_id for source in self.sources]
        raw_paths = [source.raw_path for source in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("calibration source IDs must be unique")
        if len(raw_paths) != len(set(raw_paths)):
            raise ValueError("calibration raw paths must be unique")
        if {source.label for source in self.sources} != {
            "presumed_benign",
            "suspicious",
        }:
            raise ValueError("manifest must contain both calibration labels")
        return self


class CalibrationRecord(StrictModel):
    sample_id: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_id: str = Field(pattern=r"^[a-z0-9_]+$")
    source_row_number: int = Field(gt=0)
    source_record_id: str = Field(min_length=1)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    label: Literal["presumed_benign", "suspicious"]
    split: Literal["calibration", "validation"]
    inclusion_reason: str = Field(min_length=1)


class CalibrationDataset(StrictModel):
    schema_version: Literal["1.0"]
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    source_manifest_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    random_seed: int = Field(ge=0)
    selection_method: str = Field(min_length=1)
    records: list[CalibrationRecord] = Field(min_length=4)

    @model_validator(mode="after")
    def records_are_unique_and_stratified(self) -> "CalibrationDataset":
        sample_ids = [record.sample_id for record in self.records]
        payload_hashes = [record.payload_sha256 for record in self.records]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("calibration sample IDs must be unique")
        if len(payload_hashes) != len(set(payload_hashes)):
            raise ValueError("calibration payload hashes must be unique")
        combinations = {(record.split, record.label) for record in self.records}
        required = {
            ("calibration", "presumed_benign"),
            ("calibration", "suspicious"),
            ("validation", "presumed_benign"),
            ("validation", "suspicious"),
        }
        if combinations != required:
            raise ValueError("each split must contain both calibration labels")
        return self


class CalibrationObservation(StrictModel):
    sample_id: str = Field(pattern=r"^[a-z0-9._-]+$")
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    label: Literal["presumed_benign", "suspicious"]
    split: Literal["calibration", "validation"]
    risk_score: float | None = Field(default=None, ge=0, le=100)
    judgement_score: float | None = Field(default=None, ge=0, le=100)
    verdict: str | None = None
    url_vet_status: Literal["complete", "partial", "unavailable"]
    url_vet_error_count: int = Field(ge=0)
    local_model_status: Literal["complete", "unavailable"]

    @model_validator(mode="after")
    def score_availability_matches_status(self) -> "CalibrationObservation":
        if (self.risk_score is None) != (self.url_vet_status == "unavailable"):
            raise ValueError("risk_score availability must match url_vet_status")
        if (self.judgement_score is None) != (self.local_model_status == "unavailable"):
            raise ValueError("judgement_score availability must match local_model_status")
        if self.url_vet_status == "complete" and self.url_vet_error_count != 0:
            raise ValueError("complete url.vet observations cannot contain errors")
        return self


class CalibrationObservations(StrictModel):
    schema_version: Literal["1.0"]
    observation_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    generated_at: datetime
    url_vet_version: str = Field(min_length=1)
    local_model_version: str = Field(min_length=1)
    records: list[CalibrationObservation] = Field(min_length=4)

    @model_validator(mode="after")
    def observations_are_unique_and_stratified(self) -> "CalibrationObservations":
        sample_ids = [record.sample_id for record in self.records]
        payload_hashes = [record.payload_sha256 for record in self.records]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("calibration observation sample IDs must be unique")
        if len(payload_hashes) != len(set(payload_hashes)):
            raise ValueError("calibration observation payload hashes must be unique")
        combinations = {(record.split, record.label) for record in self.records}
        required = {
            ("calibration", "presumed_benign"),
            ("calibration", "suspicious"),
            ("validation", "presumed_benign"),
            ("validation", "suspicious"),
        }
        if combinations != required:
            raise ValueError("each observation split must contain both labels")
        return self


class SuspicionThresholds(StrictModel):
    low_medium: float = Field(ge=0, le=100)
    medium_high: float = Field(ge=0, le=100)
    high_dangerous: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def thresholds_are_strictly_ordered(self) -> "SuspicionThresholds":
        if not self.low_medium < self.medium_high < self.high_dangerous:
            raise ValueError("suspicion thresholds must be strictly increasing")
        return self


class ConfusionMatrix(StrictModel):
    true_positive: int = Field(ge=0)
    true_negative: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)


class CalibrationMetrics(StrictModel):
    sample_count: int = Field(gt=0)
    presumed_benign_count: int = Field(ge=0)
    suspicious_count: int = Field(ge=0)
    completed_count: int = Field(ge=0)
    incomplete_count: int = Field(ge=0)
    confusion_matrix: ConfusionMatrix
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    false_negative_rate: float = Field(ge=0, le=1)
    false_positive_rate: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def counts_are_consistent(self) -> "CalibrationMetrics":
        if self.presumed_benign_count + self.suspicious_count != self.sample_count:
            raise ValueError("label counts must equal sample_count")
        if self.completed_count + self.incomplete_count != self.sample_count:
            raise ValueError("completion counts must equal sample_count")
        matrix_count = sum(
            (
                self.confusion_matrix.true_positive,
                self.confusion_matrix.true_negative,
                self.confusion_matrix.false_positive,
                self.confusion_matrix.false_negative,
            )
        )
        if matrix_count != self.completed_count:
            raise ValueError("confusion-matrix counts must equal completed_count")

        matrix = self.confusion_matrix
        expected = {
            "precision": _ratio(matrix.true_positive, matrix.true_positive + matrix.false_positive),
            "recall": _ratio(matrix.true_positive, matrix.true_positive + matrix.false_negative),
            "false_negative_rate": _ratio(
                matrix.false_negative,
                matrix.true_positive + matrix.false_negative,
            ),
            "false_positive_rate": _ratio(
                matrix.false_positive,
                matrix.true_negative + matrix.false_positive,
            ),
        }
        for field, expected_value in expected.items():
            if abs(getattr(self, field) - expected_value) > 0.0001:
                raise ValueError(f"{field} must match the confusion matrix")
        return self


class VerdictFloors(StrictModel):
    suspicious: Literal["High suspicion"]
    risky: Literal["Dangerous"]
    malicious: Literal["Dangerous"]


class DecisionPolicy(StrictModel):
    schema_version: Literal["1.0"]
    policy_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    status: Literal["provisional", "approved"]
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    generated_at: datetime
    risk_score_source: Literal["url.vet result.risk_score"]
    judgement_score_source: Literal["local LR phishing probability"]
    thresholds: SuspicionThresholds
    suspicious_benchmark: float = Field(ge=0, le=100)
    agreement_margin: float = Field(gt=0, le=100)
    verdict_floors: VerdictFloors
    selection_priority: Literal[
        "minimise_false_negatives_then_maximise_recall_then_minimise_false_positives"
    ]
    metrics: CalibrationMetrics
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def benchmark_is_inside_defined_suspicion_ranges(self) -> "DecisionPolicy":
        if not (
            self.thresholds.low_medium
            <= self.suspicious_benchmark
            <= self.thresholds.high_dangerous
        ):
            raise ValueError("suspicious benchmark must be between T1 and T3")
        return self


class ScoreDistribution(StrictModel):
    count: int = Field(gt=0)
    minimum: float = Field(ge=0, le=100)
    first_quartile: float = Field(ge=0, le=100)
    median: float = Field(ge=0, le=100)
    third_quartile: float = Field(ge=0, le=100)
    maximum: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def values_are_ordered(self) -> "ScoreDistribution":
        values = (
            self.minimum,
            self.first_quartile,
            self.median,
            self.third_quartile,
            self.maximum,
        )
        if tuple(sorted(values)) != values:
            raise ValueError("score distribution values must be ordered")
        return self


class ThresholdEvidence(StrictModel):
    combined_score_rule: Literal["max(risk_score, judgement_score)"]
    low_medium_method: str = Field(min_length=1)
    presumed_benign_distribution: ScoreDistribution
    presumed_benign_upper_quartile: float = Field(ge=0, le=100)
    medium_high_method: str = Field(min_length=1)
    high_dangerous_method: str = Field(min_length=1)
    suspicious_distribution: ScoreDistribution
    agreement_margin_method: str = Field(min_length=1)
    absolute_score_difference_distribution: ScoreDistribution
    adverse_verdicts: list[Literal["Suspicious", "Risky", "Malicious"]] = Field(
        min_length=3,
        max_length=3,
    )

    @model_validator(mode="after")
    def adverse_verdicts_are_complete(self) -> "ThresholdEvidence":
        if set(self.adverse_verdicts) != {"Suspicious", "Risky", "Malicious"}:
            raise ValueError("all supported adverse verdicts must be recorded")
        return self


class CalibrationReport(StrictModel):
    schema_version: Literal["1.0"]
    report_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    dataset_version: str = Field(pattern=r"^[a-z0-9._-]+$")
    generated_at: datetime
    candidate_policy_count: int = Field(gt=0)
    source_hashes: dict[str, str]
    analysis_versions: dict[Literal["url_vet", "local_judgement_model"], str]
    selected_policy: DecisionPolicy
    validation_metrics: CalibrationMetrics
    observation_count: int = Field(gt=0)
    score_pair_count: int = Field(ge=0)
    url_vet_status_counts: dict[Literal["complete", "partial", "unavailable"], int]
    verdict_counts: dict[str, int]
    threshold_evidence: ThresholdEvidence
    methodology: list[str] = Field(min_length=1)
    justification: str = Field(min_length=1)

    @field_validator("source_hashes")
    @classmethod
    def source_hashes_are_sha256(cls, value: dict[str, str]) -> dict[str, str]:
        if not value:
            raise ValueError("at least one source hash is required")
        for digest in value.values():
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError("source hashes must be lowercase SHA-256 values")
        return value

    @model_validator(mode="after")
    def report_and_policy_use_same_dataset(self) -> "CalibrationReport":
        if self.dataset_version != self.selected_policy.dataset_version:
            raise ValueError("report and selected policy must use the same dataset")
        if sum(self.url_vet_status_counts.values()) != self.observation_count:
            raise ValueError("url.vet status counts must equal observation_count")
        if set(self.url_vet_status_counts) != {"complete", "partial", "unavailable"}:
            raise ValueError("all url.vet status counts must be recorded")
        if any(count < 0 for count in self.url_vet_status_counts.values()):
            raise ValueError("url.vet status counts cannot be negative")
        if any(not verdict or count < 0 for verdict, count in self.verdict_counts.items()):
            raise ValueError("verdict counts must have names and non-negative values")
        expected_score_pairs = (
            self.selected_policy.metrics.completed_count
            + self.validation_metrics.completed_count
        )
        if self.score_pair_count != expected_score_pairs:
            raise ValueError("score_pair_count must match split metrics")
        return self


def load_calibration_manifest(
    path: Path = CALIBRATION_MANIFEST_PATH,
) -> CalibrationManifest:
    """Load and validate the committed source manifest."""
    return CalibrationManifest.model_validate_json(path.read_text(encoding="utf-8"))


def load_calibration_dataset(
    path: Path = CALIBRATION_DATASET_PATH,
) -> CalibrationDataset:
    """Load and validate the redacted sampled calibration dataset."""
    return CalibrationDataset.model_validate_json(path.read_text(encoding="utf-8"))


def load_calibration_observations(
    path: Path = CALIBRATION_OBSERVATIONS_PATH,
) -> CalibrationObservations:
    """Load score evidence without exposing the sampled URL payloads."""
    return CalibrationObservations.model_validate_json(path.read_text(encoding="utf-8"))


def load_decision_policy(path: Path = DECISION_POLICY_PATH) -> DecisionPolicy:
    """Load the selected versioned decision policy."""
    return DecisionPolicy.model_validate_json(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_local_raw_files(manifest: CalibrationManifest) -> dict[str, str]:
    """Verify optional ignored raw inputs without requiring them in CI."""
    results: dict[str, str] = {}
    for source in manifest.sources:
        path = ROOT / PurePosixPath(source.raw_path)
        if not path.is_file():
            results[source.source_id] = "not_available"
        elif path.stat().st_size != source.file_size_bytes:
            results[source.source_id] = "mismatch"
        else:
            results[source.source_id] = (
                "matched" if sha256_file(path) == source.sha256 else "mismatch"
            )
    return results
