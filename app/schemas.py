"""Response schemas for E1-US1 QR image decoding."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str


class ImageInfo(BaseModel):
    width: int
    height: int


class RiskAnalysis(BaseModel):
    # `score` remains for the existing client contract. The explicit fields
    # below prevent the two independent sources from being conflated.
    score: float
    level: str
    reasons: list[str]
    model_name: str
    model_version: str
    risk_score: float | None = None
    trust_score: float | None = None
    verdict: str | None = None
    judgement_score: float | None = None
    judgement_reasons: list[str] = Field(default_factory=list)
    judgement_model_name: str | None = None
    judgement_model_version: str | None = None
    url_vet_partial: bool = False


class RiskDecision(BaseModel):
    policy_version: str | None = None
    policy_status: Literal["provisional", "approved"] | None = None
    benchmark: float | None = None
    agreement_margin: float | None = None
    thresholds: dict[str, float] | None = None
    suspicion_level: Literal[
        "Low suspicion",
        "Medium suspicion",
        "High suspicion",
        "Dangerous",
        "Not applicable",
    ] | None = None
    conclusion: Literal[
        "Not suspicious",
        "Partially assessed",
        "Partially suspicious",
        "Suspicious",
        "Incomplete",
        "Not applicable",
    ]
    confidence_level: Literal[
        "High", "Medium", "Low", "Unavailable", "Not applicable"
    ]
    confidence_reason: str
    decision_reasons: list[str] = Field(default_factory=list)
    risk_score_level: Literal[
        "Low suspicion", "Medium suspicion", "High suspicion", "Dangerous"
    ] | None = None
    judgement_score_level: Literal[
        "Low suspicion", "Medium suspicion", "High suspicion", "Dangerous"
    ] | None = None
    risk_vote_suspicious: bool | None = None
    judgement_vote_suspicious: bool | None = None
    adverse_verdict: str | None = None


class ReviewCaseRequest(BaseModel):
    payload: str
    hostname: str | None = None
    assessment_outcome: str
    model_version: str | None = None
    reason_codes: list[str] = []
    consent: bool = False


class ReviewCaseResponse(BaseModel):
    case_id: str


class AnalyzeResponse(BaseModel):
    filename: str
    decoded_text: str
    content_type: str
    hostname: str | None
    image: ImageInfo
    block_inspection: dict[str, Any]
    payment: dict[str, Any]
    analysis: RiskAnalysis | None
    decision: RiskDecision
    analysis_status: str
    failed_check_ids: list[str]
    assessment_outcome: str
    checks: list[dict[str, Any]]
    source_versions: dict[str, str]
    principal_signals: list[str]
    message: str
