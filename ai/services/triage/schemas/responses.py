"""Response schemas for Triage service."""

from typing import Any

from pydantic import Field

from ai.common.models import BaseModel


class ClassificationResult(BaseModel):
    """Alert classification result."""

    severity: str = Field(description="Severity level")
    severity_confidence: float = Field(ge=0, le=1, description="Severity confidence")
    category: str = Field(description="Alert category")
    category_confidence: float = Field(ge=0, le=1, description="Category confidence")
    mitre_tactics: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactics",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK techniques",
    )
    risk_score: float = Field(ge=0, le=100, description="Risk score 0-100")
    is_false_positive: bool = Field(default=False, description="FP prediction")
    fp_confidence: float = Field(default=0.0, ge=0, le=1)
    explanation: str = Field(default="", description="Classification explanation")


class ClassifyResponse(BaseModel):
    """Response for alert classification."""

    alert_id: str = Field(description="Alert ID")
    classification: ClassificationResult = Field(description="Classification result")
    priority_score: float = Field(ge=0, le=100, description="Priority score")
    priority_level: str = Field(description="Priority level: critical, high, medium, low")
    recommended_actions: list[str] = Field(
        default_factory=list,
        description="Recommended response actions",
    )
    processing_time_ms: float = Field(description="Processing time")
    is_cached: bool = Field(default=False, description="Result from cache")
    model_version: str = Field(default="v1.0.0", description="Model version")


class BatchClassifyResponse(BaseModel):
    """Response for batch alert classification."""

    results: list[ClassifyResponse] = Field(description="Classification results")
    total_count: int = Field(description="Total alerts processed")
    processed_count: int = Field(description="Successfully processed")
    failed_count: int = Field(default=0, description="Failed to process")
    total_processing_time_ms: float = Field(description="Total processing time")
    avg_processing_time_ms: float = Field(description="Average per-alert time")


class DGAResult(BaseModel):
    """DGA detection result."""

    domain: str = Field(description="Input domain")
    is_dga: bool = Field(description="Whether domain is DGA")
    confidence: float = Field(ge=0, le=1, description="DGA probability")
    family: str = Field(default="unknown", description="DGA family if known")
    family_confidence: float = Field(default=0.0, ge=0, le=1)
    risk_level: str = Field(description="Risk level")
    features: dict[str, float] = Field(
        default_factory=dict,
        description="Domain features",
    )
    explanation: str = Field(description="Detection explanation")


class DGAResponse(BaseModel):
    """Response for DGA detection."""

    result: DGAResult = Field(description="Detection result")
    processing_time_ms: float = Field(description="Processing time")
    is_cached: bool = Field(default=False)


class BatchDGAResponse(BaseModel):
    """Response for batch DGA detection."""

    results: list[DGAResult] = Field(description="Detection results")
    total_count: int = Field(description="Total domains")
    dga_count: int = Field(description="DGA domains detected")
    benign_count: int = Field(description="Benign domains")
    processing_time_ms: float = Field(description="Total processing time")
    avg_time_per_domain_ms: float = Field(description="Average time per domain")


class PriorityResult(BaseModel):
    """Priority scoring result."""

    final_score: float = Field(ge=0, le=100, description="Final priority score")
    priority_level: str = Field(description="Priority level")
    components: dict[str, float] = Field(
        default_factory=dict,
        description="Score component breakdown",
    )
    factors: list[str] = Field(
        default_factory=list,
        description="Key factors affecting priority",
    )


class PriorityResponse(BaseModel):
    """Response for priority computation."""

    alert_id: str = Field(description="Alert ID")
    priority: PriorityResult = Field(description="Priority result")
    processing_time_ms: float = Field(description="Processing time")


class FeedbackResponse(BaseModel):
    """Response for feedback submission."""

    status: str = Field(description="Submission status")
    feedback_id: str = Field(description="Feedback record ID")
    alert_id: str = Field(description="Alert ID")
    message: str = Field(default="Feedback recorded successfully")


class TriageMetricsResponse(BaseModel):
    """Service metrics response."""

    # Request metrics
    total_requests: int = Field(description="Total requests processed")
    requests_per_minute: float = Field(description="Request rate")

    # Latency metrics
    avg_latency_ms: float = Field(description="Average latency")
    p50_latency_ms: float = Field(description="P50 latency")
    p95_latency_ms: float = Field(description="P95 latency")
    p99_latency_ms: float = Field(description="P99 latency")

    # Classification metrics
    classification_accuracy: float = Field(description="Model accuracy")
    fp_detection_rate: float = Field(description="False positive detection rate")

    # Cache metrics
    cache_hit_rate: float = Field(description="Cache hit rate")
    cache_size: int = Field(description="Current cache size")

    # Model info
    model_version: str = Field(description="Current model version")
    model_loaded: bool = Field(description="Model loaded status")
    uptime_seconds: float = Field(description="Service uptime")


class ModelInfoResponse(BaseModel):
    """Model information response."""

    name: str = Field(description="Model name")
    version: str = Field(description="Model version")
    type: str = Field(description="Model type (classifier, dga, etc.)")
    status: str = Field(description="Model status")
    loaded_at: str = Field(description="Load timestamp")
    device: str = Field(description="Inference device")
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Model configuration",
    )
    metrics: dict[str, float] = Field(
        default_factory=dict,
        description="Model performance metrics",
    )
