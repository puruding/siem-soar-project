"""Request schemas for Triage service."""

from typing import Any

from pydantic import Field

from ai.common.models import BaseRequest


class ClassifyRequest(BaseRequest):
    """Request to classify an alert."""

    alert: dict[str, Any] = Field(description="Alert data to classify")
    include_explanation: bool = Field(
        default=True,
        description="Include detailed explanation",
    )
    include_mitre: bool = Field(
        default=True,
        description="Include MITRE ATT&CK mapping",
    )
    use_cache: bool = Field(
        default=True,
        description="Use cached results if available",
    )


class BatchClassifyRequest(BaseRequest):
    """Request to classify multiple alerts."""

    alerts: list[dict[str, Any]] = Field(
        description="List of alerts to classify",
        min_length=1,
        max_length=1000,
    )
    include_explanation: bool = Field(default=False)
    include_mitre: bool = Field(default=True)


class DGARequest(BaseRequest):
    """Request to detect DGA domains."""

    domain: str = Field(
        description="Domain name to check",
        min_length=1,
        max_length=253,
    )
    include_features: bool = Field(
        default=True,
        description="Include domain features in response",
    )


class BatchDGARequest(BaseRequest):
    """Request to detect DGA for multiple domains."""

    domains: list[str] = Field(
        description="List of domains to check",
        min_length=1,
        max_length=10000,
    )
    include_features: bool = Field(default=False)


class PriorityRequest(BaseRequest):
    """Request to compute priority score."""

    alert: dict[str, Any] = Field(description="Alert data")
    severity: str | None = Field(
        default=None,
        description="Pre-classified severity (optional)",
    )
    category: str | None = Field(
        default=None,
        description="Pre-classified category (optional)",
    )
    context: dict[str, Any] | None = Field(
        default=None,
        description="Additional context (asset criticality, etc.)",
    )


class FeedbackRequest(BaseRequest):
    """Request to submit analyst feedback."""

    alert_id: str = Field(description="Alert ID")
    analyst_id: str = Field(description="Analyst ID who provided feedback")
    feedback_type: str = Field(
        description="Type of feedback: correction, confirmation, false_positive",
    )
    corrected_severity: str | None = Field(
        default=None,
        description="Corrected severity if changed",
    )
    corrected_category: str | None = Field(
        default=None,
        description="Corrected category if changed",
    )
    is_false_positive: bool | None = Field(
        default=None,
        description="Mark as false positive",
    )
    notes: str | None = Field(
        default=None,
        description="Analyst notes",
        max_length=2000,
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Additional tags",
    )
