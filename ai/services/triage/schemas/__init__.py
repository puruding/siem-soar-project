"""Schemas for Triage service API."""

from ai.services.triage.schemas.requests import (
    ClassifyRequest,
    BatchClassifyRequest,
    DGARequest,
    BatchDGARequest,
    PriorityRequest,
    FeedbackRequest,
)
from ai.services.triage.schemas.responses import (
    ClassifyResponse,
    BatchClassifyResponse,
    DGAResponse,
    BatchDGAResponse,
    PriorityResponse,
    FeedbackResponse,
    TriageMetricsResponse,
    ModelInfoResponse,
)

__all__ = [
    # Requests
    "ClassifyRequest",
    "BatchClassifyRequest",
    "DGARequest",
    "BatchDGARequest",
    "PriorityRequest",
    "FeedbackRequest",
    # Responses
    "ClassifyResponse",
    "BatchClassifyResponse",
    "DGAResponse",
    "BatchDGAResponse",
    "PriorityResponse",
    "FeedbackResponse",
    "TriageMetricsResponse",
    "ModelInfoResponse",
]
