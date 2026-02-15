"""DGA Detection API routes."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from services.ml_gateway.models.loader import ModelLoader, ModelType


router = APIRouter()


# Request/Response models
class DGAPredictRequest(BaseModel):
    """Request for DGA prediction."""
    domain: str = Field(..., description="Domain name to analyze", min_length=1, max_length=253)


class DGAPredictResponse(BaseModel):
    """Response for DGA prediction."""
    domain: str = Field(description="Input domain")
    is_dga: bool = Field(description="Whether domain is DGA-generated")
    dga_probability: float = Field(ge=0.0, le=1.0, description="Probability of being DGA")
    family: str | None = Field(default=None, description="Predicted DGA family if detected")
    confidence: float = Field(ge=0.0, le=1.0, description="Prediction confidence")
    processing_time_ms: float = Field(description="Processing time in milliseconds")


class DGABatchRequest(BaseModel):
    """Request for batch DGA prediction."""
    domains: list[str] = Field(..., description="List of domains to analyze", min_length=1, max_length=1000)


class DGABatchResponse(BaseModel):
    """Response for batch DGA prediction."""
    results: list[DGAPredictResponse] = Field(description="Prediction results")
    total_domains: int = Field(description="Total domains processed")
    dga_count: int = Field(description="Number of DGA domains detected")
    processing_time_ms: float = Field(description="Total processing time")


class DGAStatsResponse(BaseModel):
    """Response for DGA detection statistics."""
    total_predictions: int
    dga_detected: int
    detection_rate: float
    avg_latency_ms: float
    model_version: str | None


# Dependency to get model loader
def get_model_loader():
    """Get model loader dependency."""
    from services.ml_gateway.main import get_model_loader
    return get_model_loader()


@router.post("/predict", response_model=DGAPredictResponse)
async def predict_dga(
    request: DGAPredictRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> DGAPredictResponse:
    """Predict if a domain is DGA-generated.

    Args:
        request: Domain to analyze
        loader: Model loader instance

    Returns:
        DGA prediction result
    """
    start_time = time.time()

    try:
        model = loader.get_model(ModelType.DGA)
        result = model.predict(request.domain)

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.DGA, processing_time)

        return DGAPredictResponse(
            domain=request.domain,
            is_dga=result.is_dga,
            dga_probability=result.probability,
            family=result.family if result.is_dga else None,
            confidence=result.confidence,
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


@router.post("/predict/batch", response_model=DGABatchResponse)
async def predict_dga_batch(
    request: DGABatchRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> DGABatchResponse:
    """Predict DGA for multiple domains.

    Args:
        request: List of domains to analyze
        loader: Model loader instance

    Returns:
        Batch prediction results
    """
    start_time = time.time()

    try:
        model = loader.get_model(ModelType.DGA)
        batch_result = model.predict_batch(request.domains)

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.DGA, processing_time / len(request.domains))

        results = []
        dga_count = 0

        for domain, classification in zip(request.domains, batch_result.classifications):
            is_dga = classification.is_dga
            if is_dga:
                dga_count += 1

            results.append(DGAPredictResponse(
                domain=domain,
                is_dga=is_dga,
                dga_probability=classification.probability,
                family=classification.family if is_dga else None,
                confidence=classification.confidence,
                processing_time_ms=processing_time / len(request.domains),
            ))

        return DGABatchResponse(
            results=results,
            total_domains=len(request.domains),
            dga_count=dga_count,
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {e}")


@router.get("/stats", response_model=DGAStatsResponse)
async def get_dga_stats(
    loader: ModelLoader = Depends(get_model_loader),
) -> DGAStatsResponse:
    """Get DGA detection statistics.

    Returns:
        Detection statistics
    """
    info = loader.get_model_info(ModelType.DGA)

    return DGAStatsResponse(
        total_predictions=info.get("inference_count", 0),
        dga_detected=0,  # Would need to track this
        detection_rate=0.0,
        avg_latency_ms=info.get("avg_latency_ms", 0.0),
        model_version=info.get("config", {}).get("model_version"),
    )


@router.get("/families")
async def get_dga_families() -> dict[str, Any]:
    """Get list of detectable DGA families.

    Returns:
        List of DGA families with descriptions
    """
    from models.dga.config import DGAFamily

    families = []
    for family in DGAFamily:
        families.append({
            "name": family.value,
            "description": f"DGA family: {family.value}",
        })

    return {"families": families, "total": len(families)}


@router.post("/validate")
async def validate_domain(
    request: DGAPredictRequest,
) -> dict[str, Any]:
    """Validate domain format without DGA check.

    Args:
        request: Domain to validate

    Returns:
        Validation result
    """
    import re

    domain = request.domain.lower()

    # Basic validation
    is_valid = True
    errors = []

    # Check length
    if len(domain) > 253:
        is_valid = False
        errors.append("Domain exceeds maximum length of 253 characters")

    # Check label lengths
    labels = domain.split(".")
    for label in labels:
        if len(label) > 63:
            is_valid = False
            errors.append(f"Label '{label}' exceeds 63 characters")
        if not label:
            is_valid = False
            errors.append("Empty label found")

    # Check characters
    if not re.match(r"^[a-z0-9.-]+$", domain):
        is_valid = False
        errors.append("Domain contains invalid characters")

    # Check for valid TLD
    if len(labels) < 2:
        is_valid = False
        errors.append("Domain must have at least two labels")

    return {
        "domain": domain,
        "is_valid": is_valid,
        "errors": errors,
        "labels": labels,
    }
