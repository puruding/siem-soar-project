"""DGA detection routes."""

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Depends

from ai.common import get_logger
from ai.common.models import BaseResponse
from ai.services.triage.schemas import DGARequest, BatchDGARequest
from ai.services.triage.schemas.responses import (
    DGAResponse,
    BatchDGAResponse,
    DGAResult,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["dga"])

# Service state - injected at app startup
_dga_detector = None
_cache = None
_metrics_collector = None


def get_dga_detector():
    """Get DGA detector dependency."""
    if _dga_detector is None:
        raise HTTPException(status_code=503, detail="DGA detector not initialized")
    return _dga_detector


@router.post("/dga/detect", response_model=BaseResponse[DGAResponse])
async def detect_dga(
    request: DGARequest,
    detector=Depends(get_dga_detector),
) -> BaseResponse[DGAResponse]:
    """Detect if a domain is DGA-generated.

    Args:
        request: DGA detection request with domain

    Returns:
        DGA detection result with confidence and family
    """
    start_time = time.perf_counter()

    try:
        # Run detection
        raw_result = await detector.detect(request.domain)

        # Build response
        result = DGAResult(
            domain=raw_result.domain,
            is_dga=raw_result.is_dga,
            confidence=raw_result.confidence,
            family=raw_result.family,
            family_confidence=raw_result.family_confidence,
            risk_level=raw_result.risk_level,
            features=raw_result.features if request.include_features else {},
            explanation=raw_result.explanation,
        )

        processing_time = (time.perf_counter() - start_time) * 1000

        response = DGAResponse(
            result=result,
            processing_time_ms=processing_time,
            is_cached=False,  # Cache status from detector
        )

        # Record metrics
        if _metrics_collector:
            _metrics_collector.record_dga_detection(
                is_dga=result.is_dga,
                family=result.family,
                confidence=result.confidence,
                processing_time_ms=processing_time,
            )

        logger.debug(
            "dga_detected",
            domain=request.domain,
            is_dga=result.is_dga,
            confidence=result.confidence,
        )

        return BaseResponse.success_response(request.request_id, response)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("dga_detection_failed", domain=request.domain, error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@router.post("/dga/detect/batch", response_model=BaseResponse[BatchDGAResponse])
async def batch_detect_dga(
    request: BatchDGARequest,
    detector=Depends(get_dga_detector),
) -> BaseResponse[BatchDGAResponse]:
    """Detect DGA for multiple domains in batch.

    Optimized for high-throughput scenarios. Can process up to 10,000 domains
    per request with target latency < 10ms per domain.

    Args:
        request: Batch DGA detection request

    Returns:
        Batch detection results with statistics
    """
    start_time = time.perf_counter()

    try:
        # Run batch detection
        raw_batch_result = await detector.batch_detect(request.domains)

        # Build response
        results = []
        for raw_result in raw_batch_result.results:
            results.append(DGAResult(
                domain=raw_result.domain,
                is_dga=raw_result.is_dga,
                confidence=raw_result.confidence,
                family=raw_result.family,
                family_confidence=raw_result.family_confidence,
                risk_level=raw_result.risk_level,
                features=raw_result.features if request.include_features else {},
                explanation=raw_result.explanation,
            ))

        processing_time = (time.perf_counter() - start_time) * 1000
        dga_count = sum(1 for r in results if r.is_dga)
        benign_count = len(results) - dga_count

        response = BatchDGAResponse(
            results=results,
            total_count=len(results),
            dga_count=dga_count,
            benign_count=benign_count,
            processing_time_ms=processing_time,
            avg_time_per_domain_ms=processing_time / len(results) if results else 0,
        )

        # Record metrics
        if _metrics_collector:
            _metrics_collector.record_batch_dga_detection(
                total_count=len(results),
                dga_count=dga_count,
                processing_time_ms=processing_time,
            )

        logger.info(
            "batch_dga_completed",
            total=len(results),
            dga_count=dga_count,
            time_ms=processing_time,
            avg_ms=response.avg_time_per_domain_ms,
        )

        return BaseResponse.success_response(request.request_id, response)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_dga_failed", count=len(request.domains), error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@router.get("/dga/stats")
async def get_dga_stats(
    detector=Depends(get_dga_detector),
) -> dict[str, Any]:
    """Get DGA detection statistics.

    Returns:
        Detection statistics and model info
    """
    try:
        metrics = {}

        # Get detector metrics if available
        if hasattr(detector, "get_metrics"):
            metrics = detector.get_metrics()

        return {
            "status": "ok",
            "model_loaded": detector._is_loaded if hasattr(detector, "_is_loaded") else True,
            "metrics": metrics,
        }

    except Exception as e:
        logger.error("dga_stats_failed", error=str(e))
        return {"status": "error", "error": str(e)}


@router.post("/dga/allowlist/add")
async def add_to_allowlist(
    domains: list[str],
    detector=Depends(get_dga_detector),
) -> dict[str, Any]:
    """Add domains to allowlist.

    Args:
        domains: List of domains to allowlist

    Returns:
        Operation result
    """
    try:
        if hasattr(detector, "_allowlist"):
            added = 0
            for domain in domains:
                domain_clean = domain.lower().strip()
                if domain_clean not in detector._allowlist:
                    detector._allowlist.add(domain_clean)
                    added += 1

            return {
                "status": "ok",
                "added": added,
                "total_allowlist_size": len(detector._allowlist),
            }
        else:
            return {"status": "error", "error": "Allowlist not supported"}

    except Exception as e:
        logger.error("allowlist_add_failed", error=str(e))
        return {"status": "error", "error": str(e)}


@router.post("/dga/blocklist/add")
async def add_to_blocklist(
    domains: list[str],
    detector=Depends(get_dga_detector),
) -> dict[str, Any]:
    """Add domains to blocklist.

    Args:
        domains: List of domains to blocklist

    Returns:
        Operation result
    """
    try:
        if hasattr(detector, "_blocklist"):
            added = 0
            for domain in domains:
                domain_clean = domain.lower().strip()
                if domain_clean not in detector._blocklist:
                    detector._blocklist.add(domain_clean)
                    added += 1

            return {
                "status": "ok",
                "added": added,
                "total_blocklist_size": len(detector._blocklist),
            }
        else:
            return {"status": "error", "error": "Blocklist not supported"}

    except Exception as e:
        logger.error("blocklist_add_failed", error=str(e))
        return {"status": "error", "error": str(e)}


def set_dependencies(
    dga_detector,
    cache=None,
    metrics_collector=None,
) -> None:
    """Set service dependencies (called at app startup)."""
    global _dga_detector, _cache, _metrics_collector
    _dga_detector = dga_detector
    _cache = cache
    _metrics_collector = metrics_collector
