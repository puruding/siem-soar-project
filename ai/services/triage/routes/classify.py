"""Alert classification routes."""

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks

from ai.common import get_logger
from ai.common.models import BaseResponse
from ai.services.triage.schemas import (
    ClassifyRequest,
    BatchClassifyRequest,
    PriorityRequest,
    FeedbackRequest,
)
from ai.services.triage.schemas.responses import (
    ClassifyResponse,
    BatchClassifyResponse,
    ClassificationResult,
    PriorityResponse,
    PriorityResult,
    FeedbackResponse,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["classification"])


# Service state - injected at app startup
_classifier = None
_priority_scorer = None
_cache = None
_metrics_collector = None


def get_classifier():
    """Get classifier dependency."""
    if _classifier is None:
        raise HTTPException(status_code=503, detail="Classifier not initialized")
    return _classifier


def get_priority_scorer():
    """Get priority scorer dependency."""
    if _priority_scorer is None:
        raise HTTPException(status_code=503, detail="Priority scorer not initialized")
    return _priority_scorer


@router.post("/classify", response_model=BaseResponse[ClassifyResponse])
async def classify_alert(
    request: ClassifyRequest,
    classifier=Depends(get_classifier),
) -> BaseResponse[ClassifyResponse]:
    """Classify a single alert.

    Args:
        request: Classification request with alert data

    Returns:
        Classification result with severity, category, and recommendations
    """
    start_time = time.perf_counter()

    try:
        alert_id = request.alert.get("id", "unknown")
        is_cached = False

        # Check cache first
        if request.use_cache and _cache:
            cached_result = await _cache.get_classification(request.alert)
            if cached_result:
                is_cached = True
                classification_data = cached_result["classification"]
                priority_data = cached_result.get("priority", {})

                classification = ClassificationResult(**classification_data)
                priority_score = priority_data.get("final_score", classification_data.get("risk_score", 50))
                priority_level = priority_data.get("priority_level", "medium")
                actions = cached_result.get("recommended_actions", [])

                processing_time = (time.perf_counter() - start_time) * 1000

                result = ClassifyResponse(
                    alert_id=alert_id,
                    classification=classification,
                    priority_score=priority_score,
                    priority_level=priority_level,
                    recommended_actions=actions,
                    processing_time_ms=processing_time,
                    is_cached=True,
                )

                return BaseResponse.success_response(request.request_id, result)

        # Run classification
        inference_start = time.perf_counter()
        raw_classification = await classifier.classify(request.alert)
        inference_time = time.perf_counter() - inference_start

        # Build classification result
        classification = ClassificationResult(
            severity=raw_classification.severity.value,
            severity_confidence=raw_classification.severity_confidence,
            category=raw_classification.category.value,
            category_confidence=raw_classification.category_confidence,
            mitre_tactics=raw_classification.mitre_tactics if request.include_mitre else [],
            mitre_techniques=raw_classification.mitre_techniques if request.include_mitre else [],
            risk_score=raw_classification.risk_score,
            is_false_positive=raw_classification.is_false_positive,
            fp_confidence=raw_classification.fp_confidence,
            explanation=raw_classification.explanation if request.include_explanation else "",
        )

        # Calculate priority
        priority_result = {}
        if _priority_scorer:
            alert_with_classification = {
                **request.alert,
                "severity": raw_classification.severity.value,
                "category": raw_classification.category.value,
            }
            priority_result = _priority_scorer.score(alert_with_classification)

        priority_score = priority_result.get("final_score", raw_classification.risk_score)
        priority_level = priority_result.get("priority_level", _get_priority_level(priority_score))

        # Generate recommendations
        actions = _generate_recommendations(classification, priority_level)

        processing_time = (time.perf_counter() - start_time) * 1000

        # Cache result
        if _cache and request.use_cache:
            await _cache.set_classification(request.alert, {
                "classification": classification.model_dump(),
                "priority": priority_result,
                "recommended_actions": actions,
            })

        result = ClassifyResponse(
            alert_id=alert_id,
            classification=classification,
            priority_score=priority_score,
            priority_level=priority_level,
            recommended_actions=actions,
            processing_time_ms=processing_time,
            is_cached=False,
        )

        # Record metrics
        if _metrics_collector:
            _metrics_collector.record_alert_processed(
                severity=classification.severity,
                category=classification.category,
                is_false_positive=classification.is_false_positive,
                priority_score=priority_score,
                severity_confidence=classification.severity_confidence,
                category_confidence=classification.category_confidence,
                processing_time_seconds=processing_time / 1000,
                inference_time_seconds=inference_time,
            )

        return BaseResponse.success_response(request.request_id, result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("classify_failed", error=str(e), alert_id=request.alert.get("id"))
        return BaseResponse.error_response(request.request_id, str(e))


@router.post("/classify/batch", response_model=BaseResponse[BatchClassifyResponse])
async def batch_classify_alerts(
    request: BatchClassifyRequest,
    classifier=Depends(get_classifier),
) -> BaseResponse[BatchClassifyResponse]:
    """Classify multiple alerts in batch.

    Args:
        request: Batch classification request

    Returns:
        List of classification results
    """
    start_time = time.perf_counter()

    try:
        # Batch classify
        raw_classifications = await classifier.batch_classify(request.alerts)

        results = []
        failed_count = 0

        for alert, raw_cls in zip(request.alerts, raw_classifications):
            try:
                alert_id = alert.get("id", "unknown")

                classification = ClassificationResult(
                    severity=raw_cls.severity.value,
                    severity_confidence=raw_cls.severity_confidence,
                    category=raw_cls.category.value,
                    category_confidence=raw_cls.category_confidence,
                    mitre_tactics=raw_cls.mitre_tactics if request.include_mitre else [],
                    mitre_techniques=raw_cls.mitre_techniques if request.include_mitre else [],
                    risk_score=raw_cls.risk_score,
                    is_false_positive=raw_cls.is_false_positive,
                    fp_confidence=raw_cls.fp_confidence,
                    explanation=raw_cls.explanation if request.include_explanation else "",
                )

                # Calculate priority
                priority_score = raw_cls.risk_score
                if _priority_scorer:
                    alert_with_cls = {**alert, "severity": raw_cls.severity.value}
                    priority_result = _priority_scorer.score(alert_with_cls)
                    priority_score = priority_result.get("final_score", priority_score)

                priority_level = _get_priority_level(priority_score)
                actions = _generate_recommendations(classification, priority_level)

                results.append(ClassifyResponse(
                    alert_id=alert_id,
                    classification=classification,
                    priority_score=priority_score,
                    priority_level=priority_level,
                    recommended_actions=actions,
                    processing_time_ms=0,
                    is_cached=False,
                ))

            except Exception as e:
                logger.warning("batch_item_failed", alert_id=alert.get("id"), error=str(e))
                failed_count += 1

        total_time = (time.perf_counter() - start_time) * 1000
        avg_time = total_time / len(results) if results else 0

        response = BatchClassifyResponse(
            results=results,
            total_count=len(request.alerts),
            processed_count=len(results),
            failed_count=failed_count,
            total_processing_time_ms=total_time,
            avg_processing_time_ms=avg_time,
        )

        logger.info(
            "batch_classify_completed",
            total=len(request.alerts),
            processed=len(results),
            failed=failed_count,
            time_ms=total_time,
        )

        return BaseResponse.success_response(request.request_id, response)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_classify_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@router.post("/priority", response_model=BaseResponse[PriorityResponse])
async def compute_priority(
    request: PriorityRequest,
    priority_scorer=Depends(get_priority_scorer),
) -> BaseResponse[PriorityResponse]:
    """Compute priority score for an alert.

    Args:
        request: Priority computation request

    Returns:
        Priority score and factors
    """
    start_time = time.perf_counter()

    try:
        alert_id = request.alert.get("id", "unknown")

        # Add pre-classified values if provided
        alert_data = {**request.alert}
        if request.severity:
            alert_data["severity"] = request.severity
        if request.category:
            alert_data["category"] = request.category
        if request.context:
            alert_data.update(request.context)

        # Compute priority
        raw_result = priority_scorer.score(alert_data)

        priority = PriorityResult(
            final_score=raw_result.get("final_score", 50),
            priority_level=raw_result.get("priority_level", "medium"),
            components=raw_result.get("components", {}),
            factors=raw_result.get("factors", []),
        )

        processing_time = (time.perf_counter() - start_time) * 1000

        response = PriorityResponse(
            alert_id=alert_id,
            priority=priority,
            processing_time_ms=processing_time,
        )

        return BaseResponse.success_response(request.request_id, response)

    except Exception as e:
        logger.error("priority_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@router.post("/feedback", response_model=BaseResponse[FeedbackResponse])
async def submit_feedback(
    request: FeedbackRequest,
    background_tasks: BackgroundTasks,
) -> BaseResponse[FeedbackResponse]:
    """Submit analyst feedback for model improvement.

    Args:
        request: Feedback request

    Returns:
        Feedback submission confirmation
    """
    try:
        import uuid

        feedback_id = str(uuid.uuid4())

        # Process feedback asynchronously
        background_tasks.add_task(
            _process_feedback,
            feedback_id=feedback_id,
            alert_id=request.alert_id,
            analyst_id=request.analyst_id,
            feedback_type=request.feedback_type,
            corrected_severity=request.corrected_severity,
            corrected_category=request.corrected_category,
            is_false_positive=request.is_false_positive,
            notes=request.notes,
            tags=request.tags,
        )

        # Invalidate cache for this alert
        if _cache:
            await _cache.invalidate_alert({"id": request.alert_id})

        response = FeedbackResponse(
            status="accepted",
            feedback_id=feedback_id,
            alert_id=request.alert_id,
            message="Feedback recorded for model improvement",
        )

        return BaseResponse.success_response(request.request_id, response)

    except Exception as e:
        logger.error("feedback_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


async def _process_feedback(
    feedback_id: str,
    alert_id: str,
    analyst_id: str,
    feedback_type: str,
    corrected_severity: str | None,
    corrected_category: str | None,
    is_false_positive: bool | None,
    notes: str | None,
    tags: list[str],
) -> None:
    """Process feedback in background."""
    try:
        # Import feedback collector
        from ai.feedback.collector import FeedbackCollector, AnalystFeedback, FeedbackType

        collector = FeedbackCollector()
        await collector.connect()

        feedback = AnalystFeedback(
            alert_id=alert_id,
            analyst_id=analyst_id,
            feedback_type=FeedbackType(feedback_type),
            corrected_severity=corrected_severity,
            corrected_category=corrected_category,
            is_false_positive=is_false_positive,
            notes=notes,
        )

        await collector.collect(feedback)
        await collector.close()

        logger.info(
            "feedback_processed",
            feedback_id=feedback_id,
            alert_id=alert_id,
            feedback_type=feedback_type,
        )

    except Exception as e:
        logger.error(
            "feedback_processing_failed",
            feedback_id=feedback_id,
            error=str(e),
        )


def _get_priority_level(score: float) -> str:
    """Get priority level from score."""
    if score >= 90:
        return "critical"
    elif score >= 70:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def _generate_recommendations(
    classification: ClassificationResult,
    priority_level: str,
) -> list[str]:
    """Generate recommended actions."""
    actions = []

    # Priority-based
    if priority_level in ("critical", "high"):
        actions.append("Escalate to Tier 2 analyst immediately")
        actions.append("Check for related alerts in the last 24 hours")

    # Severity-based
    if classification.severity in ("critical", "high"):
        actions.append("Initiate incident response procedure")

    # FP recommendation
    if classification.is_false_positive and classification.fp_confidence > 0.8:
        actions.append("Review and consider tuning detection rule")
        actions.append("Mark as false positive if confirmed")

    # MITRE recommendations
    if classification.mitre_tactics:
        actions.append(
            f"Review MITRE ATT&CK tactics: {', '.join(classification.mitre_tactics[:3])}"
        )

    # Category-specific
    category_actions = {
        "malware": ["Isolate affected host", "Collect malware sample"],
        "intrusion": ["Check for lateral movement", "Review auth logs"],
        "data_exfiltration": ["Block outbound connection", "Identify data accessed"],
        "credential_access": ["Force password reset", "Review account activity"],
        "command_and_control": ["Block C2 indicators", "Hunt for compromised hosts"],
    }

    if classification.category in category_actions:
        actions.extend(category_actions[classification.category])

    # Standard
    actions.append("Verify source IP/hostname legitimacy")

    return actions[:8]


def set_dependencies(
    classifier,
    priority_scorer,
    cache,
    metrics_collector,
) -> None:
    """Set service dependencies (called at app startup)."""
    global _classifier, _priority_scorer, _cache, _metrics_collector
    _classifier = classifier
    _priority_scorer = priority_scorer
    _cache = cache
    _metrics_collector = metrics_collector
