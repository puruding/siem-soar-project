"""Alert Triage Service - Automated alert prioritization and enrichment."""

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import Field

from common import get_logger, get_settings, setup_logging
from common.models import BaseModel, BaseRequest, BaseResponse, HealthResponse
from models.classifier import AlertClassifier, AlertClassification
from models.priority import HybridPriorityScorer
from services.triage.inference import InferenceEngine
from services.triage.batching import DynamicBatcher, BatchConfig
from services.triage.cache import TieredCache, CacheConfig, ClassificationCache
from services.triage.model_loader import ModelLoader, ModelRegistry
from integration.metrics import MetricsCollector, LatencyTracker

settings = get_settings()
logger = get_logger(__name__)


class TriageRequest(BaseRequest):
    """Request for alert triage."""

    alert: dict[str, Any] = Field(description="Alert data to triage")
    enrich: bool = Field(default=True, description="Whether to enrich with context")
    auto_assign: bool = Field(default=False, description="Auto-assign to analyst")
    use_cache: bool = Field(default=True, description="Use cached results if available")


class BatchTriageRequest(BaseRequest):
    """Request for batch alert triage."""

    alerts: list[dict[str, Any]] = Field(description="List of alerts to triage")
    enrich: bool = Field(default=True, description="Whether to enrich with context")


class TriageResult(BaseModel):
    """Result of alert triage."""

    alert_id: str = Field(description="Alert ID")
    classification: AlertClassification = Field(description="Classification result")
    priority_score: float = Field(ge=0, le=100, description="Priority score")
    priority_level: str = Field(description="Priority level")
    recommended_actions: list[str] = Field(description="Recommended actions")
    similar_alerts: list[str] = Field(default_factory=list, description="Similar alert IDs")
    enrichment: dict[str, Any] = Field(default_factory=dict, description="Enrichment data")
    assigned_to: str | None = Field(default=None, description="Assigned analyst")
    processing_time_ms: float = Field(description="Processing time in ms")
    is_cached: bool = Field(default=False, description="Whether result was cached")


class FeedbackRequest(BaseRequest):
    """Request to submit analyst feedback."""

    alert_id: str = Field(description="Alert ID")
    analyst_id: str = Field(description="Analyst ID")
    feedback_type: str = Field(description="Type of feedback")
    corrected_severity: str | None = Field(default=None)
    corrected_category: str | None = Field(default=None)
    is_false_positive: bool | None = Field(default=None)
    notes: str | None = Field(default=None)


# Service state
classifier: AlertClassifier | None = None
priority_scorer: HybridPriorityScorer | None = None
cache: ClassificationCache | None = None
metrics_collector: MetricsCollector | None = None
batcher: DynamicBatcher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global classifier, priority_scorer, cache, metrics_collector, batcher

    setup_logging(
        level=settings.log_level,
        format=settings.log_format,
        service_name="ai-triage",
    )

    logger.info("starting_service", environment=settings.environment)

    # Initialize metrics collector
    metrics_collector = MetricsCollector(enable_prometheus=settings.metrics_enabled)

    # Initialize cache
    cache_backend = TieredCache(CacheConfig(
        use_redis=settings.environment != "development",
    ))
    await cache_backend.connect()
    cache = ClassificationCache(cache_backend)

    # Initialize classifier
    model_start = time.time()
    classifier = AlertClassifier(
        model_path=f"{settings.model_cache_dir}/alert_classifier/best_model.pt",
        device="cuda" if settings.environment == "production" else "cpu",
    )
    await classifier.load_model()
    model_load_time = time.time() - model_start
    metrics_collector.set_model_info("v1.0.0", model_load_time)

    # Initialize priority scorer
    priority_scorer = HybridPriorityScorer(ml_weight=0.7)

    # Initialize dynamic batcher for batch inference
    async def batch_processor(alerts: list[dict[str, Any]]) -> list[AlertClassification]:
        return await classifier.batch_classify(alerts)

    batcher = DynamicBatcher(
        batch_fn=batch_processor,
        config=BatchConfig(max_batch_size=64, max_wait_ms=50),
    )
    await batcher.start()

    logger.info(
        "service_initialized",
        model_load_time_s=model_load_time,
    )

    yield

    # Cleanup
    logger.info("shutting_down_service")

    if batcher:
        await batcher.stop()

    if cache:
        await cache._cache.disconnect()


app = FastAPI(
    title="AI Triage Service",
    description="Automated alert triage and prioritization with ML-based classification",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="ai-triage",
        version="1.0.0",
        checks={
            "classifier": classifier is not None and classifier._is_loaded,
            "priority_scorer": priority_scorer is not None,
            "cache": cache is not None,
            "batcher": batcher is not None,
        },
    )


@app.get("/metrics")
async def get_metrics() -> dict[str, Any]:
    """Get service metrics."""
    if metrics_collector:
        return metrics_collector.get_summary()
    return {}


@app.post("/api/v1/triage", response_model=BaseResponse[TriageResult])
async def triage_alert(request: TriageRequest) -> BaseResponse[TriageResult]:
    """Triage a single alert."""
    start_time = time.perf_counter()

    try:
        if classifier is None:
            raise HTTPException(status_code=503, detail="Classifier not initialized")

        alert_id = request.alert.get("id", "unknown")
        is_cached = False

        # Check cache first
        if request.use_cache and cache:
            cached_result = await cache.get_classification(request.alert)
            if cached_result:
                is_cached = True
                classification = AlertClassification(**cached_result["classification"])
                priority_result = cached_result.get("priority", {})
            else:
                cached_result = None

        if not is_cached:
            # Run inference
            inference_start = time.perf_counter()
            classification = await classifier.classify(request.alert)
            inference_time = time.perf_counter() - inference_start

            # Calculate priority
            priority_result = priority_scorer.score(
                {**request.alert, "severity": classification.severity.value},
            )

            # Cache result
            if cache:
                await cache.set_classification(request.alert, {
                    "classification": classification.model_dump(),
                    "priority": priority_result,
                })
        else:
            inference_time = 0.0

        # Calculate priority score
        priority_score = priority_result.get("final_score", classification.risk_score)
        priority_level = priority_result.get("priority_level", "medium")

        # Generate recommended actions
        actions = _generate_recommendations(classification, priority_level)

        processing_time = (time.perf_counter() - start_time) * 1000

        result = TriageResult(
            alert_id=alert_id,
            classification=classification,
            priority_score=priority_score,
            priority_level=priority_level,
            recommended_actions=actions,
            processing_time_ms=processing_time,
            is_cached=is_cached,
        )

        # Record metrics
        if metrics_collector and not is_cached:
            metrics_collector.record_alert_processed(
                severity=classification.severity.value,
                category=classification.category.value,
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
        logger.error("triage_failed", error=str(e))
        if metrics_collector:
            metrics_collector.record_alert_failed(type(e).__name__)
        return BaseResponse.error_response(request.request_id, str(e))


@app.post("/api/v1/triage/batch", response_model=BaseResponse[list[TriageResult]])
async def batch_triage_alerts(request: BatchTriageRequest) -> BaseResponse[list[TriageResult]]:
    """Triage multiple alerts in batch."""
    start_time = time.perf_counter()

    try:
        if classifier is None:
            raise HTTPException(status_code=503, detail="Classifier not initialized")

        # Batch classify
        classifications = await classifier.batch_classify(request.alerts)

        results = []
        for alert, classification in zip(request.alerts, classifications):
            alert_id = alert.get("id", "unknown")

            # Calculate priority
            priority_result = priority_scorer.score(
                {**alert, "severity": classification.severity.value},
            )

            priority_score = priority_result.get("final_score", classification.risk_score)
            priority_level = priority_result.get("priority_level", "medium")

            actions = _generate_recommendations(classification, priority_level)

            results.append(TriageResult(
                alert_id=alert_id,
                classification=classification,
                priority_score=priority_score,
                priority_level=priority_level,
                recommended_actions=actions,
                processing_time_ms=0,  # Set per-alert time if needed
                is_cached=False,
            ))

        total_time = (time.perf_counter() - start_time) * 1000

        # Record batch metrics
        if metrics_collector:
            metrics_collector.record_batch(len(request.alerts))
            for result in results:
                metrics_collector.record_alert_processed(
                    severity=result.classification.severity.value,
                    category=result.classification.category.value,
                    is_false_positive=result.classification.is_false_positive,
                    priority_score=result.priority_score,
                    severity_confidence=result.classification.severity_confidence,
                    category_confidence=result.classification.category_confidence,
                    processing_time_seconds=total_time / 1000 / len(results),
                    inference_time_seconds=total_time / 1000 / len(results),
                )

        logger.info(
            "batch_triage_completed",
            count=len(results),
            total_time_ms=total_time,
        )

        return BaseResponse.success_response(request.request_id, results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error("batch_triage_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@app.post("/api/v1/feedback")
async def submit_feedback(
    request: FeedbackRequest,
    background_tasks: BackgroundTasks,
) -> BaseResponse[dict[str, str]]:
    """Submit analyst feedback for model improvement."""
    try:
        # Process feedback asynchronously
        background_tasks.add_task(
            _process_feedback,
            request.alert_id,
            request.analyst_id,
            request.feedback_type,
            request.corrected_severity,
            request.corrected_category,
            request.is_false_positive,
            request.notes,
        )

        # Invalidate cache for this alert
        if cache:
            await cache.invalidate_alert({"id": request.alert_id})

        return BaseResponse.success_response(
            request.request_id,
            {"status": "feedback_received", "alert_id": request.alert_id}
        )

    except Exception as e:
        logger.error("feedback_submission_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


async def _process_feedback(
    alert_id: str,
    analyst_id: str,
    feedback_type: str,
    corrected_severity: str | None,
    corrected_category: str | None,
    is_false_positive: bool | None,
    notes: str | None,
) -> None:
    """Process and store analyst feedback."""
    try:
        from feedback.collector import FeedbackCollector, AnalystFeedback, FeedbackType

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
            alert_id=alert_id,
            feedback_type=feedback_type,
        )

    except Exception as e:
        logger.error("feedback_processing_failed", error=str(e))


def _generate_recommendations(
    classification: AlertClassification,
    priority_level: str,
) -> list[str]:
    """Generate recommended actions based on classification."""
    actions = []

    # Priority-based recommendations
    if priority_level in ("critical", "high"):
        actions.append("Escalate to Tier 2 analyst immediately")
        actions.append("Check for related alerts in the last 24 hours")

    # Severity-based recommendations
    if classification.severity.value in ("critical", "high"):
        actions.append("Initiate incident response procedure")

    # FP recommendation
    if classification.is_false_positive and classification.fp_confidence > 0.8:
        actions.append("Review and consider tuning detection rule")
        actions.append("Mark as false positive if confirmed")

    # MITRE recommendations
    if classification.mitre_tactics:
        actions.append(f"Review MITRE ATT&CK tactics: {', '.join(classification.mitre_tactics)}")

    # Category-specific recommendations
    category_actions = {
        "malware": ["Isolate affected host", "Collect malware sample for analysis"],
        "intrusion": ["Check for lateral movement", "Review authentication logs"],
        "data_exfiltration": ["Block outbound connection", "Identify sensitive data accessed"],
        "credential_access": ["Force password reset", "Review account activity"],
        "command_and_control": ["Block C2 indicators", "Hunt for additional compromised hosts"],
    }

    if classification.category.value in category_actions:
        actions.extend(category_actions[classification.category.value])

    # Standard recommendations
    actions.append("Verify source IP/hostname legitimacy")
    actions.append("Check asset criticality in CMDB")

    return actions[:8]  # Limit to 8 recommendations


def main() -> None:
    """Run the service."""
    import uvicorn

    uvicorn.run(
        "services.triage.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
