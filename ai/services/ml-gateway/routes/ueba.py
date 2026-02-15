"""UEBA Anomaly Detection API routes."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from services.ml_gateway.models.loader import ModelLoader, ModelType


router = APIRouter()


# Request/Response models
class EntityEvent(BaseModel):
    """Single event for an entity."""
    event_id: str | None = Field(default=None, description="Event identifier")
    timestamp: datetime | str | None = Field(default=None, description="Event timestamp")
    event_type: str | None = Field(default=None, description="Event type")
    source_ip: str | None = Field(default=None)
    destination_ip: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    user: str | None = Field(default=None)
    action: str | None = Field(default=None)
    status: str | None = Field(default=None)
    bytes_sent: int | None = Field(default=None)
    bytes_received: int | None = Field(default=None)
    severity: str | None = Field(default=None)
    extra: dict[str, Any] = Field(default_factory=dict, description="Additional event data")


class AnomalyDetectRequest(BaseModel):
    """Request for anomaly detection."""
    entity_id: str = Field(..., description="Entity identifier (user, host, etc.)")
    entity_type: str = Field(default="user", description="Type of entity")
    events: list[EntityEvent] = Field(..., description="Recent events for the entity", min_length=1)


class AnomalyScore(BaseModel):
    """Detailed anomaly scores."""
    overall_score: float = Field(ge=0.0, le=1.0)
    reconstruction_score: float = Field(ge=0.0, le=1.0)
    temporal_score: float = Field(ge=0.0, le=1.0)
    volumetric_score: float = Field(ge=0.0, le=1.0)
    behavioral_score: float = Field(ge=0.0, le=1.0)


class AnomalyDetectResponse(BaseModel):
    """Response for anomaly detection."""
    entity_id: str = Field(description="Entity identifier")
    entity_type: str = Field(description="Entity type")
    is_anomaly: bool = Field(description="Whether behavior is anomalous")
    anomaly_score: AnomalyScore = Field(description="Detailed anomaly scores")
    anomaly_types: list[str] = Field(default_factory=list, description="Types of anomalies detected")
    severity: str = Field(description="Anomaly severity")
    confidence: float = Field(ge=0.0, le=1.0, description="Detection confidence")
    explanation: str = Field(description="Human-readable explanation")
    contributing_factors: list[str] = Field(default_factory=list)
    processing_time_ms: float = Field(description="Processing time")


class BatchAnomalyRequest(BaseModel):
    """Request for batch anomaly detection."""
    entities: list[AnomalyDetectRequest] = Field(..., min_length=1, max_length=100)


class BatchAnomalyResponse(BaseModel):
    """Response for batch anomaly detection."""
    results: list[AnomalyDetectResponse] = Field(description="Detection results")
    total_entities: int = Field(description="Total entities processed")
    anomalies_detected: int = Field(description="Number of anomalies found")
    processing_time_ms: float = Field(description="Total processing time")


class ProfileStatusResponse(BaseModel):
    """Response for entity profile status."""
    entity_id: str
    entity_type: str
    profile_status: str
    samples_collected: int
    learning_progress: float
    is_ready: bool
    last_activity: datetime | None


# Dependency
def get_model_loader():
    """Get model loader dependency."""
    from services.ml_gateway.main import get_model_loader
    return get_model_loader()


@router.post("/detect", response_model=AnomalyDetectResponse)
async def detect_anomaly(
    request: AnomalyDetectRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> AnomalyDetectResponse:
    """Detect behavioral anomalies for an entity.

    Args:
        request: Entity and events to analyze
        loader: Model loader instance

    Returns:
        Anomaly detection result
    """
    start_time = time.time()

    try:
        detector = loader.get_model(ModelType.UEBA)

        # Convert events to dict format
        events = [
            {**e.model_dump(), **e.extra}
            for e in request.events
        ]

        # Get entity type enum
        from models.ueba.profile import ProfileType
        try:
            entity_type = ProfileType(request.entity_type.lower())
        except ValueError:
            entity_type = ProfileType.USER

        # Run detection
        result = detector.detect(
            entity_id=request.entity_id,
            entity_type=entity_type,
            events=events,
        )

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.UEBA, processing_time)

        return AnomalyDetectResponse(
            entity_id=request.entity_id,
            entity_type=request.entity_type,
            is_anomaly=result.is_anomaly,
            anomaly_score=AnomalyScore(
                overall_score=result.anomaly_score.overall_score,
                reconstruction_score=result.anomaly_score.reconstruction_score,
                temporal_score=result.anomaly_score.temporal_score,
                volumetric_score=result.anomaly_score.volumetric_score,
                behavioral_score=result.anomaly_score.behavioral_score,
            ),
            anomaly_types=[at.value for at in result.anomaly_types],
            severity=result.severity,
            confidence=result.confidence,
            explanation=result.explanation,
            contributing_factors=result.contributing_factors,
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {e}")


@router.post("/detect/batch", response_model=BatchAnomalyResponse)
async def detect_anomaly_batch(
    request: BatchAnomalyRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> BatchAnomalyResponse:
    """Detect anomalies for multiple entities.

    Args:
        request: List of entities to analyze
        loader: Model loader instance

    Returns:
        Batch detection results
    """
    start_time = time.time()

    try:
        detector = loader.get_model(ModelType.UEBA)
        results = []
        anomaly_count = 0

        for entity_request in request.entities:
            events = [
                {**e.model_dump(), **e.extra}
                for e in entity_request.events
            ]

            from models.ueba.profile import ProfileType
            try:
                entity_type = ProfileType(entity_request.entity_type.lower())
            except ValueError:
                entity_type = ProfileType.USER

            result = detector.detect(
                entity_id=entity_request.entity_id,
                entity_type=entity_type,
                events=events,
            )

            if result.is_anomaly:
                anomaly_count += 1

            results.append(AnomalyDetectResponse(
                entity_id=entity_request.entity_id,
                entity_type=entity_request.entity_type,
                is_anomaly=result.is_anomaly,
                anomaly_score=AnomalyScore(
                    overall_score=result.anomaly_score.overall_score,
                    reconstruction_score=result.anomaly_score.reconstruction_score,
                    temporal_score=result.anomaly_score.temporal_score,
                    volumetric_score=result.anomaly_score.volumetric_score,
                    behavioral_score=result.anomaly_score.behavioral_score,
                ),
                anomaly_types=[at.value for at in result.anomaly_types],
                severity=result.severity,
                confidence=result.confidence,
                explanation=result.explanation,
                contributing_factors=result.contributing_factors,
                processing_time_ms=0,  # Set below
            ))

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.UEBA, processing_time / len(request.entities))

        # Update processing times
        for r in results:
            r.processing_time_ms = processing_time / len(request.entities)

        return BatchAnomalyResponse(
            results=results,
            total_entities=len(request.entities),
            anomalies_detected=anomaly_count,
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch detection failed: {e}")


@router.get("/profile/{entity_id}", response_model=ProfileStatusResponse)
async def get_profile_status(
    entity_id: str,
    entity_type: str = Query(default="user", description="Entity type"),
    loader: ModelLoader = Depends(get_model_loader),
) -> ProfileStatusResponse:
    """Get profile status for an entity.

    Args:
        entity_id: Entity identifier
        entity_type: Type of entity
        loader: Model loader instance

    Returns:
        Profile status
    """
    try:
        detector = loader.get_model(ModelType.UEBA)

        from models.ueba.profile import ProfileType
        try:
            et = ProfileType(entity_type.lower())
        except ValueError:
            et = ProfileType.USER

        profile = detector.profile_manager.get_profile_by_entity(entity_id, et)

        if not profile:
            raise HTTPException(status_code=404, detail=f"Profile not found for {entity_id}")

        return ProfileStatusResponse(
            entity_id=entity_id,
            entity_type=entity_type,
            profile_status=profile.status.value,
            samples_collected=profile.samples_collected,
            learning_progress=profile.learning_progress,
            is_ready=profile.is_ready,
            last_activity=profile.last_activity_at,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get profile: {e}")


@router.get("/profiles")
async def list_profiles(
    status: str | None = Query(default=None, description="Filter by status"),
    entity_type: str | None = Query(default=None, description="Filter by entity type"),
    limit: int = Query(default=100, le=1000),
    loader: ModelLoader = Depends(get_model_loader),
) -> dict[str, Any]:
    """List all entity profiles.

    Args:
        status: Filter by profile status
        entity_type: Filter by entity type
        limit: Maximum profiles to return
        loader: Model loader instance

    Returns:
        List of profiles
    """
    try:
        detector = loader.get_model(ModelType.UEBA)

        from models.ueba.profile import ProfileStatus, ProfileType

        status_filter = None
        if status:
            try:
                status_filter = ProfileStatus(status.lower())
            except ValueError:
                pass

        type_filter = None
        if entity_type:
            try:
                type_filter = ProfileType(entity_type.lower())
            except ValueError:
                pass

        profiles = detector.profile_manager.get_all_profiles(
            status=status_filter,
            entity_type=type_filter,
        )[:limit]

        return {
            "profiles": [
                {
                    "profile_id": p.profile_id,
                    "entity_id": p.entity_id,
                    "entity_type": p.entity_type.value,
                    "status": p.status.value,
                    "samples_collected": p.samples_collected,
                    "is_ready": p.is_ready,
                }
                for p in profiles
            ],
            "total": len(profiles),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list profiles: {e}")


@router.get("/anomaly-types")
async def get_anomaly_types() -> dict[str, Any]:
    """Get list of detectable anomaly types.

    Returns:
        List of anomaly types with descriptions
    """
    from models.ueba.anomaly import AnomalyType

    types = []
    descriptions = {
        "unusual_time": "Activity at unusual time for this entity",
        "unusual_location": "Activity from unusual location",
        "unusual_volume": "Unusual activity volume",
        "unusual_resource": "Access to unusual resources",
        "credential_anomaly": "Multiple authentication failures or unusual credential use",
        "lateral_movement": "Unusual access to multiple systems",
        "privilege_escalation": "Privilege escalation attempt detected",
        "data_exfiltration": "Unusually high data transfer",
        "account_compromise": "Signs of account compromise",
        "insider_threat": "Potential insider threat indicators",
        "sequence_anomaly": "Unusual sequence of actions",
        "reconstruction_anomaly": "Behavior pattern anomaly detected by model",
    }

    for at in AnomalyType:
        types.append({
            "type": at.value,
            "description": descriptions.get(at.value, f"Anomaly type: {at.value}"),
        })

    return {"anomaly_types": types, "total": len(types)}


@router.get("/stats")
async def get_ueba_stats(
    loader: ModelLoader = Depends(get_model_loader),
) -> dict[str, Any]:
    """Get UEBA detection statistics.

    Returns:
        Detection statistics
    """
    try:
        detector = loader.get_model(ModelType.UEBA)
        info = loader.get_model_info(ModelType.UEBA)

        # Get profile statistics
        from models.ueba.profile import ProfileStatus

        all_profiles = detector.profile_manager.get_all_profiles()
        active_profiles = detector.profile_manager.get_all_profiles(status=ProfileStatus.ACTIVE)
        learning_profiles = detector.profile_manager.get_all_profiles(status=ProfileStatus.LEARNING)

        return {
            "total_profiles": len(all_profiles),
            "active_profiles": len(active_profiles),
            "learning_profiles": len(learning_profiles),
            "inference_count": info.get("inference_count", 0),
            "avg_latency_ms": info.get("avg_latency_ms", 0.0),
            "model_loaded": info.get("loaded", False),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {e}")
