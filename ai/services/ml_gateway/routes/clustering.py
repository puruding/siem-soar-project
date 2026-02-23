"""Alert Clustering API routes."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from services.ml_gateway.models.loader import ModelLoader, ModelType


router = APIRouter()


# Request/Response models
class AlertInput(BaseModel):
    """Input alert for clustering."""
    alert_id: str = Field(..., description="Unique alert identifier")
    title: str | None = Field(default=None, description="Alert title")
    description: str | None = Field(default=None, description="Alert description")
    severity: str | None = Field(default=None, description="Alert severity")
    alert_type: str | None = Field(default=None, description="Alert type/category")
    source: str | None = Field(default=None, description="Alert source")
    timestamp: datetime | str | None = Field(default=None, description="Alert timestamp")
    source_ip: str | None = Field(default=None)
    destination_ip: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    user: str | None = Field(default=None)
    mitre_tactic: str | None = Field(default=None)
    mitre_technique: str | None = Field(default=None)
    entities: list[str] | None = Field(default=None, description="Related entities")
    extra: dict[str, Any] = Field(default_factory=dict, description="Additional data")


class ClusterInfo(BaseModel):
    """Information about a cluster."""
    cluster_id: int = Field(description="Cluster identifier")
    alert_count: int = Field(description="Number of alerts in cluster")
    alert_ids: list[str] = Field(description="Alert IDs in cluster")
    representative_alert_id: str | None = Field(default=None)
    common_severity: str | None = Field(default=None)
    common_alert_type: str | None = Field(default=None)
    common_entities: list[str] = Field(default_factory=list)
    earliest_alert: datetime | None = Field(default=None)
    latest_alert: datetime | None = Field(default=None)
    intra_cluster_similarity: float = Field(default=0.0)


class ClusteringRequest(BaseModel):
    """Request for alert clustering."""
    alerts: list[AlertInput] = Field(..., min_length=2, max_length=10000)
    algorithm: str = Field(default="hdbscan", description="Clustering algorithm")
    min_cluster_size: int = Field(default=3, ge=2, le=100)
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class ClusteringResponse(BaseModel):
    """Response for alert clustering."""
    total_alerts: int = Field(description="Total alerts processed")
    total_clusters: int = Field(description="Number of clusters found")
    noise_count: int = Field(description="Number of unclustered alerts")
    clusters: list[ClusterInfo] = Field(description="Cluster information")
    alert_cluster_map: dict[str, int] = Field(description="Alert to cluster mapping")
    cluster_coverage: float = Field(description="Percentage of alerts clustered")
    silhouette_score: float | None = Field(default=None, description="Clustering quality")
    processing_time_ms: float = Field(description="Processing time")


class SimilarAlertsRequest(BaseModel):
    """Request to find similar alerts."""
    alert: AlertInput = Field(..., description="Reference alert")
    candidates: list[AlertInput] | None = Field(default=None, description="Candidates (uses last clustered if None)")
    top_k: int = Field(default=10, ge=1, le=100)


class SimilarAlertResult(BaseModel):
    """Similar alert result."""
    alert_id: str
    similarity_score: float


class SimilarAlertsResponse(BaseModel):
    """Response for similar alerts query."""
    reference_alert_id: str
    similar_alerts: list[SimilarAlertResult]
    processing_time_ms: float


class SimilarityRequest(BaseModel):
    """Request to calculate similarity between two alerts."""
    alert1: AlertInput
    alert2: AlertInput


class SimilarityResponse(BaseModel):
    """Response for similarity calculation."""
    overall_similarity: float
    embedding_similarity: float
    entity_overlap: float
    attribute_similarity: float
    temporal_proximity: float
    text_similarity: float
    matching_entities: list[str]
    matching_attributes: list[str]


# Dependency
def get_model_loader():
    """Get model loader dependency."""
    from services.ml_gateway.main import get_model_loader
    return get_model_loader()


@router.post("/cluster", response_model=ClusteringResponse)
async def cluster_alerts(
    request: ClusteringRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> ClusteringResponse:
    """Cluster alerts into groups.

    Args:
        request: Alerts to cluster with parameters
        loader: Model loader instance

    Returns:
        Clustering results
    """
    start_time = time.time()

    try:
        model = loader.get_model(ModelType.CLUSTERING)

        # Update model config if needed
        model.config.min_cluster_size = request.min_cluster_size
        model.config.similarity_threshold = request.similarity_threshold
        model.config.algorithm = request.algorithm

        # Convert alerts to dict format
        alerts = [
            {**a.model_dump(exclude={"extra"}), **a.extra}
            for a in request.alerts
        ]

        # Run clustering
        result = model.cluster(alerts)

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.CLUSTERING, processing_time)

        # Convert clusters to response format
        clusters = []
        for c in result.clusters:
            clusters.append(ClusterInfo(
                cluster_id=c.cluster_id,
                alert_count=c.alert_count,
                alert_ids=c.alert_ids,
                representative_alert_id=c.representative_alert_id,
                common_severity=c.common_severity,
                common_alert_type=c.common_alert_type,
                common_entities=c.common_entities,
                earliest_alert=c.earliest_alert,
                latest_alert=c.latest_alert,
                intra_cluster_similarity=c.intra_cluster_similarity,
            ))

        return ClusteringResponse(
            total_alerts=result.total_alerts,
            total_clusters=result.total_clusters,
            noise_count=result.noise_count,
            clusters=clusters,
            alert_cluster_map=result.alert_cluster_map,
            cluster_coverage=result.cluster_coverage,
            silhouette_score=result.silhouette_score,
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Clustering failed: {e}")


@router.post("/similar", response_model=SimilarAlertsResponse)
async def find_similar_alerts(
    request: SimilarAlertsRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> SimilarAlertsResponse:
    """Find alerts similar to a reference alert.

    Args:
        request: Reference alert and optional candidates
        loader: Model loader instance

    Returns:
        Similar alerts with scores
    """
    start_time = time.time()

    try:
        model = loader.get_model(ModelType.CLUSTERING)

        # Convert alert to dict
        alert = {**request.alert.model_dump(exclude={"extra"}), **request.alert.extra}

        # Convert candidates if provided
        candidates = None
        if request.candidates:
            candidates = [
                {**a.model_dump(exclude={"extra"}), **a.extra}
                for a in request.candidates
            ]

        # Find similar alerts
        similar = model.find_similar_alerts(
            alert=alert,
            candidate_alerts=candidates,
            top_k=request.top_k,
        )

        processing_time = (time.time() - start_time) * 1000
        loader.record_inference(ModelType.CLUSTERING, processing_time)

        return SimilarAlertsResponse(
            reference_alert_id=request.alert.alert_id,
            similar_alerts=[
                SimilarAlertResult(alert_id=aid, similarity_score=score)
                for aid, score in similar
            ],
            processing_time_ms=processing_time,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Similarity search failed: {e}")


@router.post("/similarity", response_model=SimilarityResponse)
async def calculate_similarity(
    request: SimilarityRequest,
    loader: ModelLoader = Depends(get_model_loader),
) -> SimilarityResponse:
    """Calculate detailed similarity between two alerts.

    Args:
        request: Two alerts to compare
        loader: Model loader instance

    Returns:
        Detailed similarity breakdown
    """
    try:
        model = loader.get_model(ModelType.CLUSTERING)

        # Convert alerts to dict
        alert1 = {**request.alert1.model_dump(exclude={"extra"}), **request.alert1.extra}
        alert2 = {**request.alert2.model_dump(exclude={"extra"}), **request.alert2.extra}

        # Get embeddings
        embeddings = model.embedder.embed_alerts([alert1, alert2])

        # Calculate similarity
        score = model.similarity_engine.calculate_similarity(
            alert1, alert2,
            embeddings[0], embeddings[1],
        )

        return SimilarityResponse(
            overall_similarity=score.overall_score,
            embedding_similarity=score.embedding_similarity,
            entity_overlap=score.entity_overlap,
            attribute_similarity=score.attribute_similarity,
            temporal_proximity=score.temporal_proximity,
            text_similarity=score.text_similarity,
            matching_entities=score.matching_entities,
            matching_attributes=score.matching_attributes,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Similarity calculation failed: {e}")


@router.post("/deduplicate")
async def deduplicate_alerts(
    alerts: list[AlertInput],
    similarity_threshold: float = Query(default=0.9, ge=0.5, le=1.0),
    loader: ModelLoader = Depends(get_model_loader),
) -> dict[str, Any]:
    """Identify duplicate alerts.

    Args:
        alerts: Alerts to check for duplicates
        similarity_threshold: Minimum similarity to be considered duplicate
        loader: Model loader instance

    Returns:
        Duplicate groups
    """
    start_time = time.time()

    try:
        model = loader.get_model(ModelType.CLUSTERING)

        # Convert alerts
        alert_dicts = [
            {**a.model_dump(exclude={"extra"}), **a.extra}
            for a in alerts
        ]

        # Get embeddings
        embeddings = model.embedder.embed_alerts(alert_dicts)

        # Calculate pairwise similarities
        similarity_matrix = model.similarity_engine.batch_similarity(
            alert_dicts, embeddings
        )

        # Find duplicate groups
        duplicate_groups = []
        processed = set()

        for i in range(len(alerts)):
            if i in processed:
                continue

            group = [alerts[i].alert_id]
            for j in range(i + 1, len(alerts)):
                if j not in processed and similarity_matrix[i, j] >= similarity_threshold:
                    group.append(alerts[j].alert_id)
                    processed.add(j)

            if len(group) > 1:
                duplicate_groups.append(group)
            processed.add(i)

        processing_time = (time.time() - start_time) * 1000

        return {
            "total_alerts": len(alerts),
            "duplicate_groups": len(duplicate_groups),
            "groups": duplicate_groups,
            "duplicates_found": sum(len(g) - 1 for g in duplicate_groups),
            "processing_time_ms": processing_time,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deduplication failed: {e}")


@router.get("/stats")
async def get_clustering_stats(
    loader: ModelLoader = Depends(get_model_loader),
) -> dict[str, Any]:
    """Get clustering statistics.

    Returns:
        Clustering statistics
    """
    info = loader.get_model_info(ModelType.CLUSTERING)

    return {
        "model_loaded": info.get("loaded", False),
        "inference_count": info.get("inference_count", 0),
        "avg_latency_ms": info.get("avg_latency_ms", 0.0),
        "embedding_model": info.get("config", {}).get("embedding_model"),
        "default_algorithm": info.get("config", {}).get("algorithm"),
    }


@router.get("/algorithms")
async def get_available_algorithms() -> dict[str, Any]:
    """Get available clustering algorithms.

    Returns:
        List of algorithms with descriptions
    """
    algorithms = [
        {
            "name": "hdbscan",
            "description": "Hierarchical DBSCAN - automatic cluster detection, handles varying densities",
            "requires_cluster_count": False,
            "parameters": ["min_cluster_size", "min_samples", "cluster_selection_epsilon"],
        },
        {
            "name": "dbscan",
            "description": "Density-Based Spatial Clustering - fast, requires epsilon parameter",
            "requires_cluster_count": False,
            "parameters": ["eps", "min_samples"],
        },
        {
            "name": "agglomerative",
            "description": "Hierarchical Agglomerative Clustering - builds cluster hierarchy",
            "requires_cluster_count": True,
            "parameters": ["n_clusters", "linkage"],
        },
    ]

    return {"algorithms": algorithms, "default": "hdbscan"}
