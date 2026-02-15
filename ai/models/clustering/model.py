"""Alert Clustering Model - Groups similar alerts for investigation."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import numpy as np
from pydantic import Field
from sklearn.cluster import HDBSCAN, DBSCAN
from sklearn.preprocessing import StandardScaler

from common.logging import LoggerMixin
from common.models import BaseModel

from .similarity import AlertSimilarityEngine, SimilarityScore
from .embedder import AlertEmbedder, EmbeddingConfig


class ClusteringConfig(BaseModel):
    """Configuration for alert clustering."""

    # Clustering algorithm
    algorithm: str = Field(default="hdbscan", description="Clustering algorithm")

    # HDBSCAN parameters
    min_cluster_size: int = Field(default=3, description="Minimum cluster size")
    min_samples: int = Field(default=2, description="Minimum samples for core point")
    cluster_selection_epsilon: float = Field(default=0.3, description="Cluster selection epsilon")

    # DBSCAN parameters
    eps: float = Field(default=0.5, description="DBSCAN epsilon")

    # Time-based clustering
    time_window_hours: int = Field(default=24, description="Time window for clustering")
    require_time_proximity: bool = Field(default=True, description="Require time proximity")

    # Similarity thresholds
    similarity_threshold: float = Field(default=0.7, description="Min similarity for grouping")
    entity_overlap_weight: float = Field(default=0.3, description="Weight for entity overlap")
    text_similarity_weight: float = Field(default=0.3, description="Weight for text similarity")
    embedding_similarity_weight: float = Field(default=0.4, description="Weight for embedding similarity")

    # Embedding configuration
    embedding_model: str = Field(default="all-MiniLM-L6-v2", description="Embedding model")
    embedding_dim: int = Field(default=384, description="Embedding dimension")


class ClusterInfo(BaseModel):
    """Information about a cluster."""

    cluster_id: int = Field(description="Cluster identifier")
    alert_count: int = Field(default=0, description="Number of alerts in cluster")
    alert_ids: list[str] = Field(default_factory=list, description="Alert IDs in cluster")

    # Cluster characteristics
    centroid: list[float] | None = Field(default=None, description="Cluster centroid")
    representative_alert_id: str | None = Field(default=None, description="Most central alert")

    # Common attributes
    common_severity: str | None = Field(default=None)
    common_alert_type: str | None = Field(default=None)
    common_source: str | None = Field(default=None)
    common_entities: list[str] = Field(default_factory=list)

    # Time range
    earliest_alert: datetime | None = Field(default=None)
    latest_alert: datetime | None = Field(default=None)

    # Cohesion metrics
    intra_cluster_similarity: float = Field(default=0.0, description="Average similarity within cluster")
    cluster_density: float = Field(default=0.0, description="Cluster density score")


class ClusteringResult(BaseModel):
    """Result of alert clustering."""

    # Overview
    total_alerts: int = Field(default=0)
    total_clusters: int = Field(default=0)
    noise_count: int = Field(default=0, description="Unclustered alerts")

    # Clusters
    clusters: list[ClusterInfo] = Field(default_factory=list)

    # Alert to cluster mapping
    alert_cluster_map: dict[str, int] = Field(default_factory=dict)

    # Metrics
    silhouette_score: float | None = Field(default=None, description="Clustering quality metric")
    cluster_coverage: float = Field(default=0.0, description="Percentage of alerts clustered")

    # Timing
    clustered_at: datetime = Field(default_factory=datetime.utcnow)
    time_window_start: datetime | None = Field(default=None)
    time_window_end: datetime | None = Field(default=None)


class AlertClusteringModel(LoggerMixin):
    """Clusters similar security alerts for efficient investigation.

    Features:
    - Embedding-based similarity clustering
    - HDBSCAN for automatic cluster detection
    - Time-aware clustering
    - Entity and attribute overlap analysis
    - Cluster quality metrics

    Use cases:
    - Alert deduplication
    - Incident correlation
    - Investigation grouping
    - Pattern detection
    """

    def __init__(
        self,
        config: ClusteringConfig | None = None,
    ):
        """Initialize clustering model.

        Args:
            config: Clustering configuration
        """
        self.config = config or ClusteringConfig()
        self.embedder = AlertEmbedder(
            EmbeddingConfig(
                model_name=self.config.embedding_model,
                embedding_dim=self.config.embedding_dim,
            )
        )
        self.similarity_engine = AlertSimilarityEngine()
        self.scaler = StandardScaler()

        self._fitted = False
        self._last_embeddings: np.ndarray | None = None
        self._last_alerts: list[dict[str, Any]] | None = None

    def cluster(
        self,
        alerts: list[dict[str, Any]],
        precomputed_embeddings: np.ndarray | None = None,
    ) -> ClusteringResult:
        """Cluster alerts into groups.

        Args:
            alerts: List of alert dictionaries
            precomputed_embeddings: Optional precomputed embeddings

        Returns:
            Clustering result with cluster assignments
        """
        if not alerts:
            return ClusteringResult()

        self.logger.info("clustering_alerts", alert_count=len(alerts))

        # Filter by time window if required
        if self.config.require_time_proximity:
            alerts = self._filter_by_time_window(alerts)

        if len(alerts) < self.config.min_cluster_size:
            self.logger.info("insufficient_alerts", count=len(alerts))
            return ClusteringResult(
                total_alerts=len(alerts),
                noise_count=len(alerts),
            )

        # Get embeddings
        if precomputed_embeddings is not None:
            embeddings = precomputed_embeddings
        else:
            embeddings = self.embedder.embed_alerts(alerts)

        # Store for later use
        self._last_embeddings = embeddings
        self._last_alerts = alerts

        # Normalize embeddings
        embeddings_normalized = self.scaler.fit_transform(embeddings)

        # Perform clustering
        if self.config.algorithm == "hdbscan":
            labels = self._cluster_hdbscan(embeddings_normalized)
        else:
            labels = self._cluster_dbscan(embeddings_normalized)

        # Build result
        result = self._build_result(alerts, embeddings, labels)

        self.logger.info(
            "clustering_complete",
            clusters=result.total_clusters,
            clustered=result.total_alerts - result.noise_count,
            noise=result.noise_count,
        )

        return result

    def _filter_by_time_window(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Filter alerts to time window."""
        cutoff = datetime.utcnow() - timedelta(hours=self.config.time_window_hours)

        filtered = []
        for alert in alerts:
            timestamp = alert.get("created_at") or alert.get("timestamp")
            if timestamp:
                if isinstance(timestamp, str):
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    except:
                        filtered.append(alert)
                        continue
                if timestamp >= cutoff:
                    filtered.append(alert)
            else:
                filtered.append(alert)

        return filtered

    def _cluster_hdbscan(self, embeddings: np.ndarray) -> np.ndarray:
        """Cluster using HDBSCAN."""
        clusterer = HDBSCAN(
            min_cluster_size=self.config.min_cluster_size,
            min_samples=self.config.min_samples,
            cluster_selection_epsilon=self.config.cluster_selection_epsilon,
            metric="euclidean",
        )
        labels = clusterer.fit_predict(embeddings)
        return labels

    def _cluster_dbscan(self, embeddings: np.ndarray) -> np.ndarray:
        """Cluster using DBSCAN."""
        clusterer = DBSCAN(
            eps=self.config.eps,
            min_samples=self.config.min_samples,
            metric="euclidean",
        )
        labels = clusterer.fit_predict(embeddings)
        return labels

    def _build_result(
        self,
        alerts: list[dict[str, Any]],
        embeddings: np.ndarray,
        labels: np.ndarray,
    ) -> ClusteringResult:
        """Build clustering result from labels."""
        # Count clusters (excluding noise label -1)
        unique_labels = set(labels)
        n_clusters = len([l for l in unique_labels if l >= 0])
        n_noise = int(np.sum(labels == -1))

        # Build alert to cluster mapping
        alert_cluster_map = {}
        for i, alert in enumerate(alerts):
            alert_id = alert.get("alert_id", f"alert_{i}")
            alert_cluster_map[alert_id] = int(labels[i])

        # Build cluster info
        clusters = []
        for cluster_id in unique_labels:
            if cluster_id < 0:
                continue

            cluster_mask = labels == cluster_id
            cluster_indices = np.where(cluster_mask)[0]
            cluster_alerts = [alerts[i] for i in cluster_indices]
            cluster_embeddings = embeddings[cluster_mask]

            cluster_info = self._build_cluster_info(
                cluster_id,
                cluster_alerts,
                cluster_embeddings,
            )
            clusters.append(cluster_info)

        # Sort clusters by size
        clusters.sort(key=lambda c: c.alert_count, reverse=True)

        # Calculate silhouette score if possible
        silhouette = None
        if n_clusters >= 2 and len(alerts) - n_noise >= 2:
            try:
                from sklearn.metrics import silhouette_score
                non_noise_mask = labels >= 0
                if np.sum(non_noise_mask) > 1:
                    silhouette = float(silhouette_score(
                        embeddings[non_noise_mask],
                        labels[non_noise_mask],
                    ))
            except Exception as e:
                self.logger.warning("silhouette_calculation_failed", error=str(e))

        # Time window
        timestamps = []
        for alert in alerts:
            ts = alert.get("created_at") or alert.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
            elif isinstance(ts, str):
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except:
                    pass

        time_start = min(timestamps) if timestamps else None
        time_end = max(timestamps) if timestamps else None

        return ClusteringResult(
            total_alerts=len(alerts),
            total_clusters=n_clusters,
            noise_count=n_noise,
            clusters=clusters,
            alert_cluster_map=alert_cluster_map,
            silhouette_score=silhouette,
            cluster_coverage=(len(alerts) - n_noise) / len(alerts) if alerts else 0.0,
            time_window_start=time_start,
            time_window_end=time_end,
        )

    def _build_cluster_info(
        self,
        cluster_id: int,
        alerts: list[dict[str, Any]],
        embeddings: np.ndarray,
    ) -> ClusterInfo:
        """Build information for a single cluster."""
        alert_ids = [
            a.get("alert_id", f"alert_{i}")
            for i, a in enumerate(alerts)
        ]

        # Calculate centroid
        centroid = embeddings.mean(axis=0)

        # Find representative alert (closest to centroid)
        distances = np.linalg.norm(embeddings - centroid, axis=1)
        representative_idx = int(np.argmin(distances))
        representative_id = alert_ids[representative_idx]

        # Find common attributes
        severities = [a.get("severity") for a in alerts if a.get("severity")]
        alert_types = [a.get("alert_type") for a in alerts if a.get("alert_type")]
        sources = [a.get("source") for a in alerts if a.get("source")]

        common_severity = self._most_common(severities)
        common_type = self._most_common(alert_types)
        common_source = self._most_common(sources)

        # Common entities
        all_entities = []
        for alert in alerts:
            entities = alert.get("entities", [])
            if isinstance(entities, list):
                all_entities.extend(entities)
        common_entities = list(set(all_entities))[:10]

        # Time range
        timestamps = []
        for alert in alerts:
            ts = alert.get("created_at") or alert.get("timestamp")
            if isinstance(ts, datetime):
                timestamps.append(ts)
            elif isinstance(ts, str):
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except:
                    pass

        earliest = min(timestamps) if timestamps else None
        latest = max(timestamps) if timestamps else None

        # Intra-cluster similarity
        intra_similarity = 0.0
        if len(embeddings) > 1:
            similarities = []
            for i in range(len(embeddings)):
                for j in range(i + 1, len(embeddings)):
                    sim = float(np.dot(embeddings[i], embeddings[j]) / (
                        np.linalg.norm(embeddings[i]) * np.linalg.norm(embeddings[j]) + 1e-8
                    ))
                    similarities.append(sim)
            if similarities:
                intra_similarity = float(np.mean(similarities))

        # Cluster density (inverse of average distance to centroid)
        avg_distance = float(np.mean(distances))
        density = 1.0 / (1.0 + avg_distance)

        return ClusterInfo(
            cluster_id=cluster_id,
            alert_count=len(alerts),
            alert_ids=alert_ids,
            centroid=centroid.tolist(),
            representative_alert_id=representative_id,
            common_severity=common_severity,
            common_alert_type=common_type,
            common_source=common_source,
            common_entities=common_entities,
            earliest_alert=earliest,
            latest_alert=latest,
            intra_cluster_similarity=intra_similarity,
            cluster_density=density,
        )

    def _most_common(self, items: list[Any]) -> Any | None:
        """Find most common item in list."""
        if not items:
            return None
        from collections import Counter
        counter = Counter(items)
        return counter.most_common(1)[0][0]

    def find_similar_alerts(
        self,
        alert: dict[str, Any],
        candidate_alerts: list[dict[str, Any]] | None = None,
        top_k: int = 10,
    ) -> list[tuple[str, float]]:
        """Find alerts similar to a given alert.

        Args:
            alert: Alert to find similar alerts for
            candidate_alerts: Candidate alerts (uses last clustered if None)
            top_k: Number of similar alerts to return

        Returns:
            List of (alert_id, similarity_score) tuples
        """
        candidates = candidate_alerts or self._last_alerts
        if not candidates:
            return []

        # Get embedding for query alert
        query_embedding = self.embedder.embed_single(alert)

        # Get embeddings for candidates
        if candidate_alerts is None and self._last_embeddings is not None:
            candidate_embeddings = self._last_embeddings
        else:
            candidate_embeddings = self.embedder.embed_alerts(candidates)

        # Calculate similarities
        similarities = []
        for i, candidate in enumerate(candidates):
            candidate_id = candidate.get("alert_id", f"alert_{i}")

            # Embedding similarity
            emb_sim = float(np.dot(query_embedding, candidate_embeddings[i]) / (
                np.linalg.norm(query_embedding) * np.linalg.norm(candidate_embeddings[i]) + 1e-8
            ))

            # Entity overlap
            entity_sim = self._calculate_entity_overlap(alert, candidate)

            # Combined similarity
            combined = (
                self.config.embedding_similarity_weight * emb_sim +
                self.config.entity_overlap_weight * entity_sim
            )

            similarities.append((candidate_id, combined))

        # Sort by similarity and return top_k
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]

    def _calculate_entity_overlap(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
    ) -> float:
        """Calculate entity overlap between two alerts."""
        entities1 = set()
        entities2 = set()

        # Extract entities from various fields
        entity_fields = [
            "source_ip", "dest_ip", "destination_ip",
            "hostname", "user", "username",
            "domain", "hash", "file_hash",
        ]

        for field in entity_fields:
            if val := alert1.get(field):
                entities1.add(str(val).lower())
            if val := alert2.get(field):
                entities2.add(str(val).lower())

        # Add explicit entities
        for e in alert1.get("entities", []):
            if isinstance(e, str):
                entities1.add(e.lower())
            elif isinstance(e, dict):
                entities1.add(str(e.get("value", "")).lower())

        for e in alert2.get("entities", []):
            if isinstance(e, str):
                entities2.add(e.lower())
            elif isinstance(e, dict):
                entities2.add(str(e.get("value", "")).lower())

        # Jaccard similarity
        if not entities1 or not entities2:
            return 0.0

        intersection = len(entities1 & entities2)
        union = len(entities1 | entities2)

        return intersection / union if union > 0 else 0.0

    def merge_clusters(
        self,
        cluster_ids: list[int],
        result: ClusteringResult,
    ) -> ClusteringResult:
        """Merge multiple clusters into one.

        Args:
            cluster_ids: Cluster IDs to merge
            result: Original clustering result

        Returns:
            Updated clustering result
        """
        if len(cluster_ids) < 2:
            return result

        # Find target cluster (first one)
        target_id = cluster_ids[0]

        # Update alert mappings
        new_alert_map = dict(result.alert_cluster_map)
        for alert_id, cluster_id in new_alert_map.items():
            if cluster_id in cluster_ids:
                new_alert_map[alert_id] = target_id

        # Merge cluster info
        merged_alerts = []
        for cluster in result.clusters:
            if cluster.cluster_id in cluster_ids:
                merged_alerts.extend(cluster.alert_ids)

        # Build new cluster info
        new_clusters = []
        for cluster in result.clusters:
            if cluster.cluster_id == target_id:
                # Update target cluster
                cluster.alert_ids = merged_alerts
                cluster.alert_count = len(merged_alerts)
                new_clusters.append(cluster)
            elif cluster.cluster_id not in cluster_ids:
                new_clusters.append(cluster)

        return ClusteringResult(
            total_alerts=result.total_alerts,
            total_clusters=len(new_clusters),
            noise_count=result.noise_count,
            clusters=new_clusters,
            alert_cluster_map=new_alert_map,
            silhouette_score=result.silhouette_score,
            cluster_coverage=result.cluster_coverage,
            time_window_start=result.time_window_start,
            time_window_end=result.time_window_end,
        )

    def get_cluster_summary(
        self,
        result: ClusteringResult,
    ) -> dict[str, Any]:
        """Get summary statistics for clustering result."""
        if not result.clusters:
            return {
                "total_alerts": result.total_alerts,
                "clusters": 0,
                "unclustered": result.noise_count,
            }

        cluster_sizes = [c.alert_count for c in result.clusters]

        return {
            "total_alerts": result.total_alerts,
            "clusters": result.total_clusters,
            "unclustered": result.noise_count,
            "coverage": f"{result.cluster_coverage:.1%}",
            "silhouette": result.silhouette_score,
            "avg_cluster_size": float(np.mean(cluster_sizes)),
            "max_cluster_size": int(np.max(cluster_sizes)),
            "min_cluster_size": int(np.min(cluster_sizes)),
            "severity_distribution": self._get_severity_distribution(result.clusters),
            "type_distribution": self._get_type_distribution(result.clusters),
        }

    def _get_severity_distribution(
        self,
        clusters: list[ClusterInfo],
    ) -> dict[str, int]:
        """Get severity distribution across clusters."""
        dist = {}
        for cluster in clusters:
            sev = cluster.common_severity or "unknown"
            dist[sev] = dist.get(sev, 0) + cluster.alert_count
        return dist

    def _get_type_distribution(
        self,
        clusters: list[ClusterInfo],
    ) -> dict[str, int]:
        """Get alert type distribution across clusters."""
        dist = {}
        for cluster in clusters:
            alert_type = cluster.common_alert_type or "unknown"
            dist[alert_type] = dist.get(alert_type, 0) + cluster.alert_count
        return dist
