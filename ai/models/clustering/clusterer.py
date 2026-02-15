"""Alert Clusterer - Core clustering algorithms for alert grouping."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ClusterAssignment(BaseModel):
    """Single cluster assignment."""

    alert_id: str = Field(description="Alert identifier")
    cluster_id: int = Field(description="Assigned cluster (-1 for noise)")
    confidence: float = Field(ge=0.0, le=1.0, description="Assignment confidence")
    distance_to_centroid: float = Field(default=0.0, description="Distance to cluster center")


class ClusterMetadata(BaseModel):
    """Metadata about a cluster."""

    cluster_id: int = Field(description="Cluster identifier")
    size: int = Field(default=0, description="Number of members")
    centroid: list[float] | None = Field(default=None, description="Cluster centroid")
    radius: float = Field(default=0.0, description="Cluster radius")
    density: float = Field(default=0.0, description="Cluster density")
    cohesion: float = Field(default=0.0, description="Intra-cluster similarity")


class BaseClusterer(ABC, LoggerMixin):
    """Abstract base class for clustering algorithms."""

    @abstractmethod
    def fit(self, embeddings: np.ndarray) -> None:
        """Fit clusterer to data."""
        pass

    @abstractmethod
    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Predict cluster labels for embeddings."""
        pass

    @abstractmethod
    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Fit and predict in one step."""
        pass


class HDBSCANClusterer(BaseClusterer):
    """HDBSCAN-based clustering for alerts.

    HDBSCAN is well-suited for alert clustering because:
    - Automatically determines number of clusters
    - Handles varying cluster densities
    - Identifies noise/outliers
    - Does not require cluster count specification
    """

    def __init__(
        self,
        min_cluster_size: int = 3,
        min_samples: int = 2,
        cluster_selection_epsilon: float = 0.3,
        metric: str = "euclidean",
        algorithm: str = "best",
    ):
        """Initialize HDBSCAN clusterer.

        Args:
            min_cluster_size: Minimum cluster size
            min_samples: Minimum samples for core point
            cluster_selection_epsilon: Cluster selection epsilon
            metric: Distance metric
            algorithm: Algorithm for tree construction
        """
        self.min_cluster_size = min_cluster_size
        self.min_samples = min_samples
        self.cluster_selection_epsilon = cluster_selection_epsilon
        self.metric = metric
        self.algorithm = algorithm
        self._clusterer = None

    def fit(self, embeddings: np.ndarray) -> None:
        """Fit HDBSCAN to embeddings."""
        from sklearn.cluster import HDBSCAN

        self._clusterer = HDBSCAN(
            min_cluster_size=self.min_cluster_size,
            min_samples=self.min_samples,
            cluster_selection_epsilon=self.cluster_selection_epsilon,
            metric=self.metric,
            algorithm=self.algorithm,
        )
        self._clusterer.fit(embeddings)

    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Predict clusters for new embeddings.

        Note: HDBSCAN doesn't support traditional predict, so we use
        approximate_predict or nearest centroid assignment.
        """
        if self._clusterer is None:
            raise ValueError("Clusterer must be fitted first")

        try:
            # Try to use approximate_predict if available
            from hdbscan import prediction
            labels, _ = prediction.approximate_predict(
                self._clusterer, embeddings
            )
            return labels
        except (ImportError, AttributeError):
            # Fall back to nearest neighbor assignment
            self.logger.warning("approximate_predict_unavailable", msg="Using nearest centroid")
            return self._nearest_centroid_predict(embeddings)

    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Fit and predict in one step."""
        self.fit(embeddings)
        return self._clusterer.labels_

    def _nearest_centroid_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Assign to nearest cluster centroid."""
        if not hasattr(self, "_centroids") or self._centroids is None:
            return np.full(len(embeddings), -1)

        distances = np.linalg.norm(
            embeddings[:, np.newaxis] - self._centroids[np.newaxis, :],
            axis=2,
        )
        labels = distances.argmin(axis=1)

        # Mark as noise if too far from centroid
        min_distances = distances.min(axis=1)
        threshold = np.mean(min_distances) + 2 * np.std(min_distances)
        labels[min_distances > threshold] = -1

        return labels

    def get_cluster_persistence(self) -> np.ndarray | None:
        """Get cluster persistence (stability) scores."""
        if self._clusterer is None:
            return None
        return getattr(self._clusterer, "cluster_persistence_", None)


class DBSCANClusterer(BaseClusterer):
    """DBSCAN-based clustering for alerts.

    Simpler than HDBSCAN, requires epsilon parameter but is faster.
    """

    def __init__(
        self,
        eps: float = 0.5,
        min_samples: int = 2,
        metric: str = "euclidean",
    ):
        """Initialize DBSCAN clusterer."""
        self.eps = eps
        self.min_samples = min_samples
        self.metric = metric
        self._clusterer = None

    def fit(self, embeddings: np.ndarray) -> None:
        """Fit DBSCAN to embeddings."""
        from sklearn.cluster import DBSCAN

        self._clusterer = DBSCAN(
            eps=self.eps,
            min_samples=self.min_samples,
            metric=self.metric,
        )
        self._clusterer.fit(embeddings)

    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Predict clusters for new embeddings."""
        if self._clusterer is None:
            raise ValueError("Clusterer must be fitted first")

        # DBSCAN doesn't support predict, use nearest core sample
        core_samples = self._clusterer.components_
        core_labels = self._clusterer.labels_[self._clusterer.core_sample_indices_]

        if len(core_samples) == 0:
            return np.full(len(embeddings), -1)

        # Assign to nearest core sample
        distances = np.linalg.norm(
            embeddings[:, np.newaxis] - core_samples[np.newaxis, :],
            axis=2,
        )
        nearest_core = distances.argmin(axis=1)
        min_distances = distances.min(axis=1)

        labels = core_labels[nearest_core]
        labels[min_distances > self.eps] = -1

        return labels

    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Fit and predict in one step."""
        self.fit(embeddings)
        return self._clusterer.labels_


class AgglomerativeClusterer(BaseClusterer):
    """Agglomerative hierarchical clustering.

    Useful when cluster hierarchy matters or when number of clusters is known.
    """

    def __init__(
        self,
        n_clusters: int | None = None,
        distance_threshold: float | None = 0.5,
        linkage: str = "average",
        affinity: str = "euclidean",
    ):
        """Initialize agglomerative clusterer.

        Either n_clusters or distance_threshold must be set.
        """
        self.n_clusters = n_clusters
        self.distance_threshold = distance_threshold
        self.linkage = linkage
        self.affinity = affinity
        self._clusterer = None
        self._training_embeddings = None

    def fit(self, embeddings: np.ndarray) -> None:
        """Fit agglomerative clustering."""
        from sklearn.cluster import AgglomerativeClustering

        self._clusterer = AgglomerativeClustering(
            n_clusters=self.n_clusters,
            distance_threshold=self.distance_threshold,
            linkage=self.linkage,
            metric=self.affinity if self.n_clusters is None else "euclidean",
        )
        self._clusterer.fit(embeddings)
        self._training_embeddings = embeddings
        self._labels = self._clusterer.labels_

    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Predict by assigning to nearest cluster centroid."""
        if self._clusterer is None:
            raise ValueError("Clusterer must be fitted first")

        # Calculate centroids
        unique_labels = set(self._labels)
        centroids = []
        label_map = []

        for label in unique_labels:
            mask = self._labels == label
            centroid = self._training_embeddings[mask].mean(axis=0)
            centroids.append(centroid)
            label_map.append(label)

        centroids = np.array(centroids)

        # Assign to nearest
        distances = np.linalg.norm(
            embeddings[:, np.newaxis] - centroids[np.newaxis, :],
            axis=2,
        )
        nearest_idx = distances.argmin(axis=1)
        labels = np.array([label_map[i] for i in nearest_idx])

        return labels

    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Fit and predict."""
        self.fit(embeddings)
        return self._labels


class OnlineClusterer(BaseClusterer):
    """Online clustering for streaming alerts.

    Maintains clusters incrementally as new alerts arrive.
    Uses a combination of nearest centroid assignment and cluster updates.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.7,
        max_clusters: int = 100,
        min_cluster_age_minutes: int = 60,
        decay_factor: float = 0.95,
    ):
        """Initialize online clusterer.

        Args:
            similarity_threshold: Minimum similarity to join cluster
            max_clusters: Maximum number of active clusters
            min_cluster_age_minutes: Min age before cluster can be retired
            decay_factor: Factor to decay old cluster weights
        """
        self.similarity_threshold = similarity_threshold
        self.max_clusters = max_clusters
        self.min_cluster_age = timedelta(minutes=min_cluster_age_minutes)
        self.decay_factor = decay_factor

        # Cluster state
        self._centroids: list[np.ndarray] = []
        self._cluster_sizes: list[int] = []
        self._cluster_created: list[datetime] = []
        self._cluster_updated: list[datetime] = []
        self._next_cluster_id = 0

    def fit(self, embeddings: np.ndarray) -> None:
        """Initialize with a batch of embeddings."""
        # Process each embedding
        for emb in embeddings:
            self._add_embedding(emb)

    def predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Assign embeddings to existing clusters."""
        labels = []
        for emb in embeddings:
            label = self._find_nearest_cluster(emb)
            labels.append(label)
        return np.array(labels)

    def fit_predict(self, embeddings: np.ndarray) -> np.ndarray:
        """Add embeddings and return their cluster assignments."""
        labels = []
        for emb in embeddings:
            label = self._add_embedding(emb)
            labels.append(label)
        return np.array(labels)

    def _add_embedding(self, embedding: np.ndarray) -> int:
        """Add single embedding to clusters."""
        now = datetime.utcnow()

        # Find nearest cluster
        best_cluster = -1
        best_similarity = -1

        for i, centroid in enumerate(self._centroids):
            similarity = self._cosine_similarity(embedding, centroid)
            if similarity > best_similarity:
                best_similarity = similarity
                best_cluster = i

        if best_similarity >= self.similarity_threshold:
            # Update existing cluster
            self._update_cluster(best_cluster, embedding)
            return best_cluster
        else:
            # Create new cluster
            cluster_id = self._create_cluster(embedding)
            self._maybe_retire_clusters()
            return cluster_id

    def _find_nearest_cluster(self, embedding: np.ndarray) -> int:
        """Find nearest cluster without updating."""
        if not self._centroids:
            return -1

        best_cluster = -1
        best_similarity = -1

        for i, centroid in enumerate(self._centroids):
            similarity = self._cosine_similarity(embedding, centroid)
            if similarity > best_similarity:
                best_similarity = similarity
                best_cluster = i

        if best_similarity >= self.similarity_threshold:
            return best_cluster
        return -1

    def _create_cluster(self, embedding: np.ndarray) -> int:
        """Create new cluster."""
        now = datetime.utcnow()
        cluster_id = self._next_cluster_id
        self._next_cluster_id += 1

        self._centroids.append(embedding.copy())
        self._cluster_sizes.append(1)
        self._cluster_created.append(now)
        self._cluster_updated.append(now)

        return cluster_id

    def _update_cluster(self, cluster_idx: int, embedding: np.ndarray) -> None:
        """Update cluster with new embedding."""
        now = datetime.utcnow()

        # Online centroid update
        n = self._cluster_sizes[cluster_idx]
        old_centroid = self._centroids[cluster_idx]
        new_centroid = (old_centroid * n + embedding) / (n + 1)

        self._centroids[cluster_idx] = new_centroid
        self._cluster_sizes[cluster_idx] = n + 1
        self._cluster_updated[cluster_idx] = now

    def _maybe_retire_clusters(self) -> None:
        """Retire old/small clusters if at max capacity."""
        if len(self._centroids) <= self.max_clusters:
            return

        now = datetime.utcnow()

        # Find clusters to retire
        to_retire = []
        for i in range(len(self._centroids)):
            age = now - self._cluster_created[i]
            staleness = now - self._cluster_updated[i]

            # Retire old small clusters or very stale clusters
            if age > self.min_cluster_age:
                if self._cluster_sizes[i] <= 2:
                    to_retire.append(i)
                elif staleness > timedelta(hours=24):
                    to_retire.append(i)

        # Retire oldest first if still over capacity
        while len(self._centroids) - len(to_retire) > self.max_clusters:
            remaining = [i for i in range(len(self._centroids)) if i not in to_retire]
            oldest = min(remaining, key=lambda i: self._cluster_created[i])
            to_retire.append(oldest)

        # Remove retired clusters (in reverse order to maintain indices)
        for i in sorted(to_retire, reverse=True):
            del self._centroids[i]
            del self._cluster_sizes[i]
            del self._cluster_created[i]
            del self._cluster_updated[i]

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity."""
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))

    def get_cluster_stats(self) -> list[dict[str, Any]]:
        """Get statistics for all clusters."""
        stats = []
        now = datetime.utcnow()

        for i in range(len(self._centroids)):
            stats.append({
                "cluster_id": i,
                "size": self._cluster_sizes[i],
                "age_hours": (now - self._cluster_created[i]).total_seconds() / 3600,
                "staleness_minutes": (now - self._cluster_updated[i]).total_seconds() / 60,
            })

        return stats


def calculate_cluster_metrics(
    embeddings: np.ndarray,
    labels: np.ndarray,
) -> dict[str, float]:
    """Calculate clustering quality metrics.

    Args:
        embeddings: Embedding matrix
        labels: Cluster labels

    Returns:
        Dictionary of metrics
    """
    from sklearn.metrics import silhouette_score, calinski_harabasz_score, davies_bouldin_score

    metrics = {}

    # Filter out noise points
    valid_mask = labels >= 0
    valid_embeddings = embeddings[valid_mask]
    valid_labels = labels[valid_mask]

    n_clusters = len(set(valid_labels))

    if n_clusters < 2 or len(valid_labels) < n_clusters:
        return {
            "n_clusters": n_clusters,
            "noise_ratio": 1 - valid_mask.mean(),
        }

    try:
        metrics["silhouette"] = float(silhouette_score(valid_embeddings, valid_labels))
    except:
        metrics["silhouette"] = 0.0

    try:
        metrics["calinski_harabasz"] = float(calinski_harabasz_score(valid_embeddings, valid_labels))
    except:
        metrics["calinski_harabasz"] = 0.0

    try:
        metrics["davies_bouldin"] = float(davies_bouldin_score(valid_embeddings, valid_labels))
    except:
        metrics["davies_bouldin"] = 0.0

    metrics["n_clusters"] = n_clusters
    metrics["noise_ratio"] = float(1 - valid_mask.mean())
    metrics["avg_cluster_size"] = float(len(valid_labels) / n_clusters)

    return metrics
