"""Alert Clustering module.

Provides clustering capabilities for security alerts:
- Embedding-based similarity clustering
- HDBSCAN for automatic cluster detection
- Alert deduplication and grouping
- Incident correlation
"""

from .model import (
    AlertClusteringModel,
    ClusteringConfig,
    ClusteringResult,
)
from .similarity import (
    AlertSimilarityEngine,
    SimilarityMetric,
    SimilarityScore,
)
from .embedder import (
    AlertEmbedder,
    EmbeddingConfig,
)

__all__ = [
    # Core model
    "AlertClusteringModel",
    "ClusteringConfig",
    "ClusteringResult",
    # Similarity
    "AlertSimilarityEngine",
    "SimilarityMetric",
    "SimilarityScore",
    # Embedding
    "AlertEmbedder",
    "EmbeddingConfig",
]
