"""Alert Embedder - Generates embeddings for alerts using transformer models."""

from __future__ import annotations

from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class EmbeddingConfig(BaseModel):
    """Configuration for alert embedding."""

    model_name: str = Field(default="all-MiniLM-L6-v2", description="Sentence transformer model")
    embedding_dim: int = Field(default=384, description="Embedding dimension")
    max_length: int = Field(default=512, description="Maximum text length")
    batch_size: int = Field(default=32, description="Batch size for encoding")
    normalize: bool = Field(default=True, description="Normalize embeddings")
    use_gpu: bool = Field(default=False, description="Use GPU if available")

    # Fields to include in embedding text
    text_fields: list[str] = Field(
        default_factory=lambda: [
            "title", "description", "message", "rule_name", "alert_type",
            "mitre_tactic", "mitre_technique",
        ]
    )

    # Additional feature fields for hybrid embeddings
    feature_fields: list[str] = Field(
        default_factory=lambda: [
            "severity", "category", "source", "event_type",
        ]
    )


class AlertEmbedder(LoggerMixin):
    """Generates vector embeddings for security alerts.

    Features:
    - Sentence transformer embeddings for text content
    - Feature engineering for categorical attributes
    - Hybrid embedding combining text and features
    - Batch processing for efficiency

    The embedding captures semantic meaning of alert content,
    enabling similarity comparison and clustering.
    """

    # Severity encoding
    SEVERITY_ENCODING = {
        "critical": [1.0, 0.0, 0.0, 0.0],
        "high": [0.0, 1.0, 0.0, 0.0],
        "medium": [0.0, 0.0, 1.0, 0.0],
        "low": [0.0, 0.0, 0.0, 1.0],
        "info": [0.0, 0.0, 0.0, 0.5],
    }

    def __init__(self, config: EmbeddingConfig | None = None):
        """Initialize embedder.

        Args:
            config: Embedding configuration
        """
        self.config = config or EmbeddingConfig()
        self._model = None
        self._tokenizer = None

    def _load_model(self):
        """Lazy load the embedding model."""
        if self._model is not None:
            return

        try:
            from sentence_transformers import SentenceTransformer

            device = "cuda" if self.config.use_gpu else "cpu"
            self._model = SentenceTransformer(
                self.config.model_name,
                device=device,
            )
            self.logger.info("embedding_model_loaded", model=self.config.model_name)
        except ImportError:
            self.logger.warning(
                "sentence_transformers_not_available",
                msg="Falling back to simple embedding"
            )
            self._model = "fallback"

    def embed_alerts(
        self,
        alerts: list[dict[str, Any]],
    ) -> np.ndarray:
        """Generate embeddings for multiple alerts.

        Args:
            alerts: List of alert dictionaries

        Returns:
            Numpy array of shape (n_alerts, embedding_dim)
        """
        if not alerts:
            return np.array([])

        self._load_model()

        # Extract text for each alert
        texts = [self._extract_text(alert) for alert in alerts]

        # Get text embeddings
        if self._model == "fallback":
            text_embeddings = self._fallback_embedding(texts)
        else:
            text_embeddings = self._model.encode(
                texts,
                batch_size=self.config.batch_size,
                show_progress_bar=False,
                normalize_embeddings=self.config.normalize,
            )

        # Get feature embeddings
        feature_embeddings = np.array([
            self._extract_features(alert) for alert in alerts
        ])

        # Combine (80% text, 20% features)
        text_weight = 0.8
        feature_weight = 0.2

        # Normalize feature embeddings
        if feature_embeddings.shape[1] > 0:
            feature_norm = np.linalg.norm(feature_embeddings, axis=1, keepdims=True)
            feature_norm = np.where(feature_norm == 0, 1, feature_norm)
            feature_embeddings = feature_embeddings / feature_norm

        # Combine embeddings
        # First, adjust dimensions
        text_dim = text_embeddings.shape[1]
        feature_dim = feature_embeddings.shape[1]

        # Pad features to match expected ratio
        if feature_dim < text_dim // 4:
            padding = np.zeros((len(alerts), text_dim // 4 - feature_dim))
            feature_embeddings = np.concatenate([feature_embeddings, padding], axis=1)

        # Scale and concatenate
        combined = np.concatenate([
            text_embeddings * text_weight,
            feature_embeddings[:, :text_dim // 4] * feature_weight,
        ], axis=1)

        # Truncate or pad to target dimension
        if combined.shape[1] != self.config.embedding_dim:
            if combined.shape[1] > self.config.embedding_dim:
                combined = combined[:, :self.config.embedding_dim]
            else:
                padding = np.zeros((len(alerts), self.config.embedding_dim - combined.shape[1]))
                combined = np.concatenate([combined, padding], axis=1)

        if self.config.normalize:
            norms = np.linalg.norm(combined, axis=1, keepdims=True)
            norms = np.where(norms == 0, 1, norms)
            combined = combined / norms

        return combined

    def embed_single(self, alert: dict[str, Any]) -> np.ndarray:
        """Generate embedding for a single alert.

        Args:
            alert: Alert dictionary

        Returns:
            Embedding vector
        """
        embeddings = self.embed_alerts([alert])
        return embeddings[0]

    def _extract_text(self, alert: dict[str, Any]) -> str:
        """Extract text content from alert for embedding."""
        parts = []

        for field in self.config.text_fields:
            if value := alert.get(field):
                if isinstance(value, str):
                    parts.append(value)
                elif isinstance(value, list):
                    parts.extend(str(v) for v in value)

        # Add entities if present
        if entities := alert.get("entities"):
            if isinstance(entities, list):
                for entity in entities[:10]:
                    if isinstance(entity, str):
                        parts.append(entity)
                    elif isinstance(entity, dict):
                        if val := entity.get("value"):
                            parts.append(f"{entity.get('type', 'entity')}:{val}")

        text = " ".join(parts)

        # Truncate to max length
        if len(text) > self.config.max_length * 4:  # Approximate char limit
            text = text[:self.config.max_length * 4]

        return text or "empty alert"

    def _extract_features(self, alert: dict[str, Any]) -> np.ndarray:
        """Extract numerical features from alert."""
        features = []

        # Severity one-hot encoding
        severity = str(alert.get("severity", "medium")).lower()
        severity_vec = self.SEVERITY_ENCODING.get(severity, [0.0, 0.0, 1.0, 0.0])
        features.extend(severity_vec)

        # Category hash features
        category = str(alert.get("category", "")).lower()
        category_hash = self._hash_to_features(category, 8)
        features.extend(category_hash)

        # Source hash features
        source = str(alert.get("source", "")).lower()
        source_hash = self._hash_to_features(source, 8)
        features.extend(source_hash)

        # Alert type hash features
        alert_type = str(alert.get("alert_type", "")).lower()
        type_hash = self._hash_to_features(alert_type, 8)
        features.extend(type_hash)

        # MITRE encoding
        mitre_features = self._encode_mitre(alert)
        features.extend(mitre_features)

        # Numerical features
        features.append(self._normalize_count(len(alert.get("entities", [])), 100))
        features.append(self._normalize_count(len(alert.get("source_events", [])), 50))

        return np.array(features, dtype=np.float32)

    def _hash_to_features(self, text: str, dim: int) -> list[float]:
        """Hash string to fixed-size feature vector."""
        import hashlib

        if not text:
            return [0.0] * dim

        hash_bytes = hashlib.md5(text.encode()).digest()[:dim]
        return [b / 255.0 for b in hash_bytes]

    def _encode_mitre(self, alert: dict[str, Any]) -> list[float]:
        """Encode MITRE ATT&CK information."""
        # Simplified MITRE tactic encoding (14 tactics)
        tactic_ids = {
            "reconnaissance": 0, "resource-development": 1, "initial-access": 2,
            "execution": 3, "persistence": 4, "privilege-escalation": 5,
            "defense-evasion": 6, "credential-access": 7, "discovery": 8,
            "lateral-movement": 9, "collection": 10, "command-and-control": 11,
            "exfiltration": 12, "impact": 13,
        }

        features = [0.0] * 14

        tactics = alert.get("mitre_tactics") or alert.get("mitre_tactic", [])
        if isinstance(tactics, str):
            tactics = [tactics]
        elif not isinstance(tactics, list):
            tactics = []

        for tactic in tactics:
            tactic_lower = tactic.lower().replace("_", "-")
            if idx := tactic_ids.get(tactic_lower):
                features[idx] = 1.0

        return features

    def _normalize_count(self, count: int, max_expected: int) -> float:
        """Normalize count to 0-1 range."""
        return min(count / max_expected, 1.0)

    def _fallback_embedding(self, texts: list[str]) -> np.ndarray:
        """Generate fallback embeddings using TF-IDF-like approach."""
        from collections import Counter
        import hashlib

        dim = self.config.embedding_dim
        embeddings = []

        for text in texts:
            # Simple word-based embedding
            words = text.lower().split()
            word_counts = Counter(words)

            # Hash each word to fixed positions
            embedding = np.zeros(dim, dtype=np.float32)
            for word, count in word_counts.items():
                # Hash word to get position
                hash_val = int(hashlib.md5(word.encode()).hexdigest()[:8], 16)
                pos = hash_val % dim

                # Add weighted contribution (TF-like)
                tf = np.log1p(count)
                embedding[pos] += tf

            # Normalize
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = embedding / norm

            embeddings.append(embedding)

        return np.array(embeddings, dtype=np.float32)

    def similarity(
        self,
        embedding1: np.ndarray,
        embedding2: np.ndarray,
    ) -> float:
        """Calculate cosine similarity between embeddings."""
        norm1 = np.linalg.norm(embedding1)
        norm2 = np.linalg.norm(embedding2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(np.dot(embedding1, embedding2) / (norm1 * norm2))

    def batch_similarity(
        self,
        embeddings1: np.ndarray,
        embeddings2: np.ndarray,
    ) -> np.ndarray:
        """Calculate pairwise similarities between two sets of embeddings.

        Args:
            embeddings1: First set of embeddings (n, dim)
            embeddings2: Second set of embeddings (m, dim)

        Returns:
            Similarity matrix (n, m)
        """
        # Normalize
        norms1 = np.linalg.norm(embeddings1, axis=1, keepdims=True)
        norms2 = np.linalg.norm(embeddings2, axis=1, keepdims=True)

        norms1 = np.where(norms1 == 0, 1, norms1)
        norms2 = np.where(norms2 == 0, 1, norms2)

        normalized1 = embeddings1 / norms1
        normalized2 = embeddings2 / norms2

        # Compute similarities via matrix multiplication
        similarities = np.dot(normalized1, normalized2.T)

        return similarities

    def save_embeddings(
        self,
        embeddings: np.ndarray,
        alert_ids: list[str],
        path: str,
    ) -> None:
        """Save embeddings to file."""
        np.savez(
            path,
            embeddings=embeddings,
            alert_ids=np.array(alert_ids, dtype=object),
        )
        self.logger.info("embeddings_saved", path=path, count=len(alert_ids))

    def load_embeddings(
        self,
        path: str,
    ) -> tuple[np.ndarray, list[str]]:
        """Load embeddings from file."""
        data = np.load(path, allow_pickle=True)
        embeddings = data["embeddings"]
        alert_ids = data["alert_ids"].tolist()
        self.logger.info("embeddings_loaded", path=path, count=len(alert_ids))
        return embeddings, alert_ids

    def get_embedding_stats(
        self,
        embeddings: np.ndarray,
    ) -> dict[str, Any]:
        """Get statistics about embeddings."""
        norms = np.linalg.norm(embeddings, axis=1)

        return {
            "count": len(embeddings),
            "dimension": embeddings.shape[1],
            "mean_norm": float(np.mean(norms)),
            "std_norm": float(np.std(norms)),
            "min_norm": float(np.min(norms)),
            "max_norm": float(np.max(norms)),
            "mean_embedding": embeddings.mean(axis=0).tolist()[:10],  # First 10 dims
        }
