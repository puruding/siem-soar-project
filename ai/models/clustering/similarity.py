"""Alert Similarity Engine - Calculates similarity between alerts."""

from __future__ import annotations

from enum import Enum
from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class SimilarityMetric(str, Enum):
    """Types of similarity metrics."""

    COSINE = "cosine"
    EUCLIDEAN = "euclidean"
    JACCARD = "jaccard"
    COMBINED = "combined"


class SimilarityScore(BaseModel):
    """Detailed similarity score between two alerts."""

    overall_score: float = Field(ge=0.0, le=1.0, description="Combined similarity score")

    # Component scores
    embedding_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    entity_overlap: float = Field(ge=0.0, le=1.0, default=0.0)
    attribute_similarity: float = Field(ge=0.0, le=1.0, default=0.0)
    temporal_proximity: float = Field(ge=0.0, le=1.0, default=0.0)
    text_similarity: float = Field(ge=0.0, le=1.0, default=0.0)

    # Context
    matching_entities: list[str] = Field(default_factory=list)
    matching_attributes: list[str] = Field(default_factory=list)


class AlertSimilarityEngine(LoggerMixin):
    """Engine for calculating similarity between security alerts.

    Supports multiple similarity metrics:
    - Embedding cosine similarity
    - Entity overlap (Jaccard)
    - Attribute matching
    - Temporal proximity
    - Text similarity (TF-IDF, fuzzy matching)
    """

    # Entity extraction fields
    ENTITY_FIELDS = [
        "source_ip", "src_ip", "destination_ip", "dest_ip",
        "hostname", "src_hostname", "dst_hostname",
        "user", "username", "user_id",
        "domain", "url",
        "file_hash", "md5", "sha256", "sha1",
        "process_name", "process_id",
    ]

    # Attribute fields for comparison
    ATTRIBUTE_FIELDS = [
        "severity", "alert_type", "category", "rule_id",
        "mitre_tactic", "mitre_technique", "source",
        "event_type", "action", "status",
    ]

    # Text fields for similarity
    TEXT_FIELDS = [
        "title", "description", "message", "raw_log",
    ]

    def __init__(
        self,
        weights: dict[str, float] | None = None,
    ):
        """Initialize similarity engine.

        Args:
            weights: Custom weights for similarity components
        """
        self.weights = weights or {
            "embedding": 0.35,
            "entity": 0.25,
            "attribute": 0.20,
            "temporal": 0.10,
            "text": 0.10,
        }

    def calculate_similarity(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
        embedding1: np.ndarray | None = None,
        embedding2: np.ndarray | None = None,
    ) -> SimilarityScore:
        """Calculate comprehensive similarity between two alerts.

        Args:
            alert1: First alert
            alert2: Second alert
            embedding1: Pre-computed embedding for alert1
            embedding2: Pre-computed embedding for alert2

        Returns:
            Detailed similarity score
        """
        # Calculate component similarities
        entity_sim, matching_entities = self._entity_similarity(alert1, alert2)
        attr_sim, matching_attrs = self._attribute_similarity(alert1, alert2)
        temporal_sim = self._temporal_similarity(alert1, alert2)
        text_sim = self._text_similarity(alert1, alert2)

        # Embedding similarity
        emb_sim = 0.0
        if embedding1 is not None and embedding2 is not None:
            emb_sim = self._embedding_similarity(embedding1, embedding2)

        # Weighted combination
        overall = (
            self.weights["embedding"] * emb_sim +
            self.weights["entity"] * entity_sim +
            self.weights["attribute"] * attr_sim +
            self.weights["temporal"] * temporal_sim +
            self.weights["text"] * text_sim
        )

        # Normalize by active weights
        total_weight = sum(
            w for k, w in self.weights.items()
            if k != "embedding" or (embedding1 is not None and embedding2 is not None)
        )
        if total_weight > 0:
            overall = overall / total_weight

        return SimilarityScore(
            overall_score=min(1.0, overall),
            embedding_similarity=emb_sim,
            entity_overlap=entity_sim,
            attribute_similarity=attr_sim,
            temporal_proximity=temporal_sim,
            text_similarity=text_sim,
            matching_entities=matching_entities,
            matching_attributes=matching_attrs,
        )

    def _entity_similarity(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
    ) -> tuple[float, list[str]]:
        """Calculate entity overlap similarity."""
        entities1 = self._extract_entities(alert1)
        entities2 = self._extract_entities(alert2)

        if not entities1 or not entities2:
            return 0.0, []

        intersection = entities1 & entities2
        union = entities1 | entities2

        jaccard = len(intersection) / len(union) if union else 0.0

        return jaccard, list(intersection)

    def _extract_entities(self, alert: dict[str, Any]) -> set[str]:
        """Extract entity values from alert."""
        entities = set()

        for field in self.ENTITY_FIELDS:
            if value := alert.get(field):
                if isinstance(value, str):
                    entities.add(value.lower())
                elif isinstance(value, list):
                    entities.update(str(v).lower() for v in value)

        # Handle nested entities field
        if alert_entities := alert.get("entities"):
            if isinstance(alert_entities, list):
                for e in alert_entities:
                    if isinstance(e, str):
                        entities.add(e.lower())
                    elif isinstance(e, dict):
                        if val := e.get("value"):
                            entities.add(str(val).lower())

        return entities

    def _attribute_similarity(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
    ) -> tuple[float, list[str]]:
        """Calculate attribute matching similarity."""
        matching = []
        total_compared = 0

        for field in self.ATTRIBUTE_FIELDS:
            val1 = alert1.get(field)
            val2 = alert2.get(field)

            if val1 is not None and val2 is not None:
                total_compared += 1
                if self._values_match(val1, val2):
                    matching.append(field)

        if total_compared == 0:
            return 0.0, []

        similarity = len(matching) / total_compared
        return similarity, matching

    def _values_match(self, val1: Any, val2: Any) -> bool:
        """Check if two values match."""
        if val1 == val2:
            return True

        # Handle string comparison (case insensitive)
        if isinstance(val1, str) and isinstance(val2, str):
            return val1.lower() == val2.lower()

        # Handle list overlap
        if isinstance(val1, list) and isinstance(val2, list):
            return bool(set(val1) & set(val2))

        return False

    def _temporal_similarity(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
    ) -> float:
        """Calculate temporal proximity similarity."""
        from datetime import datetime, timedelta

        ts1 = self._parse_timestamp(alert1)
        ts2 = self._parse_timestamp(alert2)

        if not ts1 or not ts2:
            return 0.5  # Neutral if timestamps unavailable

        # Calculate time difference
        diff = abs((ts1 - ts2).total_seconds())

        # Convert to similarity (exponential decay)
        # 1 hour apart = ~0.5 similarity
        # 1 day apart = ~0.05 similarity
        decay_rate = 1.0 / 3600  # 1 hour half-life
        similarity = np.exp(-decay_rate * diff)

        return float(similarity)

    def _parse_timestamp(self, alert: dict[str, Any]) -> datetime | None:
        """Parse timestamp from alert."""
        from datetime import datetime

        ts = alert.get("created_at") or alert.get("timestamp")

        if ts is None:
            return None

        if isinstance(ts, datetime):
            return ts

        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                pass

        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts)
            except (ValueError, OSError):
                pass

        return None

    def _text_similarity(
        self,
        alert1: dict[str, Any],
        alert2: dict[str, Any],
    ) -> float:
        """Calculate text similarity using token overlap."""
        text1 = self._extract_text(alert1)
        text2 = self._extract_text(alert2)

        if not text1 or not text2:
            return 0.0

        # Tokenize
        tokens1 = set(self._tokenize(text1))
        tokens2 = set(self._tokenize(text2))

        if not tokens1 or not tokens2:
            return 0.0

        # Jaccard similarity of tokens
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        return intersection / union if union else 0.0

    def _extract_text(self, alert: dict[str, Any]) -> str:
        """Extract text content from alert."""
        texts = []
        for field in self.TEXT_FIELDS:
            if value := alert.get(field):
                if isinstance(value, str):
                    texts.append(value)
        return " ".join(texts)

    def _tokenize(self, text: str) -> list[str]:
        """Tokenize text for similarity calculation."""
        import re

        # Lowercase and split on non-alphanumeric
        tokens = re.split(r'\W+', text.lower())

        # Filter stopwords and short tokens
        stopwords = {"the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "to", "for"}
        tokens = [t for t in tokens if t and len(t) > 2 and t not in stopwords]

        return tokens

    def _embedding_similarity(
        self,
        embedding1: np.ndarray,
        embedding2: np.ndarray,
        metric: SimilarityMetric = SimilarityMetric.COSINE,
    ) -> float:
        """Calculate embedding similarity."""
        if metric == SimilarityMetric.COSINE:
            # Cosine similarity
            norm1 = np.linalg.norm(embedding1)
            norm2 = np.linalg.norm(embedding2)
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return float(np.dot(embedding1, embedding2) / (norm1 * norm2))

        elif metric == SimilarityMetric.EUCLIDEAN:
            # Convert distance to similarity
            distance = np.linalg.norm(embedding1 - embedding2)
            return float(1.0 / (1.0 + distance))

        else:
            return 0.0

    def batch_similarity(
        self,
        alerts: list[dict[str, Any]],
        embeddings: np.ndarray | None = None,
    ) -> np.ndarray:
        """Calculate pairwise similarity matrix for all alerts.

        Args:
            alerts: List of alerts
            embeddings: Pre-computed embeddings

        Returns:
            Similarity matrix of shape (n_alerts, n_alerts)
        """
        n = len(alerts)
        similarity_matrix = np.zeros((n, n))

        for i in range(n):
            similarity_matrix[i, i] = 1.0  # Self-similarity
            for j in range(i + 1, n):
                emb1 = embeddings[i] if embeddings is not None else None
                emb2 = embeddings[j] if embeddings is not None else None

                score = self.calculate_similarity(alerts[i], alerts[j], emb1, emb2)
                similarity_matrix[i, j] = score.overall_score
                similarity_matrix[j, i] = score.overall_score

        return similarity_matrix

    def find_matches(
        self,
        alert: dict[str, Any],
        candidates: list[dict[str, Any]],
        threshold: float = 0.7,
        embeddings: np.ndarray | None = None,
        alert_embedding: np.ndarray | None = None,
    ) -> list[tuple[int, SimilarityScore]]:
        """Find matching alerts above similarity threshold.

        Args:
            alert: Query alert
            candidates: Candidate alerts
            threshold: Minimum similarity score
            embeddings: Pre-computed embeddings for candidates
            alert_embedding: Pre-computed embedding for query alert

        Returns:
            List of (index, similarity_score) tuples
        """
        matches = []

        for i, candidate in enumerate(candidates):
            emb = embeddings[i] if embeddings is not None else None
            score = self.calculate_similarity(alert, candidate, alert_embedding, emb)

            if score.overall_score >= threshold:
                matches.append((i, score))

        # Sort by similarity descending
        matches.sort(key=lambda x: x[1].overall_score, reverse=True)

        return matches

    def explain_similarity(
        self,
        score: SimilarityScore,
    ) -> str:
        """Generate human-readable explanation of similarity score."""
        explanations = []

        if score.embedding_similarity > 0.7:
            explanations.append("highly similar content patterns")
        elif score.embedding_similarity > 0.5:
            explanations.append("moderately similar content")

        if score.entity_overlap > 0.5:
            explanations.append(f"shared entities: {', '.join(score.matching_entities[:5])}")

        if score.attribute_similarity > 0.7:
            explanations.append(f"matching attributes: {', '.join(score.matching_attributes[:3])}")

        if score.temporal_proximity > 0.8:
            explanations.append("occurred at similar time")

        if score.text_similarity > 0.5:
            explanations.append("similar text content")

        if not explanations:
            if score.overall_score > 0.5:
                explanations.append("moderate general similarity")
            else:
                explanations.append("low overall similarity")

        return f"Similarity: {score.overall_score:.1%}. " + "; ".join(explanations) + "."
