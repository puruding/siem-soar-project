"""Feature engineering for alert classification."""

import hashlib
import re
from datetime import datetime
from typing import Any

import numpy as np
import torch
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class FeatureSpec(BaseModel):
    """Specification for a feature."""

    name: str = Field(description="Feature name")
    dtype: str = Field(default="float32", description="Data type")
    shape: list[int] = Field(default_factory=lambda: [1], description="Feature shape")
    default_value: float = Field(default=0.0, description="Default value")
    normalize: bool = Field(default=True, description="Apply normalization")


class AlertFeatures(BaseModel):
    """Extracted features from an alert."""

    # Text embeddings (from encoder)
    text_embedding: list[float] | None = Field(default=None, description="Text embedding")

    # Numeric features
    event_count: int = Field(default=1, description="Number of associated events")
    source_port: int | None = Field(default=None, description="Source port number")
    dest_port: int | None = Field(default=None, description="Destination port number")
    bytes_sent: int = Field(default=0, description="Bytes sent")
    bytes_received: int = Field(default=0, description="Bytes received")
    packet_count: int = Field(default=0, description="Number of packets")
    connection_duration: float = Field(default=0.0, description="Connection duration (seconds)")

    # Temporal features
    hour_of_day: int = Field(default=0, ge=0, le=23)
    day_of_week: int = Field(default=0, ge=0, le=6)
    is_weekend: bool = Field(default=False)
    is_business_hours: bool = Field(default=True)
    time_since_last_alert: float = Field(default=0.0, description="Seconds since last alert")

    # Categorical features (encoded)
    source_type_id: int = Field(default=0, description="Alert source type ID")
    protocol_id: int = Field(default=0, description="Network protocol ID")
    action_id: int = Field(default=0, description="Action type ID")

    # Asset features
    asset_criticality: int = Field(default=0, ge=0, le=4)
    asset_is_server: bool = Field(default=False)
    asset_is_external: bool = Field(default=False)
    asset_has_pii: bool = Field(default=False)

    # Aggregated features
    src_ip_alert_count_1h: int = Field(default=0, description="Alerts from source IP in 1h")
    src_ip_alert_count_24h: int = Field(default=0, description="Alerts from source IP in 24h")
    dst_ip_alert_count_1h: int = Field(default=0)
    dst_ip_alert_count_24h: int = Field(default=0)
    rule_fire_count_1h: int = Field(default=0, description="Rule fires in 1h")
    similar_alert_count_1h: int = Field(default=0, description="Similar alerts in 1h")

    # IP reputation features
    src_ip_reputation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    dst_ip_reputation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    src_ip_is_known_bad: bool = Field(default=False)
    dst_ip_is_known_bad: bool = Field(default=False)

    # Domain features
    domain_age_days: int = Field(default=-1, description="Domain age, -1 if unknown")
    domain_entropy: float = Field(default=0.0, description="Domain name entropy")
    domain_has_suspicious_tld: bool = Field(default=False)


class FeatureExtractor(LoggerMixin):
    """Extract features from raw alert data."""

    # Known suspicious TLDs
    SUSPICIOUS_TLDS = {
        "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
        "party", "review", "stream", "download", "racing", "win", "bid"
    }

    # Protocol mapping
    PROTOCOL_MAP = {
        "tcp": 1, "udp": 2, "icmp": 3, "http": 4, "https": 5,
        "dns": 6, "smtp": 7, "ftp": 8, "ssh": 9, "rdp": 10
    }

    # Source type mapping
    SOURCE_TYPE_MAP = {
        "firewall": 1, "ids": 2, "edr": 3, "av": 4, "proxy": 5,
        "waf": 6, "siem": 7, "dlp": 8, "email": 9, "cloud": 10
    }

    # Action mapping
    ACTION_MAP = {
        "allow": 1, "block": 2, "drop": 3, "alert": 4, "quarantine": 5,
        "redirect": 6, "reset": 7, "throttle": 8
    }

    def __init__(
        self,
        normalize_numeric: bool = True,
        include_text: bool = True,
    ) -> None:
        """Initialize the feature extractor.

        Args:
            normalize_numeric: Whether to normalize numeric features
            include_text: Whether to include text features
        """
        self.normalize_numeric = normalize_numeric
        self.include_text = include_text

        # Normalization statistics (loaded from training data)
        self._numeric_mean: dict[str, float] = {}
        self._numeric_std: dict[str, float] = {}

    def load_normalization_stats(self, stats_path: str) -> None:
        """Load normalization statistics from file."""
        import json
        with open(stats_path) as f:
            stats = json.load(f)
        self._numeric_mean = stats.get("mean", {})
        self._numeric_std = stats.get("std", {})
        self.logger.info("loaded_normalization_stats", path=stats_path)

    def extract(self, alert: dict[str, Any]) -> AlertFeatures:
        """Extract features from an alert dictionary.

        Args:
            alert: Raw alert data

        Returns:
            Extracted AlertFeatures
        """
        features = AlertFeatures()

        # Extract numeric features
        features.event_count = alert.get("event_count", 1)
        features.source_port = self._parse_port(alert.get("source_port"))
        features.dest_port = self._parse_port(alert.get("dest_port"))
        features.bytes_sent = alert.get("bytes_sent", 0) or 0
        features.bytes_received = alert.get("bytes_received", 0) or 0
        features.packet_count = alert.get("packet_count", 0) or 0
        features.connection_duration = alert.get("connection_duration", 0.0) or 0.0

        # Extract temporal features
        timestamp = self._parse_timestamp(alert.get("timestamp"))
        if timestamp:
            features.hour_of_day = timestamp.hour
            features.day_of_week = timestamp.weekday()
            features.is_weekend = timestamp.weekday() >= 5
            features.is_business_hours = 9 <= timestamp.hour < 18

        # Extract categorical features
        protocol = alert.get("protocol", "").lower()
        features.protocol_id = self.PROTOCOL_MAP.get(protocol, 0)

        source_type = alert.get("source_type", "").lower()
        features.source_type_id = self.SOURCE_TYPE_MAP.get(source_type, 0)

        action = alert.get("action", "").lower()
        features.action_id = self.ACTION_MAP.get(action, 0)

        # Extract asset features
        asset = alert.get("asset", {}) or {}
        features.asset_criticality = asset.get("criticality", 0) or 0
        features.asset_is_server = asset.get("is_server", False)
        features.asset_is_external = alert.get("is_external", False)
        features.asset_has_pii = asset.get("has_pii", False)

        # Extract aggregated features (from enrichment)
        agg = alert.get("aggregations", {}) or {}
        features.src_ip_alert_count_1h = agg.get("src_ip_alert_count_1h", 0)
        features.src_ip_alert_count_24h = agg.get("src_ip_alert_count_24h", 0)
        features.dst_ip_alert_count_1h = agg.get("dst_ip_alert_count_1h", 0)
        features.dst_ip_alert_count_24h = agg.get("dst_ip_alert_count_24h", 0)
        features.rule_fire_count_1h = agg.get("rule_fire_count_1h", 0)
        features.similar_alert_count_1h = agg.get("similar_alert_count_1h", 0)

        # Extract IP reputation features
        reputation = alert.get("reputation", {}) or {}
        features.src_ip_reputation_score = reputation.get("src_ip_score", 0.0)
        features.dst_ip_reputation_score = reputation.get("dst_ip_score", 0.0)
        features.src_ip_is_known_bad = reputation.get("src_ip_is_known_bad", False)
        features.dst_ip_is_known_bad = reputation.get("dst_ip_is_known_bad", False)

        # Extract domain features
        domain = alert.get("domain", "")
        if domain:
            features.domain_entropy = self._calculate_entropy(domain)
            features.domain_has_suspicious_tld = self._has_suspicious_tld(domain)
            features.domain_age_days = alert.get("domain_age_days", -1)

        return features

    def to_tensor(
        self,
        features: AlertFeatures,
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Convert features to tensors for model input.

        Args:
            features: Extracted features
            device: Target device

        Returns:
            Dictionary of feature tensors
        """
        # Numeric features
        numeric = np.array([
            features.event_count,
            features.source_port or 0,
            features.dest_port or 0,
            np.log1p(features.bytes_sent),
            np.log1p(features.bytes_received),
            np.log1p(features.packet_count),
            np.log1p(features.connection_duration),
            features.hour_of_day / 24.0,
            features.day_of_week / 7.0,
            float(features.is_weekend),
            float(features.is_business_hours),
            features.time_since_last_alert / 3600.0,  # Convert to hours
            features.asset_criticality / 4.0,
            float(features.asset_is_server),
            float(features.asset_is_external),
            float(features.asset_has_pii),
            np.log1p(features.src_ip_alert_count_1h),
            np.log1p(features.src_ip_alert_count_24h),
            np.log1p(features.dst_ip_alert_count_1h),
            np.log1p(features.dst_ip_alert_count_24h),
            np.log1p(features.rule_fire_count_1h),
            np.log1p(features.similar_alert_count_1h),
            features.src_ip_reputation_score,
            features.dst_ip_reputation_score,
            float(features.src_ip_is_known_bad),
            float(features.dst_ip_is_known_bad),
            features.domain_entropy,
            float(features.domain_has_suspicious_tld),
        ], dtype=np.float32)

        # Categorical features (for embedding lookup)
        categorical = np.array([
            features.source_type_id,
            features.protocol_id,
            features.action_id,
        ], dtype=np.int64)

        tensors = {
            "numeric_features": torch.tensor(numeric, device=device),
            "categorical_features": torch.tensor(categorical, device=device),
        }

        # Add text embedding if available
        if features.text_embedding is not None:
            tensors["text_embedding"] = torch.tensor(
                features.text_embedding, dtype=torch.float32, device=device
            )

        return tensors

    def batch_to_tensor(
        self,
        features_list: list[AlertFeatures],
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Convert a batch of features to tensors.

        Args:
            features_list: List of extracted features
            device: Target device

        Returns:
            Dictionary of batched feature tensors
        """
        tensors_list = [self.to_tensor(f, device) for f in features_list]

        batched = {
            "numeric_features": torch.stack([t["numeric_features"] for t in tensors_list]),
            "categorical_features": torch.stack([t["categorical_features"] for t in tensors_list]),
        }

        # Stack text embeddings if all have them
        if all("text_embedding" in t for t in tensors_list):
            batched["text_embedding"] = torch.stack([t["text_embedding"] for t in tensors_list])

        return batched

    @staticmethod
    def _parse_port(value: Any) -> int | None:
        """Parse port number from various formats."""
        if value is None:
            return None
        try:
            port = int(value)
            return port if 0 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        try:
            if isinstance(value, str):
                # ISO format
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, (int, float)):
                # Unix timestamp
                return datetime.fromtimestamp(value)
        except (ValueError, TypeError, OSError):
            pass
        return None

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)

    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check if domain has a suspicious TLD."""
        parts = domain.lower().rsplit(".", 1)
        if len(parts) < 2:
            return False
        return parts[1] in self.SUSPICIOUS_TLDS


class TextFeatureBuilder(LoggerMixin):
    """Build text features from alert content."""

    def __init__(
        self,
        max_length: int = 512,
        include_fields: list[str] | None = None,
    ) -> None:
        """Initialize the text feature builder.

        Args:
            max_length: Maximum text length
            include_fields: Fields to include in text (default: standard fields)
        """
        self.max_length = max_length
        self.include_fields = include_fields or [
            "title", "description", "rule_name", "source_name",
            "message", "raw_log", "command_line", "url", "domain"
        ]

    def build_text(self, alert: dict[str, Any]) -> str:
        """Build text representation of an alert.

        Args:
            alert: Raw alert data

        Returns:
            Combined text representation
        """
        parts = []

        for field in self.include_fields:
            value = alert.get(field)
            if value and isinstance(value, str):
                # Clean and truncate
                cleaned = self._clean_text(value)
                if cleaned:
                    parts.append(f"{field}: {cleaned}")

        text = " | ".join(parts)

        # Truncate to max length
        if len(text) > self.max_length:
            text = text[:self.max_length - 3] + "..."

        return text

    @staticmethod
    def _clean_text(text: str) -> str:
        """Clean text for processing."""
        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)
        # Remove control characters
        text = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", text)
        return text.strip()
