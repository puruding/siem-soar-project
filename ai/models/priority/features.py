"""Feature extraction for priority scoring."""

from datetime import datetime
from typing import Any

import numpy as np
import torch

from common.logging import LoggerMixin


class PriorityFeatureExtractor(LoggerMixin):
    """Extract features for priority scoring model."""

    # Severity encoding
    SEVERITY_MAP = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    # Category encoding
    CATEGORY_MAP = {
        "malware": 0,
        "intrusion": 1,
        "data_exfiltration": 2,
        "privilege_escalation": 3,
        "lateral_movement": 4,
        "credential_access": 5,
        "reconnaissance": 6,
        "command_and_control": 7,
        "impact": 8,
        "policy_violation": 9,
        "anomaly": 10,
        "other": 11,
    }

    def __init__(
        self,
        num_numeric_features: int = 32,
    ) -> None:
        """Initialize the feature extractor.

        Args:
            num_numeric_features: Expected number of numeric features
        """
        self.num_numeric_features = num_numeric_features

    def extract(
        self,
        alert: dict[str, Any],
    ) -> dict[str, np.ndarray]:
        """Extract features from an alert.

        Args:
            alert: Alert dictionary

        Returns:
            Dictionary with extracted features
        """
        # Extract numeric features
        numeric = self._extract_numeric_features(alert)

        # Extract categorical features
        severity = self._encode_severity(alert.get("severity", "medium"))
        category = self._encode_category(alert.get("category", "other"))
        asset_criticality = alert.get("asset_criticality", 2)

        return {
            "numeric_features": numeric,
            "severity": severity,
            "category": category,
            "asset_criticality": asset_criticality,
        }

    def to_tensor(
        self,
        features: dict[str, Any],
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Convert features to tensors.

        Args:
            features: Extracted features
            device: Target device

        Returns:
            Dictionary of tensors
        """
        return {
            "numeric_features": torch.tensor(
                features["numeric_features"], dtype=torch.float32, device=device
            ),
            "severity": torch.tensor(
                features["severity"], dtype=torch.long, device=device
            ),
            "category": torch.tensor(
                features["category"], dtype=torch.long, device=device
            ),
            "asset_criticality": torch.tensor(
                features["asset_criticality"], dtype=torch.long, device=device
            ),
        }

    def batch_extract(
        self,
        alerts: list[dict[str, Any]],
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Extract and batch features from multiple alerts.

        Args:
            alerts: List of alert dictionaries
            device: Target device

        Returns:
            Batched tensors
        """
        features_list = [self.extract(alert) for alert in alerts]

        return {
            "numeric_features": torch.tensor(
                np.stack([f["numeric_features"] for f in features_list]),
                dtype=torch.float32,
                device=device,
            ),
            "severity": torch.tensor(
                [f["severity"] for f in features_list],
                dtype=torch.long,
                device=device,
            ),
            "category": torch.tensor(
                [f["category"] for f in features_list],
                dtype=torch.long,
                device=device,
            ),
            "asset_criticality": torch.tensor(
                [f["asset_criticality"] for f in features_list],
                dtype=torch.long,
                device=device,
            ),
        }

    def _extract_numeric_features(self, alert: dict[str, Any]) -> np.ndarray:
        """Extract numeric features from alert.

        Args:
            alert: Alert dictionary

        Returns:
            Numeric feature array
        """
        features = []

        # Basic counts (log-scaled)
        features.append(np.log1p(alert.get("event_count", 1)))
        features.append(np.log1p(alert.get("bytes_sent", 0)))
        features.append(np.log1p(alert.get("bytes_received", 0)))
        features.append(np.log1p(alert.get("packet_count", 0)))
        features.append(np.log1p(alert.get("connection_duration", 0)))

        # Temporal features
        timestamp = alert.get("timestamp")
        if timestamp:
            from datetime import datetime
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            features.append(timestamp.hour / 24.0)
            features.append(timestamp.weekday() / 7.0)
            features.append(1.0 if timestamp.weekday() >= 5 else 0.0)  # Is weekend
        else:
            features.extend([0.5, 0.5, 0.0])

        # Aggregation features
        agg = alert.get("aggregations", {}) or {}
        features.append(np.log1p(agg.get("src_ip_alert_count_1h", 0)))
        features.append(np.log1p(agg.get("src_ip_alert_count_24h", 0)))
        features.append(np.log1p(agg.get("dst_ip_alert_count_1h", 0)))
        features.append(np.log1p(agg.get("dst_ip_alert_count_24h", 0)))
        features.append(np.log1p(agg.get("rule_fire_count_1h", 0)))
        features.append(np.log1p(agg.get("similar_alert_count_1h", 0)))

        # Reputation features
        reputation = alert.get("reputation", {}) or {}
        features.append(reputation.get("src_ip_score", 0.5))
        features.append(reputation.get("dst_ip_score", 0.5))
        features.append(1.0 if reputation.get("src_ip_is_known_bad", False) else 0.0)
        features.append(1.0 if reputation.get("dst_ip_is_known_bad", False) else 0.0)

        # Asset features
        asset = alert.get("asset", {}) or {}
        features.append(1.0 if asset.get("is_server", False) else 0.0)
        features.append(1.0 if asset.get("has_pii", False) else 0.0)
        features.append(1.0 if alert.get("is_external", False) else 0.0)

        # Detection confidence
        features.append(alert.get("confidence", 0.75))
        features.append(alert.get("severity_confidence", 0.75))

        # MITRE coverage
        mitre_tactics = alert.get("mitre_tactics", []) or []
        mitre_techniques = alert.get("mitre_techniques", []) or []
        features.append(len(mitre_tactics) / 14.0)  # Normalized tactic count
        features.append(len(mitre_techniques) / 200.0)  # Normalized technique count

        # Port features
        src_port = alert.get("source_port", 0) or 0
        dst_port = alert.get("dest_port", 0) or 0
        features.append(1.0 if src_port > 0 and src_port < 1024 else 0.0)
        features.append(1.0 if dst_port > 0 and dst_port < 1024 else 0.0)
        features.append(1.0 if dst_port in (80, 443, 8080, 8443) else 0.0)  # Web port

        # Boolean flags
        features.append(1.0 if alert.get("is_repeated", False) else 0.0)
        features.append(1.0 if alert.get("is_correlated", False) else 0.0)

        # Pad or truncate to expected size
        features = features[:self.num_numeric_features]
        while len(features) < self.num_numeric_features:
            features.append(0.0)

        return np.array(features, dtype=np.float32)

    def _encode_severity(self, severity: str) -> int:
        """Encode severity string to integer."""
        return self.SEVERITY_MAP.get(severity.lower(), 2)

    def _encode_category(self, category: str) -> int:
        """Encode category string to integer."""
        return self.CATEGORY_MAP.get(category.lower(), 11)


class ContextFeatureAggregator(LoggerMixin):
    """Aggregate contextual features from related alerts."""

    def __init__(
        self,
        time_windows: list[int] | None = None,
    ) -> None:
        """Initialize the aggregator.

        Args:
            time_windows: Time windows in minutes for aggregation
        """
        self.time_windows = time_windows or [5, 15, 60, 360, 1440]

    def aggregate(
        self,
        alert: dict[str, Any],
        related_alerts: list[dict[str, Any]],
    ) -> dict[str, float]:
        """Aggregate features from related alerts.

        Args:
            alert: Current alert
            related_alerts: List of related alerts

        Returns:
            Aggregated features
        """
        from datetime import datetime, timedelta

        features = {}
        current_time = alert.get("timestamp", datetime.utcnow())
        if isinstance(current_time, str):
            current_time = datetime.fromisoformat(current_time.replace("Z", "+00:00"))

        for window_minutes in self.time_windows:
            window_start = current_time - timedelta(minutes=window_minutes)

            # Filter alerts in window
            window_alerts = [
                a for a in related_alerts
                if self._get_timestamp(a.get("timestamp")) >= window_start
            ]

            suffix = f"_{window_minutes}m"

            # Count features
            features[f"alert_count{suffix}"] = len(window_alerts)

            # Severity distribution
            severities = [a.get("severity", "medium") for a in window_alerts]
            for sev in ["critical", "high", "medium", "low", "info"]:
                features[f"{sev}_count{suffix}"] = severities.count(sev)

            # Unique sources
            unique_sources = len(set(a.get("source_ip") for a in window_alerts if a.get("source_ip")))
            features[f"unique_sources{suffix}"] = unique_sources

            # Unique destinations
            unique_dests = len(set(a.get("dest_ip") for a in window_alerts if a.get("dest_ip")))
            features[f"unique_dests{suffix}"] = unique_dests

            # Unique rules
            unique_rules = len(set(a.get("rule_id") for a in window_alerts if a.get("rule_id")))
            features[f"unique_rules{suffix}"] = unique_rules

        return features

    @staticmethod
    def _get_timestamp(value: Any) -> datetime:
        """Parse timestamp value."""
        from datetime import datetime

        if value is None:
            return datetime.min
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return datetime.min
        return datetime.min
