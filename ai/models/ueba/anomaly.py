"""Anomaly detection for UEBA - detects behavioral anomalies."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

import numpy as np
import torch
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .model import UEBAModel, UEBAConfig, UEBAModelWrapper
from .profile import ProfileManager, BehaviorProfile, ProfileType


class AnomalyType(str, Enum):
    """Types of behavioral anomalies."""

    UNUSUAL_TIME = "unusual_time"
    UNUSUAL_LOCATION = "unusual_location"
    UNUSUAL_VOLUME = "unusual_volume"
    UNUSUAL_RESOURCE = "unusual_resource"
    CREDENTIAL_ANOMALY = "credential_anomaly"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    ACCOUNT_COMPROMISE = "account_compromise"
    INSIDER_THREAT = "insider_threat"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    RECONSTRUCTION_ANOMALY = "reconstruction_anomaly"


class AnomalyScore(BaseModel):
    """Anomaly score with breakdown."""

    overall_score: float = Field(ge=0.0, le=1.0, description="Overall anomaly score")
    reconstruction_score: float = Field(ge=0.0, le=1.0, description="Model reconstruction error")
    temporal_score: float = Field(ge=0.0, le=1.0, description="Temporal pattern deviation")
    volumetric_score: float = Field(ge=0.0, le=1.0, description="Volume deviation")
    behavioral_score: float = Field(ge=0.0, le=1.0, description="Behavioral pattern deviation")

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return self.model_dump()


class DetectionResult(BaseModel):
    """Result of anomaly detection."""

    entity_id: str = Field(description="Entity identifier")
    entity_type: ProfileType = Field(description="Entity type")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Detection outcome
    is_anomaly: bool = Field(default=False)
    anomaly_score: AnomalyScore = Field(description="Detailed anomaly scores")
    anomaly_types: list[AnomalyType] = Field(default_factory=list)

    # Context
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    severity: str = Field(default="low")  # low, medium, high, critical
    explanation: str = Field(default="")
    contributing_factors: list[str] = Field(default_factory=list)

    # Evidence
    event_ids: list[str] = Field(default_factory=list)
    baseline_comparison: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    profile_id: str | None = Field(default=None)
    detection_method: str = Field(default="transformer_autoencoder")


class AnomalyDetector(LoggerMixin):
    """Detects behavioral anomalies using UEBA model and profile baselines.

    Detection methods:
    1. Model-based: Transformer autoencoder reconstruction error
    2. Statistical: Deviation from profile baseline
    3. Rule-based: Known anomaly patterns

    Features:
    - Multi-dimensional anomaly scoring
    - Contextual anomaly classification
    - Severity assessment
    - Explanation generation
    """

    def __init__(
        self,
        model_wrapper: UEBAModelWrapper | None = None,
        profile_manager: ProfileManager | None = None,
        config: UEBAConfig | None = None,
    ):
        """Initialize anomaly detector.

        Args:
            model_wrapper: Pre-trained UEBA model wrapper
            profile_manager: Profile manager for baselines
            config: Model configuration
        """
        self.config = config or UEBAConfig()
        self.model_wrapper = model_wrapper or UEBAModelWrapper(self.config)
        self.profile_manager = profile_manager or ProfileManager()

        # Detection thresholds
        self.thresholds = {
            "overall": 0.7,
            "reconstruction": 0.8,
            "temporal": 0.75,
            "volumetric": 0.8,
            "behavioral": 0.7,
        }

        # Severity mapping
        self.severity_thresholds = {
            0.9: "critical",
            0.8: "high",
            0.6: "medium",
            0.0: "low",
        }

    def detect(
        self,
        entity_id: str,
        entity_type: ProfileType,
        events: list[dict[str, Any]],
        sequence_data: torch.Tensor | None = None,
    ) -> DetectionResult:
        """Detect anomalies for an entity.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            events: Recent events for the entity
            sequence_data: Pre-processed sequence tensor (optional)

        Returns:
            Detection result with anomaly scores
        """
        # Get or create profile
        profile = self.profile_manager.get_profile_by_entity(entity_id, entity_type)
        if not profile:
            profile = self.profile_manager.get_or_create_profile(
                entity_id, entity_type
            )

        # Update profile with new events
        self.profile_manager.update_profile(profile.profile_id, events)

        # Calculate individual scores
        reconstruction_score = self._calculate_reconstruction_score(sequence_data)
        temporal_score = self._calculate_temporal_score(events, profile)
        volumetric_score = self._calculate_volumetric_score(events, profile)
        behavioral_score = self._calculate_behavioral_score(events, profile)

        # Combine scores
        overall_score = self._combine_scores(
            reconstruction_score,
            temporal_score,
            volumetric_score,
            behavioral_score,
        )

        anomaly_score = AnomalyScore(
            overall_score=overall_score,
            reconstruction_score=reconstruction_score,
            temporal_score=temporal_score,
            volumetric_score=volumetric_score,
            behavioral_score=behavioral_score,
        )

        # Determine if anomaly
        is_anomaly = overall_score >= self.thresholds["overall"]

        # Classify anomaly types
        anomaly_types = self._classify_anomaly_types(
            events, profile, anomaly_score
        )

        # Assess severity
        severity = self._assess_severity(overall_score)

        # Generate explanation
        explanation, contributing_factors = self._generate_explanation(
            anomaly_score, anomaly_types, profile
        )

        # Calculate confidence based on profile maturity
        confidence = self._calculate_confidence(profile, anomaly_score)

        result = DetectionResult(
            entity_id=entity_id,
            entity_type=entity_type,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            anomaly_types=anomaly_types,
            confidence=confidence,
            severity=severity,
            explanation=explanation,
            contributing_factors=contributing_factors,
            event_ids=[e.get("event_id", "") for e in events if e.get("event_id")],
            baseline_comparison=self._get_baseline_comparison(events, profile),
            profile_id=profile.profile_id,
        )

        if is_anomaly:
            self.logger.warning(
                "anomaly_detected",
                entity_id=entity_id,
                entity_type=entity_type.value,
                score=overall_score,
                severity=severity,
                types=[t.value for t in anomaly_types],
            )

        return result

    def _calculate_reconstruction_score(
        self,
        sequence_data: torch.Tensor | None,
    ) -> float:
        """Calculate reconstruction error score from model."""
        if sequence_data is None:
            return 0.0

        try:
            prediction = self.model_wrapper.predict(sequence_data)
            scores = prediction["anomaly_scores"]
            # Normalize to 0-1 using sigmoid-like transformation
            max_score = float(np.max(scores))
            normalized = 1.0 / (1.0 + np.exp(-max_score))
            return normalized
        except Exception as e:
            self.logger.warning("reconstruction_score_failed", error=str(e))
            return 0.0

    def _calculate_temporal_score(
        self,
        events: list[dict[str, Any]],
        profile: BehaviorProfile,
    ) -> float:
        """Calculate temporal pattern deviation score."""
        if not events or not profile.is_ready:
            return 0.0

        # Extract hours from events
        event_hours = []
        for event in events:
            timestamp = event.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except:
                    continue
            if isinstance(timestamp, datetime):
                event_hours.append(timestamp.hour)

        if not event_hours:
            return 0.0

        # Compare with profile baseline
        baseline_hours = profile.features.activity_hours
        deviations = []

        for hour in event_hours:
            expected_prob = baseline_hours[hour] if hour < len(baseline_hours) else 0.0
            if expected_prob < 0.01:  # Activity at unusual time
                deviations.append(1.0)
            elif expected_prob < 0.05:
                deviations.append(0.7)
            else:
                deviations.append(0.0)

        return float(np.mean(deviations)) if deviations else 0.0

    def _calculate_volumetric_score(
        self,
        events: list[dict[str, Any]],
        profile: BehaviorProfile,
    ) -> float:
        """Calculate volume deviation score."""
        if not events or not profile.is_ready:
            return 0.0

        # Calculate event volume deviation
        current_volume = len(events)
        expected_volume = profile.features.average_events_per_day

        if expected_volume == 0:
            return 0.5 if current_volume > 0 else 0.0

        # Z-score based deviation
        ratio = current_volume / expected_volume
        if ratio > 5:  # 5x normal
            return 1.0
        elif ratio > 3:
            return 0.8
        elif ratio > 2:
            return 0.5
        elif ratio < 0.1:  # Much less than normal
            return 0.6
        else:
            return 0.0

    def _calculate_behavioral_score(
        self,
        events: list[dict[str, Any]],
        profile: BehaviorProfile,
    ) -> float:
        """Calculate behavioral pattern deviation score."""
        if not events or not profile.is_ready:
            return 0.0

        deviations = []

        # Check for new systems accessed
        systems_in_events = set()
        for event in events:
            if system := event.get("hostname") or event.get("system"):
                systems_in_events.add(system)

        new_systems_ratio = len(systems_in_events) / max(
            profile.features.unique_systems_accessed, 1
        )
        if new_systems_ratio > 2:
            deviations.append(0.8)

        # Check for unusual ports
        ports_in_events = set()
        for event in events:
            if port := event.get("destination_port") or event.get("dest_port"):
                ports_in_events.add(int(port))

        unusual_ports = ports_in_events - set(profile.features.common_ports)
        if unusual_ports:
            deviations.append(min(1.0, len(unusual_ports) * 0.2))

        # Check login failures
        login_events = [e for e in events if e.get("event_type") in ["login", "authentication"]]
        if login_events:
            failures = sum(1 for e in login_events if e.get("status") == "failure")
            failure_rate = failures / len(login_events)
            expected_failure_rate = 1 - profile.features.login_success_rate

            if failure_rate > expected_failure_rate + 0.2:
                deviations.append(0.9)

        return float(np.mean(deviations)) if deviations else 0.0

    def _combine_scores(
        self,
        reconstruction: float,
        temporal: float,
        volumetric: float,
        behavioral: float,
    ) -> float:
        """Combine individual scores into overall score."""
        # Weighted average with reconstruction having higher weight
        weights = {
            "reconstruction": 0.4,
            "temporal": 0.2,
            "volumetric": 0.2,
            "behavioral": 0.2,
        }

        overall = (
            weights["reconstruction"] * reconstruction +
            weights["temporal"] * temporal +
            weights["volumetric"] * volumetric +
            weights["behavioral"] * behavioral
        )

        # Apply maximum boost if any single score is very high
        max_score = max(reconstruction, temporal, volumetric, behavioral)
        if max_score > 0.9:
            overall = max(overall, 0.8)

        return min(1.0, overall)

    def _classify_anomaly_types(
        self,
        events: list[dict[str, Any]],
        profile: BehaviorProfile,
        scores: AnomalyScore,
    ) -> list[AnomalyType]:
        """Classify the types of anomalies detected."""
        anomaly_types = []

        # Check temporal anomaly
        if scores.temporal_score >= self.thresholds["temporal"]:
            anomaly_types.append(AnomalyType.UNUSUAL_TIME)

        # Check volumetric anomaly
        if scores.volumetric_score >= self.thresholds["volumetric"]:
            anomaly_types.append(AnomalyType.UNUSUAL_VOLUME)

        # Check for credential anomalies
        login_events = [e for e in events if e.get("event_type") in ["login", "authentication"]]
        if login_events:
            failures = sum(1 for e in login_events if e.get("status") == "failure")
            if failures >= 3:
                anomaly_types.append(AnomalyType.CREDENTIAL_ANOMALY)

        # Check for lateral movement
        unique_hosts = set()
        for event in events:
            if host := event.get("hostname") or event.get("destination_hostname"):
                unique_hosts.add(host)
        if len(unique_hosts) > profile.features.unique_systems_accessed * 2:
            anomaly_types.append(AnomalyType.LATERAL_MOVEMENT)

        # Check for data exfiltration
        total_bytes = sum(
            int(e.get("bytes_sent", 0) or e.get("bytes_out", 0))
            for e in events
        )
        if total_bytes > profile.features.average_data_volume * 10:
            anomaly_types.append(AnomalyType.DATA_EXFILTRATION)

        # Check for privilege escalation
        privilege_events = [
            e for e in events
            if any(kw in str(e.get("event_type", "")).lower()
                   for kw in ["privilege", "admin", "sudo", "runas", "escalat"])
        ]
        if privilege_events:
            anomaly_types.append(AnomalyType.PRIVILEGE_ESCALATION)

        # Reconstruction anomaly
        if scores.reconstruction_score >= self.thresholds["reconstruction"]:
            anomaly_types.append(AnomalyType.RECONSTRUCTION_ANOMALY)

        return anomaly_types

    def _assess_severity(self, overall_score: float) -> str:
        """Assess severity based on overall score."""
        for threshold, severity in sorted(
            self.severity_thresholds.items(), reverse=True
        ):
            if overall_score >= threshold:
                return severity
        return "low"

    def _generate_explanation(
        self,
        scores: AnomalyScore,
        anomaly_types: list[AnomalyType],
        profile: BehaviorProfile,
    ) -> tuple[str, list[str]]:
        """Generate human-readable explanation."""
        factors = []

        if scores.temporal_score >= self.thresholds["temporal"]:
            factors.append("Activity at unusual time")

        if scores.volumetric_score >= self.thresholds["volumetric"]:
            factors.append("Unusual activity volume")

        if scores.behavioral_score >= self.thresholds["behavioral"]:
            factors.append("Behavioral pattern deviation")

        if scores.reconstruction_score >= self.thresholds["reconstruction"]:
            factors.append("Sequence pattern anomaly")

        if AnomalyType.CREDENTIAL_ANOMALY in anomaly_types:
            factors.append("Multiple authentication failures")

        if AnomalyType.LATERAL_MOVEMENT in anomaly_types:
            factors.append("Unusual access to multiple systems")

        if AnomalyType.DATA_EXFILTRATION in anomaly_types:
            factors.append("Unusually high data transfer")

        if AnomalyType.PRIVILEGE_ESCALATION in anomaly_types:
            factors.append("Privilege escalation attempt")

        explanation = (
            f"Anomaly detected with score {scores.overall_score:.2f}. "
            f"Contributing factors: {', '.join(factors) or 'General deviation from baseline'}."
        )

        return explanation, factors

    def _calculate_confidence(
        self,
        profile: BehaviorProfile,
        scores: AnomalyScore,
    ) -> float:
        """Calculate detection confidence."""
        # Base confidence on profile maturity
        profile_confidence = profile.learning_progress

        # Adjust based on score magnitude
        score_confidence = min(1.0, scores.overall_score / 0.5)

        # Combined confidence
        confidence = 0.6 * profile_confidence + 0.4 * score_confidence

        return min(1.0, confidence)

    def _get_baseline_comparison(
        self,
        events: list[dict[str, Any]],
        profile: BehaviorProfile,
    ) -> dict[str, Any]:
        """Get comparison between current behavior and baseline."""
        if not profile.is_ready:
            return {"status": "profile_learning"}

        pf = profile.features

        return {
            "expected_activity_hours": pf.activity_hours,
            "expected_systems": pf.unique_systems_accessed,
            "expected_volume": pf.average_events_per_day,
            "expected_login_success_rate": pf.login_success_rate,
            "current_event_count": len(events),
        }

    def batch_detect(
        self,
        entities: list[tuple[str, ProfileType, list[dict[str, Any]]]],
    ) -> list[DetectionResult]:
        """Detect anomalies for multiple entities.

        Args:
            entities: List of (entity_id, entity_type, events) tuples

        Returns:
            List of detection results
        """
        results = []
        for entity_id, entity_type, events in entities:
            result = self.detect(entity_id, entity_type, events)
            results.append(result)
        return results

    def get_anomaly_summary(
        self,
        results: list[DetectionResult],
    ) -> dict[str, Any]:
        """Get summary statistics for detection results."""
        anomalies = [r for r in results if r.is_anomaly]

        severity_counts = {}
        type_counts = {}

        for r in anomalies:
            severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
            for at in r.anomaly_types:
                type_counts[at.value] = type_counts.get(at.value, 0) + 1

        return {
            "total_entities": len(results),
            "anomalies_detected": len(anomalies),
            "anomaly_rate": len(anomalies) / len(results) if results else 0,
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "average_score": float(np.mean([r.anomaly_score.overall_score for r in anomalies]))
            if anomalies else 0.0,
        }
