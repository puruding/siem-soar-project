"""Automatic labeling strategies for training data."""

from enum import Enum
from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class LabelingStrategy(str, Enum):
    """Strategies for automatic labeling."""

    ANALYST_FEEDBACK = "analyst_feedback"
    RULE_BASED = "rule_based"
    OUTCOME_BASED = "outcome_based"
    ENSEMBLE = "ensemble"
    ACTIVE_LEARNING = "active_learning"


class LabelConfidence(BaseModel):
    """Label with confidence score."""

    label: Any = Field(description="Label value")
    confidence: float = Field(ge=0, le=1, description="Confidence in label")
    source: LabelingStrategy = Field(description="Source of label")
    metadata: dict[str, Any] = Field(default_factory=dict)


class AutoLabeler(LoggerMixin):
    """Automatic labeling of alerts using multiple strategies."""

    # Rule-based severity patterns
    SEVERITY_PATTERNS = {
        "critical": [
            "ransomware",
            "cryptolocker",
            "data breach",
            "exfiltration confirmed",
            "active exploit",
            "rce",
            "remote code execution",
        ],
        "high": [
            "malware detected",
            "intrusion attempt",
            "privilege escalation",
            "lateral movement",
            "credential theft",
            "c2 communication",
        ],
        "medium": [
            "suspicious activity",
            "policy violation",
            "anomaly detected",
            "brute force",
            "port scan",
        ],
        "low": [
            "informational",
            "audit log",
            "configuration change",
            "login success",
        ],
    }

    # Category patterns
    CATEGORY_PATTERNS = {
        "malware": ["malware", "virus", "trojan", "worm", "ransomware", "cryptominer"],
        "intrusion": ["intrusion", "exploit", "attack", "breach", "compromise"],
        "data_exfiltration": ["exfiltration", "data leak", "data theft", "upload"],
        "privilege_escalation": ["privilege", "escalation", "admin", "root", "sudo"],
        "lateral_movement": ["lateral", "pivot", "internal", "spread"],
        "credential_access": ["credential", "password", "hash", "kerberos", "ntlm"],
        "reconnaissance": ["scan", "recon", "enumeration", "discovery"],
        "command_and_control": ["c2", "c&c", "beacon", "callback", "command"],
    }

    def __init__(
        self,
        strategy: LabelingStrategy = LabelingStrategy.ENSEMBLE,
        min_confidence: float = 0.5,
    ) -> None:
        """Initialize the auto-labeler.

        Args:
            strategy: Primary labeling strategy
            min_confidence: Minimum confidence for labels
        """
        self.strategy = strategy
        self.min_confidence = min_confidence

    async def label_alert(
        self,
        alert: dict[str, Any],
        feedback: list[Any] | None = None,
        outcome: dict[str, Any] | None = None,
    ) -> dict[str, LabelConfidence]:
        """Generate labels for an alert.

        Args:
            alert: Alert data
            feedback: Analyst feedback if available
            outcome: Investigation outcome if available

        Returns:
            Dictionary of field -> LabelConfidence
        """
        labels = {}

        if self.strategy == LabelingStrategy.ANALYST_FEEDBACK and feedback:
            labels = self._label_from_feedback(alert, feedback)

        elif self.strategy == LabelingStrategy.RULE_BASED:
            labels = self._label_rule_based(alert)

        elif self.strategy == LabelingStrategy.OUTCOME_BASED and outcome:
            labels = self._label_from_outcome(alert, outcome)

        elif self.strategy == LabelingStrategy.ENSEMBLE:
            labels = await self._label_ensemble(alert, feedback, outcome)

        elif self.strategy == LabelingStrategy.ACTIVE_LEARNING:
            labels = self._label_active_learning(alert)

        return labels

    def _label_from_feedback(
        self,
        alert: dict[str, Any],
        feedback: list[Any],
    ) -> dict[str, LabelConfidence]:
        """Label based on analyst feedback.

        Args:
            alert: Alert data
            feedback: List of analyst feedback

        Returns:
            Labels from feedback
        """
        labels = {}

        if not feedback:
            return labels

        # Use most recent feedback with highest confidence
        latest_feedback = max(feedback, key=lambda f: (f.timestamp, f.confidence))

        if latest_feedback.corrected_severity:
            labels["severity"] = LabelConfidence(
                label=latest_feedback.corrected_severity,
                confidence=latest_feedback.confidence,
                source=LabelingStrategy.ANALYST_FEEDBACK,
                metadata={"analyst_id": latest_feedback.analyst_id},
            )

        if latest_feedback.corrected_category:
            labels["category"] = LabelConfidence(
                label=latest_feedback.corrected_category,
                confidence=latest_feedback.confidence,
                source=LabelingStrategy.ANALYST_FEEDBACK,
            )

        if latest_feedback.is_false_positive is not None:
            labels["is_false_positive"] = LabelConfidence(
                label=latest_feedback.is_false_positive,
                confidence=latest_feedback.confidence,
                source=LabelingStrategy.ANALYST_FEEDBACK,
            )

        return labels

    def _label_rule_based(
        self, alert: dict[str, Any]
    ) -> dict[str, LabelConfidence]:
        """Label based on pattern matching.

        Args:
            alert: Alert data

        Returns:
            Rule-based labels
        """
        labels = {}

        # Combine text fields
        text = " ".join([
            str(alert.get("title", "")),
            str(alert.get("description", "")),
            str(alert.get("rule_name", "")),
        ]).lower()

        # Severity labeling
        for severity, patterns in self.SEVERITY_PATTERNS.items():
            if any(p in text for p in patterns):
                labels["severity"] = LabelConfidence(
                    label=severity,
                    confidence=0.7,
                    source=LabelingStrategy.RULE_BASED,
                    metadata={"matched_patterns": [p for p in patterns if p in text]},
                )
                break

        # Category labeling
        max_matches = 0
        best_category = None

        for category, patterns in self.CATEGORY_PATTERNS.items():
            matches = sum(1 for p in patterns if p in text)
            if matches > max_matches:
                max_matches = matches
                best_category = category

        if best_category:
            confidence = min(0.9, 0.5 + max_matches * 0.1)
            labels["category"] = LabelConfidence(
                label=best_category,
                confidence=confidence,
                source=LabelingStrategy.RULE_BASED,
            )

        # FP labeling heuristics
        # Known benign patterns
        benign_patterns = [
            "scheduled task",
            "backup",
            "windows update",
            "antivirus",
            "patch management",
        ]

        if any(p in text for p in benign_patterns):
            labels["is_false_positive"] = LabelConfidence(
                label=True,
                confidence=0.6,
                source=LabelingStrategy.RULE_BASED,
            )

        return labels

    def _label_from_outcome(
        self,
        alert: dict[str, Any],
        outcome: dict[str, Any],
    ) -> dict[str, LabelConfidence]:
        """Label based on investigation outcome.

        Args:
            alert: Alert data
            outcome: Investigation outcome

        Returns:
            Outcome-based labels
        """
        labels = {}

        # Check outcome status
        status = outcome.get("status", "").lower()
        resolution = outcome.get("resolution", "").lower()

        # False positive indicators
        if any(x in status for x in ["false_positive", "benign", "closed_no_action"]):
            labels["is_false_positive"] = LabelConfidence(
                label=True,
                confidence=0.9,
                source=LabelingStrategy.OUTCOME_BASED,
                metadata={"outcome_status": status},
            )
        elif any(x in status for x in ["incident", "confirmed", "true_positive"]):
            labels["is_false_positive"] = LabelConfidence(
                label=False,
                confidence=0.9,
                source=LabelingStrategy.OUTCOME_BASED,
            )

        # Severity from incident severity
        if "incident_severity" in outcome:
            labels["severity"] = LabelConfidence(
                label=outcome["incident_severity"],
                confidence=0.85,
                source=LabelingStrategy.OUTCOME_BASED,
            )

        return labels

    async def _label_ensemble(
        self,
        alert: dict[str, Any],
        feedback: list[Any] | None,
        outcome: dict[str, Any] | None,
    ) -> dict[str, LabelConfidence]:
        """Combine multiple labeling strategies.

        Args:
            alert: Alert data
            feedback: Analyst feedback
            outcome: Investigation outcome

        Returns:
            Ensemble labels
        """
        all_labels: dict[str, list[LabelConfidence]] = {}

        # Collect labels from all strategies
        strategies = [
            (LabelingStrategy.RULE_BASED, self._label_rule_based(alert)),
        ]

        if feedback:
            strategies.append((
                LabelingStrategy.ANALYST_FEEDBACK,
                self._label_from_feedback(alert, feedback)
            ))

        if outcome:
            strategies.append((
                LabelingStrategy.OUTCOME_BASED,
                self._label_from_outcome(alert, outcome)
            ))

        # Aggregate by field
        for strategy, labels in strategies:
            for field, label_conf in labels.items():
                if field not in all_labels:
                    all_labels[field] = []
                all_labels[field].append(label_conf)

        # Vote/combine for each field
        final_labels = {}
        for field, candidates in all_labels.items():
            if len(candidates) == 1:
                final_labels[field] = candidates[0]
            else:
                final_labels[field] = self._vote_labels(candidates)

        return final_labels

    def _vote_labels(
        self, candidates: list[LabelConfidence]
    ) -> LabelConfidence:
        """Vote among candidate labels.

        Args:
            candidates: List of candidate labels

        Returns:
            Winning label
        """
        # Weight by source priority and confidence
        source_weights = {
            LabelingStrategy.ANALYST_FEEDBACK: 1.0,
            LabelingStrategy.OUTCOME_BASED: 0.9,
            LabelingStrategy.RULE_BASED: 0.6,
            LabelingStrategy.ACTIVE_LEARNING: 0.7,
        }

        # Score each candidate
        scored = []
        for c in candidates:
            score = c.confidence * source_weights.get(c.source, 0.5)
            scored.append((score, c))

        # Return highest scored
        best = max(scored, key=lambda x: x[0])

        return LabelConfidence(
            label=best[1].label,
            confidence=best[0],  # Combined confidence
            source=LabelingStrategy.ENSEMBLE,
            metadata={
                "num_candidates": len(candidates),
                "winning_source": best[1].source,
            },
        )

    def _label_active_learning(
        self, alert: dict[str, Any]
    ) -> dict[str, LabelConfidence]:
        """Label for active learning (select for human review).

        Args:
            alert: Alert data

        Returns:
            Labels with uncertainty flag
        """
        # Use rule-based as baseline
        labels = self._label_rule_based(alert)

        # Mark uncertain samples for review
        for field, label_conf in labels.items():
            if label_conf.confidence < self.min_confidence:
                label_conf.metadata["needs_review"] = True

        return labels


class WeakSupervisionLabeler(LoggerMixin):
    """Weak supervision labeling using labeling functions."""

    def __init__(self) -> None:
        """Initialize weak supervision labeler."""
        self._labeling_functions: list[callable] = []
        self._function_accuracies: dict[str, float] = {}

    def add_labeling_function(
        self,
        func: callable,
        name: str,
        estimated_accuracy: float = 0.7,
    ) -> None:
        """Add a labeling function.

        Args:
            func: Labeling function (alert -> label or None)
            name: Function name
            estimated_accuracy: Estimated accuracy
        """
        self._labeling_functions.append(func)
        self._function_accuracies[name] = estimated_accuracy

    def apply_labeling_functions(
        self,
        alert: dict[str, Any],
    ) -> list[tuple[str, Any, float]]:
        """Apply all labeling functions.

        Args:
            alert: Alert data

        Returns:
            List of (function_name, label, accuracy)
        """
        results = []

        for func in self._labeling_functions:
            try:
                label = func(alert)
                if label is not None:
                    name = func.__name__
                    accuracy = self._function_accuracies.get(name, 0.5)
                    results.append((name, label, accuracy))
            except Exception as e:
                self.logger.warning(
                    "labeling_function_error",
                    function=func.__name__,
                    error=str(e),
                )

        return results

    def aggregate_labels(
        self,
        labels: list[tuple[str, Any, float]],
    ) -> tuple[Any, float]:
        """Aggregate labels using weighted voting.

        Args:
            labels: List of (function_name, label, accuracy)

        Returns:
            Tuple of (aggregated_label, confidence)
        """
        if not labels:
            return None, 0.0

        # Count weighted votes
        votes: dict[Any, float] = {}
        for name, label, accuracy in labels:
            votes[label] = votes.get(label, 0) + accuracy

        # Get winner
        winner = max(votes.items(), key=lambda x: x[1])
        total_weight = sum(votes.values())
        confidence = winner[1] / total_weight if total_weight > 0 else 0

        return winner[0], confidence
