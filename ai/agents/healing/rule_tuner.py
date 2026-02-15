"""Rule Tuner - Tune detection rules for better accuracy."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RuleType(str, Enum):
    """Types of detection rules."""

    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"


class AdjustmentType(str, Enum):
    """Types of rule adjustments."""

    THRESHOLD_INCREASE = "threshold_increase"
    THRESHOLD_DECREASE = "threshold_decrease"
    ADD_EXCEPTION = "add_exception"
    REMOVE_EXCEPTION = "remove_exception"
    MODIFY_CONDITION = "modify_condition"
    ADJUST_TIMEWINDOW = "adjust_timewindow"
    ENABLE_RULE = "enable_rule"
    DISABLE_RULE = "disable_rule"


class RulePerformance(BaseModel):
    """Performance metrics for a detection rule."""

    rule_id: str = Field(description="Rule identifier")
    rule_name: str = Field(description="Rule name")
    rule_type: RuleType = Field(default=RuleType.CORRELATION)

    # Detection metrics
    total_alerts: int = Field(default=0)
    true_positives: int = Field(default=0)
    false_positives: int = Field(default=0)
    true_negatives: int = Field(default=0)
    false_negatives: int = Field(default=0)

    # Calculated metrics
    precision: float = Field(default=0.0)
    recall: float = Field(default=0.0)
    f1_score: float = Field(default=0.0)
    false_positive_rate: float = Field(default=0.0)

    # Timing
    avg_detection_time_seconds: float = Field(default=0.0)
    first_detection: datetime | None = Field(default=None)
    last_detection: datetime | None = Field(default=None)

    # Current state
    is_enabled: bool = Field(default=True)
    current_threshold: float | None = Field(default=None)
    current_timewindow_seconds: int | None = Field(default=None)

    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TuningRecommendation(BaseModel):
    """A recommendation for tuning a rule."""

    recommendation_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str = Field(description="Target rule")
    adjustment_type: AdjustmentType = Field(description="Type of adjustment")

    title: str = Field(description="Recommendation title")
    description: str = Field(description="Detailed description")
    rationale: str = Field(description="Why this adjustment is recommended")

    # Expected impact
    expected_precision_change: float = Field(default=0.0)
    expected_recall_change: float = Field(default=0.0)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    priority: int = Field(default=5, ge=1, le=10)

    # Adjustment details
    current_value: Any = Field(default=None)
    recommended_value: Any = Field(default=None)

    # Status
    status: str = Field(default="pending")  # pending, accepted, rejected, applied
    created_at: datetime = Field(default_factory=datetime.utcnow)
    applied_at: datetime | None = Field(default=None)


class RuleAdjustment(BaseModel):
    """A rule adjustment that was applied."""

    adjustment_id: str = Field(default_factory=lambda: str(uuid4()))
    rule_id: str = Field(description="Adjusted rule")
    adjustment_type: AdjustmentType = Field(description="Type of adjustment")

    # Values
    previous_value: Any = Field(default=None)
    new_value: Any = Field(default=None)

    # Execution
    applied_at: datetime = Field(default_factory=datetime.utcnow)
    applied_by: str = Field(default="system")
    recommendation_id: str | None = Field(default=None)

    # Result tracking
    performance_before: RulePerformance | None = Field(default=None)
    performance_after: RulePerformance | None = Field(default=None)
    improvement_observed: bool | None = Field(default=None)


class RuleTuner(LoggerMixin):
    """Tuner for optimizing detection rule accuracy.

    Features:
    - Rule performance tracking
    - False positive analysis
    - Threshold optimization
    - Exception management
    - A/B testing support
    """

    def __init__(
        self,
        min_alerts_for_analysis: int = 50,
        target_precision: float = 0.8,
        target_recall: float = 0.9,
        max_false_positive_rate: float = 0.2,
    ) -> None:
        """Initialize rule tuner.

        Args:
            min_alerts_for_analysis: Minimum alerts before analysis
            target_precision: Target precision rate
            target_recall: Target recall rate
            max_false_positive_rate: Maximum acceptable false positive rate
        """
        self.min_alerts_for_analysis = min_alerts_for_analysis
        self.target_precision = target_precision
        self.target_recall = target_recall
        self.max_false_positive_rate = max_false_positive_rate

        self._rule_performance: dict[str, RulePerformance] = {}
        self._alert_history: dict[str, list[dict]] = {}
        self._recommendations: dict[str, list[TuningRecommendation]] = {}
        self._adjustments: list[RuleAdjustment] = []

    def record_alert(
        self,
        rule_id: str,
        rule_name: str,
        is_true_positive: bool,
        detection_time_seconds: float | None = None,
        details: dict[str, Any] | None = None,
        rule_type: RuleType = RuleType.CORRELATION,
    ) -> None:
        """Record an alert and its classification.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            is_true_positive: Whether alert was true positive
            detection_time_seconds: Time to detect
            details: Additional details
            rule_type: Type of rule
        """
        # Initialize if needed
        if rule_id not in self._rule_performance:
            self._rule_performance[rule_id] = RulePerformance(
                rule_id=rule_id,
                rule_name=rule_name,
                rule_type=rule_type,
                first_detection=datetime.utcnow(),
            )
            self._alert_history[rule_id] = []

        perf = self._rule_performance[rule_id]

        # Update counts
        perf.total_alerts += 1
        if is_true_positive:
            perf.true_positives += 1
        else:
            perf.false_positives += 1

        perf.last_detection = datetime.utcnow()
        perf.updated_at = datetime.utcnow()

        # Record in history
        alert_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "is_true_positive": is_true_positive,
            "detection_time_seconds": detection_time_seconds,
            "details": details or {},
        }
        self._alert_history[rule_id].append(alert_record)

        # Keep recent history
        self._alert_history[rule_id] = self._alert_history[rule_id][-1000:]

        # Update computed metrics
        self._update_metrics(rule_id)

        self.logger.debug(
            "alert_recorded",
            rule_id=rule_id,
            is_true_positive=is_true_positive,
        )

    def record_feedback(
        self,
        rule_id: str,
        alert_id: str,
        is_true_positive: bool,
        analyst_notes: str | None = None,
    ) -> None:
        """Record analyst feedback on an alert.

        Args:
            rule_id: Rule identifier
            alert_id: Alert identifier
            is_true_positive: Analyst classification
            analyst_notes: Analyst notes
        """
        # This updates the classification in our tracking
        perf = self._rule_performance.get(rule_id)
        if not perf:
            return

        # For simplicity, we treat this as a new data point
        # In a real system, we'd update the specific alert record
        self._update_metrics(rule_id)

        self.logger.info(
            "feedback_recorded",
            rule_id=rule_id,
            alert_id=alert_id,
            classification=is_true_positive,
        )

    def _update_metrics(self, rule_id: str) -> None:
        """Update computed metrics for a rule."""
        perf = self._rule_performance.get(rule_id)
        if not perf:
            return

        tp = perf.true_positives
        fp = perf.false_positives
        tn = perf.true_negatives
        fn = perf.false_negatives

        # Calculate precision
        if tp + fp > 0:
            perf.precision = tp / (tp + fp)
        else:
            perf.precision = 0

        # Calculate recall
        if tp + fn > 0:
            perf.recall = tp / (tp + fn)
        else:
            perf.recall = 0

        # Calculate F1
        if perf.precision + perf.recall > 0:
            perf.f1_score = 2 * (perf.precision * perf.recall) / (perf.precision + perf.recall)
        else:
            perf.f1_score = 0

        # Calculate false positive rate
        if fp + tn > 0:
            perf.false_positive_rate = fp / (fp + tn)
        else:
            perf.false_positive_rate = fp / max(1, fp + tp)

        # Update average detection time
        history = self._alert_history.get(rule_id, [])
        detection_times = [h.get("detection_time_seconds", 0) for h in history if h.get("detection_time_seconds")]
        if detection_times:
            perf.avg_detection_time_seconds = sum(detection_times) / len(detection_times)

    def analyze_rule(self, rule_id: str) -> list[TuningRecommendation]:
        """Analyze a rule and generate tuning recommendations.

        Args:
            rule_id: Rule to analyze

        Returns:
            List of tuning recommendations
        """
        perf = self._rule_performance.get(rule_id)
        if not perf:
            return []

        if perf.total_alerts < self.min_alerts_for_analysis:
            self.logger.info(
                "insufficient_data",
                rule_id=rule_id,
                alerts=perf.total_alerts,
            )
            return []

        self.logger.info("analyzing_rule", rule_id=rule_id)

        recommendations = []

        # Check precision
        if perf.precision < self.target_precision:
            recs = self._recommend_precision_improvement(perf)
            recommendations.extend(recs)

        # Check recall
        if perf.recall < self.target_recall:
            recs = self._recommend_recall_improvement(perf)
            recommendations.extend(recs)

        # Check false positive rate
        if perf.false_positive_rate > self.max_false_positive_rate:
            recs = self._recommend_fp_reduction(perf)
            recommendations.extend(recs)

        # Check for patterns in history
        pattern_recs = self._analyze_patterns(rule_id, perf)
        recommendations.extend(pattern_recs)

        # Store recommendations
        self._recommendations[rule_id] = recommendations

        self.logger.info(
            "analysis_complete",
            rule_id=rule_id,
            recommendations=len(recommendations),
        )

        return recommendations

    def _recommend_precision_improvement(
        self,
        perf: RulePerformance,
    ) -> list[TuningRecommendation]:
        """Generate recommendations to improve precision."""
        recommendations = []
        gap = self.target_precision - perf.precision

        # Threshold adjustment for threshold-based rules
        if perf.rule_type == RuleType.THRESHOLD and perf.current_threshold:
            recommendations.append(TuningRecommendation(
                rule_id=perf.rule_id,
                adjustment_type=AdjustmentType.THRESHOLD_INCREASE,
                title="Increase detection threshold",
                description=f"Current precision ({perf.precision:.1%}) below target ({self.target_precision:.1%}). Increasing threshold will reduce false positives.",
                rationale=f"False positive rate of {perf.false_positive_rate:.1%} suggests threshold is too sensitive.",
                expected_precision_change=gap * 0.5,
                expected_recall_change=-0.05,
                confidence=0.7,
                priority=3,
                current_value=perf.current_threshold,
                recommended_value=perf.current_threshold * 1.2,
            ))

        # Add exception recommendation
        if perf.false_positives > 10:
            recommendations.append(TuningRecommendation(
                rule_id=perf.rule_id,
                adjustment_type=AdjustmentType.ADD_EXCEPTION,
                title="Add exceptions for known benign patterns",
                description="Review false positive patterns and add exceptions for known benign activity.",
                rationale=f"{perf.false_positives} false positives indicate some patterns should be excluded.",
                expected_precision_change=gap * 0.3,
                expected_recall_change=0,
                confidence=0.6,
                priority=4,
            ))

        return recommendations

    def _recommend_recall_improvement(
        self,
        perf: RulePerformance,
    ) -> list[TuningRecommendation]:
        """Generate recommendations to improve recall."""
        recommendations = []
        gap = self.target_recall - perf.recall

        # Threshold adjustment
        if perf.rule_type == RuleType.THRESHOLD and perf.current_threshold:
            recommendations.append(TuningRecommendation(
                rule_id=perf.rule_id,
                adjustment_type=AdjustmentType.THRESHOLD_DECREASE,
                title="Decrease detection threshold",
                description=f"Current recall ({perf.recall:.1%}) below target ({self.target_recall:.1%}). Decreasing threshold will catch more threats.",
                rationale="Some threats may be going undetected due to high threshold.",
                expected_precision_change=-0.05,
                expected_recall_change=gap * 0.5,
                confidence=0.7,
                priority=3,
                current_value=perf.current_threshold,
                recommended_value=perf.current_threshold * 0.8,
            ))

        # Time window adjustment
        if perf.rule_type == RuleType.CORRELATION and perf.current_timewindow_seconds:
            recommendations.append(TuningRecommendation(
                rule_id=perf.rule_id,
                adjustment_type=AdjustmentType.ADJUST_TIMEWINDOW,
                title="Expand correlation time window",
                description="Expanding the correlation window may capture slower attack patterns.",
                rationale="Some attacks may span longer time periods than current window allows.",
                expected_precision_change=-0.02,
                expected_recall_change=gap * 0.3,
                confidence=0.5,
                priority=5,
                current_value=perf.current_timewindow_seconds,
                recommended_value=perf.current_timewindow_seconds * 1.5,
            ))

        return recommendations

    def _recommend_fp_reduction(
        self,
        perf: RulePerformance,
    ) -> list[TuningRecommendation]:
        """Generate recommendations to reduce false positives."""
        recommendations = []

        if perf.false_positive_rate > 0.5:
            # Very high FP rate - consider disabling
            recommendations.append(TuningRecommendation(
                rule_id=perf.rule_id,
                adjustment_type=AdjustmentType.DISABLE_RULE,
                title="Consider disabling rule",
                description=f"False positive rate ({perf.false_positive_rate:.1%}) is very high. Rule may need fundamental redesign.",
                rationale="Current rule generates more noise than signal.",
                expected_precision_change=0,
                expected_recall_change=-1.0,
                confidence=0.8,
                priority=1,
            ))

        # Modify conditions
        recommendations.append(TuningRecommendation(
            rule_id=perf.rule_id,
            adjustment_type=AdjustmentType.MODIFY_CONDITION,
            title="Add qualifying conditions",
            description="Add additional conditions to narrow the rule scope.",
            rationale=f"Current conditions match too broadly ({perf.false_positive_rate:.1%} FP rate).",
            expected_precision_change=0.2,
            expected_recall_change=-0.05,
            confidence=0.6,
            priority=2,
        ))

        return recommendations

    def _analyze_patterns(
        self,
        rule_id: str,
        perf: RulePerformance,
    ) -> list[TuningRecommendation]:
        """Analyze patterns in alert history."""
        recommendations = []
        history = self._alert_history.get(rule_id, [])

        if len(history) < 20:
            return recommendations

        # Check for time-based patterns in false positives
        fp_records = [h for h in history if not h.get("is_true_positive")]

        if len(fp_records) >= 10:
            # Check for common patterns in details
            details_patterns = {}
            for record in fp_records:
                for key, value in record.get("details", {}).items():
                    pattern_key = f"{key}:{value}"
                    details_patterns[pattern_key] = details_patterns.get(pattern_key, 0) + 1

            # Find high-frequency patterns
            for pattern, count in details_patterns.items():
                if count >= len(fp_records) * 0.3:  # 30% of FPs
                    recommendations.append(TuningRecommendation(
                        rule_id=rule_id,
                        adjustment_type=AdjustmentType.ADD_EXCEPTION,
                        title=f"Add exception for pattern: {pattern}",
                        description=f"Pattern '{pattern}' appears in {count}/{len(fp_records)} false positives.",
                        rationale="Recurring false positive pattern detected.",
                        expected_precision_change=0.1,
                        expected_recall_change=0,
                        confidence=0.7,
                        priority=4,
                        recommended_value=pattern,
                    ))

        return recommendations

    def apply_adjustment(
        self,
        rule_id: str,
        adjustment_type: AdjustmentType,
        new_value: Any,
        recommendation_id: str | None = None,
        applied_by: str = "system",
    ) -> RuleAdjustment:
        """Apply an adjustment to a rule.

        Args:
            rule_id: Rule to adjust
            adjustment_type: Type of adjustment
            new_value: New value to apply
            recommendation_id: Associated recommendation
            applied_by: Who applied the adjustment

        Returns:
            Applied adjustment record
        """
        perf = self._rule_performance.get(rule_id)
        previous_value = None

        if perf:
            if adjustment_type == AdjustmentType.THRESHOLD_INCREASE or adjustment_type == AdjustmentType.THRESHOLD_DECREASE:
                previous_value = perf.current_threshold
                perf.current_threshold = new_value
            elif adjustment_type == AdjustmentType.ADJUST_TIMEWINDOW:
                previous_value = perf.current_timewindow_seconds
                perf.current_timewindow_seconds = new_value
            elif adjustment_type == AdjustmentType.ENABLE_RULE:
                previous_value = perf.is_enabled
                perf.is_enabled = True
            elif adjustment_type == AdjustmentType.DISABLE_RULE:
                previous_value = perf.is_enabled
                perf.is_enabled = False

        adjustment = RuleAdjustment(
            rule_id=rule_id,
            adjustment_type=adjustment_type,
            previous_value=previous_value,
            new_value=new_value,
            applied_by=applied_by,
            recommendation_id=recommendation_id,
            performance_before=perf.model_copy() if perf else None,
        )

        self._adjustments.append(adjustment)

        # Update recommendation status if provided
        if recommendation_id:
            for recs in self._recommendations.values():
                for rec in recs:
                    if rec.recommendation_id == recommendation_id:
                        rec.status = "applied"
                        rec.applied_at = datetime.utcnow()

        self.logger.info(
            "adjustment_applied",
            rule_id=rule_id,
            type=adjustment_type.value,
            new_value=new_value,
        )

        return adjustment

    def get_rule_performance(self, rule_id: str) -> RulePerformance | None:
        """Get performance metrics for a rule."""
        return self._rule_performance.get(rule_id)

    def get_all_rules(self) -> dict[str, RulePerformance]:
        """Get all rule performance data."""
        return self._rule_performance.copy()

    def get_recommendations(self, rule_id: str) -> list[TuningRecommendation]:
        """Get recommendations for a rule."""
        return self._recommendations.get(rule_id, [])

    def get_adjustments(
        self,
        rule_id: str | None = None,
        limit: int = 100,
    ) -> list[RuleAdjustment]:
        """Get adjustment history."""
        adjustments = self._adjustments

        if rule_id:
            adjustments = [a for a in adjustments if a.rule_id == rule_id]

        return adjustments[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get tuner statistics."""
        all_perf = list(self._rule_performance.values())
        all_recs = [r for rlist in self._recommendations.values() for r in rlist]

        return {
            "rules_tracked": len(self._rule_performance),
            "total_alerts_processed": sum(p.total_alerts for p in all_perf),
            "avg_precision": sum(p.precision for p in all_perf) / len(all_perf) if all_perf else 0,
            "avg_recall": sum(p.recall for p in all_perf) / len(all_perf) if all_perf else 0,
            "rules_below_precision_target": len([p for p in all_perf if p.precision < self.target_precision]),
            "rules_below_recall_target": len([p for p in all_perf if p.recall < self.target_recall]),
            "total_recommendations": len(all_recs),
            "pending_recommendations": len([r for r in all_recs if r.status == "pending"]),
            "applied_adjustments": len(self._adjustments),
        }
