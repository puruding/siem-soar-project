"""Feedback Loop - Learning from outcomes to improve agent performance."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class FeedbackType(str, Enum):
    """Types of feedback."""

    ANALYST_REVIEW = "analyst_review"
    AUTOMATED_VALIDATION = "automated_validation"
    OUTCOME_TRACKING = "outcome_tracking"
    PERFORMANCE_METRIC = "performance_metric"
    USER_RATING = "user_rating"


class OutcomeType(str, Enum):
    """Types of outcomes to track."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    TRUE_NEGATIVE = "true_negative"
    FALSE_NEGATIVE = "false_negative"
    EFFECTIVE_RESPONSE = "effective_response"
    INEFFECTIVE_RESPONSE = "ineffective_response"
    PARTIAL_SUCCESS = "partial_success"


class FeedbackEntry(BaseModel):
    """A single feedback entry."""

    feedback_id: str = Field(default_factory=lambda: str(uuid4()))
    feedback_type: FeedbackType = Field(description="Type of feedback")

    # Context
    incident_id: str | None = Field(default=None)
    agent_id: str | None = Field(default=None)
    action_id: str | None = Field(default=None)
    decision_id: str | None = Field(default=None)

    # Feedback content
    outcome: OutcomeType | None = Field(default=None)
    rating: int | None = Field(default=None, ge=1, le=5)
    notes: str | None = Field(default=None)
    details: dict[str, Any] = Field(default_factory=dict)

    # Source
    source: str = Field(default="system")  # analyst_id, system, automated
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class LearningOutcome(BaseModel):
    """An outcome from the learning process."""

    outcome_id: str = Field(default_factory=lambda: str(uuid4()))
    category: str = Field(description="Category of learning")
    insight: str = Field(description="What was learned")

    # Impact
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    impact_score: float = Field(default=0.5, ge=0.0, le=1.0)

    # Source data
    based_on_entries: int = Field(default=0)
    time_range_days: int = Field(default=7)

    # Recommendations
    recommendations: list[str] = Field(default_factory=list)

    # Status
    status: str = Field(default="identified")  # identified, validated, applied
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FeedbackLoop(LoggerMixin):
    """Feedback loop for continuous learning and improvement.

    Features:
    - Feedback collection from multiple sources
    - Pattern analysis
    - Learning outcome generation
    - Model/behavior adjustment recommendations
    - Performance trending
    """

    def __init__(
        self,
        min_entries_for_learning: int = 20,
        learning_window_days: int = 7,
        trend_window_days: int = 30,
    ) -> None:
        """Initialize feedback loop.

        Args:
            min_entries_for_learning: Minimum entries before learning
            learning_window_days: Days to consider for learning
            trend_window_days: Days for trend analysis
        """
        self.min_entries_for_learning = min_entries_for_learning
        self.learning_window_days = learning_window_days
        self.trend_window_days = trend_window_days

        self._feedback: list[FeedbackEntry] = []
        self._outcomes: list[LearningOutcome] = []
        self._metrics_history: dict[str, list[dict]] = defaultdict(list)
        self._patterns: dict[str, dict] = {}

    def record_feedback(
        self,
        feedback_type: FeedbackType,
        outcome: OutcomeType | None = None,
        rating: int | None = None,
        notes: str | None = None,
        incident_id: str | None = None,
        agent_id: str | None = None,
        action_id: str | None = None,
        decision_id: str | None = None,
        details: dict[str, Any] | None = None,
        source: str = "system",
    ) -> FeedbackEntry:
        """Record a feedback entry.

        Args:
            feedback_type: Type of feedback
            outcome: Outcome classification
            rating: Rating (1-5)
            notes: Additional notes
            incident_id: Associated incident
            agent_id: Associated agent
            action_id: Associated action
            decision_id: Associated decision
            details: Additional details
            source: Source of feedback

        Returns:
            Created feedback entry
        """
        entry = FeedbackEntry(
            feedback_type=feedback_type,
            outcome=outcome,
            rating=rating,
            notes=notes,
            incident_id=incident_id,
            agent_id=agent_id,
            action_id=action_id,
            decision_id=decision_id,
            details=details or {},
            source=source,
        )

        self._feedback.append(entry)

        self.logger.info(
            "feedback_recorded",
            feedback_id=entry.feedback_id,
            type=feedback_type.value,
            outcome=outcome.value if outcome else None,
        )

        # Update patterns
        self._update_patterns(entry)

        return entry

    def record_analyst_review(
        self,
        incident_id: str,
        is_true_positive: bool,
        effectiveness_rating: int,
        analyst_id: str,
        notes: str | None = None,
    ) -> FeedbackEntry:
        """Record analyst review of an incident.

        Args:
            incident_id: Incident reviewed
            is_true_positive: Whether incident was true positive
            effectiveness_rating: Rating of response effectiveness
            analyst_id: Reviewing analyst
            notes: Analyst notes

        Returns:
            Feedback entry
        """
        outcome = OutcomeType.TRUE_POSITIVE if is_true_positive else OutcomeType.FALSE_POSITIVE

        return self.record_feedback(
            feedback_type=FeedbackType.ANALYST_REVIEW,
            outcome=outcome,
            rating=effectiveness_rating,
            notes=notes,
            incident_id=incident_id,
            source=analyst_id,
            details={
                "is_true_positive": is_true_positive,
                "effectiveness_rating": effectiveness_rating,
            },
        )

    def record_action_outcome(
        self,
        action_id: str,
        was_effective: bool,
        incident_id: str | None = None,
        agent_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> FeedbackEntry:
        """Record the outcome of an automated action.

        Args:
            action_id: Action ID
            was_effective: Whether action was effective
            incident_id: Associated incident
            agent_id: Agent that performed action
            details: Additional details

        Returns:
            Feedback entry
        """
        outcome = OutcomeType.EFFECTIVE_RESPONSE if was_effective else OutcomeType.INEFFECTIVE_RESPONSE

        return self.record_feedback(
            feedback_type=FeedbackType.OUTCOME_TRACKING,
            outcome=outcome,
            action_id=action_id,
            incident_id=incident_id,
            agent_id=agent_id,
            details=details or {},
        )

    def record_metric(
        self,
        metric_name: str,
        value: float,
        agent_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record a performance metric.

        Args:
            metric_name: Name of the metric
            value: Metric value
            agent_id: Associated agent
            details: Additional details
        """
        metric_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "value": value,
            "agent_id": agent_id,
            "details": details or {},
        }

        self._metrics_history[metric_name].append(metric_record)

        # Keep limited history
        self._metrics_history[metric_name] = self._metrics_history[metric_name][-1000:]

        self.logger.debug(
            "metric_recorded",
            metric=metric_name,
            value=value,
        )

    def _update_patterns(self, entry: FeedbackEntry) -> None:
        """Update tracked patterns from feedback entry."""
        # Track by agent
        if entry.agent_id:
            key = f"agent:{entry.agent_id}"
            if key not in self._patterns:
                self._patterns[key] = {
                    "total": 0,
                    "positive": 0,
                    "negative": 0,
                    "ratings": [],
                }

            self._patterns[key]["total"] += 1

            if entry.outcome in [OutcomeType.TRUE_POSITIVE, OutcomeType.EFFECTIVE_RESPONSE]:
                self._patterns[key]["positive"] += 1
            elif entry.outcome in [OutcomeType.FALSE_POSITIVE, OutcomeType.INEFFECTIVE_RESPONSE]:
                self._patterns[key]["negative"] += 1

            if entry.rating:
                self._patterns[key]["ratings"].append(entry.rating)
                self._patterns[key]["ratings"] = self._patterns[key]["ratings"][-100:]

    def analyze_and_learn(self) -> list[LearningOutcome]:
        """Analyze feedback and generate learning outcomes.

        Returns:
            List of learning outcomes
        """
        cutoff = datetime.utcnow() - timedelta(days=self.learning_window_days)
        recent_feedback = [f for f in self._feedback if f.timestamp > cutoff]

        if len(recent_feedback) < self.min_entries_for_learning:
            self.logger.info(
                "insufficient_feedback",
                count=len(recent_feedback),
                required=self.min_entries_for_learning,
            )
            return []

        self.logger.info("analyzing_feedback", count=len(recent_feedback))

        outcomes = []

        # Analyze agent performance
        agent_outcomes = self._analyze_agent_performance(recent_feedback)
        outcomes.extend(agent_outcomes)

        # Analyze outcome patterns
        pattern_outcomes = self._analyze_outcome_patterns(recent_feedback)
        outcomes.extend(pattern_outcomes)

        # Analyze effectiveness trends
        trend_outcomes = self._analyze_trends()
        outcomes.extend(trend_outcomes)

        # Store outcomes
        self._outcomes.extend(outcomes)

        self.logger.info(
            "learning_complete",
            outcomes_generated=len(outcomes),
        )

        return outcomes

    def _analyze_agent_performance(
        self,
        feedback: list[FeedbackEntry],
    ) -> list[LearningOutcome]:
        """Analyze per-agent performance."""
        outcomes = []

        # Group by agent
        agent_feedback: dict[str, list[FeedbackEntry]] = defaultdict(list)
        for entry in feedback:
            if entry.agent_id:
                agent_feedback[entry.agent_id].append(entry)

        for agent_id, entries in agent_feedback.items():
            if len(entries) < 10:
                continue

            # Calculate success rate
            positive = sum(1 for e in entries if e.outcome in [
                OutcomeType.TRUE_POSITIVE,
                OutcomeType.EFFECTIVE_RESPONSE,
            ])
            success_rate = positive / len(entries)

            # Calculate average rating
            ratings = [e.rating for e in entries if e.rating]
            avg_rating = sum(ratings) / len(ratings) if ratings else 0

            # Generate outcomes based on analysis
            if success_rate < 0.6:
                outcomes.append(LearningOutcome(
                    category="agent_performance",
                    insight=f"Agent {agent_id} has low success rate ({success_rate:.1%})",
                    confidence=0.8,
                    impact_score=0.7,
                    based_on_entries=len(entries),
                    time_range_days=self.learning_window_days,
                    recommendations=[
                        f"Review agent {agent_id} configuration",
                        "Consider retraining or updating decision logic",
                        "Analyze failure cases for common patterns",
                    ],
                ))

            if avg_rating > 0 and avg_rating < 3.0:
                outcomes.append(LearningOutcome(
                    category="agent_quality",
                    insight=f"Agent {agent_id} has low quality rating ({avg_rating:.1f}/5)",
                    confidence=0.7,
                    impact_score=0.5,
                    based_on_entries=len(ratings),
                    time_range_days=self.learning_window_days,
                    recommendations=[
                        "Review analyst feedback comments",
                        "Adjust response templates",
                        "Improve context gathering",
                    ],
                ))

        return outcomes

    def _analyze_outcome_patterns(
        self,
        feedback: list[FeedbackEntry],
    ) -> list[LearningOutcome]:
        """Analyze patterns in outcomes."""
        outcomes = []

        # Calculate overall false positive rate
        classification_feedback = [
            e for e in feedback
            if e.outcome in [OutcomeType.TRUE_POSITIVE, OutcomeType.FALSE_POSITIVE]
        ]

        if len(classification_feedback) >= 20:
            fp_count = sum(1 for e in classification_feedback if e.outcome == OutcomeType.FALSE_POSITIVE)
            fp_rate = fp_count / len(classification_feedback)

            if fp_rate > 0.3:
                outcomes.append(LearningOutcome(
                    category="detection_accuracy",
                    insight=f"High overall false positive rate ({fp_rate:.1%})",
                    confidence=0.85,
                    impact_score=0.8,
                    based_on_entries=len(classification_feedback),
                    time_range_days=self.learning_window_days,
                    recommendations=[
                        "Review detection rules for over-sensitivity",
                        "Add pre-validation checks",
                        "Consider ML-based triage",
                    ],
                ))

        # Calculate response effectiveness
        response_feedback = [
            e for e in feedback
            if e.outcome in [OutcomeType.EFFECTIVE_RESPONSE, OutcomeType.INEFFECTIVE_RESPONSE]
        ]

        if len(response_feedback) >= 20:
            ineffective = sum(1 for e in response_feedback if e.outcome == OutcomeType.INEFFECTIVE_RESPONSE)
            ineffective_rate = ineffective / len(response_feedback)

            if ineffective_rate > 0.2:
                outcomes.append(LearningOutcome(
                    category="response_effectiveness",
                    insight=f"High rate of ineffective responses ({ineffective_rate:.1%})",
                    confidence=0.8,
                    impact_score=0.7,
                    based_on_entries=len(response_feedback),
                    time_range_days=self.learning_window_days,
                    recommendations=[
                        "Review response playbooks",
                        "Enhance validation checks",
                        "Add fallback actions",
                    ],
                ))

        return outcomes

    def _analyze_trends(self) -> list[LearningOutcome]:
        """Analyze metric trends."""
        outcomes = []

        for metric_name, history in self._metrics_history.items():
            if len(history) < 20:
                continue

            # Split into recent and previous periods
            mid = len(history) // 2
            previous = [h["value"] for h in history[:mid]]
            recent = [h["value"] for h in history[mid:]]

            prev_avg = sum(previous) / len(previous)
            recent_avg = sum(recent) / len(recent)

            # Calculate change
            if prev_avg > 0:
                change = (recent_avg - prev_avg) / prev_avg

                if abs(change) > 0.2:  # 20% change
                    direction = "improved" if change > 0 else "degraded"
                    outcomes.append(LearningOutcome(
                        category="metric_trend",
                        insight=f"Metric '{metric_name}' has {direction} by {abs(change):.1%}",
                        confidence=0.7,
                        impact_score=0.4,
                        based_on_entries=len(history),
                        time_range_days=self.trend_window_days,
                        recommendations=[
                            f"Investigate cause of {direction} {metric_name}",
                            "Check for system changes during period",
                        ],
                    ))

        return outcomes

    def get_feedback(
        self,
        feedback_type: FeedbackType | None = None,
        agent_id: str | None = None,
        incident_id: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[FeedbackEntry]:
        """Get feedback entries.

        Args:
            feedback_type: Filter by type
            agent_id: Filter by agent
            incident_id: Filter by incident
            since: Filter by time
            limit: Maximum results

        Returns:
            Matching feedback entries
        """
        results = []

        for entry in reversed(self._feedback):
            if feedback_type and entry.feedback_type != feedback_type:
                continue
            if agent_id and entry.agent_id != agent_id:
                continue
            if incident_id and entry.incident_id != incident_id:
                continue
            if since and entry.timestamp < since:
                continue

            results.append(entry)

            if len(results) >= limit:
                break

        return results

    def get_learning_outcomes(
        self,
        category: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[LearningOutcome]:
        """Get learning outcomes.

        Args:
            category: Filter by category
            status: Filter by status
            limit: Maximum results

        Returns:
            Learning outcomes
        """
        results = []

        for outcome in reversed(self._outcomes):
            if category and outcome.category != category:
                continue
            if status and outcome.status != status:
                continue

            results.append(outcome)

            if len(results) >= limit:
                break

        return results

    def mark_outcome_status(
        self,
        outcome_id: str,
        status: str,
    ) -> bool:
        """Update outcome status."""
        for outcome in self._outcomes:
            if outcome.outcome_id == outcome_id:
                outcome.status = status
                return True
        return False

    def get_agent_summary(self, agent_id: str) -> dict[str, Any]:
        """Get summary for an agent."""
        pattern = self._patterns.get(f"agent:{agent_id}", {})

        total = pattern.get("total", 0)
        positive = pattern.get("positive", 0)
        ratings = pattern.get("ratings", [])

        return {
            "agent_id": agent_id,
            "total_feedback": total,
            "success_rate": positive / total if total > 0 else 0,
            "average_rating": sum(ratings) / len(ratings) if ratings else 0,
            "rating_count": len(ratings),
        }

    def get_stats(self) -> dict[str, Any]:
        """Get feedback loop statistics."""
        cutoff_7d = datetime.utcnow() - timedelta(days=7)
        cutoff_30d = datetime.utcnow() - timedelta(days=30)

        recent_7d = [f for f in self._feedback if f.timestamp > cutoff_7d]
        recent_30d = [f for f in self._feedback if f.timestamp > cutoff_30d]

        return {
            "total_feedback": len(self._feedback),
            "feedback_7d": len(recent_7d),
            "feedback_30d": len(recent_30d),
            "learning_outcomes": len(self._outcomes),
            "pending_outcomes": len([o for o in self._outcomes if o.status == "identified"]),
            "applied_outcomes": len([o for o in self._outcomes if o.status == "applied"]),
            "tracked_agents": len([k for k in self._patterns if k.startswith("agent:")]),
            "tracked_metrics": len(self._metrics_history),
        }
