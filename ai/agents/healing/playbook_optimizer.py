"""Playbook Optimizer - Optimize playbook performance and effectiveness."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class OptimizationType(str, Enum):
    """Types of optimization."""

    PERFORMANCE = "performance"
    EFFECTIVENESS = "effectiveness"
    RESOURCE = "resource"
    TIMING = "timing"
    ORDERING = "ordering"


class PlaybookMetrics(BaseModel):
    """Performance metrics for a playbook."""

    playbook_id: str = Field(description="Playbook identifier")
    playbook_name: str = Field(description="Playbook name")

    # Execution metrics
    total_executions: int = Field(default=0)
    successful_executions: int = Field(default=0)
    failed_executions: int = Field(default=0)
    avg_duration_seconds: float = Field(default=0.0)
    p95_duration_seconds: float = Field(default=0.0)

    # Effectiveness metrics
    true_positive_rate: float = Field(default=0.0)
    false_positive_rate: float = Field(default=0.0)
    containment_rate: float = Field(default=0.0)
    resolution_rate: float = Field(default=0.0)

    # Resource metrics
    avg_cpu_usage: float = Field(default=0.0)
    avg_memory_usage_mb: float = Field(default=0.0)
    avg_api_calls: int = Field(default=0)

    # Time-based
    first_execution: datetime | None = Field(default=None)
    last_execution: datetime | None = Field(default=None)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class OptimizationSuggestion(BaseModel):
    """A suggested optimization."""

    suggestion_id: str = Field(default_factory=lambda: str(uuid4()))
    playbook_id: str = Field(description="Target playbook")
    optimization_type: OptimizationType = Field(description="Type of optimization")

    title: str = Field(description="Suggestion title")
    description: str = Field(description="Detailed description")
    expected_improvement: float = Field(description="Expected improvement percentage")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    priority: int = Field(default=5, ge=1, le=10)

    # Implementation
    changes_required: list[dict[str, Any]] = Field(default_factory=list)
    implementation_difficulty: str = Field(default="medium")
    estimated_effort_hours: float = Field(default=1.0)

    # Status
    status: str = Field(default="pending")  # pending, accepted, rejected, implemented
    created_at: datetime = Field(default_factory=datetime.utcnow)


class OptimizationResult(BaseModel):
    """Result of an optimization run."""

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    playbook_id: str = Field(description="Optimized playbook")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Analysis
    metrics_before: PlaybookMetrics | None = Field(default=None)
    issues_found: list[str] = Field(default_factory=list)
    suggestions: list[OptimizationSuggestion] = Field(default_factory=list)

    # Summary
    total_suggestions: int = Field(default=0)
    estimated_improvement: float = Field(default=0.0)


class PlaybookOptimizer(LoggerMixin):
    """Optimizer for improving playbook performance and effectiveness.

    Features:
    - Performance analysis
    - Effectiveness measurement
    - Optimization suggestions
    - Automatic tuning
    - A/B testing support
    """

    def __init__(
        self,
        min_executions_for_analysis: int = 10,
        improvement_threshold: float = 0.1,
    ) -> None:
        """Initialize playbook optimizer.

        Args:
            min_executions_for_analysis: Minimum executions before analysis
            improvement_threshold: Minimum improvement to suggest
        """
        self.min_executions_for_analysis = min_executions_for_analysis
        self.improvement_threshold = improvement_threshold

        self._metrics: dict[str, PlaybookMetrics] = {}
        self._execution_history: dict[str, list[dict]] = {}
        self._suggestions: dict[str, list[OptimizationSuggestion]] = {}

    def record_execution(
        self,
        playbook_id: str,
        playbook_name: str,
        success: bool,
        duration_seconds: float,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record a playbook execution.

        Args:
            playbook_id: Playbook identifier
            playbook_name: Playbook name
            success: Whether execution succeeded
            duration_seconds: Execution duration
            details: Additional details
        """
        # Initialize metrics if needed
        if playbook_id not in self._metrics:
            self._metrics[playbook_id] = PlaybookMetrics(
                playbook_id=playbook_id,
                playbook_name=playbook_name,
                first_execution=datetime.utcnow(),
            )
            self._execution_history[playbook_id] = []

        metrics = self._metrics[playbook_id]

        # Update execution counts
        metrics.total_executions += 1
        if success:
            metrics.successful_executions += 1
        else:
            metrics.failed_executions += 1

        # Update timing
        metrics.last_execution = datetime.utcnow()
        metrics.updated_at = datetime.utcnow()

        # Record execution details
        execution = {
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "duration_seconds": duration_seconds,
            "details": details or {},
        }
        self._execution_history[playbook_id].append(execution)

        # Keep only recent history
        self._execution_history[playbook_id] = self._execution_history[playbook_id][-1000:]

        # Update computed metrics
        self._update_computed_metrics(playbook_id)

        self.logger.debug(
            "execution_recorded",
            playbook_id=playbook_id,
            success=success,
            duration=duration_seconds,
        )

    def _update_computed_metrics(self, playbook_id: str) -> None:
        """Update computed metrics from execution history."""
        history = self._execution_history.get(playbook_id, [])
        if not history:
            return

        metrics = self._metrics[playbook_id]

        # Calculate average duration
        durations = [e["duration_seconds"] for e in history]
        metrics.avg_duration_seconds = sum(durations) / len(durations)

        # Calculate P95 duration
        sorted_durations = sorted(durations)
        p95_idx = int(len(sorted_durations) * 0.95)
        metrics.p95_duration_seconds = sorted_durations[min(p95_idx, len(sorted_durations) - 1)]

        # Calculate effectiveness metrics from details
        details = [e.get("details", {}) for e in history]

        true_positives = sum(1 for d in details if d.get("true_positive", False))
        false_positives = sum(1 for d in details if d.get("false_positive", False))
        contained = sum(1 for d in details if d.get("contained", False))
        resolved = sum(1 for d in details if d.get("resolved", False))

        total = len(details)
        metrics.true_positive_rate = true_positives / total if total > 0 else 0
        metrics.false_positive_rate = false_positives / total if total > 0 else 0
        metrics.containment_rate = contained / total if total > 0 else 0
        metrics.resolution_rate = resolved / total if total > 0 else 0

        # Resource metrics from details
        cpu_usage = [d.get("cpu_usage", 0) for d in details if d.get("cpu_usage")]
        memory_usage = [d.get("memory_usage_mb", 0) for d in details if d.get("memory_usage_mb")]
        api_calls = [d.get("api_calls", 0) for d in details if d.get("api_calls")]

        metrics.avg_cpu_usage = sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0
        metrics.avg_memory_usage_mb = sum(memory_usage) / len(memory_usage) if memory_usage else 0
        metrics.avg_api_calls = int(sum(api_calls) / len(api_calls)) if api_calls else 0

    def analyze(self, playbook_id: str) -> OptimizationResult:
        """Analyze a playbook and generate optimization suggestions.

        Args:
            playbook_id: Playbook to analyze

        Returns:
            Optimization result with suggestions
        """
        metrics = self._metrics.get(playbook_id)
        if not metrics:
            return OptimizationResult(
                playbook_id=playbook_id,
                issues_found=["No metrics available"],
            )

        if metrics.total_executions < self.min_executions_for_analysis:
            return OptimizationResult(
                playbook_id=playbook_id,
                metrics_before=metrics,
                issues_found=[f"Insufficient executions ({metrics.total_executions}/{self.min_executions_for_analysis})"],
            )

        self.logger.info("analyzing_playbook", playbook_id=playbook_id)

        issues = []
        suggestions = []

        # Analyze performance
        perf_issues, perf_suggestions = self._analyze_performance(metrics)
        issues.extend(perf_issues)
        suggestions.extend(perf_suggestions)

        # Analyze effectiveness
        eff_issues, eff_suggestions = self._analyze_effectiveness(metrics)
        issues.extend(eff_issues)
        suggestions.extend(eff_suggestions)

        # Analyze resource usage
        res_issues, res_suggestions = self._analyze_resources(metrics)
        issues.extend(res_issues)
        suggestions.extend(res_suggestions)

        # Analyze patterns
        pattern_issues, pattern_suggestions = self._analyze_patterns(playbook_id, metrics)
        issues.extend(pattern_issues)
        suggestions.extend(pattern_suggestions)

        # Calculate estimated total improvement
        total_improvement = sum(s.expected_improvement for s in suggestions)

        # Store suggestions
        self._suggestions[playbook_id] = suggestions

        result = OptimizationResult(
            playbook_id=playbook_id,
            metrics_before=metrics,
            issues_found=issues,
            suggestions=suggestions,
            total_suggestions=len(suggestions),
            estimated_improvement=total_improvement,
        )

        self.logger.info(
            "analysis_complete",
            playbook_id=playbook_id,
            issues=len(issues),
            suggestions=len(suggestions),
        )

        return result

    def _analyze_performance(
        self,
        metrics: PlaybookMetrics,
    ) -> tuple[list[str], list[OptimizationSuggestion]]:
        """Analyze performance metrics."""
        issues = []
        suggestions = []

        # High average duration
        if metrics.avg_duration_seconds > 300:  # 5 minutes
            issues.append(f"High average execution time: {metrics.avg_duration_seconds:.1f}s")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.PERFORMANCE,
                title="Reduce execution time",
                description="Execution time exceeds recommended threshold. Consider parallelizing steps or optimizing queries.",
                expected_improvement=0.2,
                priority=3,
                changes_required=[
                    {"type": "parallelize_steps", "target": "independent_actions"},
                    {"type": "optimize_queries", "target": "data_collection"},
                ],
            ))

        # High P95 latency
        if metrics.p95_duration_seconds > 600:  # 10 minutes
            issues.append(f"High P95 latency: {metrics.p95_duration_seconds:.1f}s")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.PERFORMANCE,
                title="Address tail latency",
                description="P95 latency indicates some executions take significantly longer. Add timeouts and fallbacks.",
                expected_improvement=0.15,
                priority=4,
                changes_required=[
                    {"type": "add_timeout", "value": 300},
                    {"type": "add_fallback", "for": "slow_operations"},
                ],
            ))

        # High failure rate
        if metrics.total_executions > 0:
            failure_rate = metrics.failed_executions / metrics.total_executions
            if failure_rate > 0.1:  # 10%
                issues.append(f"High failure rate: {failure_rate:.1%}")
                suggestions.append(OptimizationSuggestion(
                    playbook_id=metrics.playbook_id,
                    optimization_type=OptimizationType.PERFORMANCE,
                    title="Improve reliability",
                    description=f"Failure rate of {failure_rate:.1%} exceeds acceptable threshold. Add error handling and retries.",
                    expected_improvement=failure_rate * 0.5,
                    priority=2,
                    changes_required=[
                        {"type": "add_retry", "max_attempts": 3},
                        {"type": "improve_error_handling"},
                    ],
                ))

        return issues, suggestions

    def _analyze_effectiveness(
        self,
        metrics: PlaybookMetrics,
    ) -> tuple[list[str], list[OptimizationSuggestion]]:
        """Analyze effectiveness metrics."""
        issues = []
        suggestions = []

        # Low containment rate
        if metrics.containment_rate < 0.7 and metrics.total_executions > 20:
            issues.append(f"Low containment rate: {metrics.containment_rate:.1%}")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.EFFECTIVENESS,
                title="Improve containment actions",
                description="Containment rate below target. Review and enhance containment steps.",
                expected_improvement=0.2,
                priority=2,
                changes_required=[
                    {"type": "review_containment_steps"},
                    {"type": "add_verification_checks"},
                ],
            ))

        # High false positive rate
        if metrics.false_positive_rate > 0.3:
            issues.append(f"High false positive rate: {metrics.false_positive_rate:.1%}")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.EFFECTIVENESS,
                title="Reduce false positives",
                description="False positive rate is too high. Add pre-validation checks.",
                expected_improvement=metrics.false_positive_rate * 0.4,
                priority=3,
                changes_required=[
                    {"type": "add_triage_step"},
                    {"type": "improve_filtering"},
                ],
            ))

        # Low resolution rate
        if metrics.resolution_rate < 0.5 and metrics.total_executions > 20:
            issues.append(f"Low resolution rate: {metrics.resolution_rate:.1%}")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.EFFECTIVENESS,
                title="Improve resolution workflow",
                description="Resolution rate below target. Enhance remediation steps.",
                expected_improvement=0.15,
                priority=3,
                changes_required=[
                    {"type": "enhance_remediation"},
                    {"type": "add_follow_up_validation"},
                ],
            ))

        return issues, suggestions

    def _analyze_resources(
        self,
        metrics: PlaybookMetrics,
    ) -> tuple[list[str], list[OptimizationSuggestion]]:
        """Analyze resource usage."""
        issues = []
        suggestions = []

        # High API calls
        if metrics.avg_api_calls > 50:
            issues.append(f"High API call count: {metrics.avg_api_calls}")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.RESOURCE,
                title="Reduce API calls",
                description="High number of API calls. Implement caching and batch requests.",
                expected_improvement=0.1,
                priority=5,
                changes_required=[
                    {"type": "implement_caching"},
                    {"type": "batch_api_requests"},
                ],
            ))

        # High memory usage
        if metrics.avg_memory_usage_mb > 1024:  # 1GB
            issues.append(f"High memory usage: {metrics.avg_memory_usage_mb:.0f}MB")
            suggestions.append(OptimizationSuggestion(
                playbook_id=metrics.playbook_id,
                optimization_type=OptimizationType.RESOURCE,
                title="Optimize memory usage",
                description="Memory usage exceeds recommended levels. Stream large data instead of loading all at once.",
                expected_improvement=0.1,
                priority=6,
                changes_required=[
                    {"type": "implement_streaming"},
                    {"type": "reduce_data_retention"},
                ],
            ))

        return issues, suggestions

    def _analyze_patterns(
        self,
        playbook_id: str,
        metrics: PlaybookMetrics,
    ) -> tuple[list[str], list[OptimizationSuggestion]]:
        """Analyze execution patterns."""
        issues = []
        suggestions = []

        history = self._execution_history.get(playbook_id, [])
        if len(history) < 20:
            return issues, suggestions

        # Check for time-based patterns
        recent = history[-50:]
        hours = [datetime.fromisoformat(e["timestamp"]).hour for e in recent]

        peak_hour = max(set(hours), key=hours.count)
        peak_count = hours.count(peak_hour)

        if peak_count > len(hours) * 0.3:
            issues.append(f"High concentration at hour {peak_hour}")
            suggestions.append(OptimizationSuggestion(
                playbook_id=playbook_id,
                optimization_type=OptimizationType.TIMING,
                title="Optimize execution timing",
                description=f"Many executions concentrated at hour {peak_hour}. Consider load balancing.",
                expected_improvement=0.05,
                priority=7,
                changes_required=[
                    {"type": "implement_scheduling"},
                    {"type": "add_rate_limiting"},
                ],
            ))

        return issues, suggestions

    def get_metrics(self, playbook_id: str) -> PlaybookMetrics | None:
        """Get metrics for a playbook."""
        return self._metrics.get(playbook_id)

    def get_all_metrics(self) -> dict[str, PlaybookMetrics]:
        """Get all playbook metrics."""
        return self._metrics.copy()

    def get_suggestions(self, playbook_id: str) -> list[OptimizationSuggestion]:
        """Get optimization suggestions for a playbook."""
        return self._suggestions.get(playbook_id, [])

    def mark_suggestion_status(
        self,
        suggestion_id: str,
        status: str,
    ) -> bool:
        """Update suggestion status."""
        for playbook_suggestions in self._suggestions.values():
            for suggestion in playbook_suggestions:
                if suggestion.suggestion_id == suggestion_id:
                    suggestion.status = status
                    return True
        return False

    def get_stats(self) -> dict[str, Any]:
        """Get optimizer statistics."""
        all_metrics = list(self._metrics.values())
        all_suggestions = [s for slist in self._suggestions.values() for s in slist]

        return {
            "playbooks_tracked": len(self._metrics),
            "total_executions": sum(m.total_executions for m in all_metrics),
            "avg_success_rate": (
                sum(m.successful_executions for m in all_metrics) /
                sum(m.total_executions for m in all_metrics)
                if all_metrics and sum(m.total_executions for m in all_metrics) > 0
                else 0
            ),
            "total_suggestions": len(all_suggestions),
            "pending_suggestions": len([s for s in all_suggestions if s.status == "pending"]),
            "implemented_suggestions": len([s for s in all_suggestions if s.status == "implemented"]),
        }
