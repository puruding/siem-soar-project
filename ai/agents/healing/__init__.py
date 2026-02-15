"""Self-Healing Module - Autonomous optimization and adaptation.

This module provides self-healing capabilities:
- Self Healer: System health monitoring and recovery
- Playbook Optimizer: Optimize playbook performance
- Rule Tuner: Tune detection rules
- Feedback Loop: Learning from outcomes
"""

from .self_healer import (
    SelfHealer,
    HealthCheck,
    HealthIssue,
    RecoveryAction,
    SystemHealth,
)
from .playbook_optimizer import (
    PlaybookOptimizer,
    PlaybookMetrics,
    OptimizationResult,
    OptimizationSuggestion,
)
from .rule_tuner import (
    RuleTuner,
    RulePerformance,
    TuningRecommendation,
    RuleAdjustment,
)
from .feedback_loop import (
    FeedbackLoop,
    FeedbackEntry,
    FeedbackType,
    LearningOutcome,
)

__all__ = [
    # Self Healer
    "SelfHealer",
    "HealthCheck",
    "HealthIssue",
    "RecoveryAction",
    "SystemHealth",
    # Playbook Optimizer
    "PlaybookOptimizer",
    "PlaybookMetrics",
    "OptimizationResult",
    "OptimizationSuggestion",
    # Rule Tuner
    "RuleTuner",
    "RulePerformance",
    "TuningRecommendation",
    "RuleAdjustment",
    # Feedback Loop
    "FeedbackLoop",
    "FeedbackEntry",
    "FeedbackType",
    "LearningOutcome",
]
