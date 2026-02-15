"""AI Agents Module - LangGraph-based autonomous agents for SIEM/SOAR operations.

This module provides intelligent agents for automated security operations:
- Investigation agents for automated threat investigation
- Analysis agents for root cause and impact analysis
- Response agents for automated incident response
- Orchestration for multi-agent coordination
- Safety mechanisms and guardrails
- Self-healing capabilities
"""

from .base import BaseAgent, AgentCapability, AgentConfig
from .registry import AgentRegistry, get_registry
from .state import AgentState, StateManager, StateTransition
from .memory import AgentMemory, MemoryType, MemoryItem

# Sub-modules - Import commonly used classes
from .investigation import (
    InvestigationAgent,
    ContextCollector,
    EvidenceGatherer,
    TimelineBuilder,
    create_investigation_graph,
)
from .analysis import (
    AnalysisAgent,
    RootCauseAnalyzer,
    ImpactAssessor,
    ThreatClassifier,
    create_analysis_graph,
)
from .response import (
    ResponseAgent,
    ActionPlanner,
    ActionExecutor,
    ResponseValidator,
    create_response_graph,
)
from .orchestrator import (
    SOCOrchestrator,
    OrchestratorConfig,
    AgentCoordinator,
    TaskScheduler,
    AgentSupervisor,
    create_orchestration_graph,
)
from .safety import (
    GuardrailEngine,
    ApprovalGate,
    RollbackManager,
    AuditLogger,
    ExecutionLimiter,
)
from .healing import (
    SelfHealer,
    PlaybookOptimizer,
    RuleTuner,
    FeedbackLoop,
)

__all__ = [
    # Base
    "BaseAgent",
    "AgentCapability",
    "AgentConfig",
    # Registry
    "AgentRegistry",
    "get_registry",
    # State
    "AgentState",
    "StateManager",
    "StateTransition",
    # Memory
    "AgentMemory",
    "MemoryType",
    "MemoryItem",
    # Investigation
    "InvestigationAgent",
    "ContextCollector",
    "EvidenceGatherer",
    "TimelineBuilder",
    "create_investigation_graph",
    # Analysis
    "AnalysisAgent",
    "RootCauseAnalyzer",
    "ImpactAssessor",
    "ThreatClassifier",
    "create_analysis_graph",
    # Response
    "ResponseAgent",
    "ActionPlanner",
    "ActionExecutor",
    "ResponseValidator",
    "create_response_graph",
    # Orchestrator
    "SOCOrchestrator",
    "OrchestratorConfig",
    "AgentCoordinator",
    "TaskScheduler",
    "AgentSupervisor",
    "create_orchestration_graph",
    # Safety
    "GuardrailEngine",
    "ApprovalGate",
    "RollbackManager",
    "AuditLogger",
    "ExecutionLimiter",
    # Healing
    "SelfHealer",
    "PlaybookOptimizer",
    "RuleTuner",
    "FeedbackLoop",
]
