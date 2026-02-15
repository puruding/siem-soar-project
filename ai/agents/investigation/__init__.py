"""Investigation Agents - Automated threat investigation capabilities.

This module provides agents for automated security investigation:
- Investigator: Main investigation orchestration
- ContextCollector: Gather relevant context
- EvidenceGatherer: Collect and preserve evidence
- TimelineBuilder: Construct incident timelines
"""

from .investigator import InvestigatorAgent, InvestigatorConfig
from .context_collector import ContextCollector, ContextSource
from .evidence_gatherer import EvidenceGatherer, Evidence, EvidenceType
from .timeline_builder import TimelineBuilder, TimelineEvent
from .graph import create_investigation_graph, InvestigationState

__all__ = [
    "InvestigatorAgent",
    "InvestigatorConfig",
    "ContextCollector",
    "ContextSource",
    "EvidenceGatherer",
    "Evidence",
    "EvidenceType",
    "TimelineBuilder",
    "TimelineEvent",
    "create_investigation_graph",
    "InvestigationState",
]
