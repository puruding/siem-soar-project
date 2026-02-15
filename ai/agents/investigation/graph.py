"""LangGraph workflow for investigation agent."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class InvestigationState(TypedDict, total=False):
    """State for investigation workflow."""

    # Identifiers
    execution_id: str
    alert_id: str | None
    case_id: str | None

    # Input
    input_data: dict[str, Any]
    entities: list[dict[str, str]]
    iocs: list[dict[str, str]]

    # Phase tracking
    phase: str
    step: int

    # Investigation data
    assessment: dict[str, Any] | None
    plan: dict[str, Any] | None
    context: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    analysis: dict[str, Any] | None

    # Control
    should_continue: bool
    requires_approval: bool
    error: str | None

    # Messages
    messages: list[dict[str, str]]


class InvestigationConfig(BaseModel):
    """Configuration for investigation graph."""

    llm_endpoint: str = Field(default="http://localhost:8080/v1")
    model_name: str = Field(default="solar-10.7b")
    siem_endpoint: str = Field(default="http://localhost:8000/api/v1")
    soar_endpoint: str = Field(default="http://localhost:8001/api/v1")
    max_iterations: int = Field(default=10)
    require_approval: bool = Field(default=False)


class InvestigationGraphBuilder(LoggerMixin):
    """Builder for LangGraph investigation workflow."""

    def __init__(self, config: InvestigationConfig | None = None) -> None:
        """Initialize graph builder.

        Args:
            config: Graph configuration
        """
        self.config = config or InvestigationConfig()

    def build(self) -> StateGraph:
        """Build the investigation graph.

        Returns:
            Compiled StateGraph
        """
        # Create graph
        workflow = StateGraph(InvestigationState)

        # Add nodes
        workflow.add_node("assess", self._assess_node)
        workflow.add_node("plan", self._plan_node)
        workflow.add_node("collect_context", self._collect_context_node)
        workflow.add_node("gather_evidence", self._gather_evidence_node)
        workflow.add_node("build_timeline", self._build_timeline_node)
        workflow.add_node("analyze", self._analyze_node)
        workflow.add_node("check_approval", self._check_approval_node)
        workflow.add_node("finalize", self._finalize_node)

        # Set entry point
        workflow.set_entry_point("assess")

        # Add edges
        workflow.add_edge("assess", "plan")
        workflow.add_edge("plan", "collect_context")
        workflow.add_edge("collect_context", "gather_evidence")
        workflow.add_edge("gather_evidence", "build_timeline")
        workflow.add_edge("build_timeline", "analyze")

        # Conditional edge after analyze
        workflow.add_conditional_edges(
            "analyze",
            self._should_continue,
            {
                "continue": "collect_context",  # Need more data
                "approval": "check_approval",  # Need approval
                "finalize": "finalize",  # Done
            },
        )

        workflow.add_conditional_edges(
            "check_approval",
            self._check_approval_status,
            {
                "approved": "finalize",
                "rejected": END,
                "pending": "check_approval",  # Wait
            },
        )

        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def _assess_node(self, state: InvestigationState) -> InvestigationState:
        """Initial assessment node."""
        self.logger.info("assess_node", execution_id=state.get("execution_id"))

        input_data = state.get("input_data", {})

        # Extract entities
        entities = []
        for field, entity_type in [
            ("source_ip", "ip"),
            ("destination_ip", "ip"),
            ("src_ip", "ip"),
            ("dst_ip", "ip"),
            ("hostname", "host"),
            ("host", "host"),
            ("username", "user"),
            ("user", "user"),
        ]:
            if val := input_data.get(field):
                entities.append({"type": entity_type, "value": val})

        # Extract IOCs
        iocs = []
        for field in ["md5", "sha256", "sha1", "file_hash"]:
            if val := input_data.get(field):
                iocs.append({"type": "hash", "value": val})

        if url := input_data.get("url"):
            iocs.append({"type": "url", "value": url})

        if domain := input_data.get("domain"):
            iocs.append({"type": "domain", "value": domain})

        assessment = {
            "alert_type": input_data.get("alert_type", "unknown"),
            "severity": input_data.get("severity", "medium"),
            "description": input_data.get("description", ""),
            "entity_count": len(entities),
            "ioc_count": len(iocs),
            "assessed_at": datetime.utcnow().isoformat(),
        }

        return {
            **state,
            "phase": "assess",
            "step": 1,
            "entities": entities,
            "iocs": iocs,
            "assessment": assessment,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Assessment complete: {len(entities)} entities, {len(iocs)} IOCs"},
            ],
        }

    async def _plan_node(self, state: InvestigationState) -> InvestigationState:
        """Planning node."""
        self.logger.info("plan_node", execution_id=state.get("execution_id"))

        assessment = state.get("assessment", {})
        entities = state.get("entities", [])
        iocs = state.get("iocs", [])

        # Create investigation plan
        plan = {
            "objectives": [
                "Determine scope of incident",
                "Identify affected assets",
                "Establish timeline of events",
                "Determine root cause",
            ],
            "data_sources": ["SIEM", "Threat Intel", "Asset DB"],
            "queries": [],
        }

        # Add queries based on entities
        for entity in entities:
            plan["queries"].append({
                "type": "entity_search",
                "entity": entity["value"],
                "entity_type": entity["type"],
            })

        # Add IOC enrichment
        for ioc in iocs:
            plan["queries"].append({
                "type": "ioc_enrich",
                "ioc": ioc["value"],
                "ioc_type": ioc["type"],
            })

        return {
            **state,
            "phase": "plan",
            "step": 2,
            "plan": plan,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Plan created: {len(plan['queries'])} queries planned"},
            ],
        }

    async def _collect_context_node(self, state: InvestigationState) -> InvestigationState:
        """Context collection node."""
        self.logger.info("collect_context_node", execution_id=state.get("execution_id"))

        # In real implementation, would call ContextCollector
        # For now, simulate context collection
        context = state.get("context", [])
        entities = state.get("entities", [])

        # Simulate collecting context for each entity
        for entity in entities[:10]:  # Limit to prevent infinite loops
            context.append({
                "source": "SIEM",
                "entity": entity["value"],
                "entity_type": entity["type"],
                "data": {"events": [], "alerts": []},  # Would be populated
                "collected_at": datetime.utcnow().isoformat(),
            })

        return {
            **state,
            "phase": "collect_context",
            "step": 3,
            "context": context,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Context collected: {len(context)} items"},
            ],
        }

    async def _gather_evidence_node(self, state: InvestigationState) -> InvestigationState:
        """Evidence gathering node."""
        self.logger.info("gather_evidence_node", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])
        context = state.get("context", [])

        # In real implementation, would call EvidenceGatherer
        # Transform context into evidence
        for ctx_item in context:
            evidence.append({
                "evidence_id": f"ev-{len(evidence)}",
                "type": "context",
                "source": ctx_item.get("source"),
                "data": ctx_item.get("data"),
                "relevance_score": 0.7,
            })

        return {
            **state,
            "phase": "gather_evidence",
            "step": 4,
            "evidence": evidence,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Evidence gathered: {len(evidence)} items"},
            ],
        }

    async def _build_timeline_node(self, state: InvestigationState) -> InvestigationState:
        """Timeline building node."""
        self.logger.info("build_timeline_node", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])
        timeline = state.get("timeline", [])

        # In real implementation, would call TimelineBuilder
        # Extract events from evidence
        for ev in evidence:
            if ts := ev.get("data", {}).get("timestamp"):
                timeline.append({
                    "timestamp": ts,
                    "title": f"Event from {ev.get('source')}",
                    "evidence_id": ev.get("evidence_id"),
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))

        return {
            **state,
            "phase": "build_timeline",
            "step": 5,
            "timeline": timeline,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Timeline built: {len(timeline)} events"},
            ],
        }

    async def _analyze_node(self, state: InvestigationState) -> InvestigationState:
        """Analysis node."""
        self.logger.info("analyze_node", execution_id=state.get("execution_id"))

        assessment = state.get("assessment", {})
        evidence = state.get("evidence", [])
        timeline = state.get("timeline", [])

        # In real implementation, would use LLM for analysis
        analysis = {
            "summary": f"Investigation of {assessment.get('alert_type')} alert",
            "severity_score": 5,
            "findings": [
                f"Found {len(evidence)} evidence items",
                f"Timeline spans {len(timeline)} events",
            ],
            "root_cause": "Under investigation",
            "recommendations": [
                "Continue monitoring affected assets",
                "Review related alerts",
            ],
            "analyzed_at": datetime.utcnow().isoformat(),
        }

        # Determine if we need more data or approval
        needs_more_data = len(evidence) < 5 and state.get("step", 0) < self.config.max_iterations
        needs_approval = (
            self.config.require_approval and
            assessment.get("severity") in ["critical", "high"]
        )

        return {
            **state,
            "phase": "analyze",
            "step": state.get("step", 0) + 1,
            "analysis": analysis,
            "should_continue": needs_more_data,
            "requires_approval": needs_approval,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Analysis complete: {analysis.get('summary')}"},
            ],
        }

    async def _check_approval_node(self, state: InvestigationState) -> InvestigationState:
        """Approval check node."""
        self.logger.info("check_approval_node", execution_id=state.get("execution_id"))

        # In real implementation, would check approval status
        # For now, auto-approve
        return {
            **state,
            "phase": "approval",
            "requires_approval": False,  # Auto-approved
            "messages": state.get("messages", []) + [
                {"role": "system", "content": "Approval granted"},
            ],
        }

    async def _finalize_node(self, state: InvestigationState) -> InvestigationState:
        """Finalization node."""
        self.logger.info("finalize_node", execution_id=state.get("execution_id"))

        return {
            **state,
            "phase": "complete",
            "should_continue": False,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": "Investigation complete"},
            ],
        }

    def _should_continue(self, state: InvestigationState) -> Literal["continue", "approval", "finalize"]:
        """Determine next step after analysis."""
        if state.get("should_continue"):
            return "continue"
        if state.get("requires_approval"):
            return "approval"
        return "finalize"

    def _check_approval_status(self, state: InvestigationState) -> Literal["approved", "rejected", "pending"]:
        """Check approval status."""
        if not state.get("requires_approval"):
            return "approved"
        # In real implementation, would check actual approval status
        return "approved"


def create_investigation_graph(
    config: InvestigationConfig | None = None,
) -> StateGraph:
    """Create an investigation workflow graph.

    Args:
        config: Optional configuration

    Returns:
        Compiled LangGraph workflow
    """
    builder = InvestigationGraphBuilder(config)
    return builder.build()
