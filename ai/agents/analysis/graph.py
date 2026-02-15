"""LangGraph workflow for analysis agent."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class AnalysisState(TypedDict, total=False):
    """State for analysis workflow."""

    # Identifiers
    execution_id: str
    investigation_id: str | None

    # Input
    evidence: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    context: dict[str, Any]

    # Phase tracking
    phase: str
    step: int

    # Analysis results
    root_cause: dict[str, Any] | None
    cause_chain: list[dict[str, Any]]
    impact_assessment: dict[str, Any] | None
    affected_assets: list[dict[str, Any]]
    threat_classification: dict[str, Any] | None
    mitre_mappings: list[dict[str, Any]]

    # Final results
    analysis_result: dict[str, Any] | None
    severity_score: float
    recommendations: list[str]

    # Control
    should_continue: bool
    needs_more_data: bool
    error: str | None

    # Messages
    messages: list[dict[str, str]]


class AnalysisConfig(BaseModel):
    """Configuration for analysis graph."""

    llm_endpoint: str = Field(default="http://localhost:8080/v1")
    model_name: str = Field(default="solar-10.7b")
    enable_root_cause: bool = Field(default=True)
    enable_impact: bool = Field(default=True)
    enable_mitre: bool = Field(default=True)
    max_iterations: int = Field(default=5)


class AnalysisGraphBuilder(LoggerMixin):
    """Builder for LangGraph analysis workflow."""

    def __init__(self, config: AnalysisConfig | None = None) -> None:
        """Initialize graph builder.

        Args:
            config: Graph configuration
        """
        self.config = config or AnalysisConfig()

    def build(self) -> StateGraph:
        """Build the analysis graph.

        Returns:
            Compiled StateGraph
        """
        workflow = StateGraph(AnalysisState)

        # Add nodes
        workflow.add_node("initialize", self._initialize_node)
        workflow.add_node("root_cause_analysis", self._root_cause_node)
        workflow.add_node("impact_assessment", self._impact_node)
        workflow.add_node("threat_classification", self._threat_node)
        workflow.add_node("synthesize", self._synthesize_node)
        workflow.add_node("generate_recommendations", self._recommendations_node)
        workflow.add_node("finalize", self._finalize_node)

        # Set entry point
        workflow.set_entry_point("initialize")

        # Add edges - conditional based on config
        workflow.add_conditional_edges(
            "initialize",
            self._determine_analysis_path,
            {
                "root_cause": "root_cause_analysis",
                "impact": "impact_assessment",
                "threat": "threat_classification",
                "synthesize": "synthesize",
            },
        )

        # Root cause can lead to impact or synthesize
        workflow.add_conditional_edges(
            "root_cause_analysis",
            self._after_root_cause,
            {
                "impact": "impact_assessment",
                "threat": "threat_classification",
                "synthesize": "synthesize",
            },
        )

        # Impact leads to threat or synthesize
        workflow.add_conditional_edges(
            "impact_assessment",
            self._after_impact,
            {
                "threat": "threat_classification",
                "synthesize": "synthesize",
            },
        )

        # Threat leads to synthesize
        workflow.add_edge("threat_classification", "synthesize")

        # Synthesize to recommendations
        workflow.add_edge("synthesize", "generate_recommendations")

        # Recommendations to finalize
        workflow.add_edge("generate_recommendations", "finalize")

        # Finalize ends
        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def _initialize_node(self, state: AnalysisState) -> AnalysisState:
        """Initialize analysis."""
        self.logger.info("initialize_analysis", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])
        timeline = state.get("timeline", [])

        # Basic validation
        if not evidence and not timeline:
            return {
                **state,
                "phase": "initialize",
                "error": "No evidence or timeline provided",
                "should_continue": False,
            }

        return {
            **state,
            "phase": "initialize",
            "step": 1,
            "root_cause": None,
            "cause_chain": [],
            "impact_assessment": None,
            "affected_assets": [],
            "threat_classification": None,
            "mitre_mappings": [],
            "recommendations": [],
            "should_continue": True,
            "needs_more_data": False,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Analysis initialized with {len(evidence)} evidence items"},
            ],
        }

    async def _root_cause_node(self, state: AnalysisState) -> AnalysisState:
        """Perform root cause analysis."""
        self.logger.info("root_cause_analysis", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])
        timeline = state.get("timeline", [])

        # Simulate root cause analysis
        # In real implementation, would call RootCauseAnalyzer

        # Find potential root cause from first timeline event
        root_cause = None
        if timeline:
            first_event = timeline[0]
            root_cause = {
                "cause_type": "unknown",
                "description": f"Initial event: {first_event.get('title', 'Unknown')}",
                "confidence": 0.5,
                "entry_point": first_event.get("title"),
                "first_seen": first_event.get("timestamp"),
            }

        # Build simple cause chain
        cause_chain = []
        for i, event in enumerate(timeline[:5]):
            cause_chain.append({
                "sequence": i + 1,
                "event": event.get("title", "Event"),
                "timestamp": event.get("timestamp"),
            })

        return {
            **state,
            "phase": "root_cause",
            "step": 2,
            "root_cause": root_cause,
            "cause_chain": cause_chain,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Root cause analysis complete: {root_cause.get('description', 'Unknown') if root_cause else 'Not found'}"},
            ],
        }

    async def _impact_node(self, state: AnalysisState) -> AnalysisState:
        """Perform impact assessment."""
        self.logger.info("impact_assessment", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])

        # Extract affected assets
        assets = {}
        for ev in evidence:
            data = ev.get("data", ev)
            for field in ["hostname", "source_ip", "username"]:
                if val := data.get(field):
                    if val not in assets:
                        assets[val] = {
                            "identifier": val,
                            "type": field.replace("_", " "),
                            "criticality": "medium",
                        }

        affected_assets = list(assets.values())

        # Simple impact assessment
        impact_level = "low"
        if len(affected_assets) > 10:
            impact_level = "high"
        elif len(affected_assets) > 5:
            impact_level = "medium"

        impact_assessment = {
            "impact_level": impact_level,
            "scope": "multiple_assets" if len(affected_assets) > 1 else "single_asset",
            "total_affected": len(affected_assets),
            "data_at_risk": False,  # Simplified
        }

        return {
            **state,
            "phase": "impact",
            "step": 3,
            "impact_assessment": impact_assessment,
            "affected_assets": affected_assets,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Impact assessment: {impact_level}, {len(affected_assets)} assets affected"},
            ],
        }

    async def _threat_node(self, state: AnalysisState) -> AnalysisState:
        """Perform threat classification."""
        self.logger.info("threat_classification", execution_id=state.get("execution_id"))

        evidence = state.get("evidence", [])
        timeline = state.get("timeline", [])

        # Simple threat classification
        threat_type = "unknown"
        mitre_mappings = []

        # Look for keywords
        all_text = " ".join([str(ev) for ev in evidence] + [str(t) for t in timeline]).lower()

        if "ransom" in all_text or "encrypt" in all_text:
            threat_type = "ransomware"
            mitre_mappings.append({
                "tactic": "impact",
                "technique_id": "T1486",
                "technique_name": "Data Encrypted for Impact",
            })
        elif "phishing" in all_text or "email" in all_text:
            threat_type = "phishing"
            mitre_mappings.append({
                "tactic": "initial-access",
                "technique_id": "T1566",
                "technique_name": "Phishing",
            })
        elif "lateral" in all_text or "spread" in all_text:
            threat_type = "lateral_movement"
            mitre_mappings.append({
                "tactic": "lateral-movement",
                "technique_id": "T1021",
                "technique_name": "Remote Services",
            })

        threat_classification = {
            "threat_type": threat_type,
            "actor_type": "unknown",
            "kill_chain_stage": "unknown",
            "confidence": 0.5,
        }

        return {
            **state,
            "phase": "threat",
            "step": 4,
            "threat_classification": threat_classification,
            "mitre_mappings": mitre_mappings,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Threat classified as: {threat_type}"},
            ],
        }

    async def _synthesize_node(self, state: AnalysisState) -> AnalysisState:
        """Synthesize analysis results."""
        self.logger.info("synthesize_analysis", execution_id=state.get("execution_id"))

        # Calculate severity score
        severity = 5.0

        if state.get("impact_assessment", {}).get("impact_level") == "high":
            severity += 2
        elif state.get("impact_assessment", {}).get("impact_level") == "medium":
            severity += 1

        if state.get("threat_classification", {}).get("threat_type") in ["ransomware", "apt"]:
            severity += 2

        severity = min(severity, 10.0)

        # Build analysis result
        analysis_result = {
            "root_cause": state.get("root_cause"),
            "impact": state.get("impact_assessment"),
            "threat": state.get("threat_classification"),
            "mitre_techniques": state.get("mitre_mappings", []),
            "affected_asset_count": len(state.get("affected_assets", [])),
            "severity_score": severity,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

        return {
            **state,
            "phase": "synthesize",
            "step": 5,
            "analysis_result": analysis_result,
            "severity_score": severity,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Analysis synthesized. Severity: {severity}/10"},
            ],
        }

    async def _recommendations_node(self, state: AnalysisState) -> AnalysisState:
        """Generate recommendations."""
        self.logger.info("generate_recommendations", execution_id=state.get("execution_id"))

        recommendations = []

        # Based on severity
        severity = state.get("severity_score", 5)
        if severity >= 8:
            recommendations.append("IMMEDIATE: Activate incident response team")
            recommendations.append("Notify security leadership")
        elif severity >= 6:
            recommendations.append("Escalate to senior analyst")

        # Based on threat type
        threat_type = state.get("threat_classification", {}).get("threat_type")
        if threat_type == "ransomware":
            recommendations.append("Isolate affected systems")
            recommendations.append("Verify backup availability")
        elif threat_type == "phishing":
            recommendations.append("Block sender domain")
            recommendations.append("Search for other affected users")

        # Based on impact
        if state.get("impact_assessment", {}).get("data_at_risk"):
            recommendations.append("Assess data breach notification requirements")

        # Default
        if not recommendations:
            recommendations.append("Continue monitoring")
            recommendations.append("Document findings")

        return {
            **state,
            "phase": "recommendations",
            "step": 6,
            "recommendations": recommendations,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Generated {len(recommendations)} recommendations"},
            ],
        }

    async def _finalize_node(self, state: AnalysisState) -> AnalysisState:
        """Finalize analysis."""
        self.logger.info("finalize_analysis", execution_id=state.get("execution_id"))

        return {
            **state,
            "phase": "complete",
            "should_continue": False,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": "Analysis complete"},
            ],
        }

    def _determine_analysis_path(self, state: AnalysisState) -> str:
        """Determine initial analysis path."""
        if state.get("error"):
            return "synthesize"

        if self.config.enable_root_cause:
            return "root_cause"
        if self.config.enable_impact:
            return "impact"
        if self.config.enable_mitre:
            return "threat"
        return "synthesize"

    def _after_root_cause(self, state: AnalysisState) -> str:
        """Determine path after root cause analysis."""
        if self.config.enable_impact:
            return "impact"
        if self.config.enable_mitre:
            return "threat"
        return "synthesize"

    def _after_impact(self, state: AnalysisState) -> str:
        """Determine path after impact assessment."""
        if self.config.enable_mitre:
            return "threat"
        return "synthesize"


def create_analysis_graph(config: AnalysisConfig | None = None) -> StateGraph:
    """Create an analysis workflow graph.

    Args:
        config: Optional configuration

    Returns:
        Compiled LangGraph workflow
    """
    builder = AnalysisGraphBuilder(config)
    return builder.build()
