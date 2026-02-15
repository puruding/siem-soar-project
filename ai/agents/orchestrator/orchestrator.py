"""SOC Orchestrator - Main orchestration for autonomous SOC operations."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from ..base import AgentCapability, AgentConfig, AgentContext, AgentResult
from ..registry import AgentRegistry, get_registry


class OrchestratorMode(str, Enum):
    """Orchestration modes."""

    MANUAL = "manual"  # Human triggers all actions
    ASSISTED = "assisted"  # AI suggests, human approves
    SEMI_AUTONOMOUS = "semi_autonomous"  # Auto for low risk
    FULLY_AUTONOMOUS = "fully_autonomous"  # Full auto within limits


class WorkflowStage(str, Enum):
    """Stages in the SOC workflow."""

    DETECTION = "detection"
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    ANALYSIS = "analysis"
    RESPONSE = "response"
    VALIDATION = "validation"
    RECOVERY = "recovery"
    CLOSED = "closed"


class OrchestratorConfig(BaseModel):
    """Configuration for SOC Orchestrator."""

    mode: OrchestratorMode = Field(default=OrchestratorMode.SEMI_AUTONOMOUS)
    max_concurrent_incidents: int = Field(default=10)
    auto_triage_threshold: float = Field(default=0.7)
    auto_respond_threshold: float = Field(default=0.9)
    max_auto_response_severity: int = Field(default=7)
    require_human_for_critical: bool = Field(default=True)
    llm_endpoint: str = Field(default="http://localhost:8080/v1")
    model_name: str = Field(default="solar-10.7b")
    siem_endpoint: str = Field(default="http://localhost:8000/api/v1")
    soar_endpoint: str = Field(default="http://localhost:8001/api/v1")


class IncidentState(BaseModel):
    """State of an incident being orchestrated."""

    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    alert_id: str | None = Field(default=None)
    case_id: str | None = Field(default=None)

    # Stage
    current_stage: WorkflowStage = Field(default=WorkflowStage.DETECTION)
    previous_stages: list[WorkflowStage] = Field(default_factory=list)

    # Data
    alert_data: dict[str, Any] = Field(default_factory=dict)
    triage_result: dict[str, Any] | None = Field(default=None)
    investigation_result: dict[str, Any] | None = Field(default=None)
    analysis_result: dict[str, Any] | None = Field(default=None)
    response_result: dict[str, Any] | None = Field(default=None)
    validation_result: dict[str, Any] | None = Field(default=None)

    # Metrics
    severity: float = Field(default=5.0)
    confidence: float = Field(default=0.5)
    priority: int = Field(default=5)

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    stage_started_at: datetime = Field(default_factory=datetime.utcnow)

    # Control
    requires_human: bool = Field(default=False)
    human_assigned: str | None = Field(default=None)
    is_paused: bool = Field(default=False)
    is_complete: bool = Field(default=False)


class OrchestratorResult(BaseModel):
    """Result from orchestrator execution."""

    incident_id: str
    final_stage: WorkflowStage
    success: bool
    stages_completed: list[WorkflowStage]
    total_duration_seconds: int
    auto_investigation_rate: float
    auto_response_rate: float
    summary: str


class SOCOrchestrator(LoggerMixin):
    """Main orchestrator for autonomous SOC operations.

    Coordinates the full incident lifecycle:
    1. Detection -> Triage -> Investigation -> Analysis -> Response -> Validation

    Features:
    - Multi-agent coordination
    - Workflow state management
    - Human-in-the-loop integration
    - Priority-based processing
    - Configurable autonomy levels
    """

    def __init__(
        self,
        config: OrchestratorConfig | None = None,
        registry: AgentRegistry | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            config: Orchestrator configuration
            registry: Agent registry (uses global if not provided)
        """
        self.config = config or OrchestratorConfig()
        self.registry = registry or get_registry()

        self._client: httpx.AsyncClient | None = None
        self._active_incidents: dict[str, IncidentState] = {}
        self._incident_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        return self._client

    async def close(self) -> None:
        """Close resources."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def process_alert(
        self,
        alert: dict[str, Any],
    ) -> OrchestratorResult:
        """Process an alert through the full SOC workflow.

        Args:
            alert: Alert data

        Returns:
            Orchestrator result
        """
        # Create incident state
        incident = IncidentState(
            alert_id=alert.get("alert_id"),
            alert_data=alert,
            severity=self._extract_severity(alert),
        )

        self._active_incidents[incident.incident_id] = incident

        self.logger.info(
            "processing_alert",
            incident_id=incident.incident_id,
            alert_id=alert.get("alert_id"),
            severity=incident.severity,
        )

        start_time = datetime.utcnow()
        stages_completed = []

        try:
            # Stage 1: Triage
            incident = await self._execute_triage(incident)
            stages_completed.append(WorkflowStage.TRIAGE)

            # Stage 2: Investigation
            if self._should_auto_investigate(incident):
                incident = await self._execute_investigation(incident)
                stages_completed.append(WorkflowStage.INVESTIGATION)
            else:
                incident.requires_human = True
                self.logger.info(
                    "human_required_for_investigation",
                    incident_id=incident.incident_id,
                )

            # Stage 3: Analysis
            if incident.investigation_result and not incident.requires_human:
                incident = await self._execute_analysis(incident)
                stages_completed.append(WorkflowStage.ANALYSIS)

            # Stage 4: Response
            if incident.analysis_result and self._should_auto_respond(incident):
                incident = await self._execute_response(incident)
                stages_completed.append(WorkflowStage.RESPONSE)
            elif incident.analysis_result:
                incident.requires_human = True
                self.logger.info(
                    "human_required_for_response",
                    incident_id=incident.incident_id,
                )

            # Stage 5: Validation
            if incident.response_result:
                incident = await self._execute_validation(incident)
                stages_completed.append(WorkflowStage.VALIDATION)

            # Mark complete if fully processed
            if WorkflowStage.VALIDATION in stages_completed:
                incident.is_complete = True
                incident.current_stage = WorkflowStage.CLOSED

            # Calculate metrics
            end_time = datetime.utcnow()
            duration = int((end_time - start_time).total_seconds())

            auto_investigation = 1.0 if WorkflowStage.INVESTIGATION in stages_completed else 0.0
            auto_response = 1.0 if WorkflowStage.RESPONSE in stages_completed else 0.0

            result = OrchestratorResult(
                incident_id=incident.incident_id,
                final_stage=incident.current_stage,
                success=incident.is_complete,
                stages_completed=stages_completed,
                total_duration_seconds=duration,
                auto_investigation_rate=auto_investigation,
                auto_response_rate=auto_response,
                summary=self._generate_summary(incident, stages_completed),
            )

            return result

        except Exception as e:
            self.logger.error(
                "orchestration_failed",
                incident_id=incident.incident_id,
                error=str(e),
            )
            raise

    async def _execute_triage(self, incident: IncidentState) -> IncidentState:
        """Execute triage stage."""
        incident.current_stage = WorkflowStage.TRIAGE
        incident.stage_started_at = datetime.utcnow()

        self.logger.info("executing_triage", incident_id=incident.incident_id)

        # Get triage agent
        triage_agents = self.registry.get_agents_by_capability(AgentCapability.ANALYZE)

        if not triage_agents:
            # Use direct triage logic
            triage_result = await self._perform_triage(incident.alert_data)
        else:
            # Use triage agent
            agent = triage_agents[0]
            context = AgentContext(
                alert_id=incident.alert_id,
                data=incident.alert_data,
            )
            result = await agent.run(context)
            triage_result = result.output

        incident.triage_result = triage_result
        incident.severity = triage_result.get("severity", incident.severity)
        incident.confidence = triage_result.get("confidence", incident.confidence)
        incident.priority = self._calculate_priority(incident)
        incident.updated_at = datetime.utcnow()

        return incident

    async def _execute_investigation(self, incident: IncidentState) -> IncidentState:
        """Execute investigation stage."""
        incident.previous_stages.append(incident.current_stage)
        incident.current_stage = WorkflowStage.INVESTIGATION
        incident.stage_started_at = datetime.utcnow()

        self.logger.info("executing_investigation", incident_id=incident.incident_id)

        # Get investigation agent
        agents = self.registry.get_agents_by_capability(AgentCapability.INVESTIGATE)

        investigation_result = {}
        if agents:
            agent = agents[0]
            context = AgentContext(
                alert_id=incident.alert_id,
                data={
                    "alert": incident.alert_data,
                    "triage": incident.triage_result,
                },
            )
            result = await agent.run(context)
            investigation_result = result.output
        else:
            # Fallback: minimal investigation
            investigation_result = {
                "entities": [],
                "context": [],
                "timeline": [],
                "evidence": [],
            }

        incident.investigation_result = investigation_result
        incident.updated_at = datetime.utcnow()

        return incident

    async def _execute_analysis(self, incident: IncidentState) -> IncidentState:
        """Execute analysis stage."""
        incident.previous_stages.append(incident.current_stage)
        incident.current_stage = WorkflowStage.ANALYSIS
        incident.stage_started_at = datetime.utcnow()

        self.logger.info("executing_analysis", incident_id=incident.incident_id)

        # Get analysis agent
        agents = self.registry.get_agents_by_capability(AgentCapability.ANALYZE)

        analysis_result = {}
        if agents:
            agent = agents[0]
            context = AgentContext(
                alert_id=incident.alert_id,
                data={
                    "investigation": incident.investigation_result,
                    "evidence": incident.investigation_result.get("evidence", []),
                    "timeline": incident.investigation_result.get("timeline", []),
                },
            )
            result = await agent.run(context)
            analysis_result = result.output
        else:
            # Fallback: minimal analysis
            analysis_result = {
                "severity_score": incident.severity,
                "threat_classification": {"threat_type": "unknown"},
                "indicators_of_compromise": [],
                "affected_assets": [],
                "recommendations": [],
            }

        incident.analysis_result = analysis_result
        incident.severity = analysis_result.get("severity_score", incident.severity)
        incident.updated_at = datetime.utcnow()

        return incident

    async def _execute_response(self, incident: IncidentState) -> IncidentState:
        """Execute response stage."""
        incident.previous_stages.append(incident.current_stage)
        incident.current_stage = WorkflowStage.RESPONSE
        incident.stage_started_at = datetime.utcnow()

        self.logger.info("executing_response", incident_id=incident.incident_id)

        # Get response agent
        agents = self.registry.get_agents_by_capability(AgentCapability.RESPOND)

        response_result = {}
        if agents:
            agent = agents[0]
            context = AgentContext(
                alert_id=incident.alert_id,
                data={
                    "analysis": incident.analysis_result,
                    "affected_assets": incident.analysis_result.get("affected_assets", []),
                    "recommendations": incident.analysis_result.get("recommendations", []),
                },
            )
            result = await agent.run(context)
            response_result = result.output
        else:
            # Fallback: log-only response
            response_result = {
                "status": "logged",
                "actions_taken": 0,
            }

        incident.response_result = response_result
        incident.updated_at = datetime.utcnow()

        return incident

    async def _execute_validation(self, incident: IncidentState) -> IncidentState:
        """Execute validation stage."""
        incident.previous_stages.append(incident.current_stage)
        incident.current_stage = WorkflowStage.VALIDATION
        incident.stage_started_at = datetime.utcnow()

        self.logger.info("executing_validation", incident_id=incident.incident_id)

        # Get validation agent
        agents = self.registry.get_agents_by_capability(AgentCapability.VALIDATE)

        validation_result = {}
        if agents:
            agent = agents[0]
            context = AgentContext(
                alert_id=incident.alert_id,
                data={
                    "response": incident.response_result,
                    "analysis": incident.analysis_result,
                },
            )
            result = await agent.run(context)
            validation_result = result.output
        else:
            # Fallback: assume valid
            validation_result = {
                "status": "passed",
                "effectiveness": 0.8,
            }

        incident.validation_result = validation_result
        incident.updated_at = datetime.utcnow()

        return incident

    async def _perform_triage(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Perform triage without agent."""
        severity = self._extract_severity(alert)
        alert_type = alert.get("alert_type", "unknown")

        # Simple classification
        is_true_positive = True  # Assume true until proven false
        confidence = 0.7

        # Adjust based on alert type
        high_confidence_types = ["ransomware", "apt", "data_exfil"]
        if any(t in alert_type.lower() for t in high_confidence_types):
            confidence = 0.9

        return {
            "severity": severity,
            "confidence": confidence,
            "is_true_positive": is_true_positive,
            "alert_type": alert_type,
            "category": self._categorize_alert(alert_type),
            "recommended_action": "investigate" if confidence >= 0.6 else "monitor",
        }

    def _extract_severity(self, alert: dict[str, Any]) -> float:
        """Extract severity from alert."""
        severity_str = str(alert.get("severity", "medium")).lower()
        severity_map = {
            "critical": 9.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0,
        }
        return severity_map.get(severity_str, 5.0)

    def _categorize_alert(self, alert_type: str) -> str:
        """Categorize alert type."""
        categories = {
            "malware": ["malware", "virus", "trojan", "ransomware"],
            "intrusion": ["intrusion", "breach", "unauthorized"],
            "credential": ["credential", "brute", "password"],
            "data": ["data", "exfil", "leak"],
            "network": ["network", "ddos", "scan"],
        }

        alert_lower = alert_type.lower()
        for category, keywords in categories.items():
            if any(kw in alert_lower for kw in keywords):
                return category

        return "unknown"

    def _calculate_priority(self, incident: IncidentState) -> int:
        """Calculate incident priority (1-10, 1 is highest)."""
        # Base priority from severity
        priority = 11 - int(incident.severity)  # Invert: high severity = low priority number

        # Adjust by confidence
        if incident.confidence >= 0.9:
            priority -= 1
        elif incident.confidence < 0.5:
            priority += 1

        return max(1, min(10, priority))

    def _should_auto_investigate(self, incident: IncidentState) -> bool:
        """Determine if auto-investigation should proceed."""
        if self.config.mode == OrchestratorMode.MANUAL:
            return False

        if self.config.mode == OrchestratorMode.FULLY_AUTONOMOUS:
            return True

        # Check confidence threshold
        if incident.confidence < self.config.auto_triage_threshold:
            return False

        # Check severity limits
        if self.config.require_human_for_critical and incident.severity >= 9:
            return False

        return True

    def _should_auto_respond(self, incident: IncidentState) -> bool:
        """Determine if auto-response should proceed."""
        if self.config.mode in [OrchestratorMode.MANUAL, OrchestratorMode.ASSISTED]:
            return False

        if self.config.mode == OrchestratorMode.FULLY_AUTONOMOUS:
            # Still respect critical severity limit
            if self.config.require_human_for_critical and incident.severity >= 9:
                return False
            return True

        # Semi-autonomous mode
        analysis = incident.analysis_result or {}
        confidence = analysis.get("confidence", incident.confidence)

        if confidence < self.config.auto_respond_threshold:
            return False

        if incident.severity > self.config.max_auto_response_severity:
            return False

        return True

    def _generate_summary(
        self,
        incident: IncidentState,
        stages: list[WorkflowStage],
    ) -> str:
        """Generate orchestration summary."""
        parts = [
            f"Incident {incident.incident_id}",
            f"Severity: {incident.severity}/10",
            f"Stages: {', '.join(s.value for s in stages)}",
            f"Final: {incident.current_stage.value}",
        ]

        if incident.requires_human:
            parts.append("(Human intervention required)")

        if incident.is_complete:
            parts.append("[COMPLETE]")

        return " | ".join(parts)

    def get_incident_state(self, incident_id: str) -> IncidentState | None:
        """Get incident state by ID."""
        return self._active_incidents.get(incident_id)

    def get_active_incidents(self) -> list[IncidentState]:
        """Get all active incidents."""
        return [
            i for i in self._active_incidents.values()
            if not i.is_complete
        ]

    def get_stats(self) -> dict[str, Any]:
        """Get orchestrator statistics."""
        incidents = list(self._active_incidents.values())
        return {
            "total_incidents": len(incidents),
            "active_incidents": len([i for i in incidents if not i.is_complete]),
            "completed_incidents": len([i for i in incidents if i.is_complete]),
            "awaiting_human": len([i for i in incidents if i.requires_human and not i.is_complete]),
            "mode": self.config.mode.value,
            "stage_distribution": self._get_stage_distribution(incidents),
        }

    def _get_stage_distribution(self, incidents: list[IncidentState]) -> dict[str, int]:
        """Get distribution of incidents by stage."""
        dist = {}
        for incident in incidents:
            stage = incident.current_stage.value
            dist[stage] = dist.get(stage, 0) + 1
        return dist
