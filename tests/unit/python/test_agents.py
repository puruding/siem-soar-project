"""Unit tests for LangGraph-based AI agents."""

from datetime import datetime
from enum import Enum
from typing import Any, TypedDict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# Mock types and classes
class AgentState(str, Enum):
    """Agent execution states."""

    IDLE = "idle"
    RUNNING = "running"
    WAITING = "waiting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionType(str, Enum):
    """Types of actions agents can take."""

    QUERY = "query"
    ENRICH = "enrich"
    ANALYZE = "analyze"
    RESPOND = "respond"
    NOTIFY = "notify"
    CONTAIN = "contain"


class RiskLevel(str, Enum):
    """Risk levels for actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentMessage(TypedDict):
    """Message passed between agents."""

    role: str
    content: str
    timestamp: str
    metadata: dict


class AgentAction(TypedDict):
    """An action to be executed."""

    action_id: str
    action_type: ActionType
    target: str
    parameters: dict
    risk_level: RiskLevel
    requires_approval: bool


class InvestigationState(TypedDict):
    """State for investigation agent."""

    alert_id: str
    alert_data: dict
    evidence: list[dict]
    timeline: list[dict]
    findings: list[str]
    messages: list[AgentMessage]
    status: AgentState


class AnalysisState(TypedDict):
    """State for analysis agent."""

    investigation_id: str
    evidence: list[dict]
    root_cause: str | None
    impact_assessment: dict | None
    threat_classification: str | None
    confidence: float
    messages: list[AgentMessage]
    status: AgentState


class ResponseState(TypedDict):
    """State for response agent."""

    alert_id: str
    analysis_result: dict
    planned_actions: list[AgentAction]
    executed_actions: list[dict]
    pending_approvals: list[str]
    messages: list[AgentMessage]
    status: AgentState


class BaseAgent:
    """Base class for all agents."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.state = AgentState.IDLE
        self.messages: list[AgentMessage] = []

    def add_message(self, role: str, content: str, metadata: dict | None = None):
        """Add a message to the conversation."""
        self.messages.append(
            AgentMessage(
                role=role,
                content=content,
                timestamp=datetime.utcnow().isoformat(),
                metadata=metadata or {},
            )
        )

    async def execute(self, state: dict) -> dict:
        """Execute the agent's task."""
        raise NotImplementedError


class InvestigationAgent(BaseAgent):
    """Agent for investigating security incidents."""

    def __init__(self):
        super().__init__(
            name="investigation_agent",
            description="Investigates security alerts by gathering context and evidence",
        )

    async def execute(self, state: InvestigationState) -> InvestigationState:
        """Execute investigation."""
        self.state = AgentState.RUNNING

        try:
            # Gather evidence
            evidence = await self._gather_evidence(state["alert_data"])
            state["evidence"].extend(evidence)

            # Build timeline
            timeline = self._build_timeline(evidence)
            state["timeline"] = timeline

            # Generate findings
            findings = self._analyze_evidence(evidence)
            state["findings"] = findings

            self.add_message(
                "assistant",
                f"Investigation complete. Found {len(evidence)} pieces of evidence.",
            )

            state["status"] = AgentState.COMPLETED

        except Exception as e:
            state["status"] = AgentState.FAILED
            self.add_message("system", f"Investigation failed: {str(e)}")

        return state

    async def _gather_evidence(self, alert_data: dict) -> list[dict]:
        """Gather evidence related to the alert."""
        evidence = []

        # Mock evidence gathering
        if "source_ip" in alert_data:
            evidence.append(
                {
                    "type": "network",
                    "data": {"ip": alert_data["source_ip"], "connections": 15},
                }
            )

        if "user" in alert_data:
            evidence.append(
                {
                    "type": "user_activity",
                    "data": {"user": alert_data["user"], "recent_logins": 3},
                }
            )

        if "process" in alert_data:
            evidence.append(
                {
                    "type": "process",
                    "data": {"process": alert_data["process"], "children": 5},
                }
            )

        return evidence

    def _build_timeline(self, evidence: list[dict]) -> list[dict]:
        """Build a timeline from evidence."""
        timeline = []
        for i, e in enumerate(evidence):
            timeline.append(
                {
                    "time": f"T+{i * 5}min",
                    "event": f"Evidence {e['type']} collected",
                    "data": e["data"],
                }
            )
        return timeline

    def _analyze_evidence(self, evidence: list[dict]) -> list[str]:
        """Analyze evidence and generate findings."""
        findings = []
        for e in evidence:
            if e["type"] == "network":
                findings.append(
                    f"Network activity detected from {e['data'].get('ip', 'unknown')}"
                )
            elif e["type"] == "process":
                findings.append(f"Suspicious process activity detected")
        return findings


class AnalysisAgent(BaseAgent):
    """Agent for analyzing investigation results."""

    def __init__(self):
        super().__init__(
            name="analysis_agent",
            description="Analyzes evidence to determine root cause and impact",
        )

    async def execute(self, state: AnalysisState) -> AnalysisState:
        """Execute analysis."""
        self.state = AgentState.RUNNING

        try:
            # Determine root cause
            state["root_cause"] = self._determine_root_cause(state["evidence"])

            # Assess impact
            state["impact_assessment"] = self._assess_impact(state["evidence"])

            # Classify threat
            state["threat_classification"] = self._classify_threat(state["evidence"])

            # Calculate confidence
            state["confidence"] = self._calculate_confidence(state)

            self.add_message(
                "assistant",
                f"Analysis complete. Root cause: {state['root_cause']}",
            )

            state["status"] = AgentState.COMPLETED

        except Exception as e:
            state["status"] = AgentState.FAILED
            self.add_message("system", f"Analysis failed: {str(e)}")

        return state

    def _determine_root_cause(self, evidence: list[dict]) -> str:
        """Determine root cause from evidence."""
        if any(e["type"] == "process" for e in evidence):
            return "Malicious process execution"
        if any(e["type"] == "network" for e in evidence):
            return "Network-based attack"
        return "Unknown cause"

    def _assess_impact(self, evidence: list[dict]) -> dict:
        """Assess the impact of the incident."""
        return {
            "scope": "limited" if len(evidence) < 3 else "widespread",
            "affected_systems": len(evidence),
            "data_exposure": False,
            "service_impact": "low",
        }

    def _classify_threat(self, evidence: list[dict]) -> str:
        """Classify the threat type."""
        has_process = any(e["type"] == "process" for e in evidence)
        has_network = any(e["type"] == "network" for e in evidence)

        if has_process and has_network:
            return "Advanced Persistent Threat (APT)"
        elif has_process:
            return "Malware"
        elif has_network:
            return "Network Intrusion"
        return "Unknown"

    def _calculate_confidence(self, state: AnalysisState) -> float:
        """Calculate confidence in the analysis."""
        base_confidence = 0.5
        evidence_bonus = min(len(state["evidence"]) * 0.1, 0.3)
        return base_confidence + evidence_bonus


class ResponseAgent(BaseAgent):
    """Agent for planning and executing response actions."""

    def __init__(self):
        super().__init__(
            name="response_agent",
            description="Plans and executes incident response actions",
        )
        self.action_risk_thresholds = {
            ActionType.QUERY: RiskLevel.LOW,
            ActionType.ENRICH: RiskLevel.LOW,
            ActionType.ANALYZE: RiskLevel.LOW,
            ActionType.NOTIFY: RiskLevel.MEDIUM,
            ActionType.RESPOND: RiskLevel.HIGH,
            ActionType.CONTAIN: RiskLevel.CRITICAL,
        }

    async def execute(self, state: ResponseState) -> ResponseState:
        """Execute response planning and actions."""
        self.state = AgentState.RUNNING

        try:
            # Plan actions based on analysis
            planned = self._plan_actions(state["analysis_result"])
            state["planned_actions"] = planned

            # Execute low-risk actions automatically
            for action in planned:
                if not action["requires_approval"]:
                    result = await self._execute_action(action)
                    state["executed_actions"].append(result)
                else:
                    state["pending_approvals"].append(action["action_id"])

            if state["pending_approvals"]:
                state["status"] = AgentState.WAITING
                self.add_message(
                    "assistant",
                    f"Waiting for approval of {len(state['pending_approvals'])} actions",
                )
            else:
                state["status"] = AgentState.COMPLETED
                self.add_message(
                    "assistant",
                    f"Response complete. Executed {len(state['executed_actions'])} actions",
                )

        except Exception as e:
            state["status"] = AgentState.FAILED
            self.add_message("system", f"Response failed: {str(e)}")

        return state

    def _plan_actions(self, analysis_result: dict) -> list[AgentAction]:
        """Plan response actions based on analysis."""
        actions = []

        # Always enrich
        actions.append(
            AgentAction(
                action_id="action-001",
                action_type=ActionType.ENRICH,
                target="alert",
                parameters={},
                risk_level=RiskLevel.LOW,
                requires_approval=False,
            )
        )

        # Notify if threat detected
        if analysis_result.get("threat_classification"):
            actions.append(
                AgentAction(
                    action_id="action-002",
                    action_type=ActionType.NOTIFY,
                    target="soc_team",
                    parameters={"channel": "slack"},
                    risk_level=RiskLevel.MEDIUM,
                    requires_approval=False,
                )
            )

        # Contain if high impact
        if analysis_result.get("impact_assessment", {}).get("scope") == "widespread":
            actions.append(
                AgentAction(
                    action_id="action-003",
                    action_type=ActionType.CONTAIN,
                    target="affected_hosts",
                    parameters={"action": "isolate"},
                    risk_level=RiskLevel.CRITICAL,
                    requires_approval=True,  # High-risk requires approval
                )
            )

        return actions

    async def _execute_action(self, action: AgentAction) -> dict:
        """Execute a single action."""
        return {
            "action_id": action["action_id"],
            "action_type": action["action_type"],
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat(),
        }


class Guardrails:
    """Safety guardrails for agent actions."""

    def __init__(self):
        self.max_actions_per_minute = 10
        self.blocked_targets = ["production-db", "domain-controller"]
        self.approval_required_actions = [ActionType.CONTAIN, ActionType.RESPOND]

    def check_action(self, action: AgentAction) -> tuple[bool, str]:
        """Check if an action is allowed."""
        # Check blocked targets
        if action["target"] in self.blocked_targets:
            return False, f"Target {action['target']} is blocked"

        # Check if approval required
        if action["action_type"] in self.approval_required_actions:
            if not action["requires_approval"]:
                return False, "This action requires approval"

        return True, "Action allowed"


# Test fixtures
@pytest.fixture
def investigation_agent():
    return InvestigationAgent()


@pytest.fixture
def analysis_agent():
    return AnalysisAgent()


@pytest.fixture
def response_agent():
    return ResponseAgent()


@pytest.fixture
def sample_alert_data():
    return {
        "alert_id": "alert-001",
        "source_ip": "192.168.1.100",
        "user": "admin",
        "process": "powershell.exe",
        "severity": "high",
    }


@pytest.fixture
def sample_investigation_state(sample_alert_data):
    return InvestigationState(
        alert_id="alert-001",
        alert_data=sample_alert_data,
        evidence=[],
        timeline=[],
        findings=[],
        messages=[],
        status=AgentState.IDLE,
    )


@pytest.fixture
def sample_analysis_state():
    return AnalysisState(
        investigation_id="inv-001",
        evidence=[
            {"type": "network", "data": {"ip": "192.168.1.100"}},
            {"type": "process", "data": {"process": "powershell.exe"}},
        ],
        root_cause=None,
        impact_assessment=None,
        threat_classification=None,
        confidence=0.0,
        messages=[],
        status=AgentState.IDLE,
    )


@pytest.fixture
def sample_response_state():
    return ResponseState(
        alert_id="alert-001",
        analysis_result={
            "threat_classification": "Malware",
            "impact_assessment": {"scope": "limited"},
        },
        planned_actions=[],
        executed_actions=[],
        pending_approvals=[],
        messages=[],
        status=AgentState.IDLE,
    )


class TestBaseAgent:
    """Tests for BaseAgent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = BaseAgent("test_agent", "Test description")

        assert agent.name == "test_agent"
        assert agent.description == "Test description"
        assert agent.state == AgentState.IDLE
        assert len(agent.messages) == 0

    def test_add_message(self):
        """Test adding messages."""
        agent = BaseAgent("test_agent", "Test")

        agent.add_message("user", "Hello")
        agent.add_message("assistant", "Hi there", {"key": "value"})

        assert len(agent.messages) == 2
        assert agent.messages[0]["role"] == "user"
        assert agent.messages[0]["content"] == "Hello"
        assert agent.messages[1]["metadata"]["key"] == "value"


class TestInvestigationAgent:
    """Tests for InvestigationAgent."""

    def test_agent_initialization(self, investigation_agent):
        """Test investigation agent initialization."""
        assert investigation_agent.name == "investigation_agent"
        assert investigation_agent.state == AgentState.IDLE

    @pytest.mark.asyncio
    async def test_execute_investigation(
        self, investigation_agent, sample_investigation_state
    ):
        """Test investigation execution."""
        result = await investigation_agent.execute(sample_investigation_state)

        assert result["status"] == AgentState.COMPLETED
        assert len(result["evidence"]) > 0
        assert len(result["timeline"]) > 0
        assert len(result["findings"]) > 0

    @pytest.mark.asyncio
    async def test_gather_evidence(self, investigation_agent, sample_alert_data):
        """Test evidence gathering."""
        evidence = await investigation_agent._gather_evidence(sample_alert_data)

        assert len(evidence) == 3  # network, user_activity, process
        assert any(e["type"] == "network" for e in evidence)
        assert any(e["type"] == "user_activity" for e in evidence)
        assert any(e["type"] == "process" for e in evidence)

    def test_build_timeline(self, investigation_agent):
        """Test timeline building."""
        evidence = [
            {"type": "network", "data": {"ip": "192.168.1.1"}},
            {"type": "process", "data": {"process": "cmd.exe"}},
        ]

        timeline = investigation_agent._build_timeline(evidence)

        assert len(timeline) == 2
        assert "time" in timeline[0]
        assert "event" in timeline[0]

    def test_analyze_evidence(self, investigation_agent):
        """Test evidence analysis."""
        evidence = [
            {"type": "network", "data": {"ip": "192.168.1.1"}},
            {"type": "process", "data": {"process": "cmd.exe"}},
        ]

        findings = investigation_agent._analyze_evidence(evidence)

        assert len(findings) == 2


class TestAnalysisAgent:
    """Tests for AnalysisAgent."""

    def test_agent_initialization(self, analysis_agent):
        """Test analysis agent initialization."""
        assert analysis_agent.name == "analysis_agent"
        assert analysis_agent.state == AgentState.IDLE

    @pytest.mark.asyncio
    async def test_execute_analysis(self, analysis_agent, sample_analysis_state):
        """Test analysis execution."""
        result = await analysis_agent.execute(sample_analysis_state)

        assert result["status"] == AgentState.COMPLETED
        assert result["root_cause"] is not None
        assert result["impact_assessment"] is not None
        assert result["threat_classification"] is not None
        assert result["confidence"] > 0

    def test_determine_root_cause(self, analysis_agent):
        """Test root cause determination."""
        evidence_with_process = [{"type": "process", "data": {}}]
        evidence_with_network = [{"type": "network", "data": {}}]
        empty_evidence = []

        assert "process" in analysis_agent._determine_root_cause(evidence_with_process).lower()
        assert "network" in analysis_agent._determine_root_cause(evidence_with_network).lower()
        assert "unknown" in analysis_agent._determine_root_cause(empty_evidence).lower()

    def test_assess_impact(self, analysis_agent):
        """Test impact assessment."""
        evidence = [{"type": "network", "data": {}}]

        impact = analysis_agent._assess_impact(evidence)

        assert "scope" in impact
        assert "affected_systems" in impact
        assert impact["scope"] == "limited"

    def test_classify_threat(self, analysis_agent):
        """Test threat classification."""
        both = [{"type": "process"}, {"type": "network"}]
        process_only = [{"type": "process"}]
        network_only = [{"type": "network"}]

        assert "APT" in analysis_agent._classify_threat(both)
        assert "Malware" in analysis_agent._classify_threat(process_only)
        assert "Intrusion" in analysis_agent._classify_threat(network_only)

    def test_calculate_confidence(self, analysis_agent, sample_analysis_state):
        """Test confidence calculation."""
        confidence = analysis_agent._calculate_confidence(sample_analysis_state)

        assert 0 <= confidence <= 1
        assert confidence >= 0.5  # Base confidence


class TestResponseAgent:
    """Tests for ResponseAgent."""

    def test_agent_initialization(self, response_agent):
        """Test response agent initialization."""
        assert response_agent.name == "response_agent"
        assert response_agent.state == AgentState.IDLE

    @pytest.mark.asyncio
    async def test_execute_response(self, response_agent, sample_response_state):
        """Test response execution."""
        result = await response_agent.execute(sample_response_state)

        assert len(result["planned_actions"]) > 0
        assert len(result["executed_actions"]) > 0

    def test_plan_actions(self, response_agent):
        """Test action planning."""
        analysis_result = {
            "threat_classification": "Malware",
            "impact_assessment": {"scope": "limited"},
        }

        actions = response_agent._plan_actions(analysis_result)

        assert len(actions) >= 2  # At least enrich and notify
        assert any(a["action_type"] == ActionType.ENRICH for a in actions)

    def test_plan_actions_high_impact(self, response_agent):
        """Test action planning for high impact."""
        analysis_result = {
            "threat_classification": "APT",
            "impact_assessment": {"scope": "widespread"},
        }

        actions = response_agent._plan_actions(analysis_result)

        contain_actions = [a for a in actions if a["action_type"] == ActionType.CONTAIN]
        assert len(contain_actions) == 1
        assert contain_actions[0]["requires_approval"] is True

    @pytest.mark.asyncio
    async def test_execute_action(self, response_agent):
        """Test single action execution."""
        action = AgentAction(
            action_id="test-001",
            action_type=ActionType.ENRICH,
            target="alert",
            parameters={},
            risk_level=RiskLevel.LOW,
            requires_approval=False,
        )

        result = await response_agent._execute_action(action)

        assert result["action_id"] == "test-001"
        assert result["status"] == "completed"


class TestGuardrails:
    """Tests for Guardrails."""

    @pytest.fixture
    def guardrails(self):
        return Guardrails()

    def test_allow_safe_action(self, guardrails):
        """Test allowing safe actions."""
        action = AgentAction(
            action_id="test-001",
            action_type=ActionType.QUERY,
            target="safe-target",
            parameters={},
            risk_level=RiskLevel.LOW,
            requires_approval=False,
        )

        allowed, reason = guardrails.check_action(action)

        assert allowed is True
        assert reason == "Action allowed"

    def test_block_blocked_target(self, guardrails):
        """Test blocking actions on blocked targets."""
        action = AgentAction(
            action_id="test-001",
            action_type=ActionType.CONTAIN,
            target="production-db",
            parameters={},
            risk_level=RiskLevel.CRITICAL,
            requires_approval=True,
        )

        allowed, reason = guardrails.check_action(action)

        assert allowed is False
        assert "blocked" in reason.lower()

    def test_require_approval_for_risky_actions(self, guardrails):
        """Test requiring approval for risky actions."""
        action = AgentAction(
            action_id="test-001",
            action_type=ActionType.CONTAIN,
            target="safe-target",
            parameters={},
            risk_level=RiskLevel.CRITICAL,
            requires_approval=False,  # Missing required approval
        )

        allowed, reason = guardrails.check_action(action)

        assert allowed is False
        assert "approval" in reason.lower()


class TestAgentState:
    """Tests for AgentState enum."""

    def test_state_values(self):
        """Test all state values exist."""
        assert AgentState.IDLE.value == "idle"
        assert AgentState.RUNNING.value == "running"
        assert AgentState.WAITING.value == "waiting"
        assert AgentState.COMPLETED.value == "completed"
        assert AgentState.FAILED.value == "failed"
        assert AgentState.CANCELLED.value == "cancelled"


class TestActionType:
    """Tests for ActionType enum."""

    def test_action_values(self):
        """Test all action values exist."""
        actions = [
            ActionType.QUERY,
            ActionType.ENRICH,
            ActionType.ANALYZE,
            ActionType.RESPOND,
            ActionType.NOTIFY,
            ActionType.CONTAIN,
        ]
        assert len(actions) == 6


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_values(self):
        """Test all risk values exist."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"
