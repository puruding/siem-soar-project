"""Integration tests for SOAR playbook execution.

Tests the flow: Alert -> Playbook Trigger -> Execution -> Actions -> Results
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

import pytest


# Execution states
class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlaybookStep:
    """Represents a step in a playbook."""

    step_id: str
    name: str
    action_type: str
    connector: str
    action: str
    parameters: dict = field(default_factory=dict)
    continue_on_error: bool = False
    requires_approval: bool = False
    timeout_seconds: int = 300


@dataclass
class Playbook:
    """Represents a SOAR playbook."""

    playbook_id: str
    name: str
    description: str
    trigger_conditions: list[dict]
    steps: list[PlaybookStep]
    enabled: bool = True
    version: int = 1


@dataclass
class StepResult:
    """Result of a step execution."""

    step_id: str
    status: ActionStatus
    output: dict = field(default_factory=dict)
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    duration_ms: int = 0


@dataclass
class PlaybookExecution:
    """Represents a playbook execution instance."""

    execution_id: str
    playbook_id: str
    playbook_name: str
    status: ExecutionStatus
    trigger_data: dict
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    step_results: list[StepResult] = field(default_factory=list)
    current_step: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    error: str | None = None


class ActionConnector:
    """Base class for action connectors."""

    def __init__(self, name: str):
        self.name = name

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute an action."""
        raise NotImplementedError


class EmailConnector(ActionConnector):
    """Email connector for sending notifications."""

    def __init__(self):
        super().__init__("email")
        self.sent_emails: list[dict] = []

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute email action."""
        if action == "send":
            email = {
                "to": parameters.get("to"),
                "subject": parameters.get("subject"),
                "body": parameters.get("body"),
                "sent_at": datetime.now(timezone.utc).isoformat(),
            }
            self.sent_emails.append(email)
            return {"success": True, "message_id": f"msg-{uuid.uuid4().hex[:8]}"}

        raise ValueError(f"Unknown action: {action}")


class SlackConnector(ActionConnector):
    """Slack connector for notifications."""

    def __init__(self):
        super().__init__("slack")
        self.sent_messages: list[dict] = []

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute Slack action."""
        if action == "send_message":
            msg = {
                "channel": parameters.get("channel"),
                "text": parameters.get("text"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.sent_messages.append(msg)
            return {"success": True, "ts": f"{time.time():.6f}"}

        raise ValueError(f"Unknown action: {action}")


class FirewallConnector(ActionConnector):
    """Firewall connector for containment actions."""

    def __init__(self):
        super().__init__("firewall")
        self.blocked_ips: list[str] = []
        self.blocked_domains: list[str] = []

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute firewall action."""
        if action == "block_ip":
            ip = parameters.get("ip")
            self.blocked_ips.append(ip)
            return {"success": True, "blocked": ip, "rule_id": f"rule-{len(self.blocked_ips)}"}

        if action == "block_domain":
            domain = parameters.get("domain")
            self.blocked_domains.append(domain)
            return {"success": True, "blocked": domain}

        raise ValueError(f"Unknown action: {action}")


class EDRConnector(ActionConnector):
    """EDR connector for endpoint actions."""

    def __init__(self):
        super().__init__("edr")
        self.isolated_hosts: list[str] = []
        self.scanned_hosts: list[str] = []

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute EDR action."""
        if action == "isolate_host":
            hostname = parameters.get("hostname")
            self.isolated_hosts.append(hostname)
            return {"success": True, "isolated": hostname}

        if action == "scan_host":
            hostname = parameters.get("hostname")
            self.scanned_hosts.append(hostname)
            return {
                "success": True,
                "scan_id": f"scan-{uuid.uuid4().hex[:8]}",
                "status": "initiated",
            }

        raise ValueError(f"Unknown action: {action}")


class ThreatIntelConnector(ActionConnector):
    """Threat intelligence connector for enrichment."""

    def __init__(self):
        super().__init__("threat_intel")
        self.lookups: list[dict] = []

    async def execute(self, action: str, parameters: dict) -> dict:
        """Execute threat intel action."""
        if action == "lookup_ip":
            ip = parameters.get("ip")
            self.lookups.append({"type": "ip", "value": ip})
            # Mock response
            return {
                "ip": ip,
                "reputation": "malicious" if ip.startswith("10.") else "clean",
                "score": 85 if ip.startswith("10.") else 10,
                "categories": ["malware", "c2"] if ip.startswith("10.") else [],
            }

        if action == "lookup_domain":
            domain = parameters.get("domain")
            self.lookups.append({"type": "domain", "value": domain})
            return {
                "domain": domain,
                "reputation": "suspicious",
                "score": 65,
            }

        raise ValueError(f"Unknown action: {action}")


class ConnectorRegistry:
    """Registry of action connectors."""

    def __init__(self):
        self.connectors: dict[str, ActionConnector] = {}

    def register(self, connector: ActionConnector):
        """Register a connector."""
        self.connectors[connector.name] = connector

    def get(self, name: str) -> ActionConnector | None:
        """Get a connector by name."""
        return self.connectors.get(name)


class ApprovalManager:
    """Manages approval requests for playbook steps."""

    def __init__(self):
        self.pending_approvals: dict[str, dict] = {}
        self.approval_results: dict[str, bool] = {}

    def request_approval(
        self,
        execution_id: str,
        step_id: str,
        approvers: list[str],
        message: str,
    ) -> str:
        """Request approval for a step."""
        approval_id = f"approval-{uuid.uuid4().hex[:8]}"
        self.pending_approvals[approval_id] = {
            "execution_id": execution_id,
            "step_id": step_id,
            "approvers": approvers,
            "message": message,
            "requested_at": datetime.now(timezone.utc),
        }
        return approval_id

    def approve(self, approval_id: str, approved_by: str) -> bool:
        """Approve a pending request."""
        if approval_id in self.pending_approvals:
            self.approval_results[approval_id] = True
            del self.pending_approvals[approval_id]
            return True
        return False

    def reject(self, approval_id: str, rejected_by: str, reason: str = "") -> bool:
        """Reject a pending request."""
        if approval_id in self.pending_approvals:
            self.approval_results[approval_id] = False
            del self.pending_approvals[approval_id]
            return True
        return False

    def is_approved(self, approval_id: str) -> bool | None:
        """Check if a request is approved."""
        return self.approval_results.get(approval_id)


class PlaybookExecutor:
    """Executes SOAR playbooks."""

    def __init__(
        self,
        connector_registry: ConnectorRegistry,
        approval_manager: ApprovalManager,
    ):
        self.connector_registry = connector_registry
        self.approval_manager = approval_manager
        self.executions: dict[str, PlaybookExecution] = {}

    async def execute(
        self,
        playbook: Playbook,
        trigger_data: dict,
        inputs: dict | None = None,
    ) -> PlaybookExecution:
        """Execute a playbook."""
        execution = PlaybookExecution(
            execution_id=f"exec-{uuid.uuid4().hex[:8]}",
            playbook_id=playbook.playbook_id,
            playbook_name=playbook.name,
            status=ExecutionStatus.PENDING,
            trigger_data=trigger_data,
            inputs=inputs or {},
        )

        self.executions[execution.execution_id] = execution
        execution.status = ExecutionStatus.RUNNING

        try:
            for step in playbook.steps:
                execution.current_step = step.step_id

                # Check for approval requirement
                if step.requires_approval:
                    approval_id = self.approval_manager.request_approval(
                        execution.execution_id,
                        step.step_id,
                        ["soc-analyst"],
                        f"Approve step: {step.name}",
                    )
                    execution.status = ExecutionStatus.WAITING
                    # In real implementation, would wait for approval
                    # For testing, we'll auto-approve
                    self.approval_manager.approve(approval_id, "test-user")
                    execution.status = ExecutionStatus.RUNNING

                # Execute step
                result = await self._execute_step(step, execution)
                execution.step_results.append(result)

                # Check for failure
                if result.status == ActionStatus.FAILED and not step.continue_on_error:
                    execution.status = ExecutionStatus.FAILED
                    execution.error = result.error
                    break

            # Update final status
            if execution.status == ExecutionStatus.RUNNING:
                execution.status = ExecutionStatus.COMPLETED

            execution.completed_at = datetime.now(timezone.utc)
            execution.current_step = None

        except Exception as e:
            execution.status = ExecutionStatus.FAILED
            execution.error = str(e)
            execution.completed_at = datetime.now(timezone.utc)

        return execution

    async def _execute_step(
        self,
        step: PlaybookStep,
        execution: PlaybookExecution,
    ) -> StepResult:
        """Execute a single step."""
        result = StepResult(step_id=step.step_id, status=ActionStatus.RUNNING)

        try:
            connector = self.connector_registry.get(step.connector)
            if not connector:
                raise ValueError(f"Connector not found: {step.connector}")

            # Resolve parameters with execution context
            params = self._resolve_parameters(step.parameters, execution)

            # Execute action
            output = await connector.execute(step.action, params)

            result.output = output
            result.status = ActionStatus.COMPLETED

        except Exception as e:
            result.status = ActionStatus.FAILED
            result.error = str(e)

        result.completed_at = datetime.now(timezone.utc)
        result.duration_ms = int(
            (result.completed_at - result.started_at).total_seconds() * 1000
        )

        return result

    def _resolve_parameters(self, params: dict, execution: PlaybookExecution) -> dict:
        """Resolve parameter placeholders."""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{{") and value.endswith("}}"):
                # Extract reference
                ref = value[2:-2].strip()
                resolved[key] = self._resolve_reference(ref, execution)
            else:
                resolved[key] = value
        return resolved

    def _resolve_reference(self, ref: str, execution: PlaybookExecution) -> Any:
        """Resolve a reference to execution data."""
        parts = ref.split(".")

        if parts[0] == "trigger":
            data = execution.trigger_data
            for part in parts[1:]:
                data = data.get(part)
            return data

        if parts[0] == "inputs":
            return execution.inputs.get(parts[1])

        if parts[0] == "steps":
            step_id = parts[1]
            for result in execution.step_results:
                if result.step_id == step_id:
                    data = result.output
                    for part in parts[2:]:
                        data = data.get(part)
                    return data

        return None


class PlaybookTriggerEngine:
    """Evaluates trigger conditions for playbooks."""

    def __init__(self, playbooks: list[Playbook]):
        self.playbooks = playbooks

    def evaluate(self, alert: dict) -> list[Playbook]:
        """Evaluate which playbooks should be triggered for an alert."""
        triggered = []

        for playbook in self.playbooks:
            if not playbook.enabled:
                continue

            if self._matches_conditions(alert, playbook.trigger_conditions):
                triggered.append(playbook)

        return triggered

    def _matches_conditions(self, alert: dict, conditions: list[dict]) -> bool:
        """Check if alert matches trigger conditions."""
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            alert_value = self._get_field(alert, field)

            if operator == "equals":
                if alert_value != value:
                    return False
            elif operator == "contains":
                if value not in str(alert_value):
                    return False
            elif operator == "in":
                if alert_value not in value:
                    return False
            elif operator == "greater_than":
                if not (alert_value and alert_value > value):
                    return False

        return True

    def _get_field(self, obj: dict, path: str) -> Any:
        """Get nested field from dict."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current


# Fixtures
@pytest.fixture
def email_connector():
    return EmailConnector()


@pytest.fixture
def slack_connector():
    return SlackConnector()


@pytest.fixture
def firewall_connector():
    return FirewallConnector()


@pytest.fixture
def edr_connector():
    return EDRConnector()


@pytest.fixture
def threat_intel_connector():
    return ThreatIntelConnector()


@pytest.fixture
def connector_registry(
    email_connector,
    slack_connector,
    firewall_connector,
    edr_connector,
    threat_intel_connector,
):
    registry = ConnectorRegistry()
    registry.register(email_connector)
    registry.register(slack_connector)
    registry.register(firewall_connector)
    registry.register(edr_connector)
    registry.register(threat_intel_connector)
    return registry


@pytest.fixture
def approval_manager():
    return ApprovalManager()


@pytest.fixture
def executor(connector_registry, approval_manager):
    return PlaybookExecutor(connector_registry, approval_manager)


@pytest.fixture
def enrichment_playbook():
    return Playbook(
        playbook_id="pb-enrichment",
        name="Alert Enrichment",
        description="Enrich alert with threat intelligence",
        trigger_conditions=[
            {"field": "type", "operator": "equals", "value": "malware"},
        ],
        steps=[
            PlaybookStep(
                step_id="step-1",
                name="Lookup IP",
                action_type="enrichment",
                connector="threat_intel",
                action="lookup_ip",
                parameters={"ip": "{{trigger.source_ip}}"},
            ),
            PlaybookStep(
                step_id="step-2",
                name="Notify SOC",
                action_type="notification",
                connector="slack",
                action="send_message",
                parameters={
                    "channel": "#soc-alerts",
                    "text": "Alert enriched: {{trigger.title}}",
                },
            ),
        ],
    )


@pytest.fixture
def containment_playbook():
    return Playbook(
        playbook_id="pb-containment",
        name="IP Containment",
        description="Block malicious IP addresses",
        trigger_conditions=[
            {"field": "severity", "operator": "in", "value": ["critical", "high"]},
        ],
        steps=[
            PlaybookStep(
                step_id="step-1",
                name="Block IP",
                action_type="containment",
                connector="firewall",
                action="block_ip",
                parameters={"ip": "{{trigger.source_ip}}"},
                requires_approval=True,
            ),
            PlaybookStep(
                step_id="step-2",
                name="Isolate Host",
                action_type="containment",
                connector="edr",
                action="isolate_host",
                parameters={"hostname": "{{trigger.hostname}}"},
            ),
            PlaybookStep(
                step_id="step-3",
                name="Notify Team",
                action_type="notification",
                connector="email",
                action="send",
                parameters={
                    "to": "security@company.com",
                    "subject": "Containment Action Taken",
                    "body": "IP {{trigger.source_ip}} has been blocked",
                },
            ),
        ],
    )


@pytest.fixture
def sample_alert():
    return {
        "alert_id": "alert-001",
        "title": "Malware Detected",
        "type": "malware",
        "severity": "critical",
        "source_ip": "10.0.0.100",
        "hostname": "workstation-001",
        "user": "admin",
    }


# Test cases
class TestConnectors:
    """Tests for action connectors."""

    @pytest.mark.asyncio
    async def test_email_send(self, email_connector):
        """Test email sending."""
        result = await email_connector.execute(
            "send",
            {"to": "test@example.com", "subject": "Test", "body": "Body"},
        )

        assert result["success"] is True
        assert "message_id" in result
        assert len(email_connector.sent_emails) == 1

    @pytest.mark.asyncio
    async def test_slack_message(self, slack_connector):
        """Test Slack messaging."""
        result = await slack_connector.execute(
            "send_message",
            {"channel": "#test", "text": "Hello"},
        )

        assert result["success"] is True
        assert len(slack_connector.sent_messages) == 1

    @pytest.mark.asyncio
    async def test_firewall_block_ip(self, firewall_connector):
        """Test firewall IP blocking."""
        result = await firewall_connector.execute(
            "block_ip",
            {"ip": "192.168.1.100"},
        )

        assert result["success"] is True
        assert "192.168.1.100" in firewall_connector.blocked_ips

    @pytest.mark.asyncio
    async def test_edr_isolate(self, edr_connector):
        """Test EDR host isolation."""
        result = await edr_connector.execute(
            "isolate_host",
            {"hostname": "workstation-001"},
        )

        assert result["success"] is True
        assert "workstation-001" in edr_connector.isolated_hosts

    @pytest.mark.asyncio
    async def test_threat_intel_lookup(self, threat_intel_connector):
        """Test threat intel lookup."""
        result = await threat_intel_connector.execute(
            "lookup_ip",
            {"ip": "10.0.0.100"},
        )

        assert result["reputation"] == "malicious"
        assert result["score"] == 85


class TestConnectorRegistry:
    """Tests for ConnectorRegistry."""

    def test_register_connector(self, connector_registry, email_connector):
        """Test connector registration."""
        assert connector_registry.get("email") is email_connector

    def test_get_unknown_connector(self, connector_registry):
        """Test getting unknown connector."""
        assert connector_registry.get("unknown") is None


class TestApprovalManager:
    """Tests for ApprovalManager."""

    def test_request_approval(self, approval_manager):
        """Test approval request."""
        approval_id = approval_manager.request_approval(
            "exec-1", "step-1", ["analyst"], "Please approve"
        )

        assert approval_id.startswith("approval-")
        assert approval_id in approval_manager.pending_approvals

    def test_approve(self, approval_manager):
        """Test approval."""
        approval_id = approval_manager.request_approval(
            "exec-1", "step-1", ["analyst"], "Please approve"
        )

        result = approval_manager.approve(approval_id, "analyst")

        assert result is True
        assert approval_manager.is_approved(approval_id) is True
        assert approval_id not in approval_manager.pending_approvals

    def test_reject(self, approval_manager):
        """Test rejection."""
        approval_id = approval_manager.request_approval(
            "exec-1", "step-1", ["analyst"], "Please approve"
        )

        result = approval_manager.reject(approval_id, "analyst", "Not needed")

        assert result is True
        assert approval_manager.is_approved(approval_id) is False


class TestPlaybookExecutor:
    """Tests for PlaybookExecutor."""

    @pytest.mark.asyncio
    async def test_execute_enrichment_playbook(
        self, executor, enrichment_playbook, sample_alert
    ):
        """Test executing enrichment playbook."""
        result = await executor.execute(enrichment_playbook, sample_alert)

        assert result.status == ExecutionStatus.COMPLETED
        assert len(result.step_results) == 2
        assert all(
            r.status == ActionStatus.COMPLETED for r in result.step_results
        )

    @pytest.mark.asyncio
    async def test_execute_containment_playbook(
        self, executor, containment_playbook, sample_alert, firewall_connector
    ):
        """Test executing containment playbook."""
        result = await executor.execute(containment_playbook, sample_alert)

        assert result.status == ExecutionStatus.COMPLETED
        assert len(result.step_results) == 3
        assert "10.0.0.100" in firewall_connector.blocked_ips

    @pytest.mark.asyncio
    async def test_parameter_resolution(
        self, executor, enrichment_playbook, sample_alert, threat_intel_connector
    ):
        """Test parameter resolution from trigger data."""
        result = await executor.execute(enrichment_playbook, sample_alert)

        # Verify threat intel was queried with correct IP
        assert len(threat_intel_connector.lookups) == 1
        assert threat_intel_connector.lookups[0]["value"] == "10.0.0.100"

    @pytest.mark.asyncio
    async def test_step_failure_handling(self, executor, connector_registry):
        """Test handling step failures."""
        playbook = Playbook(
            playbook_id="pb-fail",
            name="Failing Playbook",
            description="Test failure",
            trigger_conditions=[],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Unknown Action",
                    action_type="test",
                    connector="email",
                    action="unknown_action",  # Will fail
                    parameters={},
                ),
            ],
        )

        result = await executor.execute(playbook, {})

        assert result.status == ExecutionStatus.FAILED
        assert result.step_results[0].status == ActionStatus.FAILED

    @pytest.mark.asyncio
    async def test_continue_on_error(self, executor, connector_registry):
        """Test continue on error flag."""
        playbook = Playbook(
            playbook_id="pb-continue",
            name="Continue Playbook",
            description="Test continue on error",
            trigger_conditions=[],
            steps=[
                PlaybookStep(
                    step_id="step-1",
                    name="Unknown Action",
                    action_type="test",
                    connector="email",
                    action="unknown_action",
                    parameters={},
                    continue_on_error=True,  # Should continue
                ),
                PlaybookStep(
                    step_id="step-2",
                    name="Send Email",
                    action_type="notification",
                    connector="email",
                    action="send",
                    parameters={"to": "test@test.com", "subject": "Test", "body": "Body"},
                ),
            ],
        )

        result = await executor.execute(playbook, {})

        assert result.status == ExecutionStatus.COMPLETED
        assert len(result.step_results) == 2
        assert result.step_results[0].status == ActionStatus.FAILED
        assert result.step_results[1].status == ActionStatus.COMPLETED


class TestPlaybookTriggerEngine:
    """Tests for PlaybookTriggerEngine."""

    def test_trigger_matching(self, enrichment_playbook, containment_playbook):
        """Test trigger condition matching."""
        engine = PlaybookTriggerEngine([enrichment_playbook, containment_playbook])

        alert = {"type": "malware", "severity": "high"}
        triggered = engine.evaluate(alert)

        # Should trigger both playbooks
        assert len(triggered) == 2

    def test_no_match(self, enrichment_playbook):
        """Test no trigger match."""
        engine = PlaybookTriggerEngine([enrichment_playbook])

        alert = {"type": "policy_violation", "severity": "low"}
        triggered = engine.evaluate(alert)

        assert len(triggered) == 0

    def test_disabled_playbook(self, enrichment_playbook):
        """Test disabled playbook not triggered."""
        enrichment_playbook.enabled = False
        engine = PlaybookTriggerEngine([enrichment_playbook])

        alert = {"type": "malware", "severity": "high"}
        triggered = engine.evaluate(alert)

        assert len(triggered) == 0


class TestEndToEndSOAR:
    """End-to-end SOAR tests."""

    @pytest.mark.asyncio
    async def test_full_incident_response_flow(
        self,
        executor,
        enrichment_playbook,
        containment_playbook,
        sample_alert,
        firewall_connector,
        edr_connector,
        slack_connector,
    ):
        """Test full incident response flow."""
        engine = PlaybookTriggerEngine([enrichment_playbook, containment_playbook])

        # Evaluate triggers
        triggered = engine.evaluate(sample_alert)
        assert len(triggered) == 2

        # Execute all triggered playbooks
        executions = []
        for playbook in triggered:
            result = await executor.execute(playbook, sample_alert)
            executions.append(result)

        # Verify all completed
        assert all(e.status == ExecutionStatus.COMPLETED for e in executions)

        # Verify actions were taken
        assert "10.0.0.100" in firewall_connector.blocked_ips
        assert "workstation-001" in edr_connector.isolated_hosts
        assert len(slack_connector.sent_messages) >= 1

    @pytest.mark.asyncio
    async def test_high_volume_execution(self, executor, enrichment_playbook):
        """Test high volume playbook execution."""
        alerts = [
            {
                "alert_id": f"alert-{i}",
                "title": f"Alert {i}",
                "type": "malware",
                "source_ip": f"192.168.1.{i % 256}",
            }
            for i in range(100)
        ]

        start = time.time()
        executions = []
        for alert in alerts:
            result = await executor.execute(enrichment_playbook, alert)
            executions.append(result)
        elapsed = time.time() - start

        assert len(executions) == 100
        assert all(e.status == ExecutionStatus.COMPLETED for e in executions)
        assert elapsed < 5.0  # Should complete in under 5 seconds
