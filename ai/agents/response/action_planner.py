"""Action Planner - Plan response actions for incidents."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ActionType(str, Enum):
    """Types of response actions."""

    # Containment
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_URL = "block_url"
    ISOLATE_HOST = "isolate_host"
    DISABLE_ACCOUNT = "disable_account"
    TERMINATE_SESSION = "terminate_session"

    # Eradication
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"
    KILL_PROCESS = "kill_process"
    REMOVE_PERSISTENCE = "remove_persistence"

    # Recovery
    RESTORE_FILE = "restore_file"
    ENABLE_ACCOUNT = "enable_account"
    UNISOLATE_HOST = "unisolate_host"
    UNBLOCK_IP = "unblock_ip"

    # Notification
    NOTIFY_USER = "notify_user"
    NOTIFY_TEAM = "notify_team"
    CREATE_TICKET = "create_ticket"
    ESCALATE = "escalate"

    # Investigation
    COLLECT_FORENSICS = "collect_forensics"
    CAPTURE_MEMORY = "capture_memory"
    SNAPSHOT_DISK = "snapshot_disk"

    # Other
    EXECUTE_PLAYBOOK = "execute_playbook"
    RUN_SCAN = "run_scan"
    UPDATE_RULES = "update_rules"


class RiskLevel(str, Enum):
    """Risk levels for actions."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlannedAction(BaseModel):
    """A planned response action."""

    action_id: str = Field(default_factory=lambda: str(uuid4()))
    action_type: ActionType = Field(description="Type of action")
    target: str = Field(description="Target of action")
    target_type: str = Field(description="Type of target")

    # Parameters
    parameters: dict[str, Any] = Field(default_factory=dict)

    # Classification
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    priority: int = Field(default=5, ge=1, le=10)
    category: str = Field(default="containment")

    # Approval
    requires_approval: bool = Field(default=True)
    approval_reason: str | None = Field(default=None)

    # Dependencies
    depends_on: list[str] = Field(default_factory=list)
    blocks: list[str] = Field(default_factory=list)

    # Metadata
    rationale: str = Field(default="")
    expected_outcome: str = Field(default="")
    rollback_action: str | None = Field(default=None)


class ActionPlan(BaseModel):
    """Complete action plan for incident response."""

    plan_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str | None = Field(default=None)

    # Actions
    actions: list[PlannedAction] = Field(default_factory=list)

    # Summary
    total_actions: int = Field(default=0)
    high_risk_actions: int = Field(default=0)
    requires_approval: bool = Field(default=False)

    # Timing
    estimated_duration_minutes: int = Field(default=0)

    # Status
    status: str = Field(default="draft")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    approved_at: datetime | None = Field(default=None)
    approved_by: str | None = Field(default=None)


class ActionPlanner(LoggerMixin):
    """Planner for response actions.

    Features:
    - Action generation based on threat type
    - Risk assessment for each action
    - Dependency management
    - Prioritization
    - Rollback planning
    """

    # Risk levels by action type
    ACTION_RISK_LEVELS = {
        ActionType.BLOCK_IP: RiskLevel.MEDIUM,
        ActionType.BLOCK_DOMAIN: RiskLevel.MEDIUM,
        ActionType.BLOCK_URL: RiskLevel.LOW,
        ActionType.ISOLATE_HOST: RiskLevel.HIGH,
        ActionType.DISABLE_ACCOUNT: RiskLevel.HIGH,
        ActionType.TERMINATE_SESSION: RiskLevel.MEDIUM,
        ActionType.QUARANTINE_FILE: RiskLevel.MEDIUM,
        ActionType.DELETE_FILE: RiskLevel.HIGH,
        ActionType.KILL_PROCESS: RiskLevel.MEDIUM,
        ActionType.REMOVE_PERSISTENCE: RiskLevel.HIGH,
        ActionType.RESTORE_FILE: RiskLevel.MEDIUM,
        ActionType.ENABLE_ACCOUNT: RiskLevel.MEDIUM,
        ActionType.UNISOLATE_HOST: RiskLevel.MEDIUM,
        ActionType.UNBLOCK_IP: RiskLevel.LOW,
        ActionType.NOTIFY_USER: RiskLevel.NONE,
        ActionType.NOTIFY_TEAM: RiskLevel.NONE,
        ActionType.CREATE_TICKET: RiskLevel.NONE,
        ActionType.ESCALATE: RiskLevel.NONE,
        ActionType.COLLECT_FORENSICS: RiskLevel.LOW,
        ActionType.CAPTURE_MEMORY: RiskLevel.LOW,
        ActionType.SNAPSHOT_DISK: RiskLevel.LOW,
        ActionType.EXECUTE_PLAYBOOK: RiskLevel.MEDIUM,
        ActionType.RUN_SCAN: RiskLevel.LOW,
        ActionType.UPDATE_RULES: RiskLevel.LOW,
    }

    # Rollback actions
    ROLLBACK_MAPPING = {
        ActionType.BLOCK_IP: ActionType.UNBLOCK_IP,
        ActionType.ISOLATE_HOST: ActionType.UNISOLATE_HOST,
        ActionType.DISABLE_ACCOUNT: ActionType.ENABLE_ACCOUNT,
        ActionType.QUARANTINE_FILE: ActionType.RESTORE_FILE,
    }

    def __init__(
        self,
        llm_endpoint: str = "http://localhost:8080/v1",
        model_name: str = "solar-10.7b",
    ) -> None:
        """Initialize action planner.

        Args:
            llm_endpoint: LLM API endpoint
            model_name: Model name
        """
        self.llm_endpoint = llm_endpoint
        self.model_name = model_name
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def plan(
        self,
        analysis: dict[str, Any],
        affected_assets: list[dict[str, Any]],
        recommendations: list[str] | None = None,
        constraints: list[str] | None = None,
    ) -> ActionPlan:
        """Create an action plan based on analysis.

        Args:
            analysis: Incident analysis results
            affected_assets: List of affected assets
            recommendations: Analysis recommendations
            constraints: Execution constraints

        Returns:
            Complete action plan
        """
        self.logger.info(
            "creating_action_plan",
            asset_count=len(affected_assets),
        )

        plan = ActionPlan(incident_id=analysis.get("analysis_id"))
        actions = []

        # Get threat context
        threat_type = analysis.get("threat_classification", {}).get("threat_type", "unknown")
        severity = analysis.get("severity_score", 5)
        iocs = analysis.get("indicators_of_compromise", [])

        # Generate containment actions
        containment = self._plan_containment(
            threat_type,
            severity,
            affected_assets,
            iocs,
        )
        actions.extend(containment)

        # Generate notification actions
        notifications = self._plan_notifications(severity, threat_type)
        actions.extend(notifications)

        # Generate investigation actions for high severity
        if severity >= 7:
            investigation = self._plan_investigation(affected_assets)
            actions.extend(investigation)

        # Add rollback planning
        self._add_rollback_planning(actions)

        # Resolve dependencies
        self._resolve_dependencies(actions)

        # Prioritize actions
        self._prioritize_actions(actions, severity)

        # Add to plan
        plan.actions = actions
        plan.total_actions = len(actions)
        plan.high_risk_actions = sum(
            1 for a in actions
            if a.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        )
        plan.requires_approval = any(a.requires_approval for a in actions)

        # Estimate duration
        plan.estimated_duration_minutes = self._estimate_duration(actions)

        self.logger.info(
            "action_plan_created",
            plan_id=plan.plan_id,
            total_actions=plan.total_actions,
            high_risk=plan.high_risk_actions,
        )

        return plan

    def _plan_containment(
        self,
        threat_type: str,
        severity: float,
        assets: list[dict[str, Any]],
        iocs: list[dict[str, Any]],
    ) -> list[PlannedAction]:
        """Plan containment actions."""
        actions = []

        # Block malicious IPs
        for ioc in iocs:
            if ioc.get("type") == "ip":
                ip = ioc.get("value")
                if ip and not self._is_internal(ip):
                    actions.append(
                        PlannedAction(
                            action_type=ActionType.BLOCK_IP,
                            target=ip,
                            target_type="ip",
                            parameters={"ip": ip, "reason": f"IOC from {threat_type} incident"},
                            risk_level=RiskLevel.MEDIUM,
                            category="containment",
                            rationale=f"Block malicious IP identified in {threat_type}",
                            expected_outcome="IP blocked on perimeter firewall",
                            requires_approval=False,
                        )
                    )

        # Block malicious domains
        for ioc in iocs:
            if ioc.get("type") == "domain":
                domain = ioc.get("value")
                actions.append(
                    PlannedAction(
                        action_type=ActionType.BLOCK_DOMAIN,
                        target=domain,
                        target_type="domain",
                        parameters={"domain": domain},
                        risk_level=RiskLevel.MEDIUM,
                        category="containment",
                        rationale="Block malicious domain",
                        expected_outcome="Domain blocked on DNS/proxy",
                        requires_approval=False,
                    )
                )

        # Isolate hosts for high severity
        if severity >= 7:
            for asset in assets:
                if asset.get("type") == "host" or asset.get("asset_type") == "host":
                    hostname = asset.get("identifier") or asset.get("value")
                    if hostname:
                        actions.append(
                            PlannedAction(
                                action_type=ActionType.ISOLATE_HOST,
                                target=hostname,
                                target_type="host",
                                parameters={"hostname": hostname},
                                risk_level=RiskLevel.HIGH,
                                category="containment",
                                rationale="Isolate potentially compromised host",
                                expected_outcome="Host network isolated via EDR",
                                requires_approval=True,
                                approval_reason="High-impact action requiring manual approval",
                            )
                        )

        # Disable accounts for credential-related threats
        if threat_type in ["credential_compromise", "insider_threat", "brute_force"]:
            for asset in assets:
                if asset.get("type") == "user" or asset.get("asset_type") == "user":
                    username = asset.get("identifier") or asset.get("value")
                    if username:
                        actions.append(
                            PlannedAction(
                                action_type=ActionType.DISABLE_ACCOUNT,
                                target=username,
                                target_type="user",
                                parameters={"username": username},
                                risk_level=RiskLevel.HIGH,
                                category="containment",
                                rationale="Disable potentially compromised account",
                                expected_outcome="User account disabled in AD",
                                requires_approval=True,
                                approval_reason="Account actions require approval",
                            )
                        )

        return actions

    def _plan_notifications(
        self,
        severity: float,
        threat_type: str,
    ) -> list[PlannedAction]:
        """Plan notification actions."""
        actions = []

        # Always create ticket
        actions.append(
            PlannedAction(
                action_type=ActionType.CREATE_TICKET,
                target="incident_ticket",
                target_type="ticket",
                parameters={"severity": severity, "threat_type": threat_type},
                risk_level=RiskLevel.NONE,
                category="notification",
                priority=10,  # High priority
                rationale="Document incident for tracking",
                expected_outcome="Incident ticket created",
                requires_approval=False,
            )
        )

        # Notify team based on severity
        if severity >= 5:
            actions.append(
                PlannedAction(
                    action_type=ActionType.NOTIFY_TEAM,
                    target="security_team",
                    target_type="team",
                    parameters={
                        "message": f"Security incident: {threat_type} (Severity: {severity}/10)",
                    },
                    risk_level=RiskLevel.NONE,
                    category="notification",
                    priority=9,
                    rationale="Notify security team of incident",
                    expected_outcome="Team notified via configured channel",
                    requires_approval=False,
                )
            )

        # Escalate for high severity
        if severity >= 8:
            actions.append(
                PlannedAction(
                    action_type=ActionType.ESCALATE,
                    target="management",
                    target_type="escalation",
                    parameters={"level": "executive"},
                    risk_level=RiskLevel.NONE,
                    category="notification",
                    priority=8,
                    rationale="Critical incident requires executive awareness",
                    expected_outcome="Executive notification sent",
                    requires_approval=False,
                )
            )

        return actions

    def _plan_investigation(
        self,
        assets: list[dict[str, Any]],
    ) -> list[PlannedAction]:
        """Plan investigation actions."""
        actions = []

        for asset in assets[:5]:  # Limit forensic collection
            asset_type = asset.get("type") or asset.get("asset_type")
            identifier = asset.get("identifier") or asset.get("value")

            if asset_type == "host" and identifier:
                # Memory capture
                actions.append(
                    PlannedAction(
                        action_type=ActionType.CAPTURE_MEMORY,
                        target=identifier,
                        target_type="host",
                        parameters={"hostname": identifier},
                        risk_level=RiskLevel.LOW,
                        category="investigation",
                        priority=6,
                        rationale="Capture memory for forensic analysis",
                        expected_outcome="Memory dump collected",
                        requires_approval=True,
                    )
                )

                # Disk snapshot
                actions.append(
                    PlannedAction(
                        action_type=ActionType.SNAPSHOT_DISK,
                        target=identifier,
                        target_type="host",
                        parameters={"hostname": identifier},
                        risk_level=RiskLevel.LOW,
                        category="investigation",
                        priority=5,
                        rationale="Snapshot disk for forensic analysis",
                        expected_outcome="Disk snapshot created",
                        requires_approval=True,
                    )
                )

        return actions

    def _add_rollback_planning(self, actions: list[PlannedAction]) -> None:
        """Add rollback action references."""
        for action in actions:
            rollback_type = self.ROLLBACK_MAPPING.get(action.action_type)
            if rollback_type:
                action.rollback_action = rollback_type.value

    def _resolve_dependencies(self, actions: list[PlannedAction]) -> None:
        """Resolve action dependencies."""
        # Notifications should come first
        notification_ids = [
            a.action_id for a in actions
            if a.category == "notification"
        ]

        # Containment depends on notifications
        for action in actions:
            if action.category == "containment":
                # Find the ticket creation action
                for a in actions:
                    if a.action_type == ActionType.CREATE_TICKET:
                        action.depends_on.append(a.action_id)
                        break

        # Investigation depends on containment
        containment_ids = [
            a.action_id for a in actions
            if a.category == "containment"
        ]
        for action in actions:
            if action.category == "investigation":
                action.depends_on.extend(containment_ids)

    def _prioritize_actions(
        self,
        actions: list[PlannedAction],
        severity: float,
    ) -> None:
        """Prioritize actions based on severity and type."""
        for action in actions:
            base_priority = action.priority

            # Adjust by category
            category_boost = {
                "notification": 2,
                "containment": 1,
                "investigation": 0,
            }
            base_priority += category_boost.get(action.category, 0)

            # Adjust by severity
            if severity >= 8:
                base_priority += 1

            action.priority = min(base_priority, 10)

        # Sort by priority (descending)
        actions.sort(key=lambda a: a.priority, reverse=True)

    def _estimate_duration(self, actions: list[PlannedAction]) -> int:
        """Estimate plan execution duration in minutes."""
        # Base estimates by action type
        durations = {
            ActionType.BLOCK_IP: 1,
            ActionType.BLOCK_DOMAIN: 1,
            ActionType.ISOLATE_HOST: 5,
            ActionType.DISABLE_ACCOUNT: 2,
            ActionType.NOTIFY_TEAM: 1,
            ActionType.CREATE_TICKET: 2,
            ActionType.ESCALATE: 1,
            ActionType.CAPTURE_MEMORY: 15,
            ActionType.SNAPSHOT_DISK: 30,
        }

        total = sum(
            durations.get(a.action_type, 5)
            for a in actions
        )

        # Add approval overhead
        approval_count = sum(1 for a in actions if a.requires_approval)
        total += approval_count * 5  # 5 minutes per approval

        return total

    def _is_internal(self, ip: str) -> bool:
        """Check if IP is internal."""
        internal_prefixes = ["10.", "172.16.", "192.168.", "127."]
        return any(ip.startswith(p) for p in internal_prefixes)

    def validate_plan(self, plan: ActionPlan) -> list[str]:
        """Validate an action plan.

        Args:
            plan: Plan to validate

        Returns:
            List of validation issues
        """
        issues = []

        # Check for circular dependencies
        for action in plan.actions:
            if action.action_id in action.depends_on:
                issues.append(f"Action {action.action_id} has circular dependency")

        # Check for missing dependencies
        action_ids = {a.action_id for a in plan.actions}
        for action in plan.actions:
            for dep in action.depends_on:
                if dep not in action_ids:
                    issues.append(f"Action {action.action_id} depends on unknown action {dep}")

        # Check for high-risk actions without approval
        for action in plan.actions:
            if action.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                if not action.requires_approval:
                    issues.append(
                        f"High-risk action {action.action_id} ({action.action_type}) "
                        "should require approval"
                    )

        return issues
