"""Responder Agent - Main agent for automated incident response."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.models import BaseModel

from ..base import (
    AgentCapability,
    AgentConfig,
    AgentContext,
    AgentResult,
    AgentStatus,
    BaseAgent,
    ToolDefinition,
)
from ..memory import AgentMemory, MemoryType, MemoryImportance


class ResponseMode(str, Enum):
    """Response execution modes."""

    AUTOMATIC = "automatic"  # Execute without approval
    SEMI_AUTOMATIC = "semi_automatic"  # Auto for low risk, approval for high
    MANUAL = "manual"  # Require approval for all


class ResponderConfig(AgentConfig):
    """Configuration for Responder Agent."""

    llm_endpoint: str = Field(
        default="http://localhost:8080/v1",
        description="LLM API endpoint",
    )
    model_name: str = Field(
        default="solar-10.7b",
        description="LLM model name",
    )
    soar_endpoint: str = Field(default="http://localhost:8001/api/v1")
    response_mode: ResponseMode = Field(default=ResponseMode.SEMI_AUTOMATIC)
    auto_approve_risk_threshold: str = Field(
        default="low",
        description="Max risk level for auto-approval (low/medium/high)",
    )
    max_actions_per_response: int = Field(default=10)
    enable_containment: bool = Field(default=True)
    enable_eradication: bool = Field(default=True)
    enable_recovery: bool = Field(default=False)  # More risky


class ResponseAction(BaseModel):
    """An action to be taken."""

    action_id: str
    action_type: str
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: str = Field(default="low")
    requires_approval: bool = Field(default=True)
    playbook_id: str | None = Field(default=None)


class ResponseResult(BaseModel):
    """Result of response execution."""

    response_id: str
    status: str
    actions_planned: int
    actions_executed: int
    actions_succeeded: int
    actions_failed: int
    actions_pending_approval: int
    summary: str
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)
    pending_actions: list[dict[str, Any]] = Field(default_factory=list)
    failed_actions: list[dict[str, Any]] = Field(default_factory=list)


class ResponderAgent(BaseAgent):
    """Responder Agent for automated incident response.

    Capabilities:
    - Response action planning
    - Playbook selection and execution
    - Containment actions (block, isolate)
    - Eradication actions (remove, clean)
    - Recovery coordination
    """

    SYSTEM_PROMPT = """You are a security response expert executing incident response.

Your responsibilities:
1. Plan appropriate response actions
2. Execute containment measures
3. Coordinate eradication efforts
4. Validate action success
5. Minimize business impact

Follow the principle of least disruption while ensuring security.
Always verify actions before and after execution."""

    def __init__(self, config: ResponderConfig) -> None:
        """Initialize the Responder Agent."""
        config.name = config.name or "Responder"
        config.capabilities = [
            AgentCapability.RESPOND,
            AgentCapability.CONTAIN,
            AgentCapability.REMEDIATE,
            AgentCapability.EXECUTE,
        ]

        super().__init__(config)
        self.config: ResponderConfig = config

        self._client: httpx.AsyncClient | None = None
        self._memory = AgentMemory(self.agent_id)

        self._setup_tools()

    def _setup_tools(self) -> None:
        """Setup response tools."""
        # Block IP tool
        self.register_tool(
            ToolDefinition(
                name="block_ip",
                description="Block an IP address on firewall",
                parameters={
                    "ip": {"type": "string"},
                    "reason": {"type": "string"},
                    "duration": {"type": "string", "default": "permanent"},
                },
                required_parameters=["ip"],
                risk_level="medium",
                requires_approval=True,
            ),
            self._block_ip,
        )

        # Isolate host tool
        self.register_tool(
            ToolDefinition(
                name="isolate_host",
                description="Isolate a host from the network",
                parameters={
                    "hostname": {"type": "string"},
                    "reason": {"type": "string"},
                },
                required_parameters=["hostname"],
                risk_level="high",
                requires_approval=True,
            ),
            self._isolate_host,
        )

        # Disable account tool
        self.register_tool(
            ToolDefinition(
                name="disable_account",
                description="Disable a user account",
                parameters={
                    "username": {"type": "string"},
                    "reason": {"type": "string"},
                },
                required_parameters=["username"],
                risk_level="high",
                requires_approval=True,
            ),
            self._disable_account,
        )

        # Execute playbook tool
        self.register_tool(
            ToolDefinition(
                name="execute_playbook",
                description="Execute a SOAR playbook",
                parameters={
                    "playbook_id": {"type": "string"},
                    "context": {"type": "object"},
                },
                required_parameters=["playbook_id"],
                risk_level="medium",
                requires_approval=True,
            ),
            self._execute_playbook,
        )

        # Add to blocklist tool
        self.register_tool(
            ToolDefinition(
                name="add_to_blocklist",
                description="Add IOC to blocklist",
                parameters={
                    "ioc_type": {"type": "string"},
                    "ioc_value": {"type": "string"},
                },
                required_parameters=["ioc_type", "ioc_value"],
                risk_level="low",
                requires_approval=False,
            ),
            self._add_to_blocklist,
        )

        # Send notification tool
        self.register_tool(
            ToolDefinition(
                name="send_notification",
                description="Send security notification",
                parameters={
                    "channel": {"type": "string"},
                    "message": {"type": "string"},
                    "severity": {"type": "string"},
                },
                required_parameters=["channel", "message"],
                risk_level="low",
                requires_approval=False,
            ),
            self._send_notification,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def initialize(self) -> None:
        """Initialize the agent."""
        self._status = AgentStatus.IDLE
        self.logger.info("responder_initialized", agent_id=self.agent_id)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def run(self, context: AgentContext) -> AgentResult:
        """Run response.

        Args:
            context: Response context with analysis and recommendations

        Returns:
            Response results
        """
        self._current_context = context
        self._status = AgentStatus.RUNNING
        self._clear_steps()

        try:
            data = context.data
            analysis = data.get("analysis", {})
            recommendations = data.get("recommendations", [])
            affected_assets = data.get("affected_assets", [])

            result = ResponseResult(
                response_id=context.execution_id,
                status="in_progress",
                actions_planned=0,
                actions_executed=0,
                actions_succeeded=0,
                actions_failed=0,
                actions_pending_approval=0,
                summary="",
            )

            # Phase 1: Plan response actions
            self.logger.info("planning_response", execution_id=context.execution_id)
            actions = await self._plan_actions(analysis, recommendations, affected_assets)
            result.actions_planned = len(actions)

            # Phase 2: Get playbook recommendations
            playbooks = await self._get_playbook_recommendations(analysis)

            # Phase 3: Execute actions
            self.logger.info(
                "executing_response",
                action_count=len(actions),
                playbook_count=len(playbooks),
            )

            executed = []
            pending = []
            failed = []

            for action in actions:
                # Check if auto-approve
                should_execute = self._should_auto_execute(action)

                if should_execute:
                    action_result = await self._execute_action(action)
                    if action_result.get("success"):
                        executed.append({
                            "action": action.model_dump(),
                            "result": action_result,
                        })
                        result.actions_succeeded += 1
                    else:
                        failed.append({
                            "action": action.model_dump(),
                            "error": action_result.get("error"),
                        })
                        result.actions_failed += 1
                    result.actions_executed += 1
                else:
                    pending.append(action.model_dump())
                    result.actions_pending_approval += 1

            result.executed_actions = executed
            result.pending_actions = pending
            result.failed_actions = failed

            # Phase 4: Execute approved playbooks
            for playbook in playbooks[:3]:  # Limit playbooks
                if self._should_auto_execute_playbook(playbook):
                    pb_result = await self.execute_tool(
                        "execute_playbook",
                        {
                            "playbook_id": playbook.get("playbook_id"),
                            "context": {"analysis": analysis},
                        },
                    )
                    if pb_result.get("success"):
                        executed.append({
                            "type": "playbook",
                            "playbook_id": playbook.get("playbook_id"),
                            "result": pb_result,
                        })

            # Generate summary
            result.summary = self._generate_summary(result)
            result.status = "completed"

            self._status = AgentStatus.COMPLETED

            return self._create_result(
                success=True,
                output=result.model_dump(),
            )

        except Exception as e:
            self.logger.error(
                "response_failed",
                agent_id=self.agent_id,
                error=str(e),
            )
            self._status = AgentStatus.FAILED

            return self._create_result(
                success=False,
                error=str(e),
            )

    async def _plan_actions(
        self,
        analysis: dict[str, Any],
        recommendations: list[str],
        affected_assets: list[dict[str, Any]],
    ) -> list[ResponseAction]:
        """Plan response actions based on analysis."""
        actions = []
        action_counter = 0

        # Get threat type
        threat_type = analysis.get("threat_classification", {}).get("threat_type", "unknown")
        severity = analysis.get("severity_score", 5)

        # Plan containment actions
        if self.config.enable_containment:
            # Block malicious IPs
            for asset in affected_assets:
                if asset.get("type") == "ip" or asset.get("asset_type") == "ip":
                    ip = asset.get("identifier") or asset.get("value")
                    if ip and not self._is_internal_ip(ip):
                        action_counter += 1
                        actions.append(
                            ResponseAction(
                                action_id=f"action-{action_counter}",
                                action_type="block_ip",
                                target=ip,
                                parameters={"ip": ip, "reason": f"Involved in {threat_type}"},
                                risk_level="medium",
                                requires_approval=severity < 8,
                            )
                        )

            # Isolate compromised hosts for high severity
            if severity >= 7:
                for asset in affected_assets:
                    if asset.get("type") == "host" or asset.get("asset_type") == "host":
                        hostname = asset.get("identifier") or asset.get("value")
                        if hostname:
                            action_counter += 1
                            actions.append(
                                ResponseAction(
                                    action_id=f"action-{action_counter}",
                                    action_type="isolate_host",
                                    target=hostname,
                                    parameters={"hostname": hostname, "reason": "Potential compromise"},
                                    risk_level="high",
                                    requires_approval=True,
                                )
                            )

            # Disable compromised accounts
            if threat_type in ["credential_compromise", "insider_threat"]:
                for asset in affected_assets:
                    if asset.get("type") == "user" or asset.get("asset_type") == "user":
                        username = asset.get("identifier") or asset.get("value")
                        if username:
                            action_counter += 1
                            actions.append(
                                ResponseAction(
                                    action_id=f"action-{action_counter}",
                                    action_type="disable_account",
                                    target=username,
                                    parameters={"username": username, "reason": "Potential compromise"},
                                    risk_level="high",
                                    requires_approval=True,
                                )
                            )

        # Add IOCs to blocklist
        iocs = analysis.get("indicators_of_compromise", [])
        for ioc in iocs[:10]:
            action_counter += 1
            actions.append(
                ResponseAction(
                    action_id=f"action-{action_counter}",
                    action_type="add_to_blocklist",
                    target=ioc.get("value"),
                    parameters={"ioc_type": ioc.get("type"), "ioc_value": ioc.get("value")},
                    risk_level="low",
                    requires_approval=False,
                )
            )

        # Notification action
        if severity >= 6:
            action_counter += 1
            actions.append(
                ResponseAction(
                    action_id=f"action-{action_counter}",
                    action_type="send_notification",
                    target="security_team",
                    parameters={
                        "channel": "security_team",
                        "message": f"Security incident: {threat_type} (Severity: {severity}/10)",
                        "severity": "high" if severity >= 8 else "medium",
                    },
                    risk_level="low",
                    requires_approval=False,
                )
            )

        return actions[:self.config.max_actions_per_response]

    async def _get_playbook_recommendations(
        self,
        analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Get recommended playbooks based on analysis."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/recommend/playbooks",
                json={
                    "context": analysis,
                    "max_recommendations": 5,
                },
            )
            if response.status_code == 200:
                return response.json().get("recommendations", [])
        except Exception as e:
            self.logger.warning("get_playbooks_failed", error=str(e))

        return []

    def _should_auto_execute(self, action: ResponseAction) -> bool:
        """Determine if action should be auto-executed."""
        if self.config.response_mode == ResponseMode.MANUAL:
            return False

        if self.config.response_mode == ResponseMode.AUTOMATIC:
            return True

        # Semi-automatic mode
        risk_levels = ["low", "medium", "high"]
        threshold_idx = risk_levels.index(self.config.auto_approve_risk_threshold)
        action_risk_idx = risk_levels.index(action.risk_level)

        return action_risk_idx <= threshold_idx

    def _should_auto_execute_playbook(self, playbook: dict[str, Any]) -> bool:
        """Determine if playbook should be auto-executed."""
        if self.config.response_mode == ResponseMode.MANUAL:
            return False

        return playbook.get("auto_execute", False)

    async def _execute_action(self, action: ResponseAction) -> dict[str, Any]:
        """Execute a single action."""
        tool_mapping = {
            "block_ip": ("block_ip", {"ip": action.parameters.get("ip"), "reason": action.parameters.get("reason")}),
            "isolate_host": ("isolate_host", {"hostname": action.parameters.get("hostname"), "reason": action.parameters.get("reason")}),
            "disable_account": ("disable_account", {"username": action.parameters.get("username"), "reason": action.parameters.get("reason")}),
            "add_to_blocklist": ("add_to_blocklist", {"ioc_type": action.parameters.get("ioc_type"), "ioc_value": action.parameters.get("ioc_value")}),
            "send_notification": ("send_notification", action.parameters),
        }

        if action.action_type not in tool_mapping:
            return {"success": False, "error": f"Unknown action type: {action.action_type}"}

        tool_name, params = tool_mapping[action.action_type]
        return await self.execute_tool(tool_name, params)

    def _generate_summary(self, result: ResponseResult) -> str:
        """Generate response summary."""
        parts = [
            f"Response {result.response_id}",
            f"Actions: {result.actions_planned} planned",
            f"{result.actions_executed} executed",
            f"{result.actions_succeeded} succeeded",
        ]

        if result.actions_failed > 0:
            parts.append(f"{result.actions_failed} failed")

        if result.actions_pending_approval > 0:
            parts.append(f"{result.actions_pending_approval} pending approval")

        return " | ".join(parts)

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal."""
        internal_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.", "127."]
        return any(ip.startswith(p) for p in internal_prefixes)

    # Tool implementations

    async def _block_ip(
        self,
        ip: str,
        reason: str = "",
        duration: str = "permanent",
    ) -> dict[str, Any]:
        """Block IP on firewall."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/actions/block-ip",
                json={"ip": ip, "reason": reason, "duration": duration},
            )
            if response.status_code == 200:
                return {"success": True, "action": "block_ip", "target": ip}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("block_ip_failed", ip=ip, error=str(e))
            return {"success": False, "error": str(e)}

    async def _isolate_host(
        self,
        hostname: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Isolate host from network."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/actions/isolate-host",
                json={"hostname": hostname, "reason": reason},
            )
            if response.status_code == 200:
                return {"success": True, "action": "isolate_host", "target": hostname}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("isolate_host_failed", hostname=hostname, error=str(e))
            return {"success": False, "error": str(e)}

    async def _disable_account(
        self,
        username: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Disable user account."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/actions/disable-account",
                json={"username": username, "reason": reason},
            )
            if response.status_code == 200:
                return {"success": True, "action": "disable_account", "target": username}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("disable_account_failed", username=username, error=str(e))
            return {"success": False, "error": str(e)}

    async def _execute_playbook(
        self,
        playbook_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute a SOAR playbook."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/playbooks/{playbook_id}/execute",
                json={"context": context or {}},
            )
            if response.status_code == 200:
                return {"success": True, "playbook_id": playbook_id, "result": response.json()}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("execute_playbook_failed", playbook_id=playbook_id, error=str(e))
            return {"success": False, "error": str(e)}

    async def _add_to_blocklist(
        self,
        ioc_type: str,
        ioc_value: str,
    ) -> dict[str, Any]:
        """Add IOC to blocklist."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/blocklist",
                json={"type": ioc_type, "value": ioc_value},
            )
            if response.status_code in [200, 201]:
                return {"success": True, "action": "add_to_blocklist", "ioc": ioc_value}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("add_to_blocklist_failed", ioc=ioc_value, error=str(e))
            return {"success": False, "error": str(e)}

    async def _send_notification(
        self,
        channel: str,
        message: str,
        severity: str = "info",
    ) -> dict[str, Any]:
        """Send notification."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/notifications",
                json={"channel": channel, "message": message, "severity": severity},
            )
            if response.status_code in [200, 201]:
                return {"success": True, "action": "notification", "channel": channel}
            return {"success": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            self.logger.warning("send_notification_failed", channel=channel, error=str(e))
            return {"success": False, "error": str(e)}
