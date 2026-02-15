"""Action Executor - Execute planned response actions."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .action_planner import ActionPlan, ActionType, PlannedAction, RiskLevel


class ExecutionStatus(str, Enum):
    """Status of action execution."""

    PENDING = "pending"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class ActionResult(BaseModel):
    """Result of a single action execution."""

    action_id: str = Field(description="Action ID")
    status: ExecutionStatus = Field(description="Execution status")
    success: bool = Field(default=False)

    # Execution details
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    duration_ms: int | None = Field(default=None)

    # Result data
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None)

    # Rollback
    rolled_back: bool = Field(default=False)
    rollback_result: dict[str, Any] | None = Field(default=None)


class ExecutionResult(BaseModel):
    """Result of plan execution."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    plan_id: str = Field(description="Plan ID")

    # Counts
    total_actions: int = Field(default=0)
    succeeded: int = Field(default=0)
    failed: int = Field(default=0)
    skipped: int = Field(default=0)
    pending_approval: int = Field(default=0)

    # Results
    action_results: list[ActionResult] = Field(default_factory=list)

    # Timing
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = Field(default=None)
    duration_ms: int | None = Field(default=None)

    # Status
    status: str = Field(default="in_progress")


class ActionExecutor(LoggerMixin):
    """Executor for response actions.

    Features:
    - Sequential and parallel execution
    - Dependency resolution
    - Error handling and retry
    - Rollback support
    - Progress tracking
    """

    def __init__(
        self,
        soar_endpoint: str = "http://localhost:8001/api/v1",
        max_parallel: int = 5,
        retry_count: int = 2,
        retry_delay_seconds: int = 5,
    ) -> None:
        """Initialize executor.

        Args:
            soar_endpoint: SOAR API endpoint
            max_parallel: Max parallel actions
            retry_count: Number of retries on failure
            retry_delay_seconds: Delay between retries
        """
        self.soar_endpoint = soar_endpoint
        self.max_parallel = max_parallel
        self.retry_count = retry_count
        self.retry_delay_seconds = retry_delay_seconds

        self._client: httpx.AsyncClient | None = None
        self._action_handlers: dict[ActionType, Callable] = {}
        self._execution_results: dict[str, ExecutionResult] = {}
        self._approvals: dict[str, bool] = {}

        self._setup_handlers()

    def _setup_handlers(self) -> None:
        """Setup action handlers."""
        self._action_handlers = {
            ActionType.BLOCK_IP: self._execute_block_ip,
            ActionType.BLOCK_DOMAIN: self._execute_block_domain,
            ActionType.ISOLATE_HOST: self._execute_isolate_host,
            ActionType.DISABLE_ACCOUNT: self._execute_disable_account,
            ActionType.TERMINATE_SESSION: self._execute_terminate_session,
            ActionType.QUARANTINE_FILE: self._execute_quarantine_file,
            ActionType.KILL_PROCESS: self._execute_kill_process,
            ActionType.NOTIFY_TEAM: self._execute_notify_team,
            ActionType.CREATE_TICKET: self._execute_create_ticket,
            ActionType.ESCALATE: self._execute_escalate,
            ActionType.EXECUTE_PLAYBOOK: self._execute_playbook,
            ActionType.CAPTURE_MEMORY: self._execute_capture_memory,
            ActionType.SNAPSHOT_DISK: self._execute_snapshot_disk,
            ActionType.UNBLOCK_IP: self._execute_unblock_ip,
            ActionType.UNISOLATE_HOST: self._execute_unisolate_host,
            ActionType.ENABLE_ACCOUNT: self._execute_enable_account,
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def execute(
        self,
        plan: ActionPlan,
        auto_approve_low_risk: bool = True,
    ) -> ExecutionResult:
        """Execute an action plan.

        Args:
            plan: Plan to execute
            auto_approve_low_risk: Auto-approve low-risk actions

        Returns:
            Execution result
        """
        self.logger.info(
            "executing_plan",
            plan_id=plan.plan_id,
            action_count=len(plan.actions),
        )

        result = ExecutionResult(
            plan_id=plan.plan_id,
            total_actions=len(plan.actions),
        )
        self._execution_results[result.execution_id] = result

        # Build dependency graph
        action_map = {a.action_id: a for a in plan.actions}
        completed = set()

        # Process actions respecting dependencies
        while len(completed) < len(plan.actions):
            # Find actions ready to execute
            ready = []
            for action in plan.actions:
                if action.action_id in completed:
                    continue
                if all(dep in completed for dep in action.depends_on):
                    ready.append(action)

            if not ready:
                # No more actions can execute
                self.logger.warning("no_executable_actions", completed=len(completed))
                break

            # Execute ready actions (with parallelism limit)
            batch_results = await self._execute_batch(
                ready[:self.max_parallel],
                auto_approve_low_risk,
            )

            for action_result in batch_results:
                result.action_results.append(action_result)
                completed.add(action_result.action_id)

                if action_result.success:
                    result.succeeded += 1
                elif action_result.status == ExecutionStatus.SKIPPED:
                    result.skipped += 1
                elif action_result.status == ExecutionStatus.WAITING_APPROVAL:
                    result.pending_approval += 1
                else:
                    result.failed += 1

        # Finalize
        result.completed_at = datetime.utcnow()
        result.duration_ms = int(
            (result.completed_at - result.started_at).total_seconds() * 1000
        )
        result.status = "completed" if result.failed == 0 else "completed_with_errors"

        self.logger.info(
            "plan_execution_complete",
            execution_id=result.execution_id,
            succeeded=result.succeeded,
            failed=result.failed,
        )

        return result

    async def _execute_batch(
        self,
        actions: list[PlannedAction],
        auto_approve_low_risk: bool,
    ) -> list[ActionResult]:
        """Execute a batch of actions."""
        tasks = []
        for action in actions:
            tasks.append(
                self._execute_action(action, auto_approve_low_risk)
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        action_results = []
        for action, result in zip(actions, results):
            if isinstance(result, Exception):
                action_results.append(
                    ActionResult(
                        action_id=action.action_id,
                        status=ExecutionStatus.FAILED,
                        success=False,
                        error=str(result),
                    )
                )
            else:
                action_results.append(result)

        return action_results

    async def _execute_action(
        self,
        action: PlannedAction,
        auto_approve_low_risk: bool,
    ) -> ActionResult:
        """Execute a single action."""
        result = ActionResult(
            action_id=action.action_id,
            status=ExecutionStatus.PENDING,
            started_at=datetime.utcnow(),
        )

        # Check if approval needed
        if action.requires_approval:
            if auto_approve_low_risk and action.risk_level in [RiskLevel.NONE, RiskLevel.LOW]:
                # Auto-approve
                pass
            elif action.action_id in self._approvals:
                if not self._approvals[action.action_id]:
                    result.status = ExecutionStatus.REJECTED
                    result.success = False
                    result.error = "Action was rejected"
                    return result
            else:
                # Needs approval
                result.status = ExecutionStatus.WAITING_APPROVAL
                return result

        # Get handler
        handler = self._action_handlers.get(action.action_type)
        if not handler:
            result.status = ExecutionStatus.FAILED
            result.error = f"No handler for action type: {action.action_type}"
            return result

        # Execute with retry
        result.status = ExecutionStatus.IN_PROGRESS
        last_error = None

        for attempt in range(self.retry_count + 1):
            try:
                output = await handler(action)
                result.status = ExecutionStatus.SUCCEEDED
                result.success = True
                result.output = output
                break

            except Exception as e:
                last_error = str(e)
                self.logger.warning(
                    "action_attempt_failed",
                    action_id=action.action_id,
                    attempt=attempt + 1,
                    error=last_error,
                )
                if attempt < self.retry_count:
                    await asyncio.sleep(self.retry_delay_seconds)

        if not result.success:
            result.status = ExecutionStatus.FAILED
            result.error = last_error

        result.completed_at = datetime.utcnow()
        result.duration_ms = int(
            (result.completed_at - result.started_at).total_seconds() * 1000
        )

        return result

    def approve_action(self, action_id: str, approved: bool = True) -> None:
        """Approve or reject an action.

        Args:
            action_id: Action to approve/reject
            approved: Whether to approve
        """
        self._approvals[action_id] = approved
        self.logger.info(
            "action_approval_set",
            action_id=action_id,
            approved=approved,
        )

    async def rollback_action(
        self,
        action: PlannedAction,
        action_result: ActionResult,
    ) -> ActionResult:
        """Rollback a previously executed action.

        Args:
            action: Original action
            action_result: Result of original execution

        Returns:
            Rollback result
        """
        if not action.rollback_action:
            return ActionResult(
                action_id=f"rollback-{action.action_id}",
                status=ExecutionStatus.SKIPPED,
                error="No rollback action defined",
            )

        try:
            rollback_type = ActionType(action.rollback_action)
            rollback_action = PlannedAction(
                action_id=f"rollback-{action.action_id}",
                action_type=rollback_type,
                target=action.target,
                target_type=action.target_type,
                parameters=action.parameters,
                risk_level=RiskLevel.MEDIUM,
                requires_approval=False,
            )

            result = await self._execute_action(rollback_action, auto_approve_low_risk=True)
            result.rolled_back = True
            return result

        except Exception as e:
            return ActionResult(
                action_id=f"rollback-{action.action_id}",
                status=ExecutionStatus.FAILED,
                error=str(e),
            )

    def get_execution_status(self, execution_id: str) -> ExecutionResult | None:
        """Get execution status by ID."""
        return self._execution_results.get(execution_id)

    # Action handlers

    async def _execute_block_ip(self, action: PlannedAction) -> dict[str, Any]:
        """Execute block IP action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/block-ip",
            json={
                "ip": action.target,
                **action.parameters,
            },
        )
        response.raise_for_status()
        return {"action": "block_ip", "target": action.target, "response": response.json()}

    async def _execute_block_domain(self, action: PlannedAction) -> dict[str, Any]:
        """Execute block domain action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/block-domain",
            json={
                "domain": action.target,
                **action.parameters,
            },
        )
        response.raise_for_status()
        return {"action": "block_domain", "target": action.target}

    async def _execute_isolate_host(self, action: PlannedAction) -> dict[str, Any]:
        """Execute isolate host action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/isolate-host",
            json={
                "hostname": action.target,
                **action.parameters,
            },
        )
        response.raise_for_status()
        return {"action": "isolate_host", "target": action.target}

    async def _execute_disable_account(self, action: PlannedAction) -> dict[str, Any]:
        """Execute disable account action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/disable-account",
            json={
                "username": action.target,
                **action.parameters,
            },
        )
        response.raise_for_status()
        return {"action": "disable_account", "target": action.target}

    async def _execute_terminate_session(self, action: PlannedAction) -> dict[str, Any]:
        """Execute terminate session action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/terminate-session",
            json={
                "session_id": action.parameters.get("session_id"),
                "username": action.target,
            },
        )
        response.raise_for_status()
        return {"action": "terminate_session", "target": action.target}

    async def _execute_quarantine_file(self, action: PlannedAction) -> dict[str, Any]:
        """Execute quarantine file action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/quarantine-file",
            json={
                "file_path": action.target,
                "hostname": action.parameters.get("hostname"),
            },
        )
        response.raise_for_status()
        return {"action": "quarantine_file", "target": action.target}

    async def _execute_kill_process(self, action: PlannedAction) -> dict[str, Any]:
        """Execute kill process action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/kill-process",
            json={
                "process_id": action.parameters.get("pid"),
                "hostname": action.target,
            },
        )
        response.raise_for_status()
        return {"action": "kill_process", "target": action.target}

    async def _execute_notify_team(self, action: PlannedAction) -> dict[str, Any]:
        """Execute notify team action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/notifications",
            json={
                "channel": action.target,
                "message": action.parameters.get("message"),
                "severity": action.parameters.get("severity", "info"),
            },
        )
        response.raise_for_status()
        return {"action": "notify_team", "target": action.target}

    async def _execute_create_ticket(self, action: PlannedAction) -> dict[str, Any]:
        """Execute create ticket action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/tickets",
            json={
                "type": "incident",
                "severity": action.parameters.get("severity"),
                "title": action.parameters.get("title", "Security Incident"),
                "description": action.parameters.get("description", ""),
            },
        )
        response.raise_for_status()
        return {"action": "create_ticket", "ticket_id": response.json().get("ticket_id")}

    async def _execute_escalate(self, action: PlannedAction) -> dict[str, Any]:
        """Execute escalation action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/escalate",
            json={
                "level": action.parameters.get("level", "management"),
                "target": action.target,
            },
        )
        response.raise_for_status()
        return {"action": "escalate", "target": action.target}

    async def _execute_playbook(self, action: PlannedAction) -> dict[str, Any]:
        """Execute playbook action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/playbooks/{action.target}/execute",
            json={"context": action.parameters},
        )
        response.raise_for_status()
        return {"action": "execute_playbook", "playbook_id": action.target}

    async def _execute_capture_memory(self, action: PlannedAction) -> dict[str, Any]:
        """Execute memory capture action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/forensics/memory-capture",
            json={"hostname": action.target},
        )
        response.raise_for_status()
        return {"action": "capture_memory", "target": action.target}

    async def _execute_snapshot_disk(self, action: PlannedAction) -> dict[str, Any]:
        """Execute disk snapshot action."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/forensics/disk-snapshot",
            json={"hostname": action.target},
        )
        response.raise_for_status()
        return {"action": "snapshot_disk", "target": action.target}

    async def _execute_unblock_ip(self, action: PlannedAction) -> dict[str, Any]:
        """Execute unblock IP action (rollback)."""
        client = await self._get_client()
        response = await client.delete(
            f"{self.soar_endpoint}/blocklist/ip/{action.target}"
        )
        response.raise_for_status()
        return {"action": "unblock_ip", "target": action.target}

    async def _execute_unisolate_host(self, action: PlannedAction) -> dict[str, Any]:
        """Execute unisolate host action (rollback)."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/unisolate-host",
            json={"hostname": action.target},
        )
        response.raise_for_status()
        return {"action": "unisolate_host", "target": action.target}

    async def _execute_enable_account(self, action: PlannedAction) -> dict[str, Any]:
        """Execute enable account action (rollback)."""
        client = await self._get_client()
        response = await client.post(
            f"{self.soar_endpoint}/actions/enable-account",
            json={"username": action.target},
        )
        response.raise_for_status()
        return {"action": "enable_account", "target": action.target}
