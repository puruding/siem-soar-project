"""Rollback Manager - Undo mechanisms for automated actions."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RollbackStatus(str, Enum):
    """Status of a rollback operation."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ActionSnapshot(BaseModel):
    """Snapshot of state before an action."""

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    action_id: str = Field(description="ID of the action")
    action_type: str = Field(description="Type of action")
    target: str = Field(description="Target of the action")

    # State before action
    previous_state: dict[str, Any] = Field(default_factory=dict)

    # Action details
    action_params: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = Field(default="system")
    expires_at: datetime | None = Field(default=None)

    # Rollback info
    rollback_command: str | None = Field(default=None)
    is_reversible: bool = Field(default=True)


class RollbackAction(BaseModel):
    """A rollback action to undo a previous action."""

    rollback_id: str = Field(default_factory=lambda: str(uuid4()))
    snapshot_id: str = Field(description="Associated snapshot")
    action_id: str = Field(description="Original action ID")

    # Execution
    status: RollbackStatus = Field(default=RollbackStatus.PENDING)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)

    # Result
    success: bool = Field(default=False)
    error: str | None = Field(default=None)
    restored_state: dict[str, Any] | None = Field(default=None)


class RollbackResult(BaseModel):
    """Result of a rollback operation."""

    rollback_id: str
    action_id: str
    success: bool
    partial: bool = Field(default=False)
    restored_count: int = Field(default=0)
    failed_count: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = Field(default=0.0)


class RollbackManager(LoggerMixin):
    """Manager for rolling back automated actions.

    Features:
    - State snapshots before actions
    - Automatic rollback execution
    - Partial rollback support
    - Rollback verification
    - Expiration handling
    """

    def __init__(
        self,
        snapshot_retention_hours: int = 24,
        max_rollback_retries: int = 3,
    ) -> None:
        """Initialize rollback manager.

        Args:
            snapshot_retention_hours: Hours to retain snapshots
            max_rollback_retries: Max retry attempts for rollback
        """
        self.snapshot_retention_hours = snapshot_retention_hours
        self.max_rollback_retries = max_rollback_retries

        self._snapshots: dict[str, ActionSnapshot] = {}
        self._rollbacks: dict[str, RollbackAction] = {}
        self._rollback_handlers: dict[str, Callable] = {}

        # Register built-in handlers
        self._register_builtin_handlers()

    def _register_builtin_handlers(self) -> None:
        """Register built-in rollback handlers."""
        self._rollback_handlers = {
            "isolate_host": self._rollback_isolate_host,
            "disable_account": self._rollback_disable_account,
            "block_ip": self._rollback_block_ip,
            "quarantine_file": self._rollback_quarantine_file,
            "kill_process": self._rollback_kill_process,
        }

    def register_handler(
        self,
        action_type: str,
        handler: Callable,
    ) -> None:
        """Register a rollback handler for an action type.

        Args:
            action_type: Type of action
            handler: Async function to execute rollback
        """
        self._rollback_handlers[action_type] = handler
        self.logger.info("rollback_handler_registered", action_type=action_type)

    def create_snapshot(
        self,
        action_id: str,
        action_type: str,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any] | None = None,
        is_reversible: bool = True,
        created_by: str = "system",
    ) -> ActionSnapshot:
        """Create a snapshot before executing an action.

        Args:
            action_id: ID of the action
            action_type: Type of action
            target: Target entity
            previous_state: State before action
            action_params: Action parameters
            is_reversible: Whether action can be reversed
            created_by: Creator of the snapshot

        Returns:
            Created snapshot
        """
        snapshot = ActionSnapshot(
            action_id=action_id,
            action_type=action_type,
            target=target,
            previous_state=previous_state,
            action_params=action_params or {},
            created_by=created_by,
            is_reversible=is_reversible,
            rollback_command=self._generate_rollback_command(action_type, target, previous_state),
        )

        self._snapshots[snapshot.snapshot_id] = snapshot

        # Store by action_id for easy lookup
        self._snapshots[f"action:{action_id}"] = snapshot

        self.logger.info(
            "snapshot_created",
            snapshot_id=snapshot.snapshot_id,
            action_id=action_id,
            action_type=action_type,
        )

        return snapshot

    async def rollback(
        self,
        action_id: str,
        reason: str = "Rollback requested",
    ) -> RollbackResult:
        """Roll back an action.

        Args:
            action_id: Action to roll back
            reason: Reason for rollback

        Returns:
            Rollback result
        """
        # Find snapshot
        snapshot = self._snapshots.get(f"action:{action_id}")
        if not snapshot:
            return RollbackResult(
                rollback_id=str(uuid4()),
                action_id=action_id,
                success=False,
                errors=[f"No snapshot found for action: {action_id}"],
            )

        if not snapshot.is_reversible:
            return RollbackResult(
                rollback_id=str(uuid4()),
                action_id=action_id,
                success=False,
                errors=["Action is not reversible"],
            )

        # Create rollback action
        rollback_action = RollbackAction(
            snapshot_id=snapshot.snapshot_id,
            action_id=action_id,
            status=RollbackStatus.IN_PROGRESS,
            started_at=datetime.utcnow(),
        )
        self._rollbacks[rollback_action.rollback_id] = rollback_action

        self.logger.info(
            "rollback_started",
            rollback_id=rollback_action.rollback_id,
            action_id=action_id,
            reason=reason,
        )

        start_time = datetime.utcnow()

        try:
            # Get handler
            handler = self._rollback_handlers.get(snapshot.action_type)
            if not handler:
                raise ValueError(f"No rollback handler for: {snapshot.action_type}")

            # Execute rollback with retries
            success = False
            errors = []

            for attempt in range(self.max_rollback_retries):
                try:
                    restored_state = await handler(
                        snapshot.target,
                        snapshot.previous_state,
                        snapshot.action_params,
                    )
                    success = True
                    rollback_action.restored_state = restored_state
                    break
                except Exception as e:
                    errors.append(f"Attempt {attempt + 1}: {str(e)}")
                    if attempt < self.max_rollback_retries - 1:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff

            rollback_action.success = success
            rollback_action.status = RollbackStatus.COMPLETED if success else RollbackStatus.FAILED
            rollback_action.completed_at = datetime.utcnow()

            if not success:
                rollback_action.error = "; ".join(errors)

            duration = (datetime.utcnow() - start_time).total_seconds()

            result = RollbackResult(
                rollback_id=rollback_action.rollback_id,
                action_id=action_id,
                success=success,
                restored_count=1 if success else 0,
                failed_count=0 if success else 1,
                errors=errors,
                duration_seconds=duration,
            )

            self.logger.info(
                "rollback_completed",
                rollback_id=rollback_action.rollback_id,
                success=success,
                duration=duration,
            )

            return result

        except Exception as e:
            rollback_action.status = RollbackStatus.FAILED
            rollback_action.error = str(e)
            rollback_action.completed_at = datetime.utcnow()

            self.logger.error(
                "rollback_failed",
                rollback_id=rollback_action.rollback_id,
                error=str(e),
            )

            return RollbackResult(
                rollback_id=rollback_action.rollback_id,
                action_id=action_id,
                success=False,
                errors=[str(e)],
            )

    async def rollback_batch(
        self,
        action_ids: list[str],
        reason: str = "Batch rollback",
    ) -> list[RollbackResult]:
        """Roll back multiple actions.

        Args:
            action_ids: Actions to roll back
            reason: Reason for rollback

        Returns:
            List of rollback results
        """
        self.logger.info(
            "batch_rollback_started",
            count=len(action_ids),
            reason=reason,
        )

        # Execute rollbacks in parallel
        tasks = [self.rollback(action_id, reason) for action_id in action_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        processed = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed.append(RollbackResult(
                    rollback_id=str(uuid4()),
                    action_id=action_ids[i],
                    success=False,
                    errors=[str(result)],
                ))
            else:
                processed.append(result)

        success_count = sum(1 for r in processed if r.success)
        self.logger.info(
            "batch_rollback_completed",
            total=len(action_ids),
            success=success_count,
            failed=len(action_ids) - success_count,
        )

        return processed

    def _generate_rollback_command(
        self,
        action_type: str,
        target: str,
        previous_state: dict[str, Any],
    ) -> str:
        """Generate a rollback command description."""
        commands = {
            "isolate_host": f"Reconnect host {target} to network",
            "disable_account": f"Re-enable account {target}",
            "block_ip": f"Unblock IP {target}",
            "quarantine_file": f"Restore file {target} from quarantine",
            "kill_process": f"No automatic restore for process {target}",
        }
        return commands.get(action_type, f"Restore {target} to previous state")

    # Built-in rollback handlers
    async def _rollback_isolate_host(
        self,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Rollback host isolation."""
        self.logger.info("rollback_isolate_host", target=target)

        # In a real implementation, this would:
        # 1. Reconnect the host to the network
        # 2. Restore firewall rules
        # 3. Re-enable network interfaces

        return {
            "status": "connected",
            "network_restored": True,
            "restored_at": datetime.utcnow().isoformat(),
        }

    async def _rollback_disable_account(
        self,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Rollback account disable."""
        self.logger.info("rollback_disable_account", target=target)

        # In a real implementation, this would:
        # 1. Re-enable the account in AD/LDAP
        # 2. Restore group memberships if removed
        # 3. Notify the user

        return {
            "status": "enabled",
            "account_restored": True,
            "restored_at": datetime.utcnow().isoformat(),
        }

    async def _rollback_block_ip(
        self,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Rollback IP block."""
        self.logger.info("rollback_block_ip", target=target)

        # In a real implementation, this would:
        # 1. Remove firewall block rules
        # 2. Update threat intel to remove indicator
        # 3. Clear any related blocks

        return {
            "status": "unblocked",
            "firewall_updated": True,
            "restored_at": datetime.utcnow().isoformat(),
        }

    async def _rollback_quarantine_file(
        self,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Rollback file quarantine."""
        self.logger.info("rollback_quarantine_file", target=target)

        original_path = previous_state.get("original_path", target)

        # In a real implementation, this would:
        # 1. Restore file from quarantine
        # 2. Verify file integrity
        # 3. Update AV exception if needed

        return {
            "status": "restored",
            "original_path": original_path,
            "restored_at": datetime.utcnow().isoformat(),
        }

    async def _rollback_kill_process(
        self,
        target: str,
        previous_state: dict[str, Any],
        action_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Rollback process kill (limited - process restart)."""
        self.logger.info("rollback_kill_process", target=target)

        # Process kills cannot be truly reversed
        # Best effort: restart the service if it was a service

        service_name = previous_state.get("service_name")
        if service_name:
            # In a real implementation, restart the service
            return {
                "status": "restarted",
                "service_name": service_name,
                "restored_at": datetime.utcnow().isoformat(),
            }

        return {
            "status": "not_restorable",
            "reason": "Process cannot be automatically restarted",
            "timestamp": datetime.utcnow().isoformat(),
        }

    def get_snapshot(self, action_id: str) -> ActionSnapshot | None:
        """Get snapshot for an action."""
        return self._snapshots.get(f"action:{action_id}")

    def get_rollback(self, rollback_id: str) -> RollbackAction | None:
        """Get rollback action by ID."""
        return self._rollbacks.get(rollback_id)

    def get_rollbacks_for_action(self, action_id: str) -> list[RollbackAction]:
        """Get all rollbacks for an action."""
        return [r for r in self._rollbacks.values() if r.action_id == action_id]

    def cleanup_expired(self) -> int:
        """Clean up expired snapshots.

        Returns:
            Number of snapshots cleaned up
        """
        now = datetime.utcnow()
        expired = []

        for snapshot_id, snapshot in self._snapshots.items():
            if snapshot.expires_at and now > snapshot.expires_at:
                expired.append(snapshot_id)

        for snapshot_id in expired:
            del self._snapshots[snapshot_id]

        if expired:
            self.logger.info("expired_snapshots_cleaned", count=len(expired))

        return len(expired)

    def get_stats(self) -> dict[str, Any]:
        """Get rollback manager statistics."""
        rollbacks = list(self._rollbacks.values())

        return {
            "snapshots_count": len([k for k in self._snapshots.keys() if not k.startswith("action:")]),
            "rollbacks_total": len(rollbacks),
            "rollbacks_success": len([r for r in rollbacks if r.success]),
            "rollbacks_failed": len([r for r in rollbacks if r.status == RollbackStatus.FAILED]),
            "rollbacks_pending": len([r for r in rollbacks if r.status == RollbackStatus.PENDING]),
        }
