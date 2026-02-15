"""Self Healer - System health monitoring and automatic recovery."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class HealthStatus(str, Enum):
    """System health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class IssueType(str, Enum):
    """Types of health issues."""

    PERFORMANCE = "performance"
    AVAILABILITY = "availability"
    ERROR_RATE = "error_rate"
    RESOURCE = "resource"
    CONNECTIVITY = "connectivity"
    CONFIGURATION = "configuration"
    SECURITY = "security"


class HealthCheck(BaseModel):
    """A health check definition."""

    check_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(description="Check name")
    component: str = Field(description="Component being checked")
    check_type: str = Field(description="Type of check")
    interval_seconds: int = Field(default=60)
    timeout_seconds: int = Field(default=30)
    enabled: bool = Field(default=True)

    # Thresholds
    warning_threshold: float | None = Field(default=None)
    critical_threshold: float | None = Field(default=None)


class HealthIssue(BaseModel):
    """A detected health issue."""

    issue_id: str = Field(default_factory=lambda: str(uuid4()))
    check_id: str = Field(description="Check that detected the issue")
    component: str = Field(description="Affected component")
    issue_type: IssueType = Field(description="Type of issue")

    severity: HealthStatus = Field(default=HealthStatus.DEGRADED)
    description: str = Field(description="Issue description")
    details: dict[str, Any] = Field(default_factory=dict)

    detected_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: datetime | None = Field(default=None)
    is_resolved: bool = Field(default=False)

    # Recovery tracking
    recovery_attempts: int = Field(default=0)
    last_recovery_attempt: datetime | None = Field(default=None)


class RecoveryAction(BaseModel):
    """An automatic recovery action."""

    action_id: str = Field(default_factory=lambda: str(uuid4()))
    issue_id: str = Field(description="Issue being addressed")
    action_type: str = Field(description="Type of recovery action")
    component: str = Field(description="Target component")

    # Execution
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = Field(default=None)
    success: bool = Field(default=False)
    error: str | None = Field(default=None)

    # Result
    result: dict[str, Any] | None = Field(default=None)


class SystemHealth(BaseModel):
    """Overall system health status."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    overall_status: HealthStatus = Field(default=HealthStatus.UNKNOWN)

    # Component statuses
    component_statuses: dict[str, HealthStatus] = Field(default_factory=dict)

    # Issues
    active_issues: list[HealthIssue] = Field(default_factory=list)
    resolved_issues_24h: int = Field(default=0)

    # Metrics
    uptime_seconds: float = Field(default=0.0)
    last_incident: datetime | None = Field(default=None)


class SelfHealer(LoggerMixin):
    """Self-healing system for monitoring and automatic recovery.

    Features:
    - Health check execution
    - Issue detection
    - Automatic recovery actions
    - Escalation handling
    - Recovery verification
    """

    def __init__(
        self,
        max_recovery_attempts: int = 3,
        recovery_cooldown_seconds: int = 300,
        escalation_threshold: int = 2,
    ) -> None:
        """Initialize self healer.

        Args:
            max_recovery_attempts: Max attempts per issue
            recovery_cooldown_seconds: Cooldown between attempts
            escalation_threshold: Attempts before escalation
        """
        self.max_recovery_attempts = max_recovery_attempts
        self.recovery_cooldown_seconds = recovery_cooldown_seconds
        self.escalation_threshold = escalation_threshold

        self._health_checks: dict[str, HealthCheck] = {}
        self._active_issues: dict[str, HealthIssue] = {}
        self._recovery_history: list[RecoveryAction] = []
        self._check_results: dict[str, dict[str, Any]] = {}
        self._recovery_handlers: dict[str, Callable] = {}
        self._start_time = datetime.utcnow()

        # Register built-in handlers
        self._register_builtin_handlers()

    def _register_builtin_handlers(self) -> None:
        """Register built-in recovery handlers."""
        self._recovery_handlers = {
            "restart_service": self._recovery_restart_service,
            "clear_cache": self._recovery_clear_cache,
            "reset_connection": self._recovery_reset_connection,
            "scale_resources": self._recovery_scale_resources,
            "reload_config": self._recovery_reload_config,
        }

    def register_check(self, check: HealthCheck) -> None:
        """Register a health check.

        Args:
            check: Health check to register
        """
        self._health_checks[check.check_id] = check
        self.logger.info(
            "health_check_registered",
            check_id=check.check_id,
            name=check.name,
        )

    def register_recovery_handler(
        self,
        action_type: str,
        handler: Callable,
    ) -> None:
        """Register a recovery handler.

        Args:
            action_type: Type of recovery action
            handler: Async handler function
        """
        self._recovery_handlers[action_type] = handler
        self.logger.info("recovery_handler_registered", action_type=action_type)

    async def run_checks(self) -> SystemHealth:
        """Run all enabled health checks.

        Returns:
            System health status
        """
        self.logger.info("running_health_checks")

        component_statuses = {}
        issues_detected = []

        for check in self._health_checks.values():
            if not check.enabled:
                continue

            try:
                result = await self._execute_check(check)
                self._check_results[check.check_id] = result

                status = self._evaluate_check_result(check, result)
                component_statuses[check.component] = status

                if status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
                    issue = self._create_issue(check, result, status)
                    issues_detected.append(issue)

            except Exception as e:
                self.logger.error(
                    "health_check_failed",
                    check_id=check.check_id,
                    error=str(e),
                )
                component_statuses[check.component] = HealthStatus.UNKNOWN

        # Update active issues
        for issue in issues_detected:
            self._active_issues[issue.issue_id] = issue

        # Determine overall status
        overall = self._determine_overall_status(component_statuses)

        health = SystemHealth(
            overall_status=overall,
            component_statuses=component_statuses,
            active_issues=list(self._active_issues.values()),
            resolved_issues_24h=self._count_resolved_24h(),
            uptime_seconds=(datetime.utcnow() - self._start_time).total_seconds(),
            last_incident=self._get_last_incident_time(),
        )

        self.logger.info(
            "health_checks_completed",
            overall=overall.value,
            issues=len(issues_detected),
        )

        return health

    async def _execute_check(self, check: HealthCheck) -> dict[str, Any]:
        """Execute a single health check."""
        # This would be implemented based on check type
        # For now, return simulated results
        return {
            "status": "ok",
            "latency_ms": 50,
            "error_rate": 0.01,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _evaluate_check_result(
        self,
        check: HealthCheck,
        result: dict[str, Any],
    ) -> HealthStatus:
        """Evaluate check result against thresholds."""
        # Check for errors
        if result.get("status") == "error":
            return HealthStatus.UNHEALTHY

        # Check critical threshold
        if check.critical_threshold is not None:
            metric = result.get("error_rate", 0)
            if metric >= check.critical_threshold:
                return HealthStatus.CRITICAL

        # Check warning threshold
        if check.warning_threshold is not None:
            metric = result.get("error_rate", 0)
            if metric >= check.warning_threshold:
                return HealthStatus.DEGRADED

        return HealthStatus.HEALTHY

    def _create_issue(
        self,
        check: HealthCheck,
        result: dict[str, Any],
        severity: HealthStatus,
    ) -> HealthIssue:
        """Create a health issue from check result."""
        issue_type = self._determine_issue_type(check, result)

        return HealthIssue(
            check_id=check.check_id,
            component=check.component,
            issue_type=issue_type,
            severity=severity,
            description=f"{check.name} check failed",
            details=result,
        )

    def _determine_issue_type(
        self,
        check: HealthCheck,
        result: dict[str, Any],
    ) -> IssueType:
        """Determine issue type from check and result."""
        if "latency" in check.check_type.lower():
            return IssueType.PERFORMANCE
        if "error" in check.check_type.lower():
            return IssueType.ERROR_RATE
        if "connect" in check.check_type.lower():
            return IssueType.CONNECTIVITY
        if "resource" in check.check_type.lower():
            return IssueType.RESOURCE
        return IssueType.AVAILABILITY

    def _determine_overall_status(
        self,
        component_statuses: dict[str, HealthStatus],
    ) -> HealthStatus:
        """Determine overall system status."""
        if not component_statuses:
            return HealthStatus.UNKNOWN

        statuses = list(component_statuses.values())

        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        if all(s == HealthStatus.HEALTHY for s in statuses):
            return HealthStatus.HEALTHY

        return HealthStatus.DEGRADED

    async def attempt_recovery(self, issue_id: str) -> RecoveryAction | None:
        """Attempt automatic recovery for an issue.

        Args:
            issue_id: Issue to recover

        Returns:
            Recovery action result or None
        """
        issue = self._active_issues.get(issue_id)
        if not issue:
            return None

        # Check if recovery should be attempted
        if not self._should_attempt_recovery(issue):
            return None

        # Determine recovery action
        action_type = self._determine_recovery_action(issue)
        if not action_type:
            return None

        # Execute recovery
        action = RecoveryAction(
            issue_id=issue_id,
            action_type=action_type,
            component=issue.component,
        )

        self.logger.info(
            "attempting_recovery",
            issue_id=issue_id,
            action_type=action_type,
        )

        try:
            handler = self._recovery_handlers.get(action_type)
            if not handler:
                raise ValueError(f"No handler for: {action_type}")

            result = await handler(issue.component, issue.details)
            action.success = True
            action.result = result
            action.completed_at = datetime.utcnow()

            # Update issue
            issue.recovery_attempts += 1
            issue.last_recovery_attempt = datetime.utcnow()

            # Verify recovery
            await asyncio.sleep(5)  # Wait for recovery to take effect
            if await self._verify_recovery(issue):
                issue.is_resolved = True
                issue.resolved_at = datetime.utcnow()
                del self._active_issues[issue_id]

            self.logger.info(
                "recovery_succeeded",
                issue_id=issue_id,
                resolved=issue.is_resolved,
            )

        except Exception as e:
            action.success = False
            action.error = str(e)
            action.completed_at = datetime.utcnow()

            issue.recovery_attempts += 1
            issue.last_recovery_attempt = datetime.utcnow()

            self.logger.error(
                "recovery_failed",
                issue_id=issue_id,
                error=str(e),
            )

            # Check for escalation
            if issue.recovery_attempts >= self.escalation_threshold:
                self._escalate_issue(issue)

        self._recovery_history.append(action)
        return action

    def _should_attempt_recovery(self, issue: HealthIssue) -> bool:
        """Check if recovery should be attempted."""
        # Max attempts check
        if issue.recovery_attempts >= self.max_recovery_attempts:
            return False

        # Cooldown check
        if issue.last_recovery_attempt:
            cooldown_end = issue.last_recovery_attempt + timedelta(
                seconds=self.recovery_cooldown_seconds
            )
            if datetime.utcnow() < cooldown_end:
                return False

        return True

    def _determine_recovery_action(self, issue: HealthIssue) -> str | None:
        """Determine appropriate recovery action for an issue."""
        action_mapping = {
            IssueType.PERFORMANCE: "scale_resources",
            IssueType.AVAILABILITY: "restart_service",
            IssueType.ERROR_RATE: "restart_service",
            IssueType.RESOURCE: "clear_cache",
            IssueType.CONNECTIVITY: "reset_connection",
            IssueType.CONFIGURATION: "reload_config",
        }
        return action_mapping.get(issue.issue_type)

    async def _verify_recovery(self, issue: HealthIssue) -> bool:
        """Verify that recovery was successful."""
        check = self._health_checks.get(issue.check_id)
        if not check:
            return False

        try:
            result = await self._execute_check(check)
            status = self._evaluate_check_result(check, result)
            return status == HealthStatus.HEALTHY
        except Exception:
            return False

    def _escalate_issue(self, issue: HealthIssue) -> None:
        """Escalate an issue that couldn't be auto-recovered."""
        self.logger.warning(
            "issue_escalated",
            issue_id=issue.issue_id,
            component=issue.component,
            attempts=issue.recovery_attempts,
        )
        # In a real system, this would trigger alerts, pages, etc.

    # Built-in recovery handlers
    async def _recovery_restart_service(
        self,
        component: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Restart a service."""
        self.logger.info("restarting_service", component=component)
        # Simulated restart
        await asyncio.sleep(2)
        return {
            "action": "restart",
            "component": component,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _recovery_clear_cache(
        self,
        component: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Clear component cache."""
        self.logger.info("clearing_cache", component=component)
        await asyncio.sleep(1)
        return {
            "action": "clear_cache",
            "component": component,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _recovery_reset_connection(
        self,
        component: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Reset connections."""
        self.logger.info("resetting_connections", component=component)
        await asyncio.sleep(1)
        return {
            "action": "reset_connection",
            "component": component,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _recovery_scale_resources(
        self,
        component: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Scale resources."""
        self.logger.info("scaling_resources", component=component)
        await asyncio.sleep(2)
        return {
            "action": "scale",
            "component": component,
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def _recovery_reload_config(
        self,
        component: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        """Reload configuration."""
        self.logger.info("reloading_config", component=component)
        await asyncio.sleep(1)
        return {
            "action": "reload_config",
            "component": component,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _count_resolved_24h(self) -> int:
        """Count issues resolved in last 24 hours."""
        cutoff = datetime.utcnow() - timedelta(hours=24)
        return len([
            a for a in self._recovery_history
            if a.success and a.completed_at and a.completed_at > cutoff
        ])

    def _get_last_incident_time(self) -> datetime | None:
        """Get time of last incident."""
        if not self._active_issues:
            return None
        return max(i.detected_at for i in self._active_issues.values())

    def get_issue(self, issue_id: str) -> HealthIssue | None:
        """Get an issue by ID."""
        return self._active_issues.get(issue_id)

    def get_active_issues(self) -> list[HealthIssue]:
        """Get all active issues."""
        return list(self._active_issues.values())

    def get_recovery_history(
        self,
        component: str | None = None,
        limit: int = 100,
    ) -> list[RecoveryAction]:
        """Get recovery history."""
        history = self._recovery_history

        if component:
            history = [a for a in history if a.component == component]

        return history[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get self-healer statistics."""
        history = self._recovery_history

        return {
            "active_issues": len(self._active_issues),
            "registered_checks": len(self._health_checks),
            "recovery_attempts_total": len(history),
            "recovery_success_count": len([a for a in history if a.success]),
            "recovery_failure_count": len([a for a in history if not a.success]),
            "uptime_seconds": (datetime.utcnow() - self._start_time).total_seconds(),
        }
