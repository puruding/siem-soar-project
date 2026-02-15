"""Response Validator - Validate action results and response effectiveness."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .action_executor import ActionResult, ExecutionResult, ExecutionStatus
from .action_planner import ActionPlan, ActionType, PlannedAction


class ValidationStatus(str, Enum):
    """Status of validation."""

    PENDING = "pending"
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class ValidationCheck(BaseModel):
    """A single validation check."""

    check_id: str = Field(default_factory=lambda: str(uuid4()))
    check_type: str = Field(description="Type of check")
    target: str = Field(description="Target being validated")

    # Result
    status: ValidationStatus = Field(default=ValidationStatus.PENDING)
    passed: bool = Field(default=False)

    # Details
    expected: str | None = Field(default=None)
    actual: str | None = Field(default=None)
    message: str | None = Field(default=None)

    # Timing
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class ValidationResult(BaseModel):
    """Complete validation result."""

    validation_id: str = Field(default_factory=lambda: str(uuid4()))
    execution_id: str = Field(description="Execution being validated")

    # Checks
    checks: list[ValidationCheck] = Field(default_factory=list)
    total_checks: int = Field(default=0)
    passed_checks: int = Field(default=0)
    failed_checks: int = Field(default=0)

    # Overall result
    overall_status: ValidationStatus = Field(default=ValidationStatus.PENDING)
    effectiveness_score: float = Field(default=0.0, ge=0, le=1)

    # Recommendations
    remediation_needed: list[str] = Field(default_factory=list)
    follow_up_actions: list[str] = Field(default_factory=list)

    # Timing
    validated_at: datetime = Field(default_factory=datetime.utcnow)
    summary: str = Field(default="")


class ResponseValidator(LoggerMixin):
    """Validator for response actions and overall effectiveness.

    Features:
    - Individual action validation
    - State verification
    - Effectiveness scoring
    - Remediation recommendations
    """

    def __init__(
        self,
        soar_endpoint: str = "http://localhost:8001/api/v1",
        siem_endpoint: str = "http://localhost:8000/api/v1",
    ) -> None:
        """Initialize validator.

        Args:
            soar_endpoint: SOAR API endpoint
            siem_endpoint: SIEM API endpoint
        """
        self.soar_endpoint = soar_endpoint
        self.siem_endpoint = siem_endpoint
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

    async def validate(
        self,
        plan: ActionPlan,
        execution_result: ExecutionResult,
    ) -> ValidationResult:
        """Validate execution results.

        Args:
            plan: Original action plan
            execution_result: Execution results

        Returns:
            Validation result
        """
        self.logger.info(
            "validating_execution",
            execution_id=execution_result.execution_id,
        )

        result = ValidationResult(execution_id=execution_result.execution_id)
        checks = []

        # Map action results by ID
        action_results = {r.action_id: r for r in execution_result.action_results}

        # Validate each action
        for action in plan.actions:
            action_result = action_results.get(action.action_id)
            if not action_result:
                continue

            if action_result.status == ExecutionStatus.SUCCEEDED:
                # Validate the action's effect
                check = await self._validate_action(action, action_result)
                checks.append(check)

        # Calculate results
        result.checks = checks
        result.total_checks = len(checks)
        result.passed_checks = sum(1 for c in checks if c.passed)
        result.failed_checks = sum(1 for c in checks if not c.passed)

        # Determine overall status
        if result.total_checks == 0:
            result.overall_status = ValidationStatus.SKIPPED
        elif result.failed_checks == 0:
            result.overall_status = ValidationStatus.PASSED
        elif result.passed_checks == 0:
            result.overall_status = ValidationStatus.FAILED
        else:
            result.overall_status = ValidationStatus.PARTIAL

        # Calculate effectiveness
        result.effectiveness_score = self._calculate_effectiveness(
            plan,
            execution_result,
            checks,
        )

        # Generate recommendations
        result.remediation_needed = self._get_remediation_recommendations(checks)
        result.follow_up_actions = self._get_follow_up_actions(
            result.overall_status,
            result.effectiveness_score,
        )

        # Generate summary
        result.summary = self._generate_summary(result)

        return result

    async def _validate_action(
        self,
        action: PlannedAction,
        action_result: ActionResult,
    ) -> ValidationCheck:
        """Validate a single action."""
        check = ValidationCheck(
            check_type=action.action_type.value,
            target=action.target,
        )

        try:
            # Validate based on action type
            if action.action_type == ActionType.BLOCK_IP:
                check = await self._validate_ip_blocked(action, check)

            elif action.action_type == ActionType.BLOCK_DOMAIN:
                check = await self._validate_domain_blocked(action, check)

            elif action.action_type == ActionType.ISOLATE_HOST:
                check = await self._validate_host_isolated(action, check)

            elif action.action_type == ActionType.DISABLE_ACCOUNT:
                check = await self._validate_account_disabled(action, check)

            elif action.action_type == ActionType.CREATE_TICKET:
                check = await self._validate_ticket_created(action, action_result, check)

            elif action.action_type == ActionType.NOTIFY_TEAM:
                # Notifications are validated by successful API response
                check.status = ValidationStatus.PASSED
                check.passed = True
                check.message = "Notification sent successfully"

            elif action.action_type in [ActionType.CAPTURE_MEMORY, ActionType.SNAPSHOT_DISK]:
                check = await self._validate_forensic_capture(action, check)

            else:
                # Generic validation - assume success if action succeeded
                check.status = ValidationStatus.PASSED
                check.passed = True
                check.message = "Action completed successfully"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Validation error: {str(e)}"
            self.logger.warning(
                "validation_error",
                action_id=action.action_id,
                error=str(e),
            )

        return check

    async def _validate_ip_blocked(
        self,
        action: PlannedAction,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate IP is blocked."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.soar_endpoint}/blocklist/ip/{action.target}"
            )

            if response.status_code == 200:
                check.status = ValidationStatus.PASSED
                check.passed = True
                check.expected = "IP in blocklist"
                check.actual = "IP found in blocklist"
                check.message = f"IP {action.target} is blocked"
            else:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.expected = "IP in blocklist"
                check.actual = "IP not in blocklist"
                check.message = f"IP {action.target} was not found in blocklist"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Failed to verify: {str(e)}"

        return check

    async def _validate_domain_blocked(
        self,
        action: PlannedAction,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate domain is blocked."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.soar_endpoint}/blocklist/domain/{action.target}"
            )

            if response.status_code == 200:
                check.status = ValidationStatus.PASSED
                check.passed = True
                check.message = f"Domain {action.target} is blocked"
            else:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.message = f"Domain {action.target} was not found in blocklist"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Failed to verify: {str(e)}"

        return check

    async def _validate_host_isolated(
        self,
        action: PlannedAction,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate host is isolated."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.soar_endpoint}/assets/hosts/{action.target}/status"
            )

            if response.status_code == 200:
                status = response.json()
                if status.get("isolated"):
                    check.status = ValidationStatus.PASSED
                    check.passed = True
                    check.expected = "Host isolated"
                    check.actual = "Host is isolated"
                    check.message = f"Host {action.target} is isolated"
                else:
                    check.status = ValidationStatus.FAILED
                    check.passed = False
                    check.expected = "Host isolated"
                    check.actual = "Host not isolated"
                    check.message = f"Host {action.target} is not isolated"
            else:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.message = f"Unable to verify host status"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Failed to verify: {str(e)}"

        return check

    async def _validate_account_disabled(
        self,
        action: PlannedAction,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate account is disabled."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.soar_endpoint}/assets/users/{action.target}/status"
            )

            if response.status_code == 200:
                status = response.json()
                if status.get("disabled") or not status.get("enabled"):
                    check.status = ValidationStatus.PASSED
                    check.passed = True
                    check.message = f"Account {action.target} is disabled"
                else:
                    check.status = ValidationStatus.FAILED
                    check.passed = False
                    check.message = f"Account {action.target} is still enabled"
            else:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.message = f"Unable to verify account status"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Failed to verify: {str(e)}"

        return check

    async def _validate_ticket_created(
        self,
        action: PlannedAction,
        action_result: ActionResult,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate ticket was created."""
        ticket_id = action_result.output.get("ticket_id")

        if ticket_id:
            client = await self._get_client()

            try:
                response = await client.get(
                    f"{self.soar_endpoint}/tickets/{ticket_id}"
                )

                if response.status_code == 200:
                    check.status = ValidationStatus.PASSED
                    check.passed = True
                    check.message = f"Ticket {ticket_id} created successfully"
                else:
                    check.status = ValidationStatus.FAILED
                    check.passed = False
                    check.message = f"Ticket {ticket_id} not found"

            except Exception as e:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.message = f"Failed to verify: {str(e)}"
        else:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = "No ticket ID in action result"

        return check

    async def _validate_forensic_capture(
        self,
        action: PlannedAction,
        check: ValidationCheck,
    ) -> ValidationCheck:
        """Validate forensic capture was successful."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.soar_endpoint}/forensics/captures",
                params={"hostname": action.target},
            )

            if response.status_code == 200:
                captures = response.json().get("captures", [])
                if captures:
                    check.status = ValidationStatus.PASSED
                    check.passed = True
                    check.message = f"Forensic capture found for {action.target}"
                else:
                    check.status = ValidationStatus.FAILED
                    check.passed = False
                    check.message = f"No forensic capture found for {action.target}"
            else:
                check.status = ValidationStatus.FAILED
                check.passed = False
                check.message = "Unable to verify forensic capture"

        except Exception as e:
            check.status = ValidationStatus.FAILED
            check.passed = False
            check.message = f"Failed to verify: {str(e)}"

        return check

    def _calculate_effectiveness(
        self,
        plan: ActionPlan,
        execution: ExecutionResult,
        checks: list[ValidationCheck],
    ) -> float:
        """Calculate response effectiveness score."""
        score = 0.0

        # Base score from execution success
        if execution.total_actions > 0:
            execution_rate = execution.succeeded / execution.total_actions
            score += execution_rate * 0.4

        # Validation pass rate
        if checks:
            validation_rate = sum(1 for c in checks if c.passed) / len(checks)
            score += validation_rate * 0.4

        # Penalty for failed high-risk actions
        failed_high_risk = sum(
            1 for r in execution.action_results
            if r.status == ExecutionStatus.FAILED
        )
        if failed_high_risk > 0:
            score -= min(failed_high_risk * 0.1, 0.3)

        # Bonus for complete containment
        containment_actions = [
            a for a in plan.actions
            if a.category == "containment"
        ]
        if containment_actions:
            contained = sum(
                1 for a in containment_actions
                if any(
                    r.action_id == a.action_id and r.success
                    for r in execution.action_results
                )
            )
            containment_rate = contained / len(containment_actions)
            score += containment_rate * 0.2

        return max(min(score, 1.0), 0.0)

    def _get_remediation_recommendations(
        self,
        checks: list[ValidationCheck],
    ) -> list[str]:
        """Get remediation recommendations for failed checks."""
        recommendations = []

        for check in checks:
            if not check.passed:
                if check.check_type == "block_ip":
                    recommendations.append(
                        f"Re-attempt blocking IP {check.target} or verify firewall configuration"
                    )
                elif check.check_type == "isolate_host":
                    recommendations.append(
                        f"Verify EDR connectivity and re-attempt isolation of {check.target}"
                    )
                elif check.check_type == "disable_account":
                    recommendations.append(
                        f"Manually disable account {check.target} in Active Directory"
                    )

        return recommendations

    def _get_follow_up_actions(
        self,
        status: ValidationStatus,
        effectiveness: float,
    ) -> list[str]:
        """Get follow-up actions based on validation results."""
        actions = []

        if status == ValidationStatus.FAILED:
            actions.append("Review failed actions and execute remediation")
            actions.append("Consider escalating to incident commander")

        elif status == ValidationStatus.PARTIAL:
            actions.append("Address failed validation items")
            actions.append("Continue monitoring for indicators")

        if effectiveness < 0.5:
            actions.append("Response may be ineffective - consider additional measures")
            actions.append("Review containment strategy")

        elif effectiveness >= 0.8:
            actions.append("Monitor for reoccurrence")
            actions.append("Document lessons learned")

        # Always recommend
        actions.append("Update incident timeline")

        return actions

    def _generate_summary(self, result: ValidationResult) -> str:
        """Generate validation summary."""
        parts = [
            f"Validation {result.overall_status.value}",
            f"{result.passed_checks}/{result.total_checks} checks passed",
            f"Effectiveness: {result.effectiveness_score:.0%}",
        ]

        if result.failed_checks > 0:
            parts.append(f"{result.failed_checks} checks failed")

        if result.remediation_needed:
            parts.append(f"{len(result.remediation_needed)} remediation items")

        return " | ".join(parts)

    async def verify_threat_contained(
        self,
        iocs: list[dict[str, Any]],
        time_window_minutes: int = 30,
    ) -> dict[str, Any]:
        """Verify threat is contained by checking for continued activity.

        Args:
            iocs: List of IOCs from the incident
            time_window_minutes: Time window to check

        Returns:
            Containment verification result
        """
        client = await self._get_client()
        results = {
            "contained": True,
            "active_iocs": [],
            "new_alerts": 0,
        }

        for ioc in iocs[:20]:  # Limit checks
            ioc_type = ioc.get("type")
            ioc_value = ioc.get("value")

            try:
                # Check for recent activity
                response = await client.post(
                    f"{self.siem_endpoint}/query",
                    json={
                        "query": f'{ioc_type}:"{ioc_value}"',
                        "time_range": f"last_{time_window_minutes}m",
                    },
                )

                if response.status_code == 200:
                    events = response.json().get("results", [])
                    if events:
                        results["contained"] = False
                        results["active_iocs"].append({
                            "ioc": ioc_value,
                            "type": ioc_type,
                            "event_count": len(events),
                        })
                        results["new_alerts"] += len(events)

            except Exception as e:
                self.logger.warning(
                    "containment_check_failed",
                    ioc=ioc_value,
                    error=str(e),
                )

        return results
