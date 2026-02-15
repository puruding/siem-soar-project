"""Guardrails - Action constraints and validation for safe autonomous operations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RiskLevel(str, Enum):
    """Risk levels for actions."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionConstraint(BaseModel):
    """Constraint on an action type."""

    action_type: str = Field(description="Type of action")
    max_targets: int = Field(default=10, description="Max targets per execution")
    max_daily_count: int = Field(default=100, description="Max daily executions")
    require_approval_above: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Require approval above this risk level",
    )
    allowed_hours: tuple[int, int] = Field(
        default=(0, 24),
        description="Allowed hours (start, end)",
    )
    excluded_targets: list[str] = Field(
        default_factory=list,
        description="Targets that cannot be affected",
    )
    required_context: list[str] = Field(
        default_factory=list,
        description="Required context fields",
    )


class GuardrailResult(BaseModel):
    """Result from guardrail check."""

    passed: bool = Field(description="Whether the check passed")
    guardrail_id: str = Field(description="ID of the guardrail")
    message: str = Field(default="", description="Result message")
    risk_level: RiskLevel = Field(default=RiskLevel.NONE)
    blocked_reason: str | None = Field(default=None)
    recommendations: list[str] = Field(default_factory=list)


class Guardrail(BaseModel):
    """A single guardrail definition."""

    guardrail_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(description="Guardrail name")
    description: str = Field(default="")
    enabled: bool = Field(default=True)
    action_types: list[str] = Field(
        default_factory=list,
        description="Action types this guardrail applies to",
    )
    check_function: str = Field(
        description="Name of the check function",
    )
    priority: int = Field(default=5, ge=1, le=10)


class GuardrailEngine(LoggerMixin):
    """Engine for evaluating guardrails against actions.

    Features:
    - Action constraint validation
    - Risk assessment
    - Context validation
    - Time-based restrictions
    - Target exclusion
    """

    def __init__(self) -> None:
        """Initialize guardrail engine."""
        self._guardrails: dict[str, Guardrail] = {}
        self._constraints: dict[str, ActionConstraint] = {}
        self._check_functions: dict[str, Callable] = {}
        self._daily_counts: dict[str, int] = {}
        self._last_reset: datetime = datetime.utcnow()

        # Register built-in checks
        self._register_builtin_checks()
        self._register_default_constraints()

    def _register_builtin_checks(self) -> None:
        """Register built-in check functions."""
        self._check_functions = {
            "check_target_count": self._check_target_count,
            "check_excluded_targets": self._check_excluded_targets,
            "check_time_window": self._check_time_window,
            "check_required_context": self._check_required_context,
            "check_daily_limit": self._check_daily_limit,
            "check_risk_threshold": self._check_risk_threshold,
            "check_critical_assets": self._check_critical_assets,
            "check_production_safeguard": self._check_production_safeguard,
        }

    def _register_default_constraints(self) -> None:
        """Register default action constraints."""
        default_constraints = [
            ActionConstraint(
                action_type="isolate_host",
                max_targets=5,
                max_daily_count=20,
                require_approval_above=RiskLevel.LOW,
                excluded_targets=["dc01", "dc02", "dns01"],  # Domain controllers
            ),
            ActionConstraint(
                action_type="disable_account",
                max_targets=10,
                max_daily_count=50,
                require_approval_above=RiskLevel.LOW,
                excluded_targets=["admin", "service_account"],
            ),
            ActionConstraint(
                action_type="block_ip",
                max_targets=100,
                max_daily_count=500,
                require_approval_above=RiskLevel.MEDIUM,
            ),
            ActionConstraint(
                action_type="kill_process",
                max_targets=20,
                max_daily_count=100,
                require_approval_above=RiskLevel.MEDIUM,
                required_context=["process_name", "host"],
            ),
            ActionConstraint(
                action_type="quarantine_file",
                max_targets=50,
                max_daily_count=200,
                require_approval_above=RiskLevel.LOW,
            ),
            ActionConstraint(
                action_type="shutdown_service",
                max_targets=3,
                max_daily_count=10,
                require_approval_above=RiskLevel.HIGH,
                allowed_hours=(6, 22),  # Not during night hours
            ),
        ]

        for constraint in default_constraints:
            self._constraints[constraint.action_type] = constraint

    def register_guardrail(self, guardrail: Guardrail) -> None:
        """Register a guardrail.

        Args:
            guardrail: Guardrail to register
        """
        self._guardrails[guardrail.guardrail_id] = guardrail
        self.logger.info(
            "guardrail_registered",
            guardrail_id=guardrail.guardrail_id,
            name=guardrail.name,
        )

    def register_constraint(self, constraint: ActionConstraint) -> None:
        """Register an action constraint.

        Args:
            constraint: Constraint to register
        """
        self._constraints[constraint.action_type] = constraint
        self.logger.info(
            "constraint_registered",
            action_type=constraint.action_type,
        )

    def evaluate(
        self,
        action_type: str,
        targets: list[str],
        context: dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MEDIUM,
    ) -> list[GuardrailResult]:
        """Evaluate all applicable guardrails for an action.

        Args:
            action_type: Type of action
            targets: Target entities
            context: Action context
            risk_level: Assessed risk level

        Returns:
            List of guardrail results
        """
        self._reset_daily_counts_if_needed()

        results = []
        constraint = self._constraints.get(action_type)

        # Check built-in constraints
        if constraint:
            # Target count check
            results.append(self._check_target_count(
                action_type, targets, constraint, context,
            ))

            # Excluded targets check
            results.append(self._check_excluded_targets(
                action_type, targets, constraint, context,
            ))

            # Time window check
            results.append(self._check_time_window(
                action_type, targets, constraint, context,
            ))

            # Required context check
            results.append(self._check_required_context(
                action_type, targets, constraint, context,
            ))

            # Daily limit check
            results.append(self._check_daily_limit(
                action_type, targets, constraint, context,
            ))

            # Risk threshold check
            results.append(self._check_risk_threshold(
                action_type, targets, constraint, context, risk_level,
            ))

        # Check critical assets
        results.append(self._check_critical_assets(
            action_type, targets, context,
        ))

        # Check production safeguard
        results.append(self._check_production_safeguard(
            action_type, targets, context,
        ))

        # Check custom guardrails
        for guardrail in self._guardrails.values():
            if not guardrail.enabled:
                continue

            if guardrail.action_types and action_type not in guardrail.action_types:
                continue

            check_fn = self._check_functions.get(guardrail.check_function)
            if check_fn:
                result = check_fn(action_type, targets, constraint, context)
                result.guardrail_id = guardrail.guardrail_id
                results.append(result)

        # Log evaluation
        passed_count = sum(1 for r in results if r.passed)
        self.logger.info(
            "guardrail_evaluation",
            action_type=action_type,
            target_count=len(targets),
            total_checks=len(results),
            passed=passed_count,
            failed=len(results) - passed_count,
        )

        return results

    def is_allowed(
        self,
        action_type: str,
        targets: list[str],
        context: dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MEDIUM,
    ) -> tuple[bool, list[str]]:
        """Check if an action is allowed.

        Args:
            action_type: Type of action
            targets: Target entities
            context: Action context
            risk_level: Assessed risk level

        Returns:
            Tuple of (allowed, blocked_reasons)
        """
        results = self.evaluate(action_type, targets, context, risk_level)

        blocked_reasons = []
        for result in results:
            if not result.passed and result.blocked_reason:
                blocked_reasons.append(result.blocked_reason)

        return len(blocked_reasons) == 0, blocked_reasons

    def record_execution(self, action_type: str, target_count: int = 1) -> None:
        """Record an action execution for daily counting.

        Args:
            action_type: Type of action
            target_count: Number of targets affected
        """
        key = f"{action_type}:{datetime.utcnow().date().isoformat()}"
        self._daily_counts[key] = self._daily_counts.get(key, 0) + target_count

    def _reset_daily_counts_if_needed(self) -> None:
        """Reset daily counts if day has changed."""
        now = datetime.utcnow()
        if now.date() > self._last_reset.date():
            self._daily_counts.clear()
            self._last_reset = now

    def _check_target_count(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check target count constraint."""
        if not constraint:
            return GuardrailResult(
                passed=True,
                guardrail_id="target_count",
                message="No constraint defined",
            )

        if len(targets) > constraint.max_targets:
            return GuardrailResult(
                passed=False,
                guardrail_id="target_count",
                message=f"Target count {len(targets)} exceeds limit {constraint.max_targets}",
                risk_level=RiskLevel.HIGH,
                blocked_reason=f"Too many targets: {len(targets)} > {constraint.max_targets}",
                recommendations=["Split into smaller batches"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="target_count",
            message=f"Target count {len(targets)} within limit",
        )

    def _check_excluded_targets(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check excluded targets constraint."""
        if not constraint or not constraint.excluded_targets:
            return GuardrailResult(
                passed=True,
                guardrail_id="excluded_targets",
                message="No exclusions defined",
            )

        excluded_found = [t for t in targets if t.lower() in [e.lower() for e in constraint.excluded_targets]]

        if excluded_found:
            return GuardrailResult(
                passed=False,
                guardrail_id="excluded_targets",
                message=f"Excluded targets found: {excluded_found}",
                risk_level=RiskLevel.CRITICAL,
                blocked_reason=f"Protected targets: {excluded_found}",
                recommendations=["Remove protected targets from action"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="excluded_targets",
            message="No excluded targets found",
        )

    def _check_time_window(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check time window constraint."""
        if not constraint:
            return GuardrailResult(
                passed=True,
                guardrail_id="time_window",
                message="No time constraint defined",
            )

        current_hour = datetime.utcnow().hour
        start_hour, end_hour = constraint.allowed_hours

        if not (start_hour <= current_hour < end_hour):
            return GuardrailResult(
                passed=False,
                guardrail_id="time_window",
                message=f"Current hour {current_hour} outside allowed window {start_hour}-{end_hour}",
                risk_level=RiskLevel.MEDIUM,
                blocked_reason=f"Action not allowed at hour {current_hour}",
                recommendations=[f"Execute during hours {start_hour}-{end_hour}"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="time_window",
            message="Within allowed time window",
        )

    def _check_required_context(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check required context fields."""
        if not constraint or not constraint.required_context:
            return GuardrailResult(
                passed=True,
                guardrail_id="required_context",
                message="No required context defined",
            )

        missing = [f for f in constraint.required_context if f not in context]

        if missing:
            return GuardrailResult(
                passed=False,
                guardrail_id="required_context",
                message=f"Missing required context: {missing}",
                risk_level=RiskLevel.HIGH,
                blocked_reason=f"Missing context fields: {missing}",
                recommendations=[f"Provide: {', '.join(missing)}"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="required_context",
            message="All required context present",
        )

    def _check_daily_limit(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check daily execution limit."""
        if not constraint:
            return GuardrailResult(
                passed=True,
                guardrail_id="daily_limit",
                message="No daily limit defined",
            )

        key = f"{action_type}:{datetime.utcnow().date().isoformat()}"
        current_count = self._daily_counts.get(key, 0)
        new_count = current_count + len(targets)

        if new_count > constraint.max_daily_count:
            return GuardrailResult(
                passed=False,
                guardrail_id="daily_limit",
                message=f"Daily limit exceeded: {new_count} > {constraint.max_daily_count}",
                risk_level=RiskLevel.MEDIUM,
                blocked_reason=f"Daily limit: {current_count}/{constraint.max_daily_count} used",
                recommendations=["Wait until tomorrow or request limit increase"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="daily_limit",
            message=f"Within daily limit: {new_count}/{constraint.max_daily_count}",
        )

    def _check_risk_threshold(
        self,
        action_type: str,
        targets: list[str],
        constraint: ActionConstraint | None,
        context: dict[str, Any],
        risk_level: RiskLevel = RiskLevel.MEDIUM,
    ) -> GuardrailResult:
        """Check if action requires approval based on risk."""
        if not constraint:
            return GuardrailResult(
                passed=True,
                guardrail_id="risk_threshold",
                message="No risk threshold defined",
            )

        risk_order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        current_risk_idx = risk_order.index(risk_level)
        threshold_idx = risk_order.index(constraint.require_approval_above)

        if current_risk_idx > threshold_idx:
            return GuardrailResult(
                passed=False,
                guardrail_id="risk_threshold",
                message=f"Risk level {risk_level.value} requires approval",
                risk_level=risk_level,
                blocked_reason=f"Risk {risk_level.value} exceeds auto-approve threshold {constraint.require_approval_above.value}",
                recommendations=["Request human approval"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="risk_threshold",
            message=f"Risk level {risk_level.value} within auto-approve threshold",
        )

    def _check_critical_assets(
        self,
        action_type: str,
        targets: list[str],
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check if action affects critical assets."""
        critical_patterns = [
            "dc", "domain", "dns", "ad", "ldap",  # Directory services
            "db", "database", "sql", "oracle",  # Databases
            "backup", "vault",  # Backup systems
            "firewall", "fw", "router", "switch",  # Network infrastructure
            "pki", "ca", "cert",  # PKI infrastructure
        ]

        critical_found = []
        for target in targets:
            target_lower = target.lower()
            for pattern in critical_patterns:
                if pattern in target_lower:
                    critical_found.append(target)
                    break

        if critical_found:
            return GuardrailResult(
                passed=False,
                guardrail_id="critical_assets",
                message=f"Critical assets detected: {critical_found}",
                risk_level=RiskLevel.CRITICAL,
                blocked_reason=f"Cannot automatically affect critical assets: {critical_found}",
                recommendations=["Request manual approval for critical assets"],
            )

        return GuardrailResult(
            passed=True,
            guardrail_id="critical_assets",
            message="No critical assets detected",
        )

    def _check_production_safeguard(
        self,
        action_type: str,
        targets: list[str],
        context: dict[str, Any],
    ) -> GuardrailResult:
        """Check production environment safeguard."""
        environment = context.get("environment", "unknown")
        is_production = environment.lower() in ["prod", "production", "prd"]

        # High-impact actions in production require explicit flag
        high_impact_actions = ["shutdown_service", "restart_service", "delete_data", "wipe_host"]

        if is_production and action_type in high_impact_actions:
            has_prod_approval = context.get("production_approved", False)
            if not has_prod_approval:
                return GuardrailResult(
                    passed=False,
                    guardrail_id="production_safeguard",
                    message=f"High-impact action in production: {action_type}",
                    risk_level=RiskLevel.CRITICAL,
                    blocked_reason=f"Production safeguard: {action_type} requires explicit approval",
                    recommendations=["Set production_approved=true in context after approval"],
                )

        return GuardrailResult(
            passed=True,
            guardrail_id="production_safeguard",
            message="Production safeguard passed",
        )

    def get_constraint(self, action_type: str) -> ActionConstraint | None:
        """Get constraint for an action type."""
        return self._constraints.get(action_type)

    def get_all_constraints(self) -> dict[str, ActionConstraint]:
        """Get all registered constraints."""
        return self._constraints.copy()
