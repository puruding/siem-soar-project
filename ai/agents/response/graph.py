"""LangGraph workflow for response agent."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ResponseState(TypedDict, total=False):
    """State for response workflow."""

    # Identifiers
    execution_id: str
    incident_id: str | None

    # Input
    analysis: dict[str, Any]
    affected_assets: list[dict[str, Any]]
    recommendations: list[str]

    # Phase tracking
    phase: str
    step: int

    # Action planning
    action_plan: dict[str, Any] | None
    planned_actions: list[dict[str, Any]]

    # Execution
    executed_actions: list[dict[str, Any]]
    failed_actions: list[dict[str, Any]]
    pending_approval: list[dict[str, Any]]

    # Validation
    validation_result: dict[str, Any] | None
    effectiveness_score: float

    # Control
    should_continue: bool
    requires_approval: bool
    approval_granted: bool
    error: str | None

    # Messages
    messages: list[dict[str, str]]


class ResponseConfig(BaseModel):
    """Configuration for response graph."""

    soar_endpoint: str = Field(default="http://localhost:8001/api/v1")
    auto_approve_low_risk: bool = Field(default=True)
    max_actions: int = Field(default=20)
    require_validation: bool = Field(default=True)
    rollback_on_failure: bool = Field(default=True)


class ResponseGraphBuilder(LoggerMixin):
    """Builder for LangGraph response workflow."""

    def __init__(self, config: ResponseConfig | None = None) -> None:
        """Initialize graph builder.

        Args:
            config: Graph configuration
        """
        self.config = config or ResponseConfig()

    def build(self) -> StateGraph:
        """Build the response graph.

        Returns:
            Compiled StateGraph
        """
        workflow = StateGraph(ResponseState)

        # Add nodes
        workflow.add_node("plan", self._plan_node)
        workflow.add_node("approve", self._approve_node)
        workflow.add_node("execute", self._execute_node)
        workflow.add_node("validate", self._validate_node)
        workflow.add_node("rollback", self._rollback_node)
        workflow.add_node("finalize", self._finalize_node)

        # Set entry point
        workflow.set_entry_point("plan")

        # Add edges
        workflow.add_conditional_edges(
            "plan",
            self._needs_approval,
            {
                "approve": "approve",
                "execute": "execute",
            },
        )

        workflow.add_conditional_edges(
            "approve",
            self._approval_decision,
            {
                "approved": "execute",
                "rejected": "finalize",
            },
        )

        workflow.add_conditional_edges(
            "execute",
            self._execution_result,
            {
                "validate": "validate",
                "rollback": "rollback",
                "finalize": "finalize",
            },
        )

        workflow.add_conditional_edges(
            "validate",
            self._validation_result,
            {
                "success": "finalize",
                "partial": "finalize",
                "failure": "rollback",
            },
        )

        workflow.add_edge("rollback", "finalize")
        workflow.add_edge("finalize", END)

        return workflow.compile()

    async def _plan_node(self, state: ResponseState) -> ResponseState:
        """Plan response actions."""
        self.logger.info("plan_response", execution_id=state.get("execution_id"))

        analysis = state.get("analysis", {})
        affected_assets = state.get("affected_assets", [])
        recommendations = state.get("recommendations", [])

        # Build action plan
        planned_actions = []
        action_counter = 0

        # Get threat context
        threat_type = analysis.get("threat_classification", {}).get("threat_type", "unknown")
        severity = analysis.get("severity_score", 5)
        iocs = analysis.get("indicators_of_compromise", [])

        # Plan containment actions
        for ioc in iocs:
            if ioc.get("type") == "ip":
                action_counter += 1
                planned_actions.append({
                    "action_id": f"action-{action_counter}",
                    "action_type": "block_ip",
                    "target": ioc.get("value"),
                    "risk_level": "medium",
                    "requires_approval": False,
                    "category": "containment",
                })

        # Isolate hosts for high severity
        if severity >= 7:
            for asset in affected_assets:
                if asset.get("type") == "host":
                    action_counter += 1
                    planned_actions.append({
                        "action_id": f"action-{action_counter}",
                        "action_type": "isolate_host",
                        "target": asset.get("identifier"),
                        "risk_level": "high",
                        "requires_approval": True,
                        "category": "containment",
                    })

        # Notification actions
        action_counter += 1
        planned_actions.append({
            "action_id": f"action-{action_counter}",
            "action_type": "create_ticket",
            "target": "incident",
            "risk_level": "low",
            "requires_approval": False,
            "category": "notification",
        })

        if severity >= 6:
            action_counter += 1
            planned_actions.append({
                "action_id": f"action-{action_counter}",
                "action_type": "notify_team",
                "target": "security_team",
                "parameters": {"severity": severity, "threat_type": threat_type},
                "risk_level": "low",
                "requires_approval": False,
                "category": "notification",
            })

        # Limit actions
        planned_actions = planned_actions[:self.config.max_actions]

        # Check if any require approval
        requires_approval = any(
            a.get("requires_approval") and not self.config.auto_approve_low_risk
            for a in planned_actions
        )

        # Override: high risk always needs approval
        high_risk_actions = [
            a for a in planned_actions
            if a.get("risk_level") == "high"
        ]
        if high_risk_actions:
            requires_approval = True

        action_plan = {
            "plan_id": f"plan-{state.get('execution_id', 'unknown')}",
            "total_actions": len(planned_actions),
            "high_risk_count": len(high_risk_actions),
            "requires_approval": requires_approval,
        }

        return {
            **state,
            "phase": "plan",
            "step": 1,
            "action_plan": action_plan,
            "planned_actions": planned_actions,
            "requires_approval": requires_approval,
            "executed_actions": [],
            "failed_actions": [],
            "pending_approval": high_risk_actions if requires_approval else [],
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Planned {len(planned_actions)} actions ({len(high_risk_actions)} high-risk)"},
            ],
        }

    async def _approve_node(self, state: ResponseState) -> ResponseState:
        """Handle approval for high-risk actions."""
        self.logger.info("approve_actions", execution_id=state.get("execution_id"))

        # In real implementation, this would wait for human approval
        # For now, auto-approve based on config
        pending = state.get("pending_approval", [])

        # Simulate approval process
        # In production, this would integrate with an approval system
        approval_granted = True  # Simulated approval

        if approval_granted:
            # Move pending to ready for execution
            return {
                **state,
                "phase": "approve",
                "step": 2,
                "approval_granted": True,
                "pending_approval": [],
                "messages": state.get("messages", []) + [
                    {"role": "system", "content": f"Approved {len(pending)} high-risk actions"},
                ],
            }
        else:
            return {
                **state,
                "phase": "approve",
                "step": 2,
                "approval_granted": False,
                "messages": state.get("messages", []) + [
                    {"role": "system", "content": "High-risk actions rejected"},
                ],
            }

    async def _execute_node(self, state: ResponseState) -> ResponseState:
        """Execute planned actions."""
        self.logger.info("execute_actions", execution_id=state.get("execution_id"))

        planned = state.get("planned_actions", [])
        executed = []
        failed = []

        for action in planned:
            # Simulate execution
            # In real implementation, would call ActionExecutor

            # Simulate success/failure (mostly success)
            import random
            success = random.random() > 0.1  # 90% success rate

            if success:
                executed.append({
                    **action,
                    "status": "succeeded",
                    "executed_at": datetime.utcnow().isoformat(),
                })
            else:
                failed.append({
                    **action,
                    "status": "failed",
                    "error": "Simulated failure",
                    "executed_at": datetime.utcnow().isoformat(),
                })

        should_rollback = (
            self.config.rollback_on_failure and
            len(failed) > len(executed)  # More failures than successes
        )

        return {
            **state,
            "phase": "execute",
            "step": 3,
            "executed_actions": executed,
            "failed_actions": failed,
            "should_continue": not should_rollback,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Executed {len(executed)} actions, {len(failed)} failed"},
            ],
        }

    async def _validate_node(self, state: ResponseState) -> ResponseState:
        """Validate execution results."""
        self.logger.info("validate_response", execution_id=state.get("execution_id"))

        executed = state.get("executed_actions", [])
        failed = state.get("failed_actions", [])

        # Calculate effectiveness
        total = len(executed) + len(failed)
        if total > 0:
            effectiveness = len(executed) / total
        else:
            effectiveness = 0.0

        validation_result = {
            "validation_id": f"val-{state.get('execution_id', 'unknown')}",
            "total_actions": total,
            "succeeded": len(executed),
            "failed": len(failed),
            "effectiveness_score": effectiveness,
            "status": "passed" if effectiveness >= 0.8 else "partial" if effectiveness >= 0.5 else "failed",
        }

        return {
            **state,
            "phase": "validate",
            "step": 4,
            "validation_result": validation_result,
            "effectiveness_score": effectiveness,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Validation: {validation_result['status']} (effectiveness: {effectiveness:.0%})"},
            ],
        }

    async def _rollback_node(self, state: ResponseState) -> ResponseState:
        """Rollback failed actions."""
        self.logger.info("rollback_actions", execution_id=state.get("execution_id"))

        executed = state.get("executed_actions", [])
        rollback_count = 0

        # In real implementation, would call rollback for each action
        for action in executed:
            # Simulate rollback
            rollback_count += 1

        return {
            **state,
            "phase": "rollback",
            "step": 5,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": f"Rolled back {rollback_count} actions"},
            ],
        }

    async def _finalize_node(self, state: ResponseState) -> ResponseState:
        """Finalize response."""
        self.logger.info("finalize_response", execution_id=state.get("execution_id"))

        return {
            **state,
            "phase": "complete",
            "should_continue": False,
            "messages": state.get("messages", []) + [
                {"role": "system", "content": "Response complete"},
            ],
        }

    def _needs_approval(self, state: ResponseState) -> Literal["approve", "execute"]:
        """Check if approval is needed."""
        if state.get("requires_approval"):
            return "approve"
        return "execute"

    def _approval_decision(self, state: ResponseState) -> Literal["approved", "rejected"]:
        """Check approval decision."""
        if state.get("approval_granted"):
            return "approved"
        return "rejected"

    def _execution_result(self, state: ResponseState) -> Literal["validate", "rollback", "finalize"]:
        """Determine path after execution."""
        if not state.get("should_continue"):
            return "rollback"

        if self.config.require_validation:
            return "validate"

        return "finalize"

    def _validation_result(self, state: ResponseState) -> Literal["success", "partial", "failure"]:
        """Determine path after validation."""
        validation = state.get("validation_result", {})
        status = validation.get("status", "partial")

        if status == "passed":
            return "success"
        elif status == "partial":
            return "partial"
        else:
            return "failure"


def create_response_graph(config: ResponseConfig | None = None) -> StateGraph:
    """Create a response workflow graph.

    Args:
        config: Optional configuration

    Returns:
        Compiled LangGraph workflow
    """
    builder = ResponseGraphBuilder(config)
    return builder.build()
