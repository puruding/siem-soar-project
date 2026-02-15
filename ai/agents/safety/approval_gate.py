"""Approval Gate - Human approval workflow for high-risk actions."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .guardrails import RiskLevel


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ESCALATED = "escalated"


class ApprovalRequest(BaseModel):
    """Request for human approval."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: str = Field(description="Associated incident ID")
    action_type: str = Field(description="Type of action requiring approval")
    targets: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)

    # Request details
    reason: str = Field(description="Reason for the action")
    context: dict[str, Any] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)

    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(default=None)
    timeout_minutes: int = Field(default=60)

    # Status
    status: ApprovalStatus = Field(default=ApprovalStatus.PENDING)
    reviewed_by: str | None = Field(default=None)
    reviewed_at: datetime | None = Field(default=None)
    review_notes: str | None = Field(default=None)

    # Escalation
    escalation_level: int = Field(default=0)
    escalated_to: list[str] = Field(default_factory=list)


class ApprovalDecision(BaseModel):
    """Decision on an approval request."""

    request_id: str
    approved: bool
    reviewer: str
    notes: str | None = None
    conditions: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ApprovalGate(LoggerMixin):
    """Gate for human approval of high-risk actions.

    Features:
    - Request queuing
    - Expiration handling
    - Escalation paths
    - Notification integration
    - Audit trail
    """

    def __init__(
        self,
        default_timeout_minutes: int = 60,
        escalation_timeout_minutes: int = 30,
        max_escalation_levels: int = 3,
    ) -> None:
        """Initialize approval gate.

        Args:
            default_timeout_minutes: Default request timeout
            escalation_timeout_minutes: Time before escalation
            max_escalation_levels: Maximum escalation levels
        """
        self.default_timeout_minutes = default_timeout_minutes
        self.escalation_timeout_minutes = escalation_timeout_minutes
        self.max_escalation_levels = max_escalation_levels

        self._pending_requests: dict[str, ApprovalRequest] = {}
        self._completed_requests: dict[str, ApprovalRequest] = {}
        self._notification_callbacks: list = []

    def create_request(
        self,
        incident_id: str,
        action_type: str,
        targets: list[str],
        reason: str,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        context: dict[str, Any] | None = None,
        timeout_minutes: int | None = None,
    ) -> ApprovalRequest:
        """Create an approval request.

        Args:
            incident_id: Associated incident
            action_type: Type of action
            targets: Target entities
            reason: Reason for action
            risk_level: Risk level
            context: Additional context
            timeout_minutes: Request timeout

        Returns:
            Created approval request
        """
        timeout = timeout_minutes or self.default_timeout_minutes
        expires_at = datetime.utcnow() + timedelta(minutes=timeout)

        request = ApprovalRequest(
            incident_id=incident_id,
            action_type=action_type,
            targets=targets,
            reason=reason,
            risk_level=risk_level,
            context=context or {},
            timeout_minutes=timeout,
            expires_at=expires_at,
        )

        self._pending_requests[request.request_id] = request

        self.logger.info(
            "approval_request_created",
            request_id=request.request_id,
            incident_id=incident_id,
            action_type=action_type,
            risk_level=risk_level.value,
        )

        # Notify approvers
        self._notify_new_request(request)

        return request

    async def wait_for_approval(
        self,
        request_id: str,
        poll_interval_seconds: int = 5,
    ) -> ApprovalDecision | None:
        """Wait for approval decision.

        Args:
            request_id: Request to wait for
            poll_interval_seconds: Polling interval

        Returns:
            Approval decision or None if expired
        """
        while True:
            request = self._pending_requests.get(request_id)
            if not request:
                # Check completed
                completed = self._completed_requests.get(request_id)
                if completed:
                    return ApprovalDecision(
                        request_id=request_id,
                        approved=completed.status == ApprovalStatus.APPROVED,
                        reviewer=completed.reviewed_by or "system",
                        notes=completed.review_notes,
                    )
                return None

            # Check expiration
            if request.expires_at and datetime.utcnow() > request.expires_at:
                self._handle_expiration(request)
                return None

            # Check for escalation
            self._check_escalation(request)

            # Check if decided
            if request.status != ApprovalStatus.PENDING:
                return ApprovalDecision(
                    request_id=request_id,
                    approved=request.status == ApprovalStatus.APPROVED,
                    reviewer=request.reviewed_by or "system",
                    notes=request.review_notes,
                )

            await asyncio.sleep(poll_interval_seconds)

    def approve(
        self,
        request_id: str,
        reviewer: str,
        notes: str | None = None,
        conditions: list[str] | None = None,
    ) -> ApprovalDecision:
        """Approve a request.

        Args:
            request_id: Request to approve
            reviewer: Reviewer identifier
            notes: Review notes
            conditions: Approval conditions

        Returns:
            Approval decision
        """
        request = self._pending_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request already processed: {request.status.value}")

        request.status = ApprovalStatus.APPROVED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.utcnow()
        request.review_notes = notes

        # Move to completed
        del self._pending_requests[request_id]
        self._completed_requests[request_id] = request

        self.logger.info(
            "request_approved",
            request_id=request_id,
            reviewer=reviewer,
        )

        decision = ApprovalDecision(
            request_id=request_id,
            approved=True,
            reviewer=reviewer,
            notes=notes,
            conditions=conditions or [],
        )

        return decision

    def reject(
        self,
        request_id: str,
        reviewer: str,
        reason: str,
    ) -> ApprovalDecision:
        """Reject a request.

        Args:
            request_id: Request to reject
            reviewer: Reviewer identifier
            reason: Rejection reason

        Returns:
            Approval decision
        """
        request = self._pending_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request already processed: {request.status.value}")

        request.status = ApprovalStatus.REJECTED
        request.reviewed_by = reviewer
        request.reviewed_at = datetime.utcnow()
        request.review_notes = reason

        # Move to completed
        del self._pending_requests[request_id]
        self._completed_requests[request_id] = request

        self.logger.info(
            "request_rejected",
            request_id=request_id,
            reviewer=reviewer,
            reason=reason,
        )

        return ApprovalDecision(
            request_id=request_id,
            approved=False,
            reviewer=reviewer,
            notes=reason,
        )

    def escalate(
        self,
        request_id: str,
        escalate_to: list[str],
        reason: str,
    ) -> None:
        """Escalate a request.

        Args:
            request_id: Request to escalate
            escalate_to: List of escalation targets
            reason: Escalation reason
        """
        request = self._pending_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.escalation_level >= self.max_escalation_levels:
            self.logger.warning(
                "max_escalation_reached",
                request_id=request_id,
            )
            return

        request.escalation_level += 1
        request.escalated_to.extend(escalate_to)
        request.status = ApprovalStatus.ESCALATED

        # Extend timeout
        request.expires_at = datetime.utcnow() + timedelta(
            minutes=self.default_timeout_minutes,
        )

        self.logger.info(
            "request_escalated",
            request_id=request_id,
            level=request.escalation_level,
            escalated_to=escalate_to,
        )

        # Notify escalation targets
        self._notify_escalation(request, escalate_to, reason)

    def _handle_expiration(self, request: ApprovalRequest) -> None:
        """Handle request expiration."""
        request.status = ApprovalStatus.EXPIRED

        # Move to completed
        if request.request_id in self._pending_requests:
            del self._pending_requests[request.request_id]
        self._completed_requests[request.request_id] = request

        self.logger.warning(
            "request_expired",
            request_id=request.request_id,
        )

    def _check_escalation(self, request: ApprovalRequest) -> None:
        """Check if request should be escalated."""
        if request.status != ApprovalStatus.PENDING:
            return

        # Check if escalation timeout reached
        age_minutes = (datetime.utcnow() - request.created_at).total_seconds() / 60
        escalation_threshold = self.escalation_timeout_minutes * (request.escalation_level + 1)

        if age_minutes > escalation_threshold and request.escalation_level < self.max_escalation_levels:
            # Auto-escalate
            escalate_to = self._get_escalation_targets(request.escalation_level + 1)
            self.escalate(
                request.request_id,
                escalate_to,
                f"Auto-escalation after {int(age_minutes)} minutes",
            )

    def _get_escalation_targets(self, level: int) -> list[str]:
        """Get escalation targets for a level."""
        # This would typically come from configuration
        escalation_groups = {
            1: ["soc-tier2"],
            2: ["soc-manager"],
            3: ["security-director"],
        }
        return escalation_groups.get(level, ["security-team"])

    def _notify_new_request(self, request: ApprovalRequest) -> None:
        """Notify approvers of new request."""
        for callback in self._notification_callbacks:
            try:
                callback("new_request", request)
            except Exception as e:
                self.logger.error("notification_failed", error=str(e))

    def _notify_escalation(
        self,
        request: ApprovalRequest,
        escalate_to: list[str],
        reason: str,
    ) -> None:
        """Notify escalation targets."""
        for callback in self._notification_callbacks:
            try:
                callback("escalation", request, escalate_to, reason)
            except Exception as e:
                self.logger.error("escalation_notification_failed", error=str(e))

    def register_notification_callback(self, callback) -> None:
        """Register a notification callback."""
        self._notification_callbacks.append(callback)

    def get_pending_requests(
        self,
        incident_id: str | None = None,
    ) -> list[ApprovalRequest]:
        """Get pending approval requests.

        Args:
            incident_id: Filter by incident ID

        Returns:
            List of pending requests
        """
        requests = list(self._pending_requests.values())

        if incident_id:
            requests = [r for r in requests if r.incident_id == incident_id]

        return sorted(requests, key=lambda r: r.created_at)

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        """Get a specific request."""
        return (
            self._pending_requests.get(request_id)
            or self._completed_requests.get(request_id)
        )

    def get_stats(self) -> dict[str, Any]:
        """Get approval gate statistics."""
        pending = list(self._pending_requests.values())
        completed = list(self._completed_requests.values())

        return {
            "pending_count": len(pending),
            "completed_count": len(completed),
            "approved_count": len([r for r in completed if r.status == ApprovalStatus.APPROVED]),
            "rejected_count": len([r for r in completed if r.status == ApprovalStatus.REJECTED]),
            "expired_count": len([r for r in completed if r.status == ApprovalStatus.EXPIRED]),
            "escalated_count": len([r for r in pending if r.escalation_level > 0]),
            "by_risk_level": {
                level.value: len([r for r in pending if r.risk_level == level])
                for level in RiskLevel
            },
        }
