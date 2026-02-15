"""Audit Logger - Comprehensive logging for autonomous agent operations."""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class AuditEventType(str, Enum):
    """Types of audit events."""

    # Agent events
    AGENT_STARTED = "agent_started"
    AGENT_STOPPED = "agent_stopped"
    AGENT_ERROR = "agent_error"

    # Action events
    ACTION_REQUESTED = "action_requested"
    ACTION_APPROVED = "action_approved"
    ACTION_REJECTED = "action_rejected"
    ACTION_EXECUTED = "action_executed"
    ACTION_FAILED = "action_failed"
    ACTION_ROLLED_BACK = "action_rolled_back"

    # Decision events
    DECISION_MADE = "decision_made"
    ESCALATION_TRIGGERED = "escalation_triggered"
    HUMAN_INTERVENTION = "human_intervention"

    # Security events
    GUARDRAIL_TRIGGERED = "guardrail_triggered"
    LIMIT_EXCEEDED = "limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"

    # System events
    CONFIG_CHANGED = "config_changed"
    SYSTEM_ERROR = "system_error"


class AuditEvent(BaseModel):
    """An audit event record."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: AuditEventType = Field(description="Type of event")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Context
    incident_id: str | None = Field(default=None)
    agent_id: str | None = Field(default=None)
    action_id: str | None = Field(default=None)

    # Actor
    actor_type: str = Field(default="system")  # system, agent, human
    actor_id: str | None = Field(default=None)

    # Event details
    summary: str = Field(description="Brief event description")
    details: dict[str, Any] = Field(default_factory=dict)

    # Risk and impact
    risk_level: str = Field(default="low")
    affected_entities: list[str] = Field(default_factory=list)

    # Traceability
    correlation_id: str | None = Field(default=None)
    parent_event_id: str | None = Field(default=None)


class AuditTrail(BaseModel):
    """A collection of related audit events."""

    trail_id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_id: str = Field(description="Correlation ID for the trail")
    incident_id: str | None = Field(default=None)

    events: list[AuditEvent] = Field(default_factory=list)

    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: datetime | None = Field(default=None)

    summary: str | None = Field(default=None)
    outcome: str | None = Field(default=None)


class AuditLogger(LoggerMixin):
    """Logger for comprehensive audit trail of agent operations.

    Features:
    - Structured event logging
    - Correlation tracking
    - Compliance support
    - Query capabilities
    - Export formats
    """

    def __init__(
        self,
        storage_path: Path | str | None = None,
        retention_days: int = 90,
        enable_file_logging: bool = True,
    ) -> None:
        """Initialize audit logger.

        Args:
            storage_path: Path to store audit logs
            retention_days: Days to retain logs
            enable_file_logging: Whether to log to files
        """
        self.storage_path = Path(storage_path) if storage_path else Path("./audit_logs")
        self.retention_days = retention_days
        self.enable_file_logging = enable_file_logging

        self._events: list[AuditEvent] = []
        self._trails: dict[str, AuditTrail] = {}
        self._correlation_map: dict[str, list[str]] = {}  # correlation_id -> event_ids

        if self.enable_file_logging:
            self.storage_path.mkdir(parents=True, exist_ok=True)

    def log_event(
        self,
        event_type: AuditEventType,
        summary: str,
        details: dict[str, Any] | None = None,
        incident_id: str | None = None,
        agent_id: str | None = None,
        action_id: str | None = None,
        actor_type: str = "system",
        actor_id: str | None = None,
        risk_level: str = "low",
        affected_entities: list[str] | None = None,
        correlation_id: str | None = None,
        parent_event_id: str | None = None,
    ) -> AuditEvent:
        """Log an audit event.

        Args:
            event_type: Type of event
            summary: Brief description
            details: Event details
            incident_id: Associated incident
            agent_id: Acting agent
            action_id: Related action
            actor_type: Type of actor
            actor_id: Actor identifier
            risk_level: Risk level
            affected_entities: Affected entities
            correlation_id: Correlation ID
            parent_event_id: Parent event

        Returns:
            Created audit event
        """
        event = AuditEvent(
            event_type=event_type,
            summary=summary,
            details=details or {},
            incident_id=incident_id,
            agent_id=agent_id,
            action_id=action_id,
            actor_type=actor_type,
            actor_id=actor_id,
            risk_level=risk_level,
            affected_entities=affected_entities or [],
            correlation_id=correlation_id,
            parent_event_id=parent_event_id,
        )

        self._events.append(event)

        # Update correlation map
        if correlation_id:
            if correlation_id not in self._correlation_map:
                self._correlation_map[correlation_id] = []
            self._correlation_map[correlation_id].append(event.event_id)

            # Update trail if exists
            if correlation_id in self._trails:
                self._trails[correlation_id].events.append(event)

        # Log to structured logger
        self.logger.info(
            f"audit_{event_type.value}",
            event_id=event.event_id,
            summary=summary,
            incident_id=incident_id,
            risk_level=risk_level,
        )

        # Write to file
        if self.enable_file_logging:
            self._write_to_file(event)

        return event

    def start_trail(
        self,
        correlation_id: str,
        incident_id: str | None = None,
    ) -> AuditTrail:
        """Start a new audit trail.

        Args:
            correlation_id: Correlation ID for the trail
            incident_id: Associated incident

        Returns:
            Created audit trail
        """
        trail = AuditTrail(
            correlation_id=correlation_id,
            incident_id=incident_id,
        )

        self._trails[correlation_id] = trail
        self._correlation_map[correlation_id] = []

        self.logger.info(
            "audit_trail_started",
            trail_id=trail.trail_id,
            correlation_id=correlation_id,
        )

        return trail

    def end_trail(
        self,
        correlation_id: str,
        summary: str | None = None,
        outcome: str | None = None,
    ) -> AuditTrail | None:
        """End an audit trail.

        Args:
            correlation_id: Trail correlation ID
            summary: Trail summary
            outcome: Trail outcome

        Returns:
            Ended trail or None if not found
        """
        trail = self._trails.get(correlation_id)
        if not trail:
            return None

        trail.ended_at = datetime.utcnow()
        trail.summary = summary
        trail.outcome = outcome

        self.logger.info(
            "audit_trail_ended",
            trail_id=trail.trail_id,
            correlation_id=correlation_id,
            event_count=len(trail.events),
            outcome=outcome,
        )

        return trail

    # Convenience methods for common event types
    def log_action_requested(
        self,
        action_type: str,
        targets: list[str],
        reason: str,
        incident_id: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Log an action request."""
        return self.log_event(
            event_type=AuditEventType.ACTION_REQUESTED,
            summary=f"Action requested: {action_type}",
            details={
                "action_type": action_type,
                "targets": targets,
                "reason": reason,
            },
            incident_id=incident_id,
            agent_id=agent_id,
            affected_entities=targets,
            correlation_id=correlation_id,
        )

    def log_action_executed(
        self,
        action_id: str,
        action_type: str,
        targets: list[str],
        success: bool,
        result: dict[str, Any] | None = None,
        incident_id: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Log an action execution."""
        return self.log_event(
            event_type=AuditEventType.ACTION_EXECUTED if success else AuditEventType.ACTION_FAILED,
            summary=f"Action {'executed' if success else 'failed'}: {action_type}",
            details={
                "action_type": action_type,
                "targets": targets,
                "success": success,
                "result": result or {},
            },
            incident_id=incident_id,
            agent_id=agent_id,
            action_id=action_id,
            affected_entities=targets,
            correlation_id=correlation_id,
            risk_level="medium" if not success else "low",
        )

    def log_decision(
        self,
        decision_type: str,
        decision: str,
        reasoning: str,
        confidence: float,
        incident_id: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Log a decision made by an agent."""
        return self.log_event(
            event_type=AuditEventType.DECISION_MADE,
            summary=f"Decision: {decision_type} -> {decision}",
            details={
                "decision_type": decision_type,
                "decision": decision,
                "reasoning": reasoning,
                "confidence": confidence,
            },
            incident_id=incident_id,
            agent_id=agent_id,
            actor_type="agent",
            actor_id=agent_id,
            correlation_id=correlation_id,
        )

    def log_guardrail_triggered(
        self,
        guardrail_id: str,
        action_type: str,
        reason: str,
        incident_id: str | None = None,
        agent_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Log a guardrail being triggered."""
        return self.log_event(
            event_type=AuditEventType.GUARDRAIL_TRIGGERED,
            summary=f"Guardrail triggered: {guardrail_id}",
            details={
                "guardrail_id": guardrail_id,
                "action_type": action_type,
                "reason": reason,
            },
            incident_id=incident_id,
            agent_id=agent_id,
            risk_level="medium",
            correlation_id=correlation_id,
        )

    def log_human_intervention(
        self,
        intervention_type: str,
        human_id: str,
        action: str,
        incident_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditEvent:
        """Log human intervention."""
        return self.log_event(
            event_type=AuditEventType.HUMAN_INTERVENTION,
            summary=f"Human intervention: {intervention_type}",
            details={
                "intervention_type": intervention_type,
                "action": action,
            },
            incident_id=incident_id,
            actor_type="human",
            actor_id=human_id,
            correlation_id=correlation_id,
        )

    def _write_to_file(self, event: AuditEvent) -> None:
        """Write event to file."""
        date_str = event.timestamp.strftime("%Y-%m-%d")
        file_path = self.storage_path / f"audit_{date_str}.jsonl"

        event_dict = event.model_dump()
        event_dict["timestamp"] = event.timestamp.isoformat()

        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_dict) + "\n")

    def query_events(
        self,
        event_type: AuditEventType | None = None,
        incident_id: str | None = None,
        agent_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        risk_level: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events.

        Args:
            event_type: Filter by event type
            incident_id: Filter by incident
            agent_id: Filter by agent
            start_time: Start of time range
            end_time: End of time range
            risk_level: Filter by risk level
            limit: Maximum results

        Returns:
            Matching events
        """
        results = []

        for event in reversed(self._events):  # Most recent first
            if event_type and event.event_type != event_type:
                continue
            if incident_id and event.incident_id != incident_id:
                continue
            if agent_id and event.agent_id != agent_id:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            if risk_level and event.risk_level != risk_level:
                continue

            results.append(event)

            if len(results) >= limit:
                break

        return results

    def get_trail(self, correlation_id: str) -> AuditTrail | None:
        """Get an audit trail by correlation ID."""
        return self._trails.get(correlation_id)

    def get_correlated_events(self, correlation_id: str) -> list[AuditEvent]:
        """Get all events for a correlation ID."""
        event_ids = self._correlation_map.get(correlation_id, [])
        return [e for e in self._events if e.event_id in event_ids]

    def get_incident_events(self, incident_id: str) -> list[AuditEvent]:
        """Get all events for an incident."""
        return [e for e in self._events if e.incident_id == incident_id]

    def export_trail(
        self,
        correlation_id: str,
        format: str = "json",
    ) -> str:
        """Export an audit trail.

        Args:
            correlation_id: Trail to export
            format: Export format (json, csv)

        Returns:
            Exported trail data
        """
        trail = self._trails.get(correlation_id)
        if not trail:
            return ""

        if format == "json":
            trail_dict = trail.model_dump()
            trail_dict["started_at"] = trail.started_at.isoformat()
            if trail.ended_at:
                trail_dict["ended_at"] = trail.ended_at.isoformat()
            for event in trail_dict["events"]:
                event["timestamp"] = event["timestamp"].isoformat() if event["timestamp"] else None
            return json.dumps(trail_dict, indent=2)

        elif format == "csv":
            lines = ["event_id,event_type,timestamp,summary,risk_level"]
            for event in trail.events:
                lines.append(
                    f"{event.event_id},{event.event_type.value},{event.timestamp.isoformat()},{event.summary},{event.risk_level}"
                )
            return "\n".join(lines)

        return ""

    def get_stats(self) -> dict[str, Any]:
        """Get audit statistics."""
        events = self._events

        return {
            "total_events": len(events),
            "active_trails": len([t for t in self._trails.values() if not t.ended_at]),
            "completed_trails": len([t for t in self._trails.values() if t.ended_at]),
            "by_type": {
                event_type.value: len([e for e in events if e.event_type == event_type])
                for event_type in AuditEventType
            },
            "by_risk_level": {
                "low": len([e for e in events if e.risk_level == "low"]),
                "medium": len([e for e in events if e.risk_level == "medium"]),
                "high": len([e for e in events if e.risk_level == "high"]),
                "critical": len([e for e in events if e.risk_level == "critical"]),
            },
        }
