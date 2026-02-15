"""Timeline Builder - Construct incident timelines from evidence."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .evidence_gatherer import Evidence, EvidenceCollection, EvidenceType


class EventCategory(str, Enum):
    """Categories of timeline events."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    DETECTION = "detection"
    RESPONSE = "response"
    UNKNOWN = "unknown"


class TimelineEvent(BaseModel):
    """A single event in the timeline."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(description="Event timestamp")
    title: str = Field(description="Event title/summary")
    description: str = Field(default="", description="Detailed description")
    category: EventCategory = Field(default=EventCategory.UNKNOWN)

    # Source
    source: str = Field(description="Source of the event")
    source_id: str | None = Field(default=None)
    evidence_ids: list[str] = Field(default_factory=list)

    # Entities
    entities: list[dict[str, str]] = Field(default_factory=list)

    # MITRE ATT&CK
    mitre_tactic: str | None = Field(default=None)
    mitre_technique: str | None = Field(default=None)

    # Classification
    severity: str = Field(default="info")
    confidence: float = Field(default=0.5, ge=0, le=1)

    # Visual
    icon: str | None = Field(default=None)
    color: str | None = Field(default=None)


class Timeline(BaseModel):
    """Complete incident timeline."""

    timeline_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str | None = Field(default=None)
    investigation_id: str | None = Field(default=None)

    events: list[TimelineEvent] = Field(default_factory=list)

    # Time bounds
    start_time: datetime | None = Field(default=None)
    end_time: datetime | None = Field(default=None)

    # Statistics
    event_count: int = Field(default=0)
    duration_minutes: int | None = Field(default=None)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = Field(default="TimelineBuilder")
    summary: str | None = Field(default=None)


class TimelineBuilder(LoggerMixin):
    """Builder for constructing incident timelines.

    Features:
    - Event extraction from evidence
    - Timeline correlation
    - MITRE ATT&CK mapping
    - Event categorization
    - Gap detection
    """

    # MITRE tactic to category mapping
    TACTIC_MAPPING = {
        "initial-access": EventCategory.INITIAL_ACCESS,
        "execution": EventCategory.EXECUTION,
        "persistence": EventCategory.PERSISTENCE,
        "privilege-escalation": EventCategory.PRIVILEGE_ESCALATION,
        "defense-evasion": EventCategory.DEFENSE_EVASION,
        "credential-access": EventCategory.CREDENTIAL_ACCESS,
        "discovery": EventCategory.DISCOVERY,
        "lateral-movement": EventCategory.LATERAL_MOVEMENT,
        "collection": EventCategory.COLLECTION,
        "command-and-control": EventCategory.COMMAND_AND_CONTROL,
        "exfiltration": EventCategory.EXFILTRATION,
        "impact": EventCategory.IMPACT,
    }

    # Alert type to category mapping
    ALERT_TYPE_MAPPING = {
        "phishing": EventCategory.INITIAL_ACCESS,
        "malware": EventCategory.EXECUTION,
        "ransomware": EventCategory.IMPACT,
        "brute_force": EventCategory.CREDENTIAL_ACCESS,
        "lateral_movement": EventCategory.LATERAL_MOVEMENT,
        "data_exfil": EventCategory.EXFILTRATION,
        "c2_communication": EventCategory.COMMAND_AND_CONTROL,
        "privilege_escalation": EventCategory.PRIVILEGE_ESCALATION,
    }

    def __init__(self) -> None:
        """Initialize timeline builder."""
        pass

    def build_from_evidence(
        self,
        collection: EvidenceCollection,
        case_id: str | None = None,
        investigation_id: str | None = None,
    ) -> Timeline:
        """Build timeline from evidence collection.

        Args:
            collection: Evidence collection
            case_id: Associated case ID
            investigation_id: Associated investigation ID

        Returns:
            Constructed timeline
        """
        self.logger.info(
            "building_timeline",
            collection_id=collection.collection_id,
            evidence_count=len(collection.evidence_items),
        )

        timeline = Timeline(
            case_id=case_id or collection.case_id,
            investigation_id=investigation_id or collection.investigation_id,
        )

        # Extract events from each evidence item
        for evidence in collection.evidence_items:
            events = self._extract_events(evidence)
            timeline.events.extend(events)

        # Sort by timestamp
        timeline.events.sort(key=lambda e: e.timestamp)

        # Calculate statistics
        if timeline.events:
            timeline.start_time = timeline.events[0].timestamp
            timeline.end_time = timeline.events[-1].timestamp
            timeline.event_count = len(timeline.events)

            duration = timeline.end_time - timeline.start_time
            timeline.duration_minutes = int(duration.total_seconds() / 60)

        # Correlate and enrich
        self._correlate_events(timeline)

        # Generate summary
        timeline.summary = self._generate_summary(timeline)

        self.logger.info(
            "timeline_built",
            timeline_id=timeline.timeline_id,
            event_count=timeline.event_count,
        )

        return timeline

    def _extract_events(self, evidence: Evidence) -> list[TimelineEvent]:
        """Extract timeline events from evidence."""
        events = []

        # Get timestamp
        timestamp = self._get_timestamp(evidence)
        if not timestamp:
            return events

        # Extract based on evidence type
        if evidence.evidence_type == EvidenceType.ALERT:
            event = self._extract_from_alert(evidence, timestamp)
            if event:
                events.append(event)

        elif evidence.evidence_type == EvidenceType.LOG_EVENT:
            event = self._extract_from_log(evidence, timestamp)
            if event:
                events.append(event)

        elif evidence.evidence_type == EvidenceType.NETWORK_FLOW:
            event = self._extract_from_flow(evidence, timestamp)
            if event:
                events.append(event)

        elif evidence.evidence_type == EvidenceType.USER_ACTIVITY:
            event = self._extract_from_user_activity(evidence, timestamp)
            if event:
                events.append(event)

        elif evidence.evidence_type == EvidenceType.THREAT_INTEL:
            # Threat intel doesn't create timeline events directly
            pass

        elif evidence.evidence_type == EvidenceType.FILE_ARTIFACT:
            event = self._extract_from_file(evidence, timestamp)
            if event:
                events.append(event)

        elif evidence.evidence_type == EvidenceType.PROCESS_INFO:
            event = self._extract_from_process(evidence, timestamp)
            if event:
                events.append(event)

        return events

    def _get_timestamp(self, evidence: Evidence) -> datetime | None:
        """Extract timestamp from evidence."""
        # Try original timestamp first
        if evidence.original_timestamp:
            return evidence.original_timestamp

        # Try common timestamp fields in data
        data = evidence.data
        for field in ["timestamp", "@timestamp", "time", "event_time", "created_at"]:
            if ts := data.get(field):
                try:
                    if isinstance(ts, datetime):
                        return ts
                    if isinstance(ts, str):
                        # Try ISO format
                        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    continue

        # Fall back to collection time
        return evidence.collected_at

    def _extract_from_alert(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from alert evidence."""
        data = evidence.data
        alert_type = data.get("alert_type", data.get("rule_name", "Alert"))
        severity = data.get("severity", "medium")

        # Determine category
        category = EventCategory.DETECTION
        for pattern, cat in self.ALERT_TYPE_MAPPING.items():
            if pattern in alert_type.lower():
                category = cat
                break

        # Extract entities
        entities = self._extract_entities(data)

        return TimelineEvent(
            timestamp=timestamp,
            title=f"Alert: {alert_type}",
            description=data.get("description", "")[:500],
            category=category,
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=entities,
            mitre_tactic=data.get("mitre_tactic"),
            mitre_technique=data.get("mitre_technique"),
            severity=severity,
            confidence=0.9,
            icon="alert-triangle",
            color=self._severity_color(severity),
        )

    def _extract_from_log(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from log evidence."""
        data = evidence.data
        event_type = data.get("event_type", data.get("action", "Log Event"))

        # Determine category from event type
        category = self._categorize_event(event_type, data)

        return TimelineEvent(
            timestamp=timestamp,
            title=event_type,
            description=data.get("message", str(data)[:200]),
            category=category,
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=self._extract_entities(data),
            severity=data.get("severity", "info"),
            confidence=0.7,
            icon="file-text",
        )

    def _extract_from_flow(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from network flow evidence."""
        data = evidence.data

        src_ip = data.get("src_ip") or data.get("source_ip")
        dst_ip = data.get("dst_ip") or data.get("destination_ip")
        dst_port = data.get("dst_port") or data.get("destination_port")
        protocol = data.get("protocol", "TCP")
        bytes_sent = data.get("bytes_out") or data.get("bytes_sent", 0)

        title = f"Network: {src_ip} → {dst_ip}:{dst_port} ({protocol})"

        return TimelineEvent(
            timestamp=timestamp,
            title=title,
            description=f"Bytes: {bytes_sent}, Action: {data.get('action', 'allow')}",
            category=EventCategory.UNKNOWN,
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=[
                {"type": "ip", "value": src_ip, "role": "source"},
                {"type": "ip", "value": dst_ip, "role": "destination"},
            ],
            severity="info",
            confidence=0.6,
            icon="network",
        )

    def _extract_from_user_activity(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from user activity evidence."""
        data = evidence.data
        user = data.get("user") or data.get("username")
        action = data.get("action") or data.get("event_type", "User Action")

        return TimelineEvent(
            timestamp=timestamp,
            title=f"User: {action}",
            description=f"User {user}: {data.get('details', '')}",
            category=self._categorize_user_action(action),
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=[{"type": "user", "value": user}] if user else [],
            severity=data.get("severity", "info"),
            confidence=0.7,
            icon="user",
        )

    def _extract_from_file(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from file evidence."""
        data = evidence.data
        filename = data.get("filename") or data.get("file_name", "unknown")
        action = data.get("action", "file_access")

        return TimelineEvent(
            timestamp=timestamp,
            title=f"File: {action}",
            description=f"File: {filename}",
            category=EventCategory.EXECUTION if action in ["execute", "run"] else EventCategory.UNKNOWN,
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=[{"type": "file", "value": filename}],
            severity=data.get("severity", "info"),
            confidence=0.6,
            icon="file",
        )

    def _extract_from_process(
        self,
        evidence: Evidence,
        timestamp: datetime,
    ) -> TimelineEvent | None:
        """Extract event from process evidence."""
        data = evidence.data
        process_name = data.get("process_name") or data.get("image", "unknown")
        cmd_line = data.get("command_line", data.get("cmd", ""))

        return TimelineEvent(
            timestamp=timestamp,
            title=f"Process: {process_name}",
            description=cmd_line[:300] if cmd_line else "",
            category=EventCategory.EXECUTION,
            source=evidence.source,
            source_id=evidence.source_id,
            evidence_ids=[evidence.evidence_id],
            entities=[{"type": "process", "value": process_name}],
            severity=data.get("severity", "info"),
            confidence=0.7,
            icon="terminal",
        )

    def _extract_entities(self, data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract entities from event data."""
        entities = []

        # IPs
        for field in ["source_ip", "src_ip", "destination_ip", "dst_ip", "ip"]:
            if val := data.get(field):
                role = "source" if "src" in field or "source" in field else "destination"
                entities.append({"type": "ip", "value": val, "role": role})

        # Users
        for field in ["user", "username", "user_name", "account"]:
            if val := data.get(field):
                entities.append({"type": "user", "value": val})

        # Hosts
        for field in ["host", "hostname", "computer_name", "machine"]:
            if val := data.get(field):
                entities.append({"type": "host", "value": val})

        return entities

    def _categorize_event(
        self,
        event_type: str,
        data: dict[str, Any],
    ) -> EventCategory:
        """Categorize event based on type and data."""
        event_lower = event_type.lower()

        # Check for MITRE tactic in data
        if tactic := data.get("mitre_tactic"):
            tactic_key = tactic.lower().replace(" ", "-")
            if category := self.TACTIC_MAPPING.get(tactic_key):
                return category

        # Pattern matching
        patterns = {
            EventCategory.INITIAL_ACCESS: ["login", "logon", "authentication", "access"],
            EventCategory.EXECUTION: ["execute", "process", "command", "script", "powershell"],
            EventCategory.PERSISTENCE: ["scheduled", "registry", "service", "startup"],
            EventCategory.CREDENTIAL_ACCESS: ["credential", "password", "kerberos", "ntlm"],
            EventCategory.DISCOVERY: ["scan", "enumerate", "query", "discovery"],
            EventCategory.LATERAL_MOVEMENT: ["lateral", "rdp", "ssh", "wmi", "psexec"],
            EventCategory.EXFILTRATION: ["upload", "exfil", "transfer_out"],
        }

        for category, keywords in patterns.items():
            if any(kw in event_lower for kw in keywords):
                return category

        return EventCategory.UNKNOWN

    def _categorize_user_action(self, action: str) -> EventCategory:
        """Categorize user action."""
        action_lower = action.lower()

        if any(kw in action_lower for kw in ["login", "logon", "authenticate"]):
            return EventCategory.INITIAL_ACCESS
        if any(kw in action_lower for kw in ["privilege", "admin", "sudo"]):
            return EventCategory.PRIVILEGE_ESCALATION
        if any(kw in action_lower for kw in ["download", "upload", "transfer"]):
            return EventCategory.EXFILTRATION

        return EventCategory.UNKNOWN

    def _severity_color(self, severity: str) -> str:
        """Get color for severity level."""
        colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
            "info": "#3b82f6",
        }
        return colors.get(severity.lower(), "#6b7280")

    def _correlate_events(self, timeline: Timeline) -> None:
        """Correlate events in timeline."""
        events = timeline.events

        # Group by entity
        entity_events: dict[str, list[TimelineEvent]] = {}
        for event in events:
            for entity in event.entities:
                key = f"{entity.get('type')}:{entity.get('value')}"
                if key not in entity_events:
                    entity_events[key] = []
                entity_events[key].append(event)

        # Increase confidence for correlated events
        for entity_key, related_events in entity_events.items():
            if len(related_events) > 1:
                for event in related_events:
                    event.confidence = min(event.confidence + 0.1, 1.0)

    def _generate_summary(self, timeline: Timeline) -> str:
        """Generate timeline summary."""
        if not timeline.events:
            return "No events in timeline."

        # Count by category
        category_counts = {}
        for event in timeline.events:
            cat = event.category.value
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Find key events
        high_severity = [e for e in timeline.events if e.severity in ["critical", "high"]]

        parts = [
            f"Timeline Summary",
            f"Duration: {timeline.duration_minutes} minutes" if timeline.duration_minutes else "",
            f"Total Events: {timeline.event_count}",
            f"High Severity Events: {len(high_severity)}",
            "",
            "Event Categories:",
        ]

        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            parts.append(f"  - {cat}: {count}")

        if high_severity:
            parts.append("")
            parts.append("Key Events:")
            for event in high_severity[:5]:
                parts.append(f"  - [{event.timestamp.strftime('%H:%M:%S')}] {event.title}")

        return "\n".join(parts)

    def detect_gaps(
        self,
        timeline: Timeline,
        max_gap_minutes: int = 60,
    ) -> list[dict[str, Any]]:
        """Detect gaps in timeline where activity is missing.

        Args:
            timeline: Timeline to analyze
            max_gap_minutes: Threshold for significant gaps

        Returns:
            List of detected gaps
        """
        gaps = []
        events = timeline.events

        if len(events) < 2:
            return gaps

        for i in range(len(events) - 1):
            current = events[i]
            next_event = events[i + 1]

            gap_duration = (next_event.timestamp - current.timestamp).total_seconds() / 60

            if gap_duration > max_gap_minutes:
                gaps.append({
                    "start_time": current.timestamp,
                    "end_time": next_event.timestamp,
                    "duration_minutes": int(gap_duration),
                    "before_event": current.title,
                    "after_event": next_event.title,
                })

        return gaps

    def merge_timelines(self, timelines: list[Timeline]) -> Timeline:
        """Merge multiple timelines into one.

        Args:
            timelines: Timelines to merge

        Returns:
            Merged timeline
        """
        merged = Timeline()

        for timeline in timelines:
            merged.events.extend(timeline.events)

        # Sort and recalculate
        merged.events.sort(key=lambda e: e.timestamp)

        if merged.events:
            merged.start_time = merged.events[0].timestamp
            merged.end_time = merged.events[-1].timestamp
            merged.event_count = len(merged.events)

            duration = merged.end_time - merged.start_time
            merged.duration_minutes = int(duration.total_seconds() / 60)

        self._correlate_events(merged)
        merged.summary = self._generate_summary(merged)

        return merged
