"""End-to-end tests for Alert to Case workflow.

Tests the complete flow: Alert -> Triage -> Enrichment -> SOAR -> Case Creation
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import pytest


# Enums
class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    CLOSED = "closed"


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Data classes
@dataclass
class Alert:
    alert_id: str
    title: str
    description: str
    severity: str
    source: str
    category: str | None = None
    events: list[dict] = field(default_factory=list)
    enrichments: dict = field(default_factory=dict)
    status: AlertStatus = AlertStatus.NEW
    triage_result: dict | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus = CaseStatus.OPEN
    alerts: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    playbook_executions: list[str] = field(default_factory=list)
    assigned_analyst: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None


@dataclass
class Evidence:
    evidence_id: str
    type: str
    data: dict
    source: str
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Services
class AlertService:
    """Manages alerts."""

    def __init__(self):
        self.alerts: dict[str, Alert] = {}

    def create(self, alert: Alert) -> Alert:
        """Create a new alert."""
        self.alerts[alert.alert_id] = alert
        return alert

    def get(self, alert_id: str) -> Alert | None:
        """Get alert by ID."""
        return self.alerts.get(alert_id)

    def update(self, alert: Alert) -> Alert:
        """Update an alert."""
        self.alerts[alert.alert_id] = alert
        alert.updated_at = datetime.now(timezone.utc)
        return alert

    def list_by_status(self, status: AlertStatus) -> list[Alert]:
        """List alerts by status."""
        return [a for a in self.alerts.values() if a.status == status]


class TriageService:
    """AI-powered alert triage."""

    def __init__(self):
        self.category_keywords = {
            "malware": ["malware", "virus", "trojan"],
            "phishing": ["phishing", "credential"],
            "intrusion": ["intrusion", "breach"],
            "ransomware": ["ransomware", "encrypt"],
        }

    async def triage(self, alert: Alert) -> dict:
        """Triage an alert."""
        text = f"{alert.title} {alert.description}".lower()

        # Classify
        category = "unknown"
        for cat, keywords in self.category_keywords.items():
            if any(kw in text for kw in keywords):
                category = cat
                break

        # Determine if escalation needed
        escalate = alert.severity in ["critical", "high"] or category == "ransomware"

        result = {
            "category": category,
            "severity": alert.severity,
            "confidence": 0.85,
            "is_true_positive": True,
            "escalate": escalate,
            "recommended_actions": [],
        }

        if escalate:
            result["recommended_actions"].append("create_case")
            result["recommended_actions"].append("execute_containment")
        else:
            result["recommended_actions"].append("enrich")

        return result


class EnrichmentService:
    """Enriches alerts with additional context."""

    def __init__(self):
        self.threat_intel_db = {
            "malicious.com": {"reputation": "malicious", "score": 95},
            "10.0.0.100": {"reputation": "suspicious", "score": 75},
        }

    async def enrich(self, alert: Alert) -> dict:
        """Enrich an alert."""
        enrichments = {}

        # Extract indicators from events
        for event in alert.events:
            if "source_ip" in event:
                ip = event["source_ip"]
                if ip in self.threat_intel_db:
                    enrichments["threat_intel"] = self.threat_intel_db[ip]

            if "domain" in event:
                domain = event["domain"]
                if domain in self.threat_intel_db:
                    enrichments["threat_intel"] = self.threat_intel_db[domain]

        # Add GeoIP mock
        enrichments["geoip"] = {"country": "US", "city": "New York"}

        # Add asset info mock
        enrichments["asset"] = {
            "hostname": "workstation-001",
            "owner": "IT Department",
            "criticality": "medium",
        }

        return enrichments


class PlaybookService:
    """Executes SOAR playbooks."""

    def __init__(self):
        self.executions: dict[str, dict] = {}

    async def execute(
        self, playbook_id: str, trigger_data: dict
    ) -> dict:
        """Execute a playbook."""
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"

        execution = {
            "execution_id": execution_id,
            "playbook_id": playbook_id,
            "status": "running",
            "trigger_data": trigger_data,
            "steps": [],
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        # Simulate playbook execution
        if playbook_id == "pb-enrichment":
            execution["steps"] = [
                {"step": "threat_intel_lookup", "status": "completed"},
                {"step": "geoip_lookup", "status": "completed"},
            ]
        elif playbook_id == "pb-containment":
            execution["steps"] = [
                {"step": "block_ip", "status": "completed"},
                {"step": "isolate_host", "status": "completed"},
                {"step": "notify_soc", "status": "completed"},
            ]

        execution["status"] = "completed"
        execution["completed_at"] = datetime.now(timezone.utc).isoformat()

        self.executions[execution_id] = execution
        return execution


class CaseService:
    """Manages security cases."""

    def __init__(self):
        self.cases: dict[str, Case] = {}

    def create(
        self,
        title: str,
        description: str,
        priority: CasePriority,
        alerts: list[str],
    ) -> Case:
        """Create a new case."""
        case = Case(
            case_id=f"case-{uuid.uuid4().hex[:8]}",
            title=title,
            description=description,
            priority=priority,
            alerts=alerts,
        )
        self.cases[case.case_id] = case
        return case

    def get(self, case_id: str) -> Case | None:
        """Get case by ID."""
        return self.cases.get(case_id)

    def update(self, case: Case) -> Case:
        """Update a case."""
        case.updated_at = datetime.now(timezone.utc)
        self.cases[case.case_id] = case
        return case

    def add_evidence(self, case_id: str, evidence: Evidence) -> bool:
        """Add evidence to a case."""
        case = self.cases.get(case_id)
        if case:
            case.evidence.append({
                "evidence_id": evidence.evidence_id,
                "type": evidence.type,
                "data": evidence.data,
                "source": evidence.source,
            })
            case.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def add_timeline_event(self, case_id: str, event: dict) -> bool:
        """Add timeline event to a case."""
        case = self.cases.get(case_id)
        if case:
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
            case.timeline.append(event)
            case.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def assign(self, case_id: str, analyst: str) -> bool:
        """Assign case to analyst."""
        case = self.cases.get(case_id)
        if case:
            case.assigned_analyst = analyst
            case.updated_at = datetime.now(timezone.utc)
            return True
        return False


class AlertToCaseOrchestrator:
    """Orchestrates the alert to case workflow."""

    def __init__(
        self,
        alert_service: AlertService,
        triage_service: TriageService,
        enrichment_service: EnrichmentService,
        playbook_service: PlaybookService,
        case_service: CaseService,
    ):
        self.alert_service = alert_service
        self.triage_service = triage_service
        self.enrichment_service = enrichment_service
        self.playbook_service = playbook_service
        self.case_service = case_service

    async def process_alert(self, alert: Alert) -> dict:
        """Process an alert through the complete workflow."""
        result = {
            "alert_id": alert.alert_id,
            "steps": [],
            "case_id": None,
            "playbook_executions": [],
        }

        # Step 1: Store alert
        self.alert_service.create(alert)
        result["steps"].append({"step": "create_alert", "status": "completed"})

        # Step 2: Triage
        triage_result = await self.triage_service.triage(alert)
        alert.triage_result = triage_result
        alert.category = triage_result["category"]
        alert.status = AlertStatus.TRIAGED
        self.alert_service.update(alert)
        result["steps"].append({"step": "triage", "status": "completed", "result": triage_result})

        # Step 3: Enrich
        enrichments = await self.enrichment_service.enrich(alert)
        alert.enrichments = enrichments
        self.alert_service.update(alert)
        result["steps"].append({"step": "enrich", "status": "completed"})

        # Step 4: Execute playbooks based on recommendations
        for action in triage_result.get("recommended_actions", []):
            if action == "enrich":
                execution = await self.playbook_service.execute(
                    "pb-enrichment", {"alert_id": alert.alert_id}
                )
                result["playbook_executions"].append(execution)

            elif action == "execute_containment":
                execution = await self.playbook_service.execute(
                    "pb-containment", {"alert_id": alert.alert_id}
                )
                result["playbook_executions"].append(execution)

        # Step 5: Create case if escalation needed
        if triage_result.get("escalate"):
            priority = CasePriority.CRITICAL if alert.severity == "critical" else CasePriority.HIGH

            case = self.case_service.create(
                title=f"Investigation: {alert.title}",
                description=f"Case created from alert {alert.alert_id}",
                priority=priority,
                alerts=[alert.alert_id],
            )

            # Add evidence
            evidence = Evidence(
                evidence_id=f"ev-{uuid.uuid4().hex[:8]}",
                type="alert",
                data={"alert": alert.__dict__},
                source="alert_triage",
            )
            self.case_service.add_evidence(case.case_id, evidence)

            # Add timeline event
            self.case_service.add_timeline_event(case.case_id, {
                "event": "case_created",
                "description": f"Case created from alert {alert.alert_id}",
            })

            alert.status = AlertStatus.ESCALATED
            self.alert_service.update(alert)

            result["case_id"] = case.case_id
            result["steps"].append({"step": "create_case", "status": "completed"})

        return result


# Fixtures
@pytest.fixture
def alert_service():
    return AlertService()


@pytest.fixture
def triage_service():
    return TriageService()


@pytest.fixture
def enrichment_service():
    return EnrichmentService()


@pytest.fixture
def playbook_service():
    return PlaybookService()


@pytest.fixture
def case_service():
    return CaseService()


@pytest.fixture
def orchestrator(
    alert_service,
    triage_service,
    enrichment_service,
    playbook_service,
    case_service,
):
    return AlertToCaseOrchestrator(
        alert_service,
        triage_service,
        enrichment_service,
        playbook_service,
        case_service,
    )


@pytest.fixture
def critical_alert():
    return Alert(
        alert_id="alert-001",
        title="Ransomware Detected",
        description="Critical ransomware encryption activity detected",
        severity="critical",
        source="edr",
        events=[
            {"source_ip": "10.0.0.100", "process": "suspicious.exe"},
        ],
    )


@pytest.fixture
def medium_alert():
    return Alert(
        alert_id="alert-002",
        title="Suspicious Network Activity",
        description="Unusual outbound connections detected",
        severity="medium",
        source="ndr",
        events=[
            {"source_ip": "192.168.1.50", "destination": "external.com"},
        ],
    )


# Test cases
class TestAlertService:
    """Tests for AlertService."""

    def test_create_alert(self, alert_service, critical_alert):
        """Test alert creation."""
        result = alert_service.create(critical_alert)

        assert result.alert_id == critical_alert.alert_id
        assert alert_service.get(critical_alert.alert_id) is not None

    def test_update_alert(self, alert_service, critical_alert):
        """Test alert update."""
        alert_service.create(critical_alert)

        critical_alert.status = AlertStatus.TRIAGED
        result = alert_service.update(critical_alert)

        assert result.status == AlertStatus.TRIAGED

    def test_list_by_status(self, alert_service, critical_alert, medium_alert):
        """Test listing alerts by status."""
        alert_service.create(critical_alert)
        alert_service.create(medium_alert)

        critical_alert.status = AlertStatus.TRIAGED
        alert_service.update(critical_alert)

        triaged = alert_service.list_by_status(AlertStatus.TRIAGED)
        new = alert_service.list_by_status(AlertStatus.NEW)

        assert len(triaged) == 1
        assert len(new) == 1


class TestTriageService:
    """Tests for TriageService."""

    @pytest.mark.asyncio
    async def test_triage_ransomware(self, triage_service, critical_alert):
        """Test ransomware triage."""
        result = await triage_service.triage(critical_alert)

        assert result["category"] == "ransomware"
        assert result["escalate"] is True
        assert "create_case" in result["recommended_actions"]

    @pytest.mark.asyncio
    async def test_triage_low_severity(self, triage_service, medium_alert):
        """Test low severity triage."""
        result = await triage_service.triage(medium_alert)

        assert result["escalate"] is False
        assert "enrich" in result["recommended_actions"]


class TestEnrichmentService:
    """Tests for EnrichmentService."""

    @pytest.mark.asyncio
    async def test_enrich_with_threat_intel(self, enrichment_service, critical_alert):
        """Test enrichment with threat intel."""
        result = await enrichment_service.enrich(critical_alert)

        assert "threat_intel" in result
        assert "geoip" in result
        assert "asset" in result


class TestPlaybookService:
    """Tests for PlaybookService."""

    @pytest.mark.asyncio
    async def test_execute_enrichment_playbook(self, playbook_service):
        """Test enrichment playbook execution."""
        result = await playbook_service.execute(
            "pb-enrichment", {"alert_id": "test"}
        )

        assert result["status"] == "completed"
        assert len(result["steps"]) > 0

    @pytest.mark.asyncio
    async def test_execute_containment_playbook(self, playbook_service):
        """Test containment playbook execution."""
        result = await playbook_service.execute(
            "pb-containment", {"alert_id": "test"}
        )

        assert result["status"] == "completed"
        assert any(s["step"] == "block_ip" for s in result["steps"])


class TestCaseService:
    """Tests for CaseService."""

    def test_create_case(self, case_service):
        """Test case creation."""
        case = case_service.create(
            title="Test Case",
            description="Test description",
            priority=CasePriority.HIGH,
            alerts=["alert-001"],
        )

        assert case.case_id.startswith("case-")
        assert case.status == CaseStatus.OPEN
        assert case_service.get(case.case_id) is not None

    def test_add_evidence(self, case_service):
        """Test adding evidence to case."""
        case = case_service.create(
            title="Test Case",
            description="Test",
            priority=CasePriority.MEDIUM,
            alerts=[],
        )

        evidence = Evidence(
            evidence_id="ev-001",
            type="log",
            data={"log": "test"},
            source="test",
        )

        result = case_service.add_evidence(case.case_id, evidence)

        assert result is True
        assert len(case.evidence) == 1

    def test_add_timeline_event(self, case_service):
        """Test adding timeline event."""
        case = case_service.create(
            title="Test Case",
            description="Test",
            priority=CasePriority.MEDIUM,
            alerts=[],
        )

        result = case_service.add_timeline_event(case.case_id, {
            "event": "test_event",
            "description": "Test happened",
        })

        assert result is True
        assert len(case.timeline) == 1

    def test_assign_analyst(self, case_service):
        """Test assigning analyst."""
        case = case_service.create(
            title="Test Case",
            description="Test",
            priority=CasePriority.MEDIUM,
            alerts=[],
        )

        result = case_service.assign(case.case_id, "analyst-1")

        assert result is True
        assert case.assigned_analyst == "analyst-1"


class TestAlertToCaseOrchestrator:
    """Tests for AlertToCaseOrchestrator."""

    @pytest.mark.asyncio
    async def test_process_critical_alert(
        self, orchestrator, critical_alert, case_service
    ):
        """Test processing critical alert creates case."""
        result = await orchestrator.process_alert(critical_alert)

        assert result["case_id"] is not None
        assert len(result["steps"]) >= 3
        assert len(result["playbook_executions"]) > 0

        # Verify case was created
        case = case_service.get(result["case_id"])
        assert case is not None
        assert case.priority == CasePriority.CRITICAL
        assert critical_alert.alert_id in case.alerts

    @pytest.mark.asyncio
    async def test_process_medium_alert(
        self, orchestrator, medium_alert, case_service
    ):
        """Test processing medium alert does not create case."""
        result = await orchestrator.process_alert(medium_alert)

        assert result["case_id"] is None
        assert len(result["steps"]) >= 2  # triage + enrich

    @pytest.mark.asyncio
    async def test_complete_workflow(self, orchestrator, critical_alert, case_service):
        """Test complete workflow execution."""
        result = await orchestrator.process_alert(critical_alert)

        # Verify all steps completed
        step_names = [s["step"] for s in result["steps"]]
        assert "create_alert" in step_names
        assert "triage" in step_names
        assert "enrich" in step_names
        assert "create_case" in step_names

        # Verify case has evidence
        case = case_service.get(result["case_id"])
        assert len(case.evidence) > 0

        # Verify case has timeline
        assert len(case.timeline) > 0


class TestEndToEndWorkflow:
    """End-to-end workflow tests."""

    @pytest.mark.asyncio
    async def test_multiple_alerts_same_incident(self, orchestrator, case_service):
        """Test handling multiple related alerts."""
        alerts = [
            Alert(
                alert_id=f"alert-{i}",
                title="Ransomware Activity",
                description=f"Encryption detected on host-{i}",
                severity="critical",
                source="edr",
                events=[{"host": f"host-{i}"}],
            )
            for i in range(3)
        ]

        results = []
        for alert in alerts:
            result = await orchestrator.process_alert(alert)
            results.append(result)

        # Each alert creates a case (in real scenario they might be merged)
        assert all(r["case_id"] is not None for r in results)

    @pytest.mark.asyncio
    async def test_workflow_performance(self, orchestrator):
        """Test workflow performance with many alerts."""
        alerts = [
            Alert(
                alert_id=f"perf-alert-{i}",
                title="Performance Test Alert",
                description="Test alert for performance",
                severity="medium",
                source="test",
                events=[],
            )
            for i in range(100)
        ]

        start = time.time()
        for alert in alerts:
            await orchestrator.process_alert(alert)
        elapsed = time.time() - start

        assert elapsed < 5.0  # Process 100 alerts in under 5 seconds

    @pytest.mark.asyncio
    async def test_workflow_state_consistency(
        self, orchestrator, alert_service, case_service, critical_alert
    ):
        """Test state consistency after workflow."""
        result = await orchestrator.process_alert(critical_alert)

        # Verify alert state
        alert = alert_service.get(critical_alert.alert_id)
        assert alert.status == AlertStatus.ESCALATED
        assert alert.triage_result is not None
        assert alert.enrichments is not None

        # Verify case state
        case = case_service.get(result["case_id"])
        assert case.status == CaseStatus.OPEN
        assert len(case.alerts) == 1
        assert len(case.evidence) > 0
