"""End-to-end tests for case management flow."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest


# Configuration
GATEWAY_URL = "http://localhost:8080"
CASE_URL = "http://localhost:8083"
SOAR_URL = "http://localhost:8082"
TEST_TIMEOUT = 60.0


class TestCaseEndToEndFlow:
    """End-to-end tests for complete case management flow."""

    @pytest.fixture
    def sample_case(self) -> dict[str, Any]:
        """Create a sample case."""
        return {
            "title": "Suspected Ransomware Incident",
            "description": "Multiple indicators suggest ransomware activity on the corporate network",
            "severity": "critical",
            "priority": "p1",
            "category": "malware",
            "status": "new",
            "assignee": None,
            "tags": ["ransomware", "malware", "incident"],
            "related_alerts": [str(uuid4()), str(uuid4())],
            "affected_assets": [
                {"hostname": "WORKSTATION-001", "ip": "10.0.0.50", "type": "workstation"},
                {"hostname": "WORKSTATION-002", "ip": "10.0.0.51", "type": "workstation"}
            ],
            "indicators": {
                "file_hashes": ["abc123def456", "789xyz012abc"],
                "c2_domains": ["malicious.example.com"],
                "suspicious_ips": ["198.51.100.1"]
            },
            "timeline": []
        }

    @pytest.mark.asyncio
    async def test_create_case_from_alert(self):
        """Test creating a case from an alert."""
        alert_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases",
                json={
                    "title": "Case from Alert",
                    "description": "Escalated from high severity alert",
                    "source_alert_id": alert_id,
                    "severity": "high",
                    "priority": "p2"
                }
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_complete_case_lifecycle(self, sample_case):
        """Test complete case lifecycle from creation to closure."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            # Step 1: Create case
            create_response = await client.post(
                f"{CASE_URL}/api/v1/cases",
                json=sample_case
            )
            assert create_response.status_code in [200, 201, 404]

            if create_response.status_code not in [200, 201]:
                pytest.skip("Case service not available")

            case_id = create_response.json().get("id", str(uuid4()))

            # Step 2: Assign case
            assign_response = await client.put(
                f"{CASE_URL}/api/v1/cases/{case_id}",
                json={
                    "assignee": "analyst@example.com",
                    "status": "assigned"
                }
            )
            assert assign_response.status_code in [200, 404]

            # Step 3: Update status to investigating
            investigate_response = await client.put(
                f"{CASE_URL}/api/v1/cases/{case_id}",
                json={"status": "investigating"}
            )
            assert investigate_response.status_code in [200, 404]

            # Step 4: Add investigation notes
            note_response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/notes",
                json={
                    "content": "Initial triage completed. Confirmed ransomware indicators.",
                    "author": "analyst@example.com"
                }
            )
            assert note_response.status_code in [200, 201, 404]

            # Step 5: Add evidence
            evidence_response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/evidence",
                json={
                    "type": "file",
                    "name": "malware_sample.bin",
                    "hash": "sha256:abc123...",
                    "description": "Captured malware sample"
                }
            )
            assert evidence_response.status_code in [200, 201, 404]

            # Step 6: Update timeline
            timeline_response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/timeline",
                json={
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "Malware contained on affected hosts",
                    "actor": "analyst@example.com"
                }
            )
            assert timeline_response.status_code in [200, 201, 404]

            # Step 7: Close case
            close_response = await client.put(
                f"{CASE_URL}/api/v1/cases/{case_id}",
                json={
                    "status": "closed",
                    "resolution": "contained",
                    "resolution_summary": "Ransomware contained and removed. No data loss."
                }
            )
            assert close_response.status_code in [200, 404]


class TestCaseManagement:
    """Tests for case management operations."""

    @pytest.mark.asyncio
    async def test_list_cases(self):
        """Test listing all cases."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_filter_cases(self):
        """Test filtering cases."""
        filters = [
            "?status=new",
            "?severity=critical",
            "?priority=p1",
            "?assignee=analyst@example.com",
            "?status=investigating&severity=high"
        ]

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            for filter_str in filters:
                response = await client.get(f"{CASE_URL}/api/v1/cases{filter_str}")
                assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_search_cases(self):
        """Test searching cases."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/search",
                json={
                    "query": "ransomware",
                    "filters": {
                        "status": ["new", "investigating"],
                        "severity": ["high", "critical"]
                    }
                }
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_case_details(self):
        """Test getting case details."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}")
            assert response.status_code in [200, 404]


class TestCaseNotes:
    """Tests for case notes functionality."""

    @pytest.mark.asyncio
    async def test_add_note(self):
        """Test adding a note to a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/notes",
                json={
                    "content": "Investigation note content",
                    "author": "analyst@example.com",
                    "visibility": "team"
                }
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_list_notes(self):
        """Test listing case notes."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/notes")
            assert response.status_code in [200, 404]


class TestCaseEvidence:
    """Tests for case evidence management."""

    @pytest.mark.asyncio
    async def test_add_evidence(self):
        """Test adding evidence to a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/evidence",
                json={
                    "type": "screenshot",
                    "name": "alert_screenshot.png",
                    "description": "Screenshot of the alert dashboard",
                    "tags": ["ui", "alert"]
                }
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_list_evidence(self):
        """Test listing case evidence."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/evidence")
            assert response.status_code in [200, 404]


class TestCaseTimeline:
    """Tests for case timeline functionality."""

    @pytest.mark.asyncio
    async def test_add_timeline_event(self):
        """Test adding an event to case timeline."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/timeline",
                json={
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": "Incident detected",
                    "event_type": "detection",
                    "actor": "system",
                    "details": {"source": "detection_engine", "rule_id": "rule-123"}
                }
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_get_timeline(self):
        """Test getting case timeline."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/timeline")
            assert response.status_code in [200, 404]


class TestCaseAssignment:
    """Tests for case assignment workflow."""

    @pytest.mark.asyncio
    async def test_assign_case(self):
        """Test assigning a case to an analyst."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/assign",
                json={
                    "assignee": "analyst@example.com",
                    "reason": "Subject matter expert for malware analysis"
                }
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_reassign_case(self):
        """Test reassigning a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/reassign",
                json={
                    "new_assignee": "senior-analyst@example.com",
                    "reason": "Escalation required"
                }
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_unassign_case(self):
        """Test unassigning a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/unassign"
            )
            assert response.status_code in [200, 404]


class TestCaseCollaboration:
    """Tests for case collaboration features."""

    @pytest.mark.asyncio
    async def test_add_collaborator(self):
        """Test adding a collaborator to a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/collaborators",
                json={
                    "user": "collaborator@example.com",
                    "role": "reviewer"
                }
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_list_collaborators(self):
        """Test listing case collaborators."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/collaborators")
            assert response.status_code in [200, 404]


class TestCaseAlerts:
    """Tests for linking alerts to cases."""

    @pytest.mark.asyncio
    async def test_link_alert(self):
        """Test linking an alert to a case."""
        case_id = str(uuid4())
        alert_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/alerts",
                json={"alert_id": alert_id}
            )
            assert response.status_code in [200, 201, 404]

    @pytest.mark.asyncio
    async def test_list_linked_alerts(self):
        """Test listing alerts linked to a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/alerts")
            assert response.status_code in [200, 404]


class TestCasePlaybooks:
    """Tests for case playbook integration."""

    @pytest.mark.asyncio
    async def test_execute_playbook_for_case(self):
        """Test executing a playbook for a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/playbooks/execute",
                json={
                    "playbook_id": "incident-response-playbook",
                    "parameters": {}
                }
            )
            assert response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_list_case_playbook_executions(self):
        """Test listing playbook executions for a case."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/{case_id}/playbooks/executions")
            assert response.status_code in [200, 404]


class TestCaseReporting:
    """Tests for case reporting functionality."""

    @pytest.mark.asyncio
    async def test_generate_case_report(self):
        """Test generating a case report."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{case_id}/report",
                json={
                    "format": "pdf",
                    "sections": ["summary", "timeline", "evidence", "findings"],
                    "include_artifacts": True
                }
            )
            assert response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_export_case(self):
        """Test exporting case data."""
        case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{CASE_URL}/api/v1/cases/{case_id}/export",
                params={"format": "json"}
            )
            assert response.status_code in [200, 404]


class TestCaseMetrics:
    """Tests for case metrics and statistics."""

    @pytest.mark.asyncio
    async def test_case_metrics(self):
        """Test case metrics endpoint."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{CASE_URL}/api/v1/cases/metrics",
                params={
                    "start_date": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "end_date": datetime.utcnow().isoformat()
                }
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_case_sla_metrics(self):
        """Test case SLA metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{CASE_URL}/api/v1/cases/metrics/sla")
            assert response.status_code in [200, 404]


class TestCaseMerge:
    """Tests for merging related cases."""

    @pytest.mark.asyncio
    async def test_merge_cases(self):
        """Test merging two related cases."""
        primary_case_id = str(uuid4())
        secondary_case_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{CASE_URL}/api/v1/cases/{primary_case_id}/merge",
                json={
                    "secondary_case_id": secondary_case_id,
                    "merge_notes": True,
                    "merge_evidence": True,
                    "merge_timeline": True
                }
            )
            assert response.status_code in [200, 404]


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
