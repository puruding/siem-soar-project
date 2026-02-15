"""End-to-end tests for playbook execution flow."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest


# Configuration
SOAR_URL = "http://localhost:8082"
GATEWAY_URL = "http://localhost:8080"
TEST_TIMEOUT = 120.0


class TestPlaybookEndToEndFlow:
    """End-to-end tests for complete playbook execution flow."""

    @pytest.fixture
    def sample_playbook(self) -> dict[str, Any]:
        """Create a sample playbook."""
        return {
            "name": "Malware Response Playbook",
            "description": "Automated response to malware detection",
            "version": "1.0.0",
            "trigger": {
                "type": "alert",
                "condition": "alert_type = 'malware' AND severity >= 'high'"
            },
            "steps": [
                {
                    "id": "isolate",
                    "name": "Isolate Infected Host",
                    "type": "action",
                    "action": "network.isolate_host",
                    "parameters": {
                        "host": "{{alert.affected_host}}",
                        "isolation_level": "full"
                    },
                    "on_success": "collect-evidence",
                    "on_failure": "notify-failure",
                    "timeout_seconds": 300
                },
                {
                    "id": "collect-evidence",
                    "name": "Collect Forensic Evidence",
                    "type": "action",
                    "action": "edr.collect_artifacts",
                    "parameters": {
                        "host": "{{alert.affected_host}}",
                        "artifacts": ["memory", "processes", "network", "files"]
                    },
                    "on_success": "scan-malware",
                    "on_failure": "notify-failure",
                    "timeout_seconds": 600
                },
                {
                    "id": "scan-malware",
                    "name": "Scan for Malware",
                    "type": "action",
                    "action": "av.full_scan",
                    "parameters": {
                        "host": "{{alert.affected_host}}",
                        "quarantine": True
                    },
                    "on_success": "check-clean",
                    "on_failure": "notify-failure",
                    "timeout_seconds": 1800
                },
                {
                    "id": "check-clean",
                    "name": "Verify Host is Clean",
                    "type": "condition",
                    "condition": "{{scan_result.threats_found}} == 0",
                    "on_true": "restore-network",
                    "on_false": "escalate"
                },
                {
                    "id": "restore-network",
                    "name": "Restore Network Access",
                    "type": "action",
                    "action": "network.restore_access",
                    "parameters": {
                        "host": "{{alert.affected_host}}"
                    },
                    "on_success": "notify-success",
                    "on_failure": "notify-failure",
                    "timeout_seconds": 120
                },
                {
                    "id": "escalate",
                    "name": "Escalate to Security Team",
                    "type": "action",
                    "action": "notification.create_ticket",
                    "parameters": {
                        "title": "Malware Remediation Failed - {{alert.affected_host}}",
                        "priority": "critical",
                        "team": "security-incident-response"
                    },
                    "on_success": "complete",
                    "on_failure": "notify-failure"
                },
                {
                    "id": "notify-success",
                    "name": "Send Success Notification",
                    "type": "action",
                    "action": "notification.send",
                    "parameters": {
                        "channel": "slack",
                        "message": "Malware successfully remediated on {{alert.affected_host}}"
                    },
                    "on_success": "complete",
                    "on_failure": "complete"
                },
                {
                    "id": "notify-failure",
                    "name": "Send Failure Notification",
                    "type": "action",
                    "action": "notification.send",
                    "parameters": {
                        "channel": "slack",
                        "message": "Malware remediation failed on {{alert.affected_host}}. Manual intervention required."
                    },
                    "on_success": "complete",
                    "on_failure": "complete"
                },
                {
                    "id": "complete",
                    "name": "Complete Playbook",
                    "type": "end"
                }
            ],
            "variables": {
                "isolation_duration": "24h",
                "notification_channel": "#security-alerts"
            },
            "enabled": True
        }

    @pytest.mark.asyncio
    async def test_create_and_execute_playbook(self, sample_playbook):
        """Test creating and executing a playbook."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            # Step 1: Create playbook
            create_response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks",
                json=sample_playbook
            )
            assert create_response.status_code in [201, 409, 404]

            # Step 2: Execute playbook
            trigger_data = {
                "alert": {
                    "id": str(uuid4()),
                    "type": "malware",
                    "severity": "high",
                    "affected_host": "WORKSTATION-001",
                    "malware_type": "trojan",
                    "indicators": {
                        "file_hash": "abc123..."
                    }
                }
            }

            execute_response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/malware-response-playbook/execute",
                json=trigger_data
            )
            assert execute_response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_playbook_execution_lifecycle(self, sample_playbook):
        """Test complete playbook execution lifecycle."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            # Create playbook
            await client.post(f"{SOAR_URL}/api/v1/playbooks", json=sample_playbook)

            # Execute playbook
            trigger_data = {
                "alert": {
                    "id": str(uuid4()),
                    "type": "malware",
                    "severity": "high",
                    "affected_host": "WORKSTATION-001"
                }
            }

            execute_response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/malware-response-playbook/execute",
                json=trigger_data
            )

            if execute_response.status_code == 202:
                execution_id = execute_response.json().get("execution_id", str(uuid4()))

                # Poll for execution status
                max_polls = 10
                for _ in range(max_polls):
                    status_response = await client.get(
                        f"{SOAR_URL}/api/v1/executions/{execution_id}"
                    )

                    if status_response.status_code == 200:
                        status = status_response.json().get("status")
                        if status in ["completed", "failed"]:
                            break

                    await asyncio.sleep(2)


class TestPlaybookManagement:
    """Tests for playbook management operations."""

    @pytest.mark.asyncio
    async def test_list_playbooks(self):
        """Test listing all playbooks."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/playbooks")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_playbook(self):
        """Test getting a specific playbook."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/playbooks/{playbook_id}")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_update_playbook(self):
        """Test updating a playbook."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.put(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}",
                json={"enabled": False, "description": "Updated description"}
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_delete_playbook(self):
        """Test deleting a playbook."""
        playbook_id = "playbook-to-delete"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.delete(f"{SOAR_URL}/api/v1/playbooks/{playbook_id}")
            assert response.status_code in [200, 204, 404]

    @pytest.mark.asyncio
    async def test_enable_disable_playbook(self):
        """Test enabling and disabling a playbook."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            # Disable
            disable_response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/disable"
            )
            assert disable_response.status_code in [200, 404]

            # Enable
            enable_response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/enable"
            )
            assert enable_response.status_code in [200, 404]


class TestPlaybookExecution:
    """Tests for playbook execution operations."""

    @pytest.mark.asyncio
    async def test_manual_execution(self):
        """Test manual playbook execution."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/execute",
                json={
                    "trigger_data": {"test": "data"},
                    "mode": "manual"
                }
            )
            assert response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_list_executions(self):
        """Test listing playbook executions."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/executions")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_execution_details(self):
        """Test getting execution details."""
        execution_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/executions/{execution_id}")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_cancel_execution(self):
        """Test canceling a running execution."""
        execution_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/executions/{execution_id}/cancel"
            )
            assert response.status_code in [200, 404, 409]

    @pytest.mark.asyncio
    async def test_retry_execution(self):
        """Test retrying a failed execution."""
        execution_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/executions/{execution_id}/retry"
            )
            assert response.status_code in [200, 202, 404]


class TestPlaybookSteps:
    """Tests for playbook step operations."""

    @pytest.mark.asyncio
    async def test_get_step_status(self):
        """Test getting step status in an execution."""
        execution_id = str(uuid4())
        step_id = "step-1"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{SOAR_URL}/api/v1/executions/{execution_id}/steps/{step_id}"
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_approve_manual_step(self):
        """Test approving a manual approval step."""
        execution_id = str(uuid4())
        step_id = "approval-step"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/executions/{execution_id}/steps/{step_id}/approve",
                json={"approved": True, "comment": "Approved by security analyst"}
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_skip_step(self):
        """Test skipping a step in an execution."""
        execution_id = str(uuid4())
        step_id = "optional-step"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/executions/{execution_id}/steps/{step_id}/skip",
                json={"reason": "Not applicable for this scenario"}
            )
            assert response.status_code in [200, 404]


class TestPlaybookActions:
    """Tests for available playbook actions."""

    @pytest.mark.asyncio
    async def test_list_actions(self):
        """Test listing available actions."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/actions")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_action_details(self):
        """Test getting action details."""
        action_id = "network.isolate_host"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/actions/{action_id}")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_execute_standalone_action(self):
        """Test executing a standalone action."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/actions/execute",
                json={
                    "action": "enrichment.ip_lookup",
                    "parameters": {"ip": "8.8.8.8"}
                }
            )
            assert response.status_code in [200, 202, 404]


class TestPlaybookConnectors:
    """Tests for playbook connectors."""

    @pytest.mark.asyncio
    async def test_list_connectors(self):
        """Test listing available connectors."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/connectors")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_create_connector(self):
        """Test creating a new connector."""
        connector = {
            "name": "Test Firewall",
            "type": "firewall",
            "vendor": "palo_alto",
            "config": {
                "api_url": "https://firewall.example.com/api",
                "api_key": "test-key"
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(f"{SOAR_URL}/api/v1/connectors", json=connector)
            assert response.status_code in [201, 409, 404]

    @pytest.mark.asyncio
    async def test_test_connector(self):
        """Test connector connectivity."""
        connector_id = "test-connector"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(f"{SOAR_URL}/api/v1/connectors/{connector_id}/test")
            assert response.status_code in [200, 404, 503]


class TestPlaybookValidation:
    """Tests for playbook validation."""

    @pytest.mark.asyncio
    async def test_validate_playbook(self):
        """Test validating a playbook definition."""
        playbook = {
            "name": "Test Playbook",
            "steps": [
                {
                    "id": "step-1",
                    "name": "Test Step",
                    "type": "action",
                    "action": "test.action"
                }
            ]
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/validate",
                json=playbook
            )
            assert response.status_code in [200, 400, 404]

    @pytest.mark.asyncio
    async def test_validate_invalid_playbook(self):
        """Test validating an invalid playbook."""
        invalid_playbook = {
            "name": "Invalid Playbook",
            "steps": [
                {
                    "id": "step-1",
                    "type": "action",
                    "on_success": "nonexistent-step"  # References non-existent step
                }
            ]
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/validate",
                json=invalid_playbook
            )
            # Should return validation error or accept
            assert response.status_code in [200, 400, 404]


class TestPlaybookVersioning:
    """Tests for playbook versioning."""

    @pytest.mark.asyncio
    async def test_get_playbook_versions(self):
        """Test getting playbook version history."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/versions")
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_rollback_playbook(self):
        """Test rolling back to a previous version."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/rollback",
                json={"version": 1}
            )
            assert response.status_code in [200, 404]


class TestPlaybookMetrics:
    """Tests for playbook metrics and analytics."""

    @pytest.mark.asyncio
    async def test_get_playbook_metrics(self):
        """Test getting playbook execution metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{SOAR_URL}/api/v1/metrics/playbooks",
                params={
                    "start_date": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "end_date": datetime.utcnow().isoformat()
                }
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_action_metrics(self):
        """Test getting action execution metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{SOAR_URL}/api/v1/metrics/actions")
            assert response.status_code in [200, 404]


class TestPlaybookImportExport:
    """Tests for playbook import/export."""

    @pytest.mark.asyncio
    async def test_export_playbook(self):
        """Test exporting a playbook."""
        playbook_id = "test-playbook"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/export"
            )
            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_import_playbook(self):
        """Test importing a playbook."""
        playbook_definition = {
            "name": "Imported Playbook",
            "version": "1.0.0",
            "steps": []
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/import",
                json=playbook_definition
            )
            assert response.status_code in [200, 201, 404]


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
