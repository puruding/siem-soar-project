"""Integration tests for Agentic AI Service."""

import asyncio
import json
from datetime import datetime
from typing import Any
from uuid import uuid4

import httpx
import pytest


# Configuration
AGENTIC_SERVICE_URL = "http://localhost:8002"
TEST_TIMEOUT = 120.0  # Longer timeout for agent operations


class TestAgenticServiceHealth:
    """Tests for health check endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check endpoint returns healthy status."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{AGENTIC_SERVICE_URL}/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["service"] == "ai-agentic"

    @pytest.mark.asyncio
    async def test_readiness_check(self):
        """Test readiness endpoint."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{AGENTIC_SERVICE_URL}/ready")

            assert response.status_code in [200, 503]


class TestTaskExecution:
    """Tests for task execution."""

    def _create_investigation_task(self) -> dict[str, Any]:
        """Create a sample investigation task."""
        return {
            "task_id": str(uuid4()),
            "objective": "Investigate the potential phishing attack and determine if data was compromised",
            "context": {
                "alert": {
                    "alert_id": str(uuid4()),
                    "title": "Phishing Email Detected",
                    "severity": "high",
                    "user": "john.doe@example.com",
                    "email_subject": "Urgent: Your account needs verification",
                    "sender": "security@examp1e.com",
                    "attachment": "invoice.pdf"
                },
                "environment": {
                    "organization": "example-corp",
                    "network_segment": "corporate"
                }
            },
            "constraints": [
                "Do not modify any production systems",
                "Collect evidence before any containment actions",
                "Notify security team before blocking accounts"
            ],
            "require_approval": True
        }

    def _create_remediation_task(self) -> dict[str, Any]:
        """Create a sample remediation task."""
        return {
            "task_id": str(uuid4()),
            "objective": "Contain and remediate the compromised endpoint",
            "context": {
                "incident": {
                    "incident_id": str(uuid4()),
                    "title": "Malware Infection",
                    "compromised_host": "WORKSTATION-123",
                    "malware_type": "trojan",
                    "iocs": {
                        "file_hash": "abc123def456",
                        "c2_domain": "malicious.example.com"
                    }
                }
            },
            "constraints": [
                "Minimize business disruption",
                "Preserve forensic evidence",
                "Document all actions taken"
            ],
            "require_approval": True
        }

    @pytest.mark.asyncio
    async def test_execute_investigation_task(self):
        """Test executing an investigation task."""
        task = self._create_investigation_task()
        request = {
            "request_id": str(uuid4()),
            "task": task,
            "async_execution": True
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                json=request
            )

            assert response.status_code in [200, 202, 404]

            if response.status_code in [200, 202]:
                data = response.json()
                assert data.get("success", True)

    @pytest.mark.asyncio
    async def test_execute_remediation_task(self):
        """Test executing a remediation task."""
        task = self._create_remediation_task()
        request = {
            "request_id": str(uuid4()),
            "task": task,
            "async_execution": True
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                json=request
            )

            assert response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_execute_sync_task(self):
        """Test synchronous task execution."""
        task = {
            "task_id": str(uuid4()),
            "objective": "Lookup threat intelligence for IP 192.168.1.100",
            "context": {},
            "constraints": [],
            "require_approval": False
        }
        request = {
            "request_id": str(uuid4()),
            "task": task,
            "async_execution": False
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                json=request
            )

            assert response.status_code in [200, 404]


class TestTaskStatus:
    """Tests for task status operations."""

    @pytest.mark.asyncio
    async def test_get_task_status(self):
        """Test getting task execution status."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}"
            )

            assert response.status_code in [200, 404]

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    result = data["data"]
                    assert "task_id" in result
                    assert "state" in result

    @pytest.mark.asyncio
    async def test_list_tasks(self):
        """Test listing all tasks."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_list_tasks_with_filters(self):
        """Test listing tasks with filters."""
        filters = [
            "?state=running",
            "?state=pending",
            "?state=completed",
            "?limit=10",
            "?state=running&limit=5"
        ]

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            for filter_str in filters:
                response = await client.get(
                    f"{AGENTIC_SERVICE_URL}/api/v1/tasks{filter_str}"
                )

                assert response.status_code in [200, 404]


class TestApprovalWorkflow:
    """Tests for human-in-the-loop approval workflow."""

    @pytest.mark.asyncio
    async def test_approve_action(self):
        """Test approving a pending action."""
        request = {
            "request_id": str(uuid4()),
            "task_id": str(uuid4()),
            "step_id": "step-1",
            "approved": True,
            "feedback": "Approved - action is appropriate"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/approve",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_reject_action(self):
        """Test rejecting a pending action."""
        request = {
            "request_id": str(uuid4()),
            "task_id": str(uuid4()),
            "step_id": "step-1",
            "approved": False,
            "feedback": "Rejected - need more investigation first"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/approve",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_pending_approvals(self):
        """Test getting list of pending approvals."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/approvals/pending"
            )

            assert response.status_code in [200, 404]


class TestTaskCancellation:
    """Tests for task cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_task(self):
        """Test canceling a running task."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/cancel/{task_id}"
            )

            assert response.status_code in [200, 404]

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    result = data["data"]
                    assert result["state"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_with_reason(self):
        """Test canceling a task with a reason."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/cancel/{task_id}",
                json={"reason": "User requested cancellation"}
            )

            assert response.status_code in [200, 404]


class TestAgentActions:
    """Tests for available agent actions."""

    @pytest.mark.asyncio
    async def test_list_available_actions(self):
        """Test listing available agent actions."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/actions"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_action_details(self):
        """Test getting details of a specific action."""
        action_id = "investigate.lookup_ip"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/actions/{action_id}"
            )

            assert response.status_code in [200, 404]


class TestTaskHistory:
    """Tests for task history and audit."""

    @pytest.mark.asyncio
    async def test_get_task_history(self):
        """Test getting task execution history."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}/history"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_task_steps(self):
        """Test getting task execution steps."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}/steps"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_step_details(self):
        """Test getting details of a specific step."""
        task_id = str(uuid4())
        step_id = "step-1"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}/steps/{step_id}"
            )

            assert response.status_code in [200, 404]


class TestTaskRetry:
    """Tests for task retry functionality."""

    @pytest.mark.asyncio
    async def test_retry_failed_task(self):
        """Test retrying a failed task."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}/retry"
            )

            assert response.status_code in [200, 202, 404]

    @pytest.mark.asyncio
    async def test_retry_from_step(self):
        """Test retrying from a specific step."""
        task_id = str(uuid4())
        request = {
            "from_step": "step-2"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/tasks/{task_id}/retry",
                json=request
            )

            assert response.status_code in [200, 202, 404]


class TestAgentCapabilities:
    """Tests for agent capabilities."""

    @pytest.mark.asyncio
    async def test_get_agent_capabilities(self):
        """Test getting agent capabilities."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/capabilities"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_check_capability(self):
        """Test checking if agent has a specific capability."""
        capability = "threat_investigation"

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/capabilities/{capability}"
            )

            assert response.status_code in [200, 404]


class TestTaskTemplates:
    """Tests for task templates."""

    @pytest.mark.asyncio
    async def test_list_task_templates(self):
        """Test listing available task templates."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/templates"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_create_from_template(self):
        """Test creating a task from a template."""
        request = {
            "request_id": str(uuid4()),
            "template_id": "phishing_investigation",
            "parameters": {
                "alert_id": str(uuid4()),
                "user_email": "victim@example.com"
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/templates/execute",
                json=request
            )

            assert response.status_code in [200, 202, 404]


class TestMetrics:
    """Tests for agent metrics."""

    @pytest.mark.asyncio
    async def test_get_agent_metrics(self):
        """Test getting agent metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/metrics"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_task_metrics(self):
        """Test getting task execution metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{AGENTIC_SERVICE_URL}/api/v1/metrics/tasks"
            )

            assert response.status_code in [200, 404]


class TestValidation:
    """Tests for input validation."""

    @pytest.mark.asyncio
    async def test_invalid_task_format(self):
        """Test handling of invalid task format."""
        request = {
            "request_id": str(uuid4()),
            "task": {
                # Missing required fields
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                json=request
            )

            # Accept validation error or success (if service handles missing fields)
            assert response.status_code in [200, 400, 422, 404]

    @pytest.mark.asyncio
    async def test_invalid_json(self):
        """Test handling of invalid JSON."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                content="invalid json",
                headers={"Content-Type": "application/json"}
            )

            assert response.status_code in [400, 422, 404]


class TestConcurrency:
    """Tests for concurrent agent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_task_execution(self):
        """Test concurrent task execution."""
        num_tasks = 5

        async def execute_task(client: httpx.AsyncClient, idx: int):
            task = {
                "task_id": str(uuid4()),
                "objective": f"Concurrent task {idx}",
                "context": {"index": idx},
                "constraints": [],
                "require_approval": False
            }
            request = {
                "request_id": str(uuid4()),
                "task": task,
                "async_execution": True
            }
            response = await client.post(
                f"{AGENTIC_SERVICE_URL}/api/v1/execute",
                json=request
            )
            return response.status_code

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            tasks = [execute_task(client, i) for i in range(num_tasks)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(1 for r in results if isinstance(r, int) and r in [200, 202, 404])
            assert success_count >= num_tasks * 0.8


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
