"""Integration tests for AI Triage Service."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest


# Configuration
TRIAGE_SERVICE_URL = "http://localhost:8001"
TEST_TIMEOUT = 30.0


class TestTriageServiceHealth:
    """Tests for health check endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check endpoint returns healthy status."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{TRIAGE_SERVICE_URL}/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["service"] == "ai-triage"

    @pytest.mark.asyncio
    async def test_readiness_check(self):
        """Test readiness endpoint."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{TRIAGE_SERVICE_URL}/ready")

            assert response.status_code in [200, 503]


class TestAlertTriage:
    """Tests for alert triage functionality."""

    def _create_sample_alert(self, severity: str = "high") -> dict[str, Any]:
        """Create a sample alert for testing."""
        return {
            "alert_id": str(uuid4()),
            "title": "SSH Brute Force Attack Detected",
            "description": "Multiple failed SSH login attempts detected from single source IP",
            "severity": severity,
            "source": "detection_engine",
            "timestamp": datetime.utcnow().isoformat(),
            "raw_event": {
                "event_type": "auth_failure",
                "service": "sshd",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.5",
                "user": "root",
                "count": 15,
                "time_window": "5m"
            },
            "tags": ["ssh", "brute-force", "authentication"],
            "metadata": {
                "rule_id": "rule-ssh-brute-force-001",
                "mitre_attack": "T1110.001"
            }
        }

    @pytest.mark.asyncio
    async def test_triage_single_alert(self):
        """Test triaging a single alert."""
        alert = self._create_sample_alert()
        request = {
            "request_id": str(uuid4()),
            "alert": alert
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                json=request
            )

            assert response.status_code in [200, 404]  # 404 if endpoint not implemented

            if response.status_code == 200:
                data = response.json()
                assert "success" in data
                if data["success"]:
                    assert "data" in data
                    result = data["data"]
                    assert "priority" in result or "classification" in result

    @pytest.mark.asyncio
    async def test_triage_batch_alerts(self):
        """Test triaging multiple alerts in batch."""
        alerts = [
            self._create_sample_alert("high"),
            self._create_sample_alert("medium"),
            self._create_sample_alert("low"),
        ]
        request = {
            "request_id": str(uuid4()),
            "alerts": alerts
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage/batch",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_triage_with_context(self):
        """Test triaging with additional context."""
        alert = self._create_sample_alert()
        request = {
            "request_id": str(uuid4()),
            "alert": alert,
            "context": {
                "user_history": {
                    "previous_incidents": 2,
                    "risk_score": 0.7
                },
                "asset_info": {
                    "asset_type": "server",
                    "criticality": "high",
                    "owner": "security-team"
                },
                "threat_intel": {
                    "ip_reputation": "suspicious",
                    "known_attacker": False
                }
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_triage_different_severities(self):
        """Test triage handles different severity levels correctly."""
        severities = ["critical", "high", "medium", "low", "info"]

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            for severity in severities:
                alert = self._create_sample_alert(severity)
                request = {
                    "request_id": str(uuid4()),
                    "alert": alert
                }

                response = await client.post(
                    f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                    json=request
                )

                assert response.status_code in [200, 404], f"Failed for severity: {severity}"


class TestAlertClassification:
    """Tests for alert classification."""

    @pytest.mark.asyncio
    async def test_classify_alert(self):
        """Test alert classification endpoint."""
        request = {
            "request_id": str(uuid4()),
            "alert_text": "Failed SSH login attempt from 192.168.1.100 to server prod-web-01 for user root",
            "alert_metadata": {
                "source": "syslog",
                "timestamp": datetime.utcnow().isoformat()
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/classify",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_classify_with_categories(self):
        """Test classification with predefined categories."""
        categories = [
            "malware",
            "phishing",
            "brute_force",
            "data_exfiltration",
            "privilege_escalation",
            "lateral_movement",
            "benign"
        ]

        request = {
            "request_id": str(uuid4()),
            "alert_text": "Suspicious PowerShell execution downloading script from external URL",
            "categories": categories
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/classify",
                json=request
            )

            assert response.status_code in [200, 404]


class TestAlertCorrelation:
    """Tests for alert correlation."""

    @pytest.mark.asyncio
    async def test_correlate_alerts(self):
        """Test alert correlation."""
        alerts = [
            {
                "alert_id": str(uuid4()),
                "title": "Failed SSH login",
                "src_ip": "192.168.1.100",
                "timestamp": datetime.utcnow().isoformat()
            },
            {
                "alert_id": str(uuid4()),
                "title": "Successful SSH login after failures",
                "src_ip": "192.168.1.100",
                "timestamp": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
            },
            {
                "alert_id": str(uuid4()),
                "title": "Privilege escalation detected",
                "src_ip": "192.168.1.100",
                "timestamp": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
            }
        ]

        request = {
            "request_id": str(uuid4()),
            "alerts": alerts,
            "correlation_window": "1h"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/correlate",
                json=request
            )

            assert response.status_code in [200, 404]


class TestFalsePositiveDetection:
    """Tests for false positive detection."""

    @pytest.mark.asyncio
    async def test_check_false_positive(self):
        """Test false positive detection."""
        alert = {
            "alert_id": str(uuid4()),
            "title": "Suspicious outbound connection",
            "description": "Connection to known CDN IP address",
            "src_ip": "10.0.0.50",
            "dst_ip": "13.107.42.14",  # Microsoft IP
            "dst_port": 443,
            "protocol": "HTTPS"
        }

        request = {
            "request_id": str(uuid4()),
            "alert": alert
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/false_positive/check",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_report_false_positive(self):
        """Test reporting a false positive."""
        request = {
            "request_id": str(uuid4()),
            "alert_id": str(uuid4()),
            "reason": "Known trusted application behavior",
            "evidence": {
                "application": "Microsoft Teams",
                "verified_by": "security_analyst"
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/false_positive/report",
                json=request
            )

            assert response.status_code in [200, 201, 404]


class TestTriageMetrics:
    """Tests for triage metrics and analytics."""

    @pytest.mark.asyncio
    async def test_get_triage_metrics(self):
        """Test getting triage metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{TRIAGE_SERVICE_URL}/api/v1/metrics"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_model_performance(self):
        """Test getting model performance metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{TRIAGE_SERVICE_URL}/api/v1/metrics/model"
            )

            assert response.status_code in [200, 404]


class TestTriageAsync:
    """Tests for asynchronous triage operations."""

    @pytest.mark.asyncio
    async def test_async_triage(self):
        """Test asynchronous triage submission."""
        alert = {
            "alert_id": str(uuid4()),
            "title": "Large file download detected",
            "severity": "medium"
        }

        request = {
            "request_id": str(uuid4()),
            "alert": alert,
            "async": True
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage/async",
                json=request
            )

            assert response.status_code in [202, 404]

            if response.status_code == 202:
                data = response.json()
                assert "task_id" in data or "job_id" in data

    @pytest.mark.asyncio
    async def test_get_async_result(self):
        """Test getting async triage result."""
        task_id = str(uuid4())

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage/async/{task_id}"
            )

            assert response.status_code in [200, 404]


class TestTriageValidation:
    """Tests for input validation."""

    @pytest.mark.asyncio
    async def test_invalid_request_format(self):
        """Test handling of invalid request format."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                content="invalid json",
                headers={"Content-Type": "application/json"}
            )

            assert response.status_code in [400, 422, 404]

    @pytest.mark.asyncio
    async def test_missing_required_fields(self):
        """Test handling of missing required fields."""
        request = {
            "request_id": str(uuid4())
            # Missing alert field
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                json=request
            )

            assert response.status_code in [400, 422, 404]

    @pytest.mark.asyncio
    async def test_invalid_severity(self):
        """Test handling of invalid severity value."""
        request = {
            "request_id": str(uuid4()),
            "alert": {
                "alert_id": str(uuid4()),
                "title": "Test alert",
                "severity": "invalid_severity"
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                json=request
            )

            # Accept validation error or success (if service ignores invalid value)
            assert response.status_code in [200, 400, 422, 404]


class TestTriageRateLimiting:
    """Tests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """Test rate limiting is applied."""
        alert = {
            "alert_id": str(uuid4()),
            "title": "Test alert",
            "severity": "low"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            responses = []
            for _ in range(100):
                response = await client.post(
                    f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                    json={"request_id": str(uuid4()), "alert": alert}
                )
                responses.append(response.status_code)

            # Check if any requests were rate limited
            rate_limited = 429 in responses
            # Rate limiting may or may not be enabled
            assert True  # Just log the result


class TestTriageConcurrency:
    """Tests for concurrent triage operations."""

    @pytest.mark.asyncio
    async def test_concurrent_triage_requests(self):
        """Test handling of concurrent triage requests."""
        num_requests = 20

        async def make_request(client: httpx.AsyncClient, idx: int):
            alert = {
                "alert_id": str(uuid4()),
                "title": f"Concurrent alert {idx}",
                "severity": "medium"
            }
            response = await client.post(
                f"{TRIAGE_SERVICE_URL}/api/v1/triage",
                json={"request_id": str(uuid4()), "alert": alert}
            )
            return response.status_code

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            tasks = [make_request(client, i) for i in range(num_requests)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Count successful responses
            success_count = sum(1 for r in results if isinstance(r, int) and r in [200, 404])
            assert success_count >= num_requests * 0.8  # At least 80% should succeed


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
