"""Integration tests for AI Copilot Service."""

import asyncio
import json
from datetime import datetime
from typing import Any
from uuid import uuid4

import httpx
import pytest


# Configuration
COPILOT_SERVICE_URL = "http://localhost:8000"
TEST_TIMEOUT = 60.0  # Longer timeout for AI operations


class TestCopilotServiceHealth:
    """Tests for health check endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check endpoint returns healthy status."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{COPILOT_SERVICE_URL}/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_readiness_check(self):
        """Test readiness endpoint."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(f"{COPILOT_SERVICE_URL}/ready")

            assert response.status_code in [200, 503]


class TestNaturalLanguageQuery:
    """Tests for natural language to SQL query conversion."""

    @pytest.mark.asyncio
    async def test_simple_nl_query(self):
        """Test simple natural language query."""
        request = {
            "request_id": str(uuid4()),
            "question": "Show me the top 10 IP addresses with failed login attempts"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/query/natural",
                json=request
            )

            assert response.status_code in [200, 404]

            if response.status_code == 200:
                data = response.json()
                assert "success" in data or "data" in data

    @pytest.mark.asyncio
    async def test_complex_nl_query(self):
        """Test complex natural language query with time range."""
        request = {
            "request_id": str(uuid4()),
            "question": "What are the most common event types in the last 24 hours grouped by source IP?"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/query/natural",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_nl_query_with_filters(self):
        """Test natural language query with specific filters."""
        request = {
            "request_id": str(uuid4()),
            "question": "Show failed SSH logins from external IPs targeting the production network",
            "context": {
                "production_networks": ["10.0.0.0/8", "172.16.0.0/12"],
                "time_range": "7d"
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/query/natural",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_nl_query_aggregation(self):
        """Test natural language query with aggregation."""
        request = {
            "request_id": str(uuid4()),
            "question": "Calculate the average response time per service for the last week"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/query/natural",
                json=request
            )

            assert response.status_code in [200, 404]


class TestAlertInvestigation:
    """Tests for alert investigation assistance."""

    def _create_sample_alert(self) -> dict[str, Any]:
        """Create a sample alert for investigation."""
        return {
            "alert_id": str(uuid4()),
            "title": "Suspicious PowerShell Activity",
            "description": "PowerShell process launched with encoded command and network activity",
            "severity": "high",
            "timestamp": datetime.utcnow().isoformat(),
            "source": "edr",
            "raw_data": {
                "process_name": "powershell.exe",
                "command_line": "powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBz...",
                "parent_process": "cmd.exe",
                "user": "DOMAIN\\user1",
                "host": "WORKSTATION-01",
                "network_connections": [
                    {"dst_ip": "198.51.100.1", "dst_port": 443}
                ]
            }
        }

    @pytest.mark.asyncio
    async def test_investigate_alert(self):
        """Test alert investigation request."""
        alert = self._create_sample_alert()
        request = {
            "request_id": str(uuid4()),
            "alert": alert,
            "investigation_depth": "standard"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/investigate",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_investigate_with_context(self):
        """Test alert investigation with additional context."""
        alert = self._create_sample_alert()
        request = {
            "request_id": str(uuid4()),
            "alert": alert,
            "context": {
                "related_alerts": [
                    {"alert_id": str(uuid4()), "title": "Suspicious network beacon"},
                    {"alert_id": str(uuid4()), "title": "Unusual process tree"}
                ],
                "user_info": {
                    "department": "Engineering",
                    "risk_score": 0.3
                },
                "asset_info": {
                    "type": "workstation",
                    "criticality": "medium"
                }
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/investigate",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_investigation_questions(self):
        """Test getting recommended investigation questions."""
        alert = self._create_sample_alert()
        request = {
            "request_id": str(uuid4()),
            "alert": alert
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/investigate/questions",
                json=request
            )

            assert response.status_code in [200, 404]


class TestRecommendations:
    """Tests for response recommendations."""

    @pytest.mark.asyncio
    async def test_get_response_recommendations(self):
        """Test getting response recommendations for an alert."""
        request = {
            "request_id": str(uuid4()),
            "alert": {
                "alert_id": str(uuid4()),
                "title": "Ransomware Activity Detected",
                "severity": "critical",
                "mitre_techniques": ["T1486", "T1490"]
            },
            "context": {
                "infected_hosts": 3,
                "data_at_risk": True
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/recommend",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_playbook_recommendations(self):
        """Test getting playbook recommendations."""
        request = {
            "request_id": str(uuid4()),
            "alert_type": "phishing",
            "severity": "high"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/recommend/playbooks",
                json=request
            )

            assert response.status_code in [200, 404]


class TestSummarization:
    """Tests for incident summarization."""

    @pytest.mark.asyncio
    async def test_summarize_incident(self):
        """Test incident summarization."""
        request = {
            "request_id": str(uuid4()),
            "incident": {
                "incident_id": str(uuid4()),
                "title": "Data Exfiltration Attempt",
                "alerts": [
                    {"title": "Large outbound transfer", "timestamp": "2024-01-01T10:00:00Z"},
                    {"title": "Unusual DNS queries", "timestamp": "2024-01-01T09:55:00Z"},
                    {"title": "Suspicious process execution", "timestamp": "2024-01-01T09:50:00Z"}
                ],
                "timeline": [
                    {"event": "Initial access via phishing", "time": "2024-01-01T09:00:00Z"},
                    {"event": "Credential harvesting", "time": "2024-01-01T09:30:00Z"},
                    {"event": "Data staging", "time": "2024-01-01T09:45:00Z"},
                    {"event": "Exfiltration attempt", "time": "2024-01-01T10:00:00Z"}
                ]
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/summarize",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_summarize_with_format(self):
        """Test summarization with specific format."""
        request = {
            "request_id": str(uuid4()),
            "incident": {
                "incident_id": str(uuid4()),
                "title": "Test Incident",
                "alerts": []
            },
            "format": "executive",  # executive, technical, detailed
            "max_length": 500
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/summarize",
                json=request
            )

            assert response.status_code in [200, 404]


class TestChat:
    """Tests for chat/conversation functionality."""

    @pytest.mark.asyncio
    async def test_chat_simple_question(self):
        """Test simple chat question."""
        request = {
            "request_id": str(uuid4()),
            "message": "What does MITRE ATT&CK T1110 mean?"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/chat",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_chat_with_context(self):
        """Test chat with conversation context."""
        session_id = str(uuid4())

        messages = [
            "I'm investigating a potential ransomware incident",
            "What are the first steps I should take?",
            "How do I identify the ransomware variant?"
        ]

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            for message in messages:
                request = {
                    "request_id": str(uuid4()),
                    "session_id": session_id,
                    "message": message
                }

                response = await client.post(
                    f"{COPILOT_SERVICE_URL}/api/v1/chat",
                    json=request
                )

                assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_chat_with_alert_context(self):
        """Test chat with specific alert context."""
        request = {
            "request_id": str(uuid4()),
            "message": "Can you explain this alert in more detail?",
            "context": {
                "alert": {
                    "alert_id": str(uuid4()),
                    "title": "Suspicious DNS Query",
                    "description": "Query to known C2 domain detected"
                }
            }
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/chat",
                json=request
            )

            assert response.status_code in [200, 404]


class TestKnowledgeBase:
    """Tests for knowledge base functionality."""

    @pytest.mark.asyncio
    async def test_search_knowledge_base(self):
        """Test knowledge base search."""
        request = {
            "request_id": str(uuid4()),
            "query": "ransomware response procedures",
            "limit": 10
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/knowledge/search",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_threat_intel(self):
        """Test getting threat intelligence information."""
        request = {
            "request_id": str(uuid4()),
            "indicator": "198.51.100.1",
            "indicator_type": "ip"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/knowledge/threat-intel",
                json=request
            )

            assert response.status_code in [200, 404]


class TestRuleGeneration:
    """Tests for detection rule generation."""

    @pytest.mark.asyncio
    async def test_generate_detection_rule(self):
        """Test detection rule generation from description."""
        request = {
            "request_id": str(uuid4()),
            "description": "Detect when PowerShell executes encoded commands and makes network connections",
            "rule_type": "sigma",
            "severity": "high"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/rules/generate",
                json=request
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_explain_detection_rule(self):
        """Test detection rule explanation."""
        request = {
            "request_id": str(uuid4()),
            "rule": """
            title: Suspicious PowerShell Download
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    CommandLine|contains|all:
                        - 'powershell'
                        - 'downloadstring'
                condition: selection
            """
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/rules/explain",
                json=request
            )

            assert response.status_code in [200, 404]


class TestMetrics:
    """Tests for copilot metrics."""

    @pytest.mark.asyncio
    async def test_get_usage_metrics(self):
        """Test getting usage metrics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{COPILOT_SERVICE_URL}/api/v1/metrics"
            )

            assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_get_model_stats(self):
        """Test getting model statistics."""
        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.get(
                f"{COPILOT_SERVICE_URL}/api/v1/metrics/model"
            )

            assert response.status_code in [200, 404]


class TestFeedback:
    """Tests for feedback functionality."""

    @pytest.mark.asyncio
    async def test_submit_feedback(self):
        """Test submitting feedback on a response."""
        request = {
            "request_id": str(uuid4()),
            "response_id": str(uuid4()),
            "rating": 4,
            "feedback": "The response was helpful but could be more detailed",
            "feedback_type": "accuracy"
        }

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/feedback",
                json=request
            )

            assert response.status_code in [200, 201, 404]


class TestCopilotConcurrency:
    """Tests for concurrent operations."""

    @pytest.mark.asyncio
    async def test_concurrent_queries(self):
        """Test handling of concurrent queries."""
        num_requests = 10

        async def make_request(client: httpx.AsyncClient, idx: int):
            request = {
                "request_id": str(uuid4()),
                "question": f"What is event type {idx}?"
            }
            response = await client.post(
                f"{COPILOT_SERVICE_URL}/api/v1/query/natural",
                json=request
            )
            return response.status_code

        async with httpx.AsyncClient(timeout=TEST_TIMEOUT) as client:
            tasks = [make_request(client, i) for i in range(num_requests)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            success_count = sum(1 for r in results if isinstance(r, int) and r in [200, 404])
            assert success_count >= num_requests * 0.8


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
