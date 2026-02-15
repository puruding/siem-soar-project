"""Mock services for Python integration tests."""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn


# Mock Data Models
class MockAlert(BaseModel):
    """Mock alert model."""
    id: str
    title: str
    severity: str
    status: str
    source: str
    timestamp: datetime
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class MockEvent(BaseModel):
    """Mock event model."""
    event_id: str
    timestamp: datetime
    event_type: str
    source: Optional[Dict[str, Any]] = None
    message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class MockTriageResult(BaseModel):
    """Mock triage result."""
    alert_id: str
    priority: str
    classification: str
    confidence: float
    reasoning: str


class MockAgentExecution(BaseModel):
    """Mock agent execution."""
    task_id: str
    state: str
    steps: List[Dict[str, Any]]
    current_step: int
    final_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# Mock Data Store
class MockDataStore:
    """In-memory data store for mocks."""

    def __init__(self):
        self.alerts: Dict[str, MockAlert] = {}
        self.events: List[MockEvent] = []
        self.triage_results: Dict[str, MockTriageResult] = {}
        self.agent_executions: Dict[str, MockAgentExecution] = {}
        self._load_sample_data()

    def _load_sample_data(self):
        """Load sample data into the store."""
        # Sample alerts
        self.alerts["alert-001"] = MockAlert(
            id="alert-001",
            title="SSH Brute Force Detected",
            severity="high",
            status="new",
            source="detection_engine",
            timestamp=datetime.utcnow() - timedelta(hours=1),
            description="Multiple failed SSH login attempts detected",
        )

        self.alerts["alert-002"] = MockAlert(
            id="alert-002",
            title="Malware Detected",
            severity="critical",
            status="investigating",
            source="edr",
            timestamp=datetime.utcnow() - timedelta(minutes=30),
            description="Ransomware signature detected on endpoint",
        )

    def add_alert(self, alert: MockAlert) -> MockAlert:
        """Add an alert to the store."""
        if not alert.id:
            alert.id = f"alert-{uuid4()}"
        self.alerts[alert.id] = alert
        return alert

    def add_event(self, event: MockEvent) -> MockEvent:
        """Add an event to the store."""
        if not event.event_id:
            event.event_id = f"evt-{uuid4()}"
        self.events.append(event)
        return event


# Mock Triage Service
def create_mock_triage_app(store: MockDataStore) -> FastAPI:
    """Create a mock triage service FastAPI app."""
    app = FastAPI(title="Mock Triage Service")

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "ai-triage"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.post("/api/v1/triage")
    async def triage_alert(request: Dict[str, Any]):
        alert = request.get("alert", {})
        alert_id = alert.get("id", str(uuid4()))

        result = MockTriageResult(
            alert_id=alert_id,
            priority="high" if alert.get("severity") in ["high", "critical"] else "medium",
            classification="true_positive",
            confidence=0.85,
            reasoning="Mock triage result for testing",
        )

        store.triage_results[alert_id] = result

        return {
            "success": True,
            "data": result.dict(),
            "request_id": request.get("request_id"),
        }

    @app.post("/api/v1/triage/batch")
    async def triage_batch(request: Dict[str, Any]):
        alerts = request.get("alerts", [])
        results = []

        for alert in alerts:
            alert_id = alert.get("id", str(uuid4()))
            result = MockTriageResult(
                alert_id=alert_id,
                priority="medium",
                classification="needs_review",
                confidence=0.75,
                reasoning="Batch mock triage",
            )
            results.append(result.dict())

        return {
            "success": True,
            "data": results,
            "request_id": request.get("request_id"),
        }

    @app.post("/api/v1/classify")
    async def classify_alert(request: Dict[str, Any]):
        return {
            "success": True,
            "data": {
                "category": "malware",
                "confidence": 0.9,
                "categories_scores": {
                    "malware": 0.9,
                    "phishing": 0.05,
                    "brute_force": 0.05,
                },
            },
        }

    @app.post("/api/v1/correlate")
    async def correlate_alerts(request: Dict[str, Any]):
        alerts = request.get("alerts", [])
        return {
            "success": True,
            "data": {
                "correlation_id": str(uuid4()),
                "correlated_alerts": [a.get("alert_id") for a in alerts],
                "correlation_type": "temporal",
                "confidence": 0.8,
            },
        }

    return app


# Mock Copilot Service
def create_mock_copilot_app(store: MockDataStore) -> FastAPI:
    """Create a mock copilot service FastAPI app."""
    app = FastAPI(title="Mock Copilot Service")

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "ai-copilot"}

    @app.post("/api/v1/query/natural")
    async def nl_query(request: Dict[str, Any]):
        question = request.get("question", "")
        return {
            "success": True,
            "data": {
                "generated_sql": "SELECT count(*) FROM events WHERE timestamp >= now() - INTERVAL 1 HOUR",
                "explanation": f"Query generated for: {question}",
                "results": [],
            },
        }

    @app.post("/api/v1/investigate")
    async def investigate(request: Dict[str, Any]):
        alert = request.get("alert", {})
        return {
            "success": True,
            "data": {
                "alert_id": alert.get("id"),
                "findings": [
                    "Initial analysis suggests malicious activity",
                    "Source IP has no prior history",
                    "Similar patterns detected in recent alerts",
                ],
                "recommended_actions": [
                    "Isolate affected host",
                    "Collect forensic evidence",
                    "Block source IP at firewall",
                ],
                "confidence": 0.85,
            },
        }

    @app.post("/api/v1/recommend")
    async def recommend(request: Dict[str, Any]):
        return {
            "success": True,
            "data": {
                "recommendations": [
                    {
                        "action": "Isolate affected systems",
                        "priority": "high",
                        "rationale": "Prevent lateral movement",
                    },
                    {
                        "action": "Collect forensic evidence",
                        "priority": "high",
                        "rationale": "Preserve evidence for investigation",
                    },
                ],
                "playbook_suggestions": ["playbook-malware-response"],
            },
        }

    @app.post("/api/v1/summarize")
    async def summarize(request: Dict[str, Any]):
        incident = request.get("incident", {})
        return {
            "success": True,
            "data": {
                "summary": f"Incident {incident.get('incident_id')} involves potential malware activity.",
                "key_findings": ["Malware detected", "Lateral movement attempted"],
                "timeline_summary": "Attack progression over 2 hours",
            },
        }

    @app.post("/api/v1/chat")
    async def chat(request: Dict[str, Any]):
        message = request.get("message", "")
        return {
            "success": True,
            "data": {
                "response": f"Mock response to: {message}",
                "suggestions": ["Follow up question 1", "Follow up question 2"],
            },
        }

    return app


# Mock Agentic Service
def create_mock_agentic_app(store: MockDataStore) -> FastAPI:
    """Create a mock agentic service FastAPI app."""
    app = FastAPI(title="Mock Agentic Service")

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "ai-agentic", "version": "0.1.0"}

    @app.post("/api/v1/execute")
    async def execute_task(request: Dict[str, Any]):
        task = request.get("task", {})
        task_id = task.get("task_id", str(uuid4()))

        execution = MockAgentExecution(
            task_id=task_id,
            state="pending",
            steps=[],
            current_step=0,
        )

        store.agent_executions[task_id] = execution

        return {
            "success": True,
            "data": execution.dict(),
            "request_id": request.get("request_id"),
        }

    @app.get("/api/v1/tasks/{task_id}")
    async def get_task(task_id: str):
        execution = store.agent_executions.get(task_id)
        if execution:
            return {
                "success": True,
                "data": execution.dict(),
            }
        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Task not found"},
        )

    @app.get("/api/v1/tasks")
    async def list_tasks():
        return {
            "success": True,
            "data": [e.dict() for e in store.agent_executions.values()],
        }

    @app.post("/api/v1/approve")
    async def approve_action(request: Dict[str, Any]):
        task_id = request.get("task_id")
        approved = request.get("approved", False)

        execution = store.agent_executions.get(task_id)
        if execution:
            execution.state = "running" if approved else "cancelled"
            return {
                "success": True,
                "data": execution.dict(),
            }

        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Task not found"},
        )

    @app.post("/api/v1/cancel/{task_id}")
    async def cancel_task(task_id: str):
        execution = store.agent_executions.get(task_id)
        if execution:
            execution.state = "cancelled"
            return {
                "success": True,
                "data": execution.dict(),
            }

        return JSONResponse(
            status_code=404,
            content={"success": False, "error": "Task not found"},
        )

    return app


# Mock HTTP Client for Testing
class MockHTTPClient:
    """Mock HTTP client for testing."""

    def __init__(self, responses: Optional[Dict[str, Any]] = None):
        self.responses = responses or {}
        self.requests: List[Dict[str, Any]] = []

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock GET request."""
        self.requests.append({"method": "GET", "url": url, "kwargs": kwargs})
        return self._get_response(url, "GET")

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock POST request."""
        self.requests.append({"method": "POST", "url": url, "kwargs": kwargs})
        return self._get_response(url, "POST")

    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock PUT request."""
        self.requests.append({"method": "PUT", "url": url, "kwargs": kwargs})
        return self._get_response(url, "PUT")

    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Mock DELETE request."""
        self.requests.append({"method": "DELETE", "url": url, "kwargs": kwargs})
        return self._get_response(url, "DELETE")

    def _get_response(self, url: str, method: str) -> Dict[str, Any]:
        """Get mock response for URL and method."""
        key = f"{method}:{url}"
        if key in self.responses:
            return self.responses[key]

        # Default responses
        if "/health" in url:
            return {"status": 200, "body": {"status": "healthy"}}

        return {"status": 200, "body": {}}


# Mock ClickHouse Client
class MockClickHouseClient:
    """Mock ClickHouse client for testing."""

    def __init__(self):
        self.queries: List[str] = []
        self.results: Dict[str, Any] = {
            "SELECT count() FROM events": [{"count()": 1000}],
        }

    async def execute(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Execute a mock query."""
        self.queries.append(query)

        if query in self.results:
            return self.results[query]

        return []

    def set_result(self, query: str, result: Any):
        """Set mock result for a query."""
        self.results[query] = result


# Mock Kafka Producer
class MockKafkaProducer:
    """Mock Kafka producer for testing."""

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []

    async def send(self, topic: str, value: bytes, key: Optional[bytes] = None):
        """Send a mock message."""
        self.messages.append({
            "topic": topic,
            "key": key,
            "value": value,
            "timestamp": datetime.utcnow().isoformat(),
        })

    async def flush(self):
        """Flush mock producer."""
        pass


# Utility functions for running mock servers
def run_mock_triage_server(port: int = 8001):
    """Run mock triage server."""
    store = MockDataStore()
    app = create_mock_triage_app(store)
    uvicorn.run(app, host="0.0.0.0", port=port)


def run_mock_copilot_server(port: int = 8000):
    """Run mock copilot server."""
    store = MockDataStore()
    app = create_mock_copilot_app(store)
    uvicorn.run(app, host="0.0.0.0", port=port)


def run_mock_agentic_server(port: int = 8002):
    """Run mock agentic server."""
    store = MockDataStore()
    app = create_mock_agentic_app(store)
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        service = sys.argv[1]
        if service == "triage":
            run_mock_triage_server()
        elif service == "copilot":
            run_mock_copilot_server()
        elif service == "agentic":
            run_mock_agentic_server()
        else:
            print(f"Unknown service: {service}")
            print("Usage: python mock_services.py [triage|copilot|agentic]")
    else:
        print("Usage: python mock_services.py [triage|copilot|agentic]")
