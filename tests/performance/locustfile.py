"""Locust performance tests for SIEM-SOAR platform.

Run with: locust -f locustfile.py --host=http://localhost:8080
"""

import json
import random
import string
import time
import uuid
from datetime import datetime, timezone

from locust import HttpUser, between, events, task


def generate_event():
    """Generate a random security event."""
    event_types = [
        "PROCESS_LAUNCH",
        "NETWORK_CONNECTION",
        "FILE_CREATION",
        "USER_LOGIN",
        "REGISTRY_MODIFICATION",
    ]

    severities = ["critical", "high", "medium", "low", "info"]

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": random.choice(event_types),
        "severity": random.choice(severities),
        "source": {
            "ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "hostname": f"host-{random.randint(1, 1000):04d}",
            "user": f"user{random.randint(1, 100)}",
        },
        "destination": {
            "ip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "port": random.choice([22, 80, 443, 445, 3389, 8080]),
        },
        "process": {
            "name": random.choice(["cmd.exe", "powershell.exe", "python.exe", "bash"]),
            "pid": random.randint(1000, 65000),
            "command_line": "".join(random.choices(string.ascii_letters, k=50)),
        },
        "metadata": {
            "raw_log": "".join(random.choices(string.ascii_letters + " ", k=200)),
        },
    }


def generate_alert():
    """Generate a random security alert."""
    categories = ["malware", "phishing", "intrusion", "lateral_movement", "data_exfiltration"]
    severities = ["critical", "high", "medium", "low"]

    return {
        "alert_id": str(uuid.uuid4()),
        "title": f"Security Alert - {random.choice(categories).replace('_', ' ').title()}",
        "description": "Suspicious activity detected on the network.",
        "severity": random.choice(severities),
        "category": random.choice(categories),
        "source": "detection_engine",
        "events": [generate_event() for _ in range(random.randint(1, 5))],
        "mitre_techniques": [f"T{random.randint(1000, 1999)}" for _ in range(random.randint(1, 3))],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_query():
    """Generate a random query request."""
    query_templates = [
        "SELECT * FROM events WHERE severity = 'high' LIMIT 100",
        "SELECT COUNT(*) FROM events WHERE event_type = 'NETWORK_CONNECTION'",
        "SELECT source_ip, COUNT(*) FROM events GROUP BY source_ip LIMIT 50",
        "SELECT * FROM alerts WHERE status = 'new' ORDER BY created_at DESC LIMIT 20",
        "SELECT * FROM events WHERE timestamp > now() - INTERVAL 1 HOUR",
    ]

    return {
        "query": random.choice(query_templates),
        "timeout": 30000,
    }


class EventIngestionUser(HttpUser):
    """User simulating event ingestion."""

    wait_time = between(0.01, 0.1)  # Very short wait for high throughput
    weight = 5  # Higher weight for ingestion load

    @task(10)
    def ingest_single_event(self):
        """Ingest a single event."""
        event = generate_event()
        with self.client.post(
            "/api/v1/events",
            json=event,
            headers={"Content-Type": "application/json"},
            catch_response=True,
        ) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(3)
    def ingest_batch_events(self):
        """Ingest a batch of events."""
        events = [generate_event() for _ in range(100)]
        with self.client.post(
            "/api/v1/events/batch",
            json={"events": events},
            headers={"Content-Type": "application/json"},
            catch_response=True,
        ) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")


class AlertTriageUser(HttpUser):
    """User simulating alert triage operations."""

    wait_time = between(0.5, 2)
    weight = 3

    @task(5)
    def create_alert(self):
        """Create a new alert."""
        alert = generate_alert()
        with self.client.post(
            "/api/v1/alerts",
            json=alert,
            headers={"Content-Type": "application/json"},
            catch_response=True,
        ) as response:
            if response.status_code in [200, 201, 202]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(10)
    def list_alerts(self):
        """List recent alerts."""
        with self.client.get(
            "/api/v1/alerts?limit=50&status=new",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(5)
    def get_alert(self):
        """Get a specific alert."""
        alert_id = f"alert-{uuid.uuid4().hex[:8]}"
        with self.client.get(
            f"/api/v1/alerts/{alert_id}",
            catch_response=True,
        ) as response:
            if response.status_code in [200, 404]:  # 404 is expected for random IDs
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(3)
    def triage_alert(self):
        """Request AI triage for an alert."""
        alert_id = f"alert-{uuid.uuid4().hex[:8]}"
        with self.client.post(
            f"/api/v1/alerts/{alert_id}/triage",
            json={"auto_respond": False},
            catch_response=True,
        ) as response:
            if response.status_code in [200, 202, 404]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")


class QueryUser(HttpUser):
    """User simulating query operations."""

    wait_time = between(1, 5)
    weight = 2

    @task(5)
    def execute_query(self):
        """Execute a query."""
        query = generate_query()
        with self.client.post(
            "/api/v1/query",
            json=query,
            headers={"Content-Type": "application/json"},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            elif response.status_code == 408:  # Timeout
                response.failure("Query timeout")
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(3)
    def natural_language_query(self):
        """Execute a natural language query."""
        queries = [
            "show me critical alerts",
            "how many events in the last hour",
            "find network connections to port 443",
            "list failed logins",
        ]
        with self.client.post(
            "/api/v1/copilot/query",
            json={"query": random.choice(queries)},
            headers={"Content-Type": "application/json"},
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")


class SOARUser(HttpUser):
    """User simulating SOAR operations."""

    wait_time = between(2, 10)
    weight = 1

    @task(3)
    def list_playbooks(self):
        """List available playbooks."""
        with self.client.get(
            "/api/v1/playbooks",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(2)
    def execute_playbook(self):
        """Execute a playbook."""
        playbook_id = random.choice([
            "pb-enrichment",
            "pb-containment",
            "pb-notification",
        ])
        with self.client.post(
            f"/api/v1/playbooks/{playbook_id}/execute",
            json={
                "trigger_data": {
                    "alert_id": f"alert-{uuid.uuid4().hex[:8]}",
                    "source_ip": f"192.168.1.{random.randint(1, 254)}",
                }
            },
            catch_response=True,
        ) as response:
            if response.status_code in [200, 202, 404]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")

    @task(5)
    def get_execution_status(self):
        """Check playbook execution status."""
        execution_id = f"exec-{uuid.uuid4().hex[:8]}"
        with self.client.get(
            f"/api/v1/playbooks/executions/{execution_id}",
            catch_response=True,
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Failed with status {response.status_code}")


class HealthCheckUser(HttpUser):
    """User for health checks and monitoring."""

    wait_time = between(5, 10)
    weight = 1

    @task
    def health_check(self):
        """Check service health."""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")

    @task
    def ready_check(self):
        """Check service readiness."""
        with self.client.get("/ready", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Ready check failed: {response.status_code}")

    @task
    def metrics(self):
        """Get service metrics."""
        with self.client.get("/metrics", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Metrics failed: {response.status_code}")


# Custom event handlers for reporting
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts."""
    print("=" * 60)
    print("SIEM-SOAR Performance Test Starting")
    print(f"Target: {environment.host}")
    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops."""
    print("=" * 60)
    print("SIEM-SOAR Performance Test Complete")
    print("=" * 60)


@events.request.add_listener
def on_request(
    request_type,
    name,
    response_time,
    response_length,
    response,
    context,
    exception,
    **kwargs,
):
    """Called on each request for custom logging."""
    # Log slow requests
    if response_time > 5000:  # > 5 seconds
        print(f"SLOW REQUEST: {request_type} {name} took {response_time}ms")


# Custom shape for ramping up load
class StagesShape:
    """Custom load shape for staged testing.

    Stages:
    1. Warmup (1 min): 10 users
    2. Ramp (2 min): 10 -> 100 users
    3. Steady (5 min): 100 users
    4. Peak (2 min): 100 -> 500 users
    5. Sustained peak (3 min): 500 users
    6. Cooldown (2 min): 500 -> 10 users
    """

    stages = [
        {"duration": 60, "users": 10, "spawn_rate": 1},   # Warmup
        {"duration": 120, "users": 100, "spawn_rate": 5}, # Ramp
        {"duration": 300, "users": 100, "spawn_rate": 1}, # Steady
        {"duration": 120, "users": 500, "spawn_rate": 20}, # Peak
        {"duration": 180, "users": 500, "spawn_rate": 1}, # Sustained
        {"duration": 120, "users": 10, "spawn_rate": 10}, # Cooldown
    ]

    def tick(self):
        """Calculate current stage."""
        run_time = self.get_run_time()

        for stage in self.stages:
            run_time -= stage["duration"]
            if run_time < 0:
                return (stage["users"], stage["spawn_rate"])

        return None  # Stop test


if __name__ == "__main__":
    import subprocess
    import sys

    # Run with default settings
    subprocess.run([
        sys.executable, "-m", "locust",
        "-f", __file__,
        "--host", "http://localhost:8080",
        "--headless",
        "-u", "100",  # users
        "-r", "10",   # spawn rate
        "-t", "5m",   # duration
    ])
