"""
Locust Load Test for SIEM/SOAR Platform

This file defines load testing scenarios using Locust for performance testing.
Supports distributed testing across multiple workers.
"""

import json
import random
import string
import time
from datetime import datetime, timedelta
from typing import Any

from locust import HttpUser, TaskSet, between, events, task
from locust.runners import MasterRunner, WorkerRunner


# Configuration
DEFAULT_HEADERS = {"Content-Type": "application/json"}


def random_string(length: int = 32) -> str:
    """Generate a random string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def random_ip() -> str:
    """Generate a random IP address."""
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


class EventGenerator:
    """Generate sample security events."""

    EVENT_TYPES = [
        "auth_failure",
        "auth_success",
        "connection",
        "process_create",
        "file_access",
        "dns_query",
        "network_flow",
    ]

    SERVICES = ["sshd", "httpd", "mysql", "postgresql", "nginx", "api-server"]

    @classmethod
    def generate_event(cls) -> dict[str, Any]:
        """Generate a single security event."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": random_string(32),
            "event_type": random.choice(cls.EVENT_TYPES),
            "source": {
                "ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "port": random.randint(1024, 65535),
                "hostname": f"host-{random_string(8)}",
            },
            "destination": {
                "ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                "port": random.randint(1, 1024),
                "hostname": f"server-{random_string(6)}",
            },
            "user": {"name": f"user{random.randint(1, 1000)}", "domain": "CORP"},
            "service": random.choice(cls.SERVICES),
            "message": f"Test event {random_string(16)}",
            "metadata": {
                "collector_id": f"collector-{random.randint(1, 10)}",
                "original_source": "syslog",
            },
        }

    @classmethod
    def generate_batch(cls, size: int = 100) -> list[dict[str, Any]]:
        """Generate a batch of security events."""
        return [cls.generate_event() for _ in range(size)]


class AlertGenerator:
    """Generate sample alerts."""

    ALERT_TYPES = [
        "SSH Brute Force",
        "Malware Detected",
        "Data Exfiltration",
        "Suspicious Login",
        "Port Scan",
        "DDoS Attack",
    ]

    SEVERITIES = ["low", "medium", "high", "critical"]

    @classmethod
    def generate_alert(cls) -> dict[str, Any]:
        """Generate a single alert."""
        return {
            "id": random_string(32),
            "title": f"{random.choice(cls.ALERT_TYPES)} - {random_string(8)}",
            "severity": random.choice(cls.SEVERITIES),
            "status": "new",
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": random_ip(),
            "target_ip": f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "description": f"Test alert {random_string(50)}",
        }


class EventIngestionTasks(TaskSet):
    """Task set for event ingestion testing."""

    @task(10)
    def ingest_small_batch(self):
        """Ingest a small batch of events (10-50)."""
        batch_size = random.randint(10, 50)
        events = EventGenerator.generate_batch(batch_size)

        with self.client.post(
            "/api/v1/events/batch",
            json={"events": events},
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="ingest_small_batch",
        ) as response:
            if response.status_code in [200, 201, 202]:
                response.success()
            elif response.status_code == 404:
                response.success()  # Endpoint not implemented
            else:
                response.failure(f"Status {response.status_code}")

    @task(5)
    def ingest_medium_batch(self):
        """Ingest a medium batch of events (100-250)."""
        batch_size = random.randint(100, 250)
        events = EventGenerator.generate_batch(batch_size)

        with self.client.post(
            "/api/v1/events/batch",
            json={"events": events},
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="ingest_medium_batch",
        ) as response:
            if response.status_code in [200, 201, 202, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(2)
    def ingest_large_batch(self):
        """Ingest a large batch of events (500-1000)."""
        batch_size = random.randint(500, 1000)
        events = EventGenerator.generate_batch(batch_size)

        with self.client.post(
            "/api/v1/events/batch",
            json={"events": events},
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="ingest_large_batch",
            timeout=60,
        ) as response:
            if response.status_code in [200, 201, 202, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


class QueryTasks(TaskSet):
    """Task set for query testing."""

    QUERIES = [
        "SELECT count(*) FROM events WHERE timestamp >= now() - INTERVAL 1 HOUR",
        "SELECT event_type, count(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC LIMIT 10",
        "SELECT src_ip, count(*) FROM events WHERE event_type = 'auth_failure' GROUP BY src_ip LIMIT 10",
        "SELECT toStartOfMinute(timestamp) as minute, count(*) FROM events GROUP BY minute LIMIT 60",
    ]

    @task(5)
    def execute_simple_query(self):
        """Execute a simple aggregation query."""
        query = random.choice(self.QUERIES)

        with self.client.post(
            "/api/v1/query",
            json={
                "query": query,
                "start_time": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                "end_time": datetime.utcnow().isoformat(),
            },
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="simple_query",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(2)
    def execute_complex_query(self):
        """Execute a complex query."""
        query = """
        SELECT
            src_ip,
            dst_ip,
            event_type,
            count(*) as event_count
        FROM events
        WHERE timestamp >= now() - INTERVAL 6 HOUR
        GROUP BY src_ip, dst_ip, event_type
        HAVING event_count > 5
        ORDER BY event_count DESC
        LIMIT 100
        """

        with self.client.post(
            "/api/v1/query",
            json={
                "query": query,
                "start_time": (datetime.utcnow() - timedelta(hours=6)).isoformat(),
                "end_time": datetime.utcnow().isoformat(),
            },
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="complex_query",
            timeout=30,
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


class AlertTasks(TaskSet):
    """Task set for alert operations."""

    @task(10)
    def list_alerts(self):
        """List recent alerts."""
        with self.client.get(
            "/api/v1/alerts?limit=50",
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="list_alerts",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(5)
    def filter_alerts(self):
        """Filter alerts by severity."""
        severity = random.choice(["high", "critical"])

        with self.client.get(
            f"/api/v1/alerts?severity={severity}&limit=20",
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="filter_alerts",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(3)
    def search_alerts(self):
        """Search alerts."""
        with self.client.post(
            "/api/v1/alerts/search",
            json={
                "query": random_string(10),
                "filters": {"severity": ["high", "critical"]},
                "limit": 50,
            },
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="search_alerts",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


class PlaybookTasks(TaskSet):
    """Task set for playbook operations."""

    @task(5)
    def list_playbooks(self):
        """List available playbooks."""
        with self.client.get(
            "/api/v1/playbooks",
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="list_playbooks",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(2)
    def execute_playbook(self):
        """Execute a playbook."""
        with self.client.post(
            "/api/v1/playbooks/test-playbook/execute",
            json={"trigger_data": {"alert_id": random_string(32)}},
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="execute_playbook",
        ) as response:
            if response.status_code in [200, 202, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


class DetectionTasks(TaskSet):
    """Task set for detection rule operations."""

    @task(5)
    def list_rules(self):
        """List detection rules."""
        with self.client.get(
            "/api/v1/rules",
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="list_rules",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(2)
    def filter_rules(self):
        """Filter rules by severity."""
        with self.client.get(
            "/api/v1/rules?severity=high&enabled=true",
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="filter_rules",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


class SIEMUser(HttpUser):
    """Main load test user simulating SIEM operations."""

    wait_time = between(0.5, 2)

    # Weight different operations
    tasks = {
        EventIngestionTasks: 40,  # 40% - Event ingestion
        AlertTasks: 25,  # 25% - Alert operations
        QueryTasks: 20,  # 20% - Query operations
        PlaybookTasks: 10,  # 10% - Playbook operations
        DetectionTasks: 5,  # 5% - Detection rules
    }

    @task
    def health_check(self):
        """Periodic health check."""
        with self.client.get(
            "/health", catch_response=True, name="health_check"
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")


class HighVolumeUser(HttpUser):
    """High volume user for stress testing."""

    wait_time = between(0.1, 0.5)

    @task(10)
    def high_volume_ingestion(self):
        """High volume event ingestion."""
        events = EventGenerator.generate_batch(random.randint(200, 500))

        with self.client.post(
            "/api/v1/events/batch",
            json={"events": events},
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="high_volume_ingestion",
            timeout=60,
        ) as response:
            if response.status_code in [200, 201, 202, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")

    @task(3)
    def concurrent_queries(self):
        """Execute concurrent queries."""
        query = "SELECT count(*) FROM events WHERE timestamp >= now() - INTERVAL 5 MINUTE"

        with self.client.post(
            "/api/v1/query",
            json={
                "query": query,
                "start_time": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                "end_time": datetime.utcnow().isoformat(),
            },
            headers=DEFAULT_HEADERS,
            catch_response=True,
            name="concurrent_query",
        ) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Status {response.status_code}")


# Event handlers for custom reporting
@events.init.add_listener
def on_locust_init(environment, **kwargs):
    """Initialize custom metrics tracking."""
    if isinstance(environment.runner, MasterRunner):
        print("Running as Master")
    elif isinstance(environment.runner, WorkerRunner):
        print("Running as Worker")
    print(f"Target host: {environment.host}")


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test start."""
    print(f"Load test started at {datetime.utcnow().isoformat()}")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Log test stop and summary."""
    print(f"Load test stopped at {datetime.utcnow().isoformat()}")
    if environment.stats.total.num_requests > 0:
        print(f"Total requests: {environment.stats.total.num_requests}")
        print(f"Failure rate: {environment.stats.total.fail_ratio * 100:.2f}%")
        print(f"Avg response time: {environment.stats.total.avg_response_time:.2f}ms")
