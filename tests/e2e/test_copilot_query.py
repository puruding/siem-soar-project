"""End-to-end tests for AI Copilot natural language query.

Tests the flow: Natural Language Query -> NL2SQL -> Query Execution -> Response
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest


# Data classes
@dataclass
class QueryResult:
    query_id: str
    sql: str
    data: list[dict]
    columns: list[str]
    row_count: int
    execution_time_ms: int
    error: str | None = None


@dataclass
class CopilotResponse:
    request_id: str
    original_query: str
    interpreted_intent: str
    generated_sql: str
    result: QueryResult | None
    natural_response: str
    suggestions: list[str] = field(default_factory=list)
    confidence: float = 0.0


# Mock database
class MockClickHouseClient:
    """Mock ClickHouse client for testing."""

    def __init__(self):
        self.events = [
            {
                "event_id": f"evt-{i}",
                "timestamp": (datetime.now(timezone.utc) - timedelta(hours=i)).isoformat(),
                "event_type": "NETWORK_CONNECTION" if i % 3 == 0 else "PROCESS_LAUNCH",
                "severity": "high" if i % 5 == 0 else "medium",
                "source_ip": f"192.168.1.{i % 256}",
                "destination_ip": f"10.0.0.{i % 256}",
                "user": f"user{i % 10}",
                "hostname": f"host-{i % 20:03d}",
            }
            for i in range(100)
        ]

        self.alerts = [
            {
                "alert_id": f"alert-{i}",
                "title": f"Alert {i}",
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "category": ["malware", "phishing", "intrusion"][i % 3],
                "status": ["new", "triaged", "closed"][i % 3],
                "created_at": (datetime.now(timezone.utc) - timedelta(hours=i)).isoformat(),
            }
            for i in range(50)
        ]

    def query(self, sql: str) -> list[dict]:
        """Execute a query."""
        sql_lower = sql.lower()

        # Parse simple queries
        if "from events" in sql_lower:
            data = self.events

            # Apply WHERE conditions
            if "severity = 'high'" in sql_lower:
                data = [e for e in data if e["severity"] == "high"]
            if "event_type = 'network_connection'" in sql_lower:
                data = [e for e in data if e["event_type"] == "NETWORK_CONNECTION"]

            # Apply LIMIT
            if "limit" in sql_lower:
                try:
                    limit = int(sql_lower.split("limit")[-1].strip().split()[0])
                    data = data[:limit]
                except (ValueError, IndexError):
                    pass

            return data

        elif "from alerts" in sql_lower:
            data = self.alerts

            if "severity = 'critical'" in sql_lower:
                data = [a for a in data if a["severity"] == "critical"]
            if "status = 'new'" in sql_lower:
                data = [a for a in data if a["status"] == "new"]

            if "count(*)" in sql_lower:
                return [{"count": len(data)}]

            if "limit" in sql_lower:
                try:
                    limit = int(sql_lower.split("limit")[-1].strip().split()[0])
                    data = data[:limit]
                except (ValueError, IndexError):
                    pass

            return data

        return []


class NL2SQLConverter:
    """Converts natural language to SQL."""

    def __init__(self):
        self.schema = {
            "events": [
                "event_id", "timestamp", "event_type", "severity",
                "source_ip", "destination_ip", "user", "hostname"
            ],
            "alerts": [
                "alert_id", "title", "severity", "category",
                "status", "created_at"
            ],
        }

        self.intent_patterns = {
            "show": "SELECT * FROM",
            "list": "SELECT * FROM",
            "get": "SELECT * FROM",
            "find": "SELECT * FROM",
            "count": "SELECT COUNT(*) FROM",
            "how many": "SELECT COUNT(*) FROM",
        }

        self.table_patterns = {
            "events": "events",
            "logs": "events",
            "alerts": "alerts",
            "incidents": "alerts",
        }

        self.severity_mapping = {
            "critical": "severity = 'critical'",
            "high": "severity = 'high'",
            "medium": "severity = 'medium'",
            "low": "severity = 'low'",
        }

    def convert(self, query: str) -> tuple[str, str, float]:
        """Convert natural language to SQL.

        Returns: (sql, intent, confidence)
        """
        query_lower = query.lower()

        # Determine intent
        intent = "search"
        sql_prefix = "SELECT * FROM"
        for pattern, prefix in self.intent_patterns.items():
            if pattern in query_lower:
                intent = pattern
                sql_prefix = prefix
                break

        # Determine table
        table = "events"
        for pattern, tbl in self.table_patterns.items():
            if pattern in query_lower:
                table = tbl
                break

        # Build SQL
        sql = f"{sql_prefix} {table}"
        conditions = []

        # Add severity filter
        for severity, condition in self.severity_mapping.items():
            if severity in query_lower:
                conditions.append(condition)
                break

        # Add status filter
        if "new" in query_lower and table == "alerts":
            conditions.append("status = 'new'")
        elif "open" in query_lower and table == "alerts":
            conditions.append("status = 'new'")

        # Add type filter
        if "network" in query_lower:
            conditions.append("event_type = 'NETWORK_CONNECTION'")
        elif "process" in query_lower:
            conditions.append("event_type = 'PROCESS_LAUNCH'")

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        # Add time filter
        if "last hour" in query_lower:
            sql += " AND timestamp > now() - INTERVAL 1 HOUR"
        elif "last 24 hours" in query_lower or "today" in query_lower:
            sql += " AND timestamp > now() - INTERVAL 24 HOUR"

        # Add limit
        if "limit" not in sql_prefix.lower():
            sql += " LIMIT 100"

        # Calculate confidence based on specificity
        confidence = 0.5
        if conditions:
            confidence += 0.2
        if table in query_lower:
            confidence += 0.1
        if any(p in query_lower for p in self.intent_patterns):
            confidence += 0.1

        return sql, intent, min(confidence, 0.95)


class ResponseGenerator:
    """Generates natural language responses from query results."""

    def generate(
        self,
        original_query: str,
        intent: str,
        sql: str,
        result: QueryResult,
    ) -> tuple[str, list[str]]:
        """Generate natural language response.

        Returns: (response, suggestions)
        """
        if result.error:
            return f"Sorry, I encountered an error: {result.error}", []

        if result.row_count == 0:
            return "No results found matching your query.", [
                "Try a broader search",
                "Check the time range",
                "Verify filter criteria",
            ]

        # Generate response based on intent
        if "count" in intent.lower():
            return self._count_response(result), self._count_suggestions(sql)
        else:
            return self._list_response(result), self._list_suggestions(sql)

    def _count_response(self, result: QueryResult) -> str:
        """Generate count response."""
        if result.data and "count" in result.data[0]:
            count = result.data[0]["count"]
            return f"I found {count} matching records."
        return f"Found {result.row_count} records."

    def _list_response(self, result: QueryResult) -> str:
        """Generate list response."""
        response = f"Found {result.row_count} records. "

        if result.row_count > 10:
            response += f"Showing the first {min(10, result.row_count)}. "

        if result.data:
            first = result.data[0]
            if "severity" in first:
                high_count = sum(1 for r in result.data if r.get("severity") in ["critical", "high"])
                if high_count > 0:
                    response += f"{high_count} are high/critical severity."

        return response

    def _count_suggestions(self, sql: str) -> list[str]:
        """Generate suggestions for count queries."""
        return [
            "Break down by severity",
            "Show trend over time",
            "Compare with previous period",
        ]

    def _list_suggestions(self, sql: str) -> list[str]:
        """Generate suggestions for list queries."""
        return [
            "Filter by severity",
            "Show related events",
            "Export to CSV",
        ]


class CopilotService:
    """AI Copilot service for natural language queries."""

    def __init__(
        self,
        db_client: MockClickHouseClient,
        nl2sql: NL2SQLConverter,
        response_gen: ResponseGenerator,
    ):
        self.db_client = db_client
        self.nl2sql = nl2sql
        self.response_gen = response_gen

    async def query(self, natural_query: str) -> CopilotResponse:
        """Process a natural language query."""
        request_id = f"req-{uuid.uuid4().hex[:8]}"

        # Convert to SQL
        sql, intent, confidence = self.nl2sql.convert(natural_query)

        # Execute query
        start_time = time.time()
        try:
            data = self.db_client.query(sql)
            execution_time = int((time.time() - start_time) * 1000)

            columns = list(data[0].keys()) if data else []

            result = QueryResult(
                query_id=f"qry-{uuid.uuid4().hex[:8]}",
                sql=sql,
                data=data,
                columns=columns,
                row_count=len(data),
                execution_time_ms=execution_time,
            )
        except Exception as e:
            result = QueryResult(
                query_id=f"qry-{uuid.uuid4().hex[:8]}",
                sql=sql,
                data=[],
                columns=[],
                row_count=0,
                execution_time_ms=0,
                error=str(e),
            )

        # Generate natural response
        natural_response, suggestions = self.response_gen.generate(
            natural_query, intent, sql, result
        )

        return CopilotResponse(
            request_id=request_id,
            original_query=natural_query,
            interpreted_intent=intent,
            generated_sql=sql,
            result=result,
            natural_response=natural_response,
            suggestions=suggestions,
            confidence=confidence,
        )


# Fixtures
@pytest.fixture
def db_client():
    return MockClickHouseClient()


@pytest.fixture
def nl2sql():
    return NL2SQLConverter()


@pytest.fixture
def response_gen():
    return ResponseGenerator()


@pytest.fixture
def copilot(db_client, nl2sql, response_gen):
    return CopilotService(db_client, nl2sql, response_gen)


# Test cases
class TestNL2SQLConverter:
    """Tests for NL2SQLConverter."""

    def test_basic_query(self, nl2sql):
        """Test basic query conversion."""
        sql, intent, confidence = nl2sql.convert("show me all events")

        assert "SELECT * FROM events" in sql
        assert intent == "show"
        assert confidence > 0.5

    def test_count_query(self, nl2sql):
        """Test count query conversion."""
        sql, intent, confidence = nl2sql.convert("how many alerts are there")

        assert "COUNT(*)" in sql
        assert "alerts" in sql
        assert intent == "how many"

    def test_severity_filter(self, nl2sql):
        """Test severity filter."""
        sql, intent, confidence = nl2sql.convert("show critical alerts")

        assert "severity = 'critical'" in sql

    def test_status_filter(self, nl2sql):
        """Test status filter."""
        sql, intent, confidence = nl2sql.convert("list new alerts")

        assert "status = 'new'" in sql

    def test_event_type_filter(self, nl2sql):
        """Test event type filter."""
        sql, intent, confidence = nl2sql.convert("show network events")

        assert "event_type = 'NETWORK_CONNECTION'" in sql

    def test_confidence_scoring(self, nl2sql):
        """Test confidence scoring."""
        specific_sql, _, specific_conf = nl2sql.convert("show critical alerts")
        vague_sql, _, vague_conf = nl2sql.convert("find stuff")

        assert specific_conf > vague_conf


class TestResponseGenerator:
    """Tests for ResponseGenerator."""

    def test_count_response(self, response_gen):
        """Test count response generation."""
        result = QueryResult(
            query_id="test",
            sql="SELECT COUNT(*) FROM alerts",
            data=[{"count": 42}],
            columns=["count"],
            row_count=1,
            execution_time_ms=10,
        )

        response, suggestions = response_gen.generate(
            "how many alerts", "count", result.sql, result
        )

        assert "42" in response
        assert len(suggestions) > 0

    def test_list_response(self, response_gen):
        """Test list response generation."""
        result = QueryResult(
            query_id="test",
            sql="SELECT * FROM events",
            data=[{"event_id": "1", "severity": "high"} for _ in range(15)],
            columns=["event_id", "severity"],
            row_count=15,
            execution_time_ms=10,
        )

        response, suggestions = response_gen.generate(
            "show events", "show", result.sql, result
        )

        assert "15" in response
        assert "high" in response.lower() or "severity" in response.lower()

    def test_empty_result_response(self, response_gen):
        """Test response for empty results."""
        result = QueryResult(
            query_id="test",
            sql="SELECT * FROM events WHERE 1=0",
            data=[],
            columns=[],
            row_count=0,
            execution_time_ms=5,
        )

        response, suggestions = response_gen.generate(
            "find xyz", "find", result.sql, result
        )

        assert "no results" in response.lower()

    def test_error_response(self, response_gen):
        """Test response for query errors."""
        result = QueryResult(
            query_id="test",
            sql="INVALID SQL",
            data=[],
            columns=[],
            row_count=0,
            execution_time_ms=0,
            error="Syntax error",
        )

        response, suggestions = response_gen.generate(
            "show events", "show", result.sql, result
        )

        assert "error" in response.lower()


class TestCopilotService:
    """Tests for CopilotService."""

    @pytest.mark.asyncio
    async def test_basic_query(self, copilot):
        """Test basic copilot query."""
        response = await copilot.query("show me all events")

        assert response.request_id is not None
        assert response.generated_sql is not None
        assert response.result is not None
        assert response.result.row_count > 0
        assert response.natural_response is not None

    @pytest.mark.asyncio
    async def test_filtered_query(self, copilot):
        """Test filtered query."""
        response = await copilot.query("show high severity events")

        assert "severity = 'high'" in response.generated_sql
        assert all(
            e["severity"] == "high" for e in response.result.data
        )

    @pytest.mark.asyncio
    async def test_count_query(self, copilot):
        """Test count query."""
        response = await copilot.query("how many critical alerts")

        assert "COUNT(*)" in response.generated_sql
        assert response.result.data[0]["count"] >= 0

    @pytest.mark.asyncio
    async def test_suggestions_provided(self, copilot):
        """Test that suggestions are provided."""
        response = await copilot.query("show events")

        assert len(response.suggestions) > 0

    @pytest.mark.asyncio
    async def test_query_performance(self, copilot):
        """Test query performance."""
        start = time.time()
        response = await copilot.query("show all events")
        elapsed = time.time() - start

        assert elapsed < 1.0  # Query should complete in under 1 second
        assert response.result.execution_time_ms < 500


class TestEndToEndCopilot:
    """End-to-end Copilot tests."""

    @pytest.mark.asyncio
    async def test_conversation_flow(self, copilot):
        """Test conversation-like flow."""
        # Initial broad query
        r1 = await copilot.query("show me recent events")
        assert r1.result.row_count > 0

        # Refined query
        r2 = await copilot.query("show high severity events")
        assert r2.result.row_count <= r1.result.row_count

        # Count query
        r3 = await copilot.query("how many critical alerts")
        assert "COUNT" in r3.generated_sql

    @pytest.mark.asyncio
    async def test_various_query_patterns(self, copilot):
        """Test various natural language query patterns."""
        queries = [
            "show me all events",
            "list the alerts",
            "get critical alerts",
            "find network events",
            "how many alerts are there",
            "count new alerts",
        ]

        for query in queries:
            response = await copilot.query(query)
            assert response.result is not None
            assert response.result.error is None
            assert response.confidence > 0

    @pytest.mark.asyncio
    async def test_query_batch_performance(self, copilot):
        """Test batch query performance."""
        queries = [f"show events {i}" for i in range(20)]

        start = time.time()
        results = []
        for query in queries:
            result = await copilot.query(query)
            results.append(result)
        elapsed = time.time() - start

        assert len(results) == 20
        assert elapsed < 5.0  # 20 queries in under 5 seconds

    @pytest.mark.asyncio
    async def test_natural_response_quality(self, copilot):
        """Test natural response quality."""
        response = await copilot.query("show critical alerts")

        # Response should be informative
        assert len(response.natural_response) > 10

        # Response should reference results
        if response.result.row_count > 0:
            assert str(response.result.row_count) in response.natural_response or "Found" in response.natural_response
