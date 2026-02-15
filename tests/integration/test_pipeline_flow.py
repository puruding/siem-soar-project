"""Integration tests for the data pipeline flow.

Tests the complete flow: Raw Event -> Parser -> Normalizer -> Enricher -> Router -> Storage
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# Mock infrastructure components
class MockKafkaProducer:
    """Mock Kafka producer for testing."""

    def __init__(self, bootstrap_servers: str):
        self.bootstrap_servers = bootstrap_servers
        self.messages: dict[str, list] = {}
        self.closed = False

    def send(self, topic: str, value: dict, key: str | None = None):
        """Send a message to a topic."""
        if topic not in self.messages:
            self.messages[topic] = []
        self.messages[topic].append({"key": key, "value": value})
        return MockFuture()

    def flush(self, timeout: int = 30):
        """Flush pending messages."""
        pass

    def close(self):
        """Close the producer."""
        self.closed = True


class MockKafkaConsumer:
    """Mock Kafka consumer for testing."""

    def __init__(self, topic: str, bootstrap_servers: str, group_id: str = None):
        self.topic = topic
        self.bootstrap_servers = bootstrap_servers
        self.group_id = group_id
        self._messages: list = []
        self._index = 0
        self.closed = False

    def add_message(self, value: dict, key: str | None = None):
        """Add a message for consumption."""
        self._messages.append(MockKafkaMessage(self.topic, value, key))

    def __iter__(self):
        return self

    def __next__(self):
        if self._index < len(self._messages):
            msg = self._messages[self._index]
            self._index += 1
            return msg
        raise StopIteration

    def poll(self, timeout_ms: int = 1000):
        """Poll for messages."""
        if self._index < len(self._messages):
            msg = self._messages[self._index]
            self._index += 1
            return {self.topic: [msg]}
        return {}

    def close(self):
        """Close the consumer."""
        self.closed = True


class MockKafkaMessage:
    """Mock Kafka message."""

    def __init__(self, topic: str, value: dict, key: str | None = None):
        self.topic = topic
        self._value = value
        self._key = key
        self.offset = 0
        self.partition = 0

    @property
    def value(self):
        return self._value

    @property
    def key(self):
        return self._key


class MockFuture:
    """Mock future for async operations."""

    def get(self, timeout: int = 30):
        return {"offset": 0, "partition": 0}


class MockClickHouseClient:
    """Mock ClickHouse client for testing."""

    def __init__(self, host: str, port: int = 9000):
        self.host = host
        self.port = port
        self.tables: dict[str, list] = {}
        self.connected = True

    def execute(self, query: str, params: dict | None = None):
        """Execute a query."""
        if query.startswith("INSERT"):
            # Extract table name and data
            table = query.split("INTO")[1].split()[0].strip()
            if table not in self.tables:
                self.tables[table] = []
            if params:
                self.tables[table].append(params)
        return []

    def insert(self, table: str, data: list[dict]):
        """Insert data into a table."""
        if table not in self.tables:
            self.tables[table] = []
        self.tables[table].extend(data)

    def query(self, sql: str):
        """Query data."""
        return []


# Pipeline components
class EventParser:
    """Parses raw events into structured format."""

    def __init__(self):
        self.supported_formats = ["json", "cef", "syslog", "leef"]

    def parse(self, raw_event: str | bytes, format_hint: str | None = None) -> dict:
        """Parse a raw event."""
        if isinstance(raw_event, bytes):
            raw_event = raw_event.decode("utf-8")

        detected_format = format_hint or self._detect_format(raw_event)

        if detected_format == "json":
            return self._parse_json(raw_event)
        elif detected_format == "cef":
            return self._parse_cef(raw_event)
        elif detected_format == "syslog":
            return self._parse_syslog(raw_event)
        else:
            return {"raw": raw_event, "format": "unknown"}

    def _detect_format(self, raw: str) -> str:
        """Detect the format of a raw event."""
        raw = raw.strip()
        if raw.startswith("{"):
            return "json"
        if raw.startswith("CEF:"):
            return "cef"
        if raw.startswith("LEEF:"):
            return "leef"
        return "syslog"

    def _parse_json(self, raw: str) -> dict:
        """Parse JSON event."""
        data = json.loads(raw)
        data["_format"] = "json"
        return data

    def _parse_cef(self, raw: str) -> dict:
        """Parse CEF event."""
        parts = raw.split("|")
        return {
            "cef_version": parts[0].replace("CEF:", ""),
            "device_vendor": parts[1] if len(parts) > 1 else "",
            "device_product": parts[2] if len(parts) > 2 else "",
            "signature_id": parts[4] if len(parts) > 4 else "",
            "name": parts[5] if len(parts) > 5 else "",
            "severity": parts[6] if len(parts) > 6 else "",
            "_format": "cef",
        }

    def _parse_syslog(self, raw: str) -> dict:
        """Parse syslog event."""
        return {"message": raw, "_format": "syslog"}


class EventNormalizer:
    """Normalizes events to UDM format."""

    def __init__(self):
        self.field_mappings = {
            "src": "principal.ip",
            "dst": "target.ip",
            "user": "principal.user.name",
            "action": "security_result.action",
        }

    def normalize(self, event: dict) -> dict:
        """Normalize an event to UDM format."""
        udm_event = {
            "metadata": {
                "event_timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": self._determine_event_type(event),
                "vendor_name": event.get("device_vendor", "unknown"),
                "product_name": event.get("device_product", "unknown"),
                "normalized": True,
            },
            "principal": {},
            "target": {},
            "network": {},
            "security_result": {},
        }

        # Map fields
        for src_field, dst_field in self.field_mappings.items():
            if src_field in event:
                self._set_nested_field(udm_event, dst_field, event[src_field])

        return udm_event

    def _determine_event_type(self, event: dict) -> str:
        """Determine UDM event type."""
        if "authentication" in str(event).lower():
            return "USER_LOGIN"
        if "process" in str(event).lower():
            return "PROCESS_LAUNCH"
        if "network" in str(event).lower():
            return "NETWORK_CONNECTION"
        return "GENERIC_EVENT"

    def _set_nested_field(self, obj: dict, path: str, value: Any):
        """Set a nested field in a dictionary."""
        parts = path.split(".")
        for part in parts[:-1]:
            if part not in obj:
                obj[part] = {}
            obj = obj[part]
        obj[parts[-1]] = value


class EventEnricher:
    """Enriches events with additional context."""

    def __init__(self):
        self.geoip_db = {"192.168.1.100": {"country": "US", "city": "New York"}}
        self.asset_db = {"workstation-001": {"owner": "admin", "type": "desktop"}}
        self.threat_db = {"malicious.com": {"score": 100, "type": "malware"}}

    def enrich(self, event: dict) -> dict:
        """Enrich an event."""
        enriched = event.copy()
        enrichments = {}

        # GeoIP enrichment
        if "principal" in enriched and "ip" in enriched.get("principal", {}):
            ip = enriched["principal"]["ip"]
            if ip in self.geoip_db:
                enrichments["geoip"] = self.geoip_db[ip]

        # Asset enrichment
        hostname = enriched.get("principal", {}).get("hostname")
        if hostname and hostname in self.asset_db:
            enrichments["asset"] = self.asset_db[hostname]

        # Threat intelligence enrichment
        for field in ["domain", "url"]:
            if field in enriched:
                domain = enriched[field]
                if domain in self.threat_db:
                    enrichments["threat_intel"] = self.threat_db[domain]

        enriched["enrichments"] = enrichments
        return enriched


class EventRouter:
    """Routes events to appropriate destinations."""

    def __init__(
        self,
        kafka_producer: MockKafkaProducer,
        clickhouse_client: MockClickHouseClient,
    ):
        self.kafka_producer = kafka_producer
        self.clickhouse_client = clickhouse_client
        self.routing_rules = []

    def add_rule(self, condition: callable, destination: str):
        """Add a routing rule."""
        self.routing_rules.append((condition, destination))

    def route(self, event: dict):
        """Route an event based on rules."""
        destinations = []

        for condition, destination in self.routing_rules:
            if condition(event):
                destinations.append(destination)

        if not destinations:
            destinations = ["events.default"]

        for dest in destinations:
            if dest.startswith("kafka:"):
                topic = dest.replace("kafka:", "")
                self.kafka_producer.send(topic, event)
            elif dest.startswith("clickhouse:"):
                table = dest.replace("clickhouse:", "")
                self.clickhouse_client.insert(table, [event])


class Pipeline:
    """Complete data pipeline."""

    def __init__(
        self,
        parser: EventParser,
        normalizer: EventNormalizer,
        enricher: EventEnricher,
        router: EventRouter,
    ):
        self.parser = parser
        self.normalizer = normalizer
        self.enricher = enricher
        self.router = router
        self.metrics = {
            "events_processed": 0,
            "events_failed": 0,
            "processing_time_ms": [],
        }

    def process(self, raw_event: str) -> dict:
        """Process a raw event through the pipeline."""
        start_time = time.time()

        try:
            # Parse
            parsed = self.parser.parse(raw_event)

            # Normalize
            normalized = self.normalizer.normalize(parsed)

            # Enrich
            enriched = self.enricher.enrich(normalized)

            # Route
            self.router.route(enriched)

            self.metrics["events_processed"] += 1
            self.metrics["processing_time_ms"].append(
                (time.time() - start_time) * 1000
            )

            return enriched

        except Exception as e:
            self.metrics["events_failed"] += 1
            raise


# Fixtures
@pytest.fixture
def kafka_producer():
    return MockKafkaProducer("localhost:9092")


@pytest.fixture
def kafka_consumer():
    return MockKafkaConsumer("events.raw", "localhost:9092")


@pytest.fixture
def clickhouse_client():
    return MockClickHouseClient("localhost")


@pytest.fixture
def parser():
    return EventParser()


@pytest.fixture
def normalizer():
    return EventNormalizer()


@pytest.fixture
def enricher():
    return EventEnricher()


@pytest.fixture
def router(kafka_producer, clickhouse_client):
    r = EventRouter(kafka_producer, clickhouse_client)

    # Add default rules
    r.add_rule(
        lambda e: e.get("metadata", {}).get("event_type") == "USER_LOGIN",
        "kafka:events.auth",
    )
    r.add_rule(
        lambda e: "threat_intel" in e.get("enrichments", {}),
        "kafka:events.threats",
    )
    r.add_rule(lambda e: True, "clickhouse:events")

    return r


@pytest.fixture
def pipeline(parser, normalizer, enricher, router):
    return Pipeline(parser, normalizer, enricher, router)


# Test cases
class TestEventParser:
    """Tests for EventParser."""

    def test_parse_json(self, parser):
        """Test parsing JSON events."""
        raw = '{"user": "admin", "action": "login", "src": "192.168.1.100"}'
        result = parser.parse(raw)

        assert result["user"] == "admin"
        assert result["_format"] == "json"

    def test_parse_cef(self, parser):
        """Test parsing CEF events."""
        raw = "CEF:0|Security|IDS|1.0|100|Intrusion|10|src=10.0.0.1"
        result = parser.parse(raw)

        assert result["cef_version"] == "0"
        assert result["device_vendor"] == "Security"
        assert result["_format"] == "cef"

    def test_parse_syslog(self, parser):
        """Test parsing syslog events."""
        raw = "Jan 15 10:30:00 host sshd: Failed password for root"
        result = parser.parse(raw)

        assert "Failed password" in result["message"]
        assert result["_format"] == "syslog"

    def test_auto_detect_format(self, parser):
        """Test automatic format detection."""
        assert parser._detect_format('{"key": "value"}') == "json"
        assert parser._detect_format("CEF:0|Test") == "cef"
        assert parser._detect_format("Jan 15 10:30:00") == "syslog"


class TestEventNormalizer:
    """Tests for EventNormalizer."""

    def test_normalize_basic(self, normalizer):
        """Test basic normalization."""
        event = {"src": "192.168.1.100", "dst": "10.0.0.1", "user": "admin"}
        result = normalizer.normalize(event)

        assert result["metadata"]["normalized"] is True
        assert "event_timestamp" in result["metadata"]

    def test_field_mapping(self, normalizer):
        """Test field mapping."""
        event = {"src": "192.168.1.100", "user": "admin"}
        result = normalizer.normalize(event)

        assert result["principal"]["ip"] == "192.168.1.100"
        assert result["principal"]["user"]["name"] == "admin"

    def test_event_type_detection(self, normalizer):
        """Test event type detection."""
        auth_event = {"message": "authentication failed"}
        process_event = {"message": "process started"}
        network_event = {"message": "network connection"}

        assert normalizer._determine_event_type(auth_event) == "USER_LOGIN"
        assert normalizer._determine_event_type(process_event) == "PROCESS_LAUNCH"
        assert normalizer._determine_event_type(network_event) == "NETWORK_CONNECTION"


class TestEventEnricher:
    """Tests for EventEnricher."""

    def test_geoip_enrichment(self, enricher):
        """Test GeoIP enrichment."""
        event = {"principal": {"ip": "192.168.1.100"}}
        result = enricher.enrich(event)

        assert "geoip" in result["enrichments"]
        assert result["enrichments"]["geoip"]["country"] == "US"

    def test_asset_enrichment(self, enricher):
        """Test asset enrichment."""
        event = {"principal": {"hostname": "workstation-001"}}
        result = enricher.enrich(event)

        assert "asset" in result["enrichments"]
        assert result["enrichments"]["asset"]["owner"] == "admin"

    def test_threat_intel_enrichment(self, enricher):
        """Test threat intelligence enrichment."""
        event = {"domain": "malicious.com"}
        result = enricher.enrich(event)

        assert "threat_intel" in result["enrichments"]
        assert result["enrichments"]["threat_intel"]["score"] == 100


class TestEventRouter:
    """Tests for EventRouter."""

    def test_route_to_kafka(self, router, kafka_producer):
        """Test routing to Kafka."""
        event = {
            "metadata": {"event_type": "USER_LOGIN"},
            "enrichments": {},
        }
        router.route(event)

        assert "events.auth" in kafka_producer.messages
        assert len(kafka_producer.messages["events.auth"]) == 1

    def test_route_threat_events(self, router, kafka_producer):
        """Test routing threat events."""
        event = {
            "metadata": {"event_type": "GENERIC_EVENT"},
            "enrichments": {"threat_intel": {"score": 100}},
        }
        router.route(event)

        assert "events.threats" in kafka_producer.messages

    def test_route_to_clickhouse(self, router, clickhouse_client):
        """Test routing to ClickHouse."""
        event = {"metadata": {"event_type": "GENERIC_EVENT"}, "enrichments": {}}
        router.route(event)

        assert "events" in clickhouse_client.tables
        assert len(clickhouse_client.tables["events"]) == 1


class TestPipeline:
    """Tests for complete Pipeline."""

    def test_process_json_event(self, pipeline):
        """Test processing JSON event."""
        raw = '{"user": "admin", "src": "192.168.1.100", "action": "login"}'
        result = pipeline.process(raw)

        assert result["metadata"]["normalized"] is True
        assert "enrichments" in result

    def test_process_cef_event(self, pipeline):
        """Test processing CEF event."""
        raw = "CEF:0|Security|IDS|1.0|100|Intrusion|10|src=10.0.0.1"
        result = pipeline.process(raw)

        assert result["metadata"]["normalized"] is True

    def test_pipeline_metrics(self, pipeline):
        """Test pipeline metrics tracking."""
        raw = '{"event": "test"}'
        pipeline.process(raw)
        pipeline.process(raw)

        assert pipeline.metrics["events_processed"] == 2
        assert len(pipeline.metrics["processing_time_ms"]) == 2

    def test_pipeline_error_handling(self, pipeline):
        """Test pipeline error handling."""
        raw = "not valid json {{"

        with pytest.raises(Exception):
            pipeline.process(raw)

        assert pipeline.metrics["events_failed"] == 1


class TestKafkaIntegration:
    """Tests for Kafka integration."""

    def test_producer_send(self, kafka_producer):
        """Test Kafka producer send."""
        kafka_producer.send("test-topic", {"key": "value"})

        assert "test-topic" in kafka_producer.messages
        assert len(kafka_producer.messages["test-topic"]) == 1

    def test_consumer_consume(self, kafka_consumer):
        """Test Kafka consumer consume."""
        kafka_consumer.add_message({"key": "value"})

        messages = list(kafka_consumer)
        assert len(messages) == 1
        assert messages[0].value["key"] == "value"

    def test_producer_flush(self, kafka_producer):
        """Test producer flush."""
        kafka_producer.send("topic", {"data": "test"})
        kafka_producer.flush()  # Should not raise

    def test_producer_close(self, kafka_producer):
        """Test producer close."""
        kafka_producer.close()
        assert kafka_producer.closed is True


class TestClickHouseIntegration:
    """Tests for ClickHouse integration."""

    def test_insert(self, clickhouse_client):
        """Test ClickHouse insert."""
        data = [{"event_id": "1", "data": "test"}]
        clickhouse_client.insert("events", data)

        assert "events" in clickhouse_client.tables
        assert len(clickhouse_client.tables["events"]) == 1

    def test_multiple_inserts(self, clickhouse_client):
        """Test multiple inserts."""
        for i in range(10):
            clickhouse_client.insert("events", [{"id": str(i)}])

        assert len(clickhouse_client.tables["events"]) == 10


class TestEndToEndFlow:
    """End-to-end tests for the pipeline."""

    def test_complete_flow(self, pipeline, kafka_producer, clickhouse_client):
        """Test complete event flow."""
        # Simulate multiple events
        events = [
            '{"user": "admin", "action": "login", "src": "192.168.1.100"}',
            '{"user": "guest", "action": "logout", "src": "192.168.1.101"}',
            'CEF:0|AV|Scanner|1.0|1|Malware|9|src=10.0.0.1',
        ]

        for event in events:
            pipeline.process(event)

        # Verify metrics
        assert pipeline.metrics["events_processed"] == 3
        assert pipeline.metrics["events_failed"] == 0

        # Verify storage
        assert "events" in clickhouse_client.tables
        assert len(clickhouse_client.tables["events"]) == 3

    def test_high_volume_processing(self, pipeline):
        """Test high volume event processing."""
        event_template = '{"user": "user_%d", "action": "test"}'

        start = time.time()
        for i in range(1000):
            pipeline.process(event_template % i)
        elapsed = time.time() - start

        assert pipeline.metrics["events_processed"] == 1000
        assert elapsed < 5.0  # Should process 1000 events in under 5 seconds

    def test_concurrent_processing(self, parser, normalizer, enricher):
        """Test concurrent event processing."""

        async def process_event(raw: str) -> dict:
            parsed = parser.parse(raw)
            normalized = normalizer.normalize(parsed)
            enriched = enricher.enrich(normalized)
            return enriched

        async def run_concurrent():
            events = ['{"id": "%d"}' % i for i in range(100)]
            tasks = [process_event(e) for e in events]
            results = await asyncio.gather(*tasks)
            return results

        results = asyncio.run(run_concurrent())
        assert len(results) == 100
