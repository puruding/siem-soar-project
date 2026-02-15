"""Integration tests for Detection -> Alert flow.

Tests the flow: Event -> Detection Engine -> Alert Generation -> Alert Storage
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest


# Detection models
class SigmaRule:
    """Represents a Sigma detection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        conditions: list[dict],
        mitre_techniques: list[str] | None = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.conditions = conditions
        self.mitre_techniques = mitre_techniques or []
        self.enabled = True

    def matches(self, event: dict) -> bool:
        """Check if event matches this rule."""
        for condition in self.conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            event_value = self._get_nested_value(event, field)
            if event_value is None:
                return False

            if operator == "equals":
                if str(event_value) != str(value):
                    return False
            elif operator == "contains":
                if str(value) not in str(event_value):
                    return False
            elif operator == "in":
                if event_value not in value:
                    return False

        return True

    def _get_nested_value(self, obj: dict, path: str) -> Any:
        """Get a nested value from a dict using dot notation."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current


class CorrelationRule:
    """Represents a correlation rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        group_by: list[str],
        threshold: int,
        window_seconds: int,
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.group_by = group_by
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.enabled = True


class Alert:
    """Represents a generated alert."""

    def __init__(
        self,
        alert_id: str,
        title: str,
        severity: str,
        rule_id: str,
        events: list[dict],
        mitre_techniques: list[str] | None = None,
        enrichments: dict | None = None,
    ):
        self.alert_id = alert_id
        self.title = title
        self.severity = severity
        self.rule_id = rule_id
        self.events = events
        self.mitre_techniques = mitre_techniques or []
        self.enrichments = enrichments or {}
        self.created_at = datetime.now(timezone.utc)
        self.status = "new"


class DetectionEngine:
    """Detection engine that matches events against rules."""

    def __init__(self):
        self.sigma_rules: list[SigmaRule] = []
        self.correlation_rules: list[CorrelationRule] = []
        self.event_windows: dict[str, list] = {}
        self.metrics = {
            "events_processed": 0,
            "rules_evaluated": 0,
            "matches": 0,
        }

    def add_sigma_rule(self, rule: SigmaRule):
        """Add a Sigma rule."""
        self.sigma_rules.append(rule)

    def add_correlation_rule(self, rule: CorrelationRule):
        """Add a correlation rule."""
        self.correlation_rules.append(rule)

    def process_event(self, event: dict) -> list[tuple[str, SigmaRule]]:
        """Process an event and return matching rules."""
        matches = []
        self.metrics["events_processed"] += 1

        for rule in self.sigma_rules:
            if not rule.enabled:
                continue

            self.metrics["rules_evaluated"] += 1

            if rule.matches(event):
                matches.append(("sigma", rule))
                self.metrics["matches"] += 1

        # Track events for correlation
        self._track_event(event)

        # Check correlation rules
        correlation_matches = self._check_correlations(event)
        matches.extend(correlation_matches)

        return matches

    def _track_event(self, event: dict):
        """Track event for correlation."""
        for rule in self.correlation_rules:
            key = self._get_correlation_key(event, rule.group_by)
            if key:
                if key not in self.event_windows:
                    self.event_windows[key] = []

                self.event_windows[key].append(
                    {"event": event, "timestamp": time.time()}
                )

                # Clean old events
                cutoff = time.time() - rule.window_seconds
                self.event_windows[key] = [
                    e for e in self.event_windows[key] if e["timestamp"] > cutoff
                ]

    def _get_correlation_key(self, event: dict, group_by: list[str]) -> str | None:
        """Get correlation grouping key."""
        parts = []
        for field in group_by:
            value = self._get_nested_value(event, field)
            if value:
                parts.append(f"{field}={value}")
        return ":".join(parts) if parts else None

    def _get_nested_value(self, obj: dict, path: str) -> Any:
        """Get nested value from dict."""
        parts = path.split(".")
        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _check_correlations(self, event: dict) -> list[tuple[str, CorrelationRule]]:
        """Check if any correlation rules are triggered."""
        matches = []

        for rule in self.correlation_rules:
            if not rule.enabled:
                continue

            key = self._get_correlation_key(event, rule.group_by)
            if key and key in self.event_windows:
                if len(self.event_windows[key]) >= rule.threshold:
                    matches.append(("correlation", rule))
                    self.metrics["matches"] += 1

        return matches


class AlertGenerator:
    """Generates alerts from detection matches."""

    def __init__(self):
        self.generated_alerts: list[Alert] = []
        self.dedup_window_seconds = 300
        self._recent_alerts: dict[str, datetime] = {}

    def generate(self, event: dict, rule: SigmaRule | CorrelationRule) -> Alert | None:
        """Generate an alert from a detection match."""
        # Check for duplicates
        dedup_key = f"{rule.rule_id}:{self._get_dedup_key(event)}"
        if self._is_duplicate(dedup_key):
            return None

        alert = Alert(
            alert_id=f"alert-{uuid.uuid4().hex[:8]}",
            title=rule.name,
            severity=rule.severity,
            rule_id=rule.rule_id,
            events=[event],
            mitre_techniques=getattr(rule, "mitre_techniques", []),
        )

        self.generated_alerts.append(alert)
        self._recent_alerts[dedup_key] = datetime.now(timezone.utc)

        return alert

    def _get_dedup_key(self, event: dict) -> str:
        """Generate deduplication key from event."""
        parts = [
            event.get("principal", {}).get("ip", ""),
            event.get("target", {}).get("ip", ""),
            event.get("metadata", {}).get("event_type", ""),
        ]
        return ":".join(filter(None, parts))

    def _is_duplicate(self, key: str) -> bool:
        """Check if this is a duplicate alert."""
        if key in self._recent_alerts:
            last_alert = self._recent_alerts[key]
            elapsed = (datetime.now(timezone.utc) - last_alert).total_seconds()
            if elapsed < self.dedup_window_seconds:
                return True
        return False


class AlertEnricher:
    """Enriches alerts with additional context."""

    def __init__(self):
        self.enrichment_sources = {
            "threat_intel": self._enrich_threat_intel,
            "asset": self._enrich_asset,
            "historical": self._enrich_historical,
        }

    def enrich(self, alert: Alert) -> Alert:
        """Enrich an alert with additional context."""
        for source, enricher in self.enrichment_sources.items():
            try:
                enrichment = enricher(alert)
                if enrichment:
                    alert.enrichments[source] = enrichment
            except Exception:
                pass

        return alert

    def _enrich_threat_intel(self, alert: Alert) -> dict | None:
        """Enrich with threat intelligence."""
        # Mock threat intel enrichment
        for event in alert.events:
            ip = event.get("principal", {}).get("ip")
            if ip:
                return {
                    "ip": ip,
                    "reputation": "suspicious",
                    "confidence": 0.85,
                }
        return None

    def _enrich_asset(self, alert: Alert) -> dict | None:
        """Enrich with asset information."""
        # Mock asset enrichment
        for event in alert.events:
            hostname = event.get("principal", {}).get("hostname")
            if hostname:
                return {
                    "hostname": hostname,
                    "type": "workstation",
                    "owner": "IT Department",
                    "criticality": "medium",
                }
        return None

    def _enrich_historical(self, alert: Alert) -> dict | None:
        """Enrich with historical context."""
        return {
            "similar_alerts_24h": 3,
            "related_cases": [],
            "last_seen": datetime.now(timezone.utc).isoformat(),
        }


class AlertPublisher:
    """Publishes alerts to various destinations."""

    def __init__(self):
        self.published_alerts: list[Alert] = []
        self.destinations = []

    def add_destination(self, destination: str):
        """Add a publish destination."""
        self.destinations.append(destination)

    def publish(self, alert: Alert) -> bool:
        """Publish an alert."""
        self.published_alerts.append(alert)
        return True


class DetectionAlertPipeline:
    """Complete detection to alert pipeline."""

    def __init__(
        self,
        detection_engine: DetectionEngine,
        alert_generator: AlertGenerator,
        alert_enricher: AlertEnricher,
        alert_publisher: AlertPublisher,
    ):
        self.detection_engine = detection_engine
        self.alert_generator = alert_generator
        self.alert_enricher = alert_enricher
        self.alert_publisher = alert_publisher

    def process(self, event: dict) -> list[Alert]:
        """Process an event through the detection-alert pipeline."""
        alerts = []

        # Run detection
        matches = self.detection_engine.process_event(event)

        # Generate alerts
        for match_type, rule in matches:
            alert = self.alert_generator.generate(event, rule)
            if alert:
                # Enrich
                alert = self.alert_enricher.enrich(alert)

                # Publish
                self.alert_publisher.publish(alert)

                alerts.append(alert)

        return alerts


# Fixtures
@pytest.fixture
def detection_engine():
    return DetectionEngine()


@pytest.fixture
def alert_generator():
    return AlertGenerator()


@pytest.fixture
def alert_enricher():
    return AlertEnricher()


@pytest.fixture
def alert_publisher():
    return AlertPublisher()


@pytest.fixture
def pipeline(detection_engine, alert_generator, alert_enricher, alert_publisher):
    return DetectionAlertPipeline(
        detection_engine, alert_generator, alert_enricher, alert_publisher
    )


@pytest.fixture
def powershell_rule():
    return SigmaRule(
        rule_id="sigma-001",
        name="Suspicious PowerShell Command",
        severity="high",
        conditions=[
            {"field": "process.name", "operator": "equals", "value": "powershell.exe"},
            {
                "field": "process.command_line",
                "operator": "contains",
                "value": "-EncodedCommand",
            },
        ],
        mitre_techniques=["T1059.001"],
    )


@pytest.fixture
def brute_force_rule():
    return CorrelationRule(
        rule_id="corr-001",
        name="Brute Force Login Detection",
        severity="critical",
        group_by=["principal.ip"],
        threshold=5,
        window_seconds=300,
    )


@pytest.fixture
def sample_event():
    return {
        "metadata": {"event_type": "PROCESS_LAUNCH"},
        "principal": {"ip": "192.168.1.100", "hostname": "workstation-001"},
        "process": {"name": "powershell.exe", "command_line": "powershell -EncodedCommand abc123"},
    }


# Test cases
class TestSigmaRule:
    """Tests for SigmaRule."""

    def test_rule_creation(self, powershell_rule):
        """Test rule creation."""
        assert powershell_rule.rule_id == "sigma-001"
        assert powershell_rule.severity == "high"
        assert len(powershell_rule.conditions) == 2

    def test_rule_matches(self, powershell_rule, sample_event):
        """Test rule matching."""
        assert powershell_rule.matches(sample_event) is True

    def test_rule_not_matches(self, powershell_rule):
        """Test rule not matching."""
        event = {
            "process": {"name": "cmd.exe", "command_line": "dir"},
        }
        assert powershell_rule.matches(event) is False

    def test_contains_operator(self):
        """Test contains operator."""
        rule = SigmaRule(
            rule_id="test",
            name="Test",
            severity="low",
            conditions=[{"field": "message", "operator": "contains", "value": "error"}],
        )

        assert rule.matches({"message": "An error occurred"}) is True
        assert rule.matches({"message": "Success"}) is False

    def test_in_operator(self):
        """Test in operator."""
        rule = SigmaRule(
            rule_id="test",
            name="Test",
            severity="low",
            conditions=[
                {"field": "action", "operator": "in", "value": ["login", "logout"]}
            ],
        )

        assert rule.matches({"action": "login"}) is True
        assert rule.matches({"action": "create"}) is False


class TestCorrelationRule:
    """Tests for CorrelationRule."""

    def test_rule_creation(self, brute_force_rule):
        """Test correlation rule creation."""
        assert brute_force_rule.rule_id == "corr-001"
        assert brute_force_rule.threshold == 5
        assert brute_force_rule.window_seconds == 300


class TestDetectionEngine:
    """Tests for DetectionEngine."""

    def test_add_sigma_rule(self, detection_engine, powershell_rule):
        """Test adding Sigma rule."""
        detection_engine.add_sigma_rule(powershell_rule)
        assert len(detection_engine.sigma_rules) == 1

    def test_process_event_with_match(
        self, detection_engine, powershell_rule, sample_event
    ):
        """Test processing event with matching rule."""
        detection_engine.add_sigma_rule(powershell_rule)
        matches = detection_engine.process_event(sample_event)

        assert len(matches) == 1
        assert matches[0][0] == "sigma"
        assert matches[0][1] == powershell_rule

    def test_process_event_no_match(self, detection_engine, powershell_rule):
        """Test processing event with no matching rule."""
        detection_engine.add_sigma_rule(powershell_rule)
        event = {"process": {"name": "notepad.exe"}}
        matches = detection_engine.process_event(event)

        assert len(matches) == 0

    def test_correlation_detection(self, detection_engine, brute_force_rule):
        """Test correlation rule detection."""
        detection_engine.add_correlation_rule(brute_force_rule)

        # Generate events to trigger correlation
        for i in range(5):
            event = {
                "metadata": {"event_type": "AUTH_FAILURE"},
                "principal": {"ip": "192.168.1.100"},
            }
            matches = detection_engine.process_event(event)

        # The 5th event should trigger the correlation
        assert len(matches) == 1
        assert matches[0][0] == "correlation"

    def test_metrics_tracking(self, detection_engine, powershell_rule, sample_event):
        """Test metrics tracking."""
        detection_engine.add_sigma_rule(powershell_rule)
        detection_engine.process_event(sample_event)

        assert detection_engine.metrics["events_processed"] == 1
        assert detection_engine.metrics["rules_evaluated"] == 1
        assert detection_engine.metrics["matches"] == 1


class TestAlertGenerator:
    """Tests for AlertGenerator."""

    def test_generate_alert(self, alert_generator, powershell_rule, sample_event):
        """Test alert generation."""
        alert = alert_generator.generate(sample_event, powershell_rule)

        assert alert is not None
        assert alert.title == powershell_rule.name
        assert alert.severity == powershell_rule.severity
        assert alert.rule_id == powershell_rule.rule_id

    def test_deduplication(self, alert_generator, powershell_rule, sample_event):
        """Test alert deduplication."""
        alert1 = alert_generator.generate(sample_event, powershell_rule)
        alert2 = alert_generator.generate(sample_event, powershell_rule)

        assert alert1 is not None
        assert alert2 is None  # Duplicate

    def test_unique_alert_ids(self, alert_generator, powershell_rule):
        """Test unique alert IDs."""
        event1 = {"principal": {"ip": "192.168.1.1"}}
        event2 = {"principal": {"ip": "192.168.1.2"}}

        alert1 = alert_generator.generate(event1, powershell_rule)
        alert2 = alert_generator.generate(event2, powershell_rule)

        assert alert1.alert_id != alert2.alert_id


class TestAlertEnricher:
    """Tests for AlertEnricher."""

    def test_threat_intel_enrichment(self, alert_enricher):
        """Test threat intel enrichment."""
        alert = Alert(
            alert_id="test",
            title="Test",
            severity="high",
            rule_id="test",
            events=[{"principal": {"ip": "192.168.1.100"}}],
        )

        enriched = alert_enricher.enrich(alert)

        assert "threat_intel" in enriched.enrichments
        assert enriched.enrichments["threat_intel"]["ip"] == "192.168.1.100"

    def test_asset_enrichment(self, alert_enricher):
        """Test asset enrichment."""
        alert = Alert(
            alert_id="test",
            title="Test",
            severity="high",
            rule_id="test",
            events=[{"principal": {"hostname": "workstation-001"}}],
        )

        enriched = alert_enricher.enrich(alert)

        assert "asset" in enriched.enrichments

    def test_historical_enrichment(self, alert_enricher):
        """Test historical enrichment."""
        alert = Alert(
            alert_id="test",
            title="Test",
            severity="high",
            rule_id="test",
            events=[{}],
        )

        enriched = alert_enricher.enrich(alert)

        assert "historical" in enriched.enrichments
        assert "similar_alerts_24h" in enriched.enrichments["historical"]


class TestAlertPublisher:
    """Tests for AlertPublisher."""

    def test_publish_alert(self, alert_publisher):
        """Test alert publishing."""
        alert = Alert(
            alert_id="test",
            title="Test",
            severity="high",
            rule_id="test",
            events=[{}],
        )

        result = alert_publisher.publish(alert)

        assert result is True
        assert len(alert_publisher.published_alerts) == 1


class TestDetectionAlertPipeline:
    """Tests for complete DetectionAlertPipeline."""

    def test_end_to_end_flow(self, pipeline, sample_event, powershell_rule):
        """Test end-to-end detection to alert flow."""
        pipeline.detection_engine.add_sigma_rule(powershell_rule)

        alerts = pipeline.process(sample_event)

        assert len(alerts) == 1
        assert alerts[0].title == powershell_rule.name
        assert "threat_intel" in alerts[0].enrichments

    def test_multiple_rules(self, pipeline, sample_event):
        """Test multiple rules matching."""
        rule1 = SigmaRule(
            rule_id="rule-1",
            name="Rule 1",
            severity="high",
            conditions=[{"field": "process.name", "operator": "equals", "value": "powershell.exe"}],
        )
        rule2 = SigmaRule(
            rule_id="rule-2",
            name="Rule 2",
            severity="medium",
            conditions=[
                {
                    "field": "process.command_line",
                    "operator": "contains",
                    "value": "EncodedCommand",
                }
            ],
        )

        pipeline.detection_engine.add_sigma_rule(rule1)
        pipeline.detection_engine.add_sigma_rule(rule2)

        alerts = pipeline.process(sample_event)

        assert len(alerts) == 2

    def test_no_alerts_for_benign_event(self, pipeline, powershell_rule):
        """Test no alerts for benign events."""
        pipeline.detection_engine.add_sigma_rule(powershell_rule)

        benign_event = {
            "process": {"name": "notepad.exe", "command_line": "notepad.exe"},
        }
        alerts = pipeline.process(benign_event)

        assert len(alerts) == 0

    def test_high_volume_detection(self, pipeline, powershell_rule):
        """Test high volume event processing."""
        pipeline.detection_engine.add_sigma_rule(powershell_rule)

        start = time.time()
        for i in range(1000):
            event = {
                "process": {"name": "cmd.exe"},
                "principal": {"ip": f"192.168.1.{i % 256}"},
            }
            pipeline.process(event)
        elapsed = time.time() - start

        assert elapsed < 2.0  # Should process 1000 events in under 2 seconds
        assert pipeline.detection_engine.metrics["events_processed"] == 1000


class TestMITREIntegration:
    """Tests for MITRE ATT&CK integration."""

    def test_mitre_techniques_in_alert(self, pipeline, sample_event, powershell_rule):
        """Test MITRE techniques in generated alerts."""
        pipeline.detection_engine.add_sigma_rule(powershell_rule)

        alerts = pipeline.process(sample_event)

        assert len(alerts) == 1
        assert "T1059.001" in alerts[0].mitre_techniques

    def test_multiple_techniques(self, pipeline, sample_event):
        """Test rule with multiple MITRE techniques."""
        rule = SigmaRule(
            rule_id="multi-mitre",
            name="Multi MITRE",
            severity="high",
            conditions=[{"field": "process.name", "operator": "equals", "value": "powershell.exe"}],
            mitre_techniques=["T1059.001", "T1086", "T1064"],
        )

        pipeline.detection_engine.add_sigma_rule(rule)
        alerts = pipeline.process(sample_event)

        assert len(alerts[0].mitre_techniques) == 3
