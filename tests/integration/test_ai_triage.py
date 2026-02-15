"""Integration tests for AI Alert Triage.

Tests the flow: Alert -> AI Classification -> Priority Scoring -> Routing
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import pytest


# Models
class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    RANSOMWARE = "ransomware"
    UNKNOWN = "unknown"


class TriageDecision(str, Enum):
    ESCALATE = "escalate"
    INVESTIGATE = "investigate"
    AUTOMATE = "automate"
    CLOSE = "close"


@dataclass
class Alert:
    """Represents a security alert."""

    alert_id: str
    title: str
    description: str
    source: str
    raw_severity: str
    events: list[dict] = field(default_factory=list)
    enrichments: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ClassificationResult:
    """Result of AI classification."""

    category: AlertCategory
    severity: AlertSeverity
    confidence: float
    is_true_positive: bool
    fp_probability: float
    mitre_techniques: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass
class PriorityScore:
    """Priority scoring result."""

    score: int  # 1-100
    factors: dict = field(default_factory=dict)
    queue: str = "default"


@dataclass
class TriageResult:
    """Complete triage result."""

    alert_id: str
    classification: ClassificationResult
    priority: PriorityScore
    decision: TriageDecision
    recommended_actions: list[str] = field(default_factory=list)
    assigned_analyst: str | None = None
    processing_time_ms: int = 0


# AI Components
class AlertClassifier:
    """AI-powered alert classifier."""

    def __init__(self):
        self.model_loaded = True
        self.keyword_patterns = {
            AlertCategory.MALWARE: ["malware", "virus", "trojan", "worm", "backdoor"],
            AlertCategory.PHISHING: ["phishing", "credential", "login page", "fake"],
            AlertCategory.RANSOMWARE: ["ransomware", "encrypt", "ransom", "bitcoin"],
            AlertCategory.INTRUSION: ["intrusion", "breach", "unauthorized", "exploit"],
            AlertCategory.LATERAL_MOVEMENT: ["lateral", "psexec", "wmi", "remote"],
            AlertCategory.CREDENTIAL_THEFT: ["mimikatz", "password", "hash", "dump"],
            AlertCategory.DATA_EXFILTRATION: ["exfil", "data leak", "upload", "transfer"],
        }

        self.severity_keywords = {
            AlertSeverity.CRITICAL: ["critical", "emergency", "breach", "ransomware"],
            AlertSeverity.HIGH: ["high", "severe", "malware", "intrusion"],
            AlertSeverity.MEDIUM: ["medium", "moderate", "suspicious"],
            AlertSeverity.LOW: ["low", "minor", "informational"],
        }

        self.fp_indicators = ["test", "demo", "false", "benign", "scanner", "pentest"]

    def classify(self, alert: Alert) -> ClassificationResult:
        """Classify an alert."""
        text = f"{alert.title} {alert.description}".lower()

        # Determine category
        category = self._classify_category(text)

        # Determine severity
        severity = self._classify_severity(text, alert.raw_severity)

        # Calculate FP probability
        fp_prob = self._calculate_fp_probability(text, alert)

        # Extract MITRE techniques
        techniques = self._extract_mitre_techniques(text, category)

        # Calculate confidence
        confidence = self._calculate_confidence(text, category)

        return ClassificationResult(
            category=category,
            severity=severity,
            confidence=confidence,
            is_true_positive=fp_prob < 0.5,
            fp_probability=fp_prob,
            mitre_techniques=techniques,
            explanation=f"Classified as {category.value} with {confidence:.0%} confidence",
        )

    def _classify_category(self, text: str) -> AlertCategory:
        """Classify alert category."""
        max_matches = 0
        best_category = AlertCategory.UNKNOWN

        for category, keywords in self.keyword_patterns.items():
            matches = sum(1 for kw in keywords if kw in text)
            if matches > max_matches:
                max_matches = matches
                best_category = category

        return best_category

    def _classify_severity(self, text: str, raw_severity: str) -> AlertSeverity:
        """Classify alert severity."""
        # Use raw severity if valid
        try:
            return AlertSeverity(raw_severity.lower())
        except ValueError:
            pass

        # Infer from text
        for severity, keywords in self.severity_keywords.items():
            if any(kw in text for kw in keywords):
                return severity

        return AlertSeverity.MEDIUM

    def _calculate_fp_probability(self, text: str, alert: Alert) -> float:
        """Calculate false positive probability."""
        fp_score = 0.0

        # Check FP indicators
        for indicator in self.fp_indicators:
            if indicator in text:
                fp_score += 0.2

        # Check source reliability
        trusted_sources = ["edr", "av", "siem"]
        if alert.source.lower() in trusted_sources:
            fp_score -= 0.1

        return max(0.0, min(1.0, fp_score))

    def _extract_mitre_techniques(self, text: str, category: AlertCategory) -> list[str]:
        """Extract MITRE ATT&CK techniques."""
        technique_map = {
            AlertCategory.MALWARE: ["T1059", "T1204"],
            AlertCategory.PHISHING: ["T1566", "T1598"],
            AlertCategory.RANSOMWARE: ["T1486", "T1490"],
            AlertCategory.LATERAL_MOVEMENT: ["T1021", "T1570"],
            AlertCategory.CREDENTIAL_THEFT: ["T1003", "T1558"],
        }
        return technique_map.get(category, [])

    def _calculate_confidence(self, text: str, category: AlertCategory) -> float:
        """Calculate classification confidence."""
        if category == AlertCategory.UNKNOWN:
            return 0.3

        # Base confidence
        confidence = 0.7

        # Boost for keyword matches
        keywords = self.keyword_patterns.get(category, [])
        matches = sum(1 for kw in keywords if kw in text)
        confidence += min(matches * 0.1, 0.25)

        return min(confidence, 0.95)


class PriorityScorer:
    """Calculates alert priority scores."""

    def __init__(self):
        self.severity_weights = {
            AlertSeverity.CRITICAL: 40,
            AlertSeverity.HIGH: 30,
            AlertSeverity.MEDIUM: 20,
            AlertSeverity.LOW: 10,
            AlertSeverity.INFO: 5,
        }

        self.category_weights = {
            AlertCategory.RANSOMWARE: 20,
            AlertCategory.DATA_EXFILTRATION: 15,
            AlertCategory.INTRUSION: 15,
            AlertCategory.CREDENTIAL_THEFT: 12,
            AlertCategory.MALWARE: 10,
            AlertCategory.LATERAL_MOVEMENT: 10,
            AlertCategory.PHISHING: 8,
            AlertCategory.UNKNOWN: 5,
        }

        self.queues = {
            (90, 100): "tier1-critical",
            (70, 89): "tier1-high",
            (50, 69): "tier2-medium",
            (30, 49): "tier2-low",
            (0, 29): "tier3-review",
        }

    def score(self, alert: Alert, classification: ClassificationResult) -> PriorityScore:
        """Calculate priority score."""
        factors = {}

        # Severity factor
        severity_score = self.severity_weights.get(classification.severity, 15)
        factors["severity"] = severity_score

        # Category factor
        category_score = self.category_weights.get(classification.category, 5)
        factors["category"] = category_score

        # Confidence factor
        confidence_score = int(classification.confidence * 20)
        factors["confidence"] = confidence_score

        # True positive factor
        tp_score = 20 if classification.is_true_positive else -10
        factors["true_positive"] = tp_score

        # Calculate total
        total = sum(factors.values())
        total = max(1, min(100, total))  # Clamp to 1-100

        # Determine queue
        queue = "default"
        for (min_score, max_score), q in self.queues.items():
            if min_score <= total <= max_score:
                queue = q
                break

        return PriorityScore(score=total, factors=factors, queue=queue)


class TriageDecisionEngine:
    """Makes triage decisions based on classification and priority."""

    def __init__(self):
        self.automation_categories = {AlertCategory.PHISHING, AlertCategory.MALWARE}
        self.escalation_threshold = 80
        self.close_threshold = 20

    def decide(
        self,
        classification: ClassificationResult,
        priority: PriorityScore,
    ) -> tuple[TriageDecision, list[str]]:
        """Make triage decision."""
        actions = []

        # High priority -> Escalate
        if priority.score >= self.escalation_threshold:
            decision = TriageDecision.ESCALATE
            actions.append("Notify SOC Lead")
            actions.append("Create incident ticket")
            actions.append("Start investigation")

        # Low priority false positive -> Close
        elif priority.score <= self.close_threshold and not classification.is_true_positive:
            decision = TriageDecision.CLOSE
            actions.append("Mark as false positive")
            actions.append("Update detection rules")

        # Automatable categories -> Automate
        elif (
            classification.category in self.automation_categories
            and classification.confidence > 0.8
        ):
            decision = TriageDecision.AUTOMATE
            actions.append("Execute enrichment playbook")
            if classification.category == AlertCategory.MALWARE:
                actions.append("Execute containment playbook")

        # Default -> Investigate
        else:
            decision = TriageDecision.INVESTIGATE
            actions.append("Assign to analyst")
            actions.append("Gather additional context")

        return decision, actions


class AnalystRouter:
    """Routes alerts to appropriate analysts."""

    def __init__(self):
        self.analysts = {
            "tier1-critical": ["senior-analyst-1", "senior-analyst-2"],
            "tier1-high": ["analyst-1", "analyst-2", "analyst-3"],
            "tier2-medium": ["analyst-4", "analyst-5"],
            "tier2-low": ["analyst-6"],
            "tier3-review": ["junior-analyst-1", "junior-analyst-2"],
        }

        self.workloads: dict[str, int] = {}

    def route(self, queue: str) -> str | None:
        """Route to analyst with lowest workload."""
        analysts = self.analysts.get(queue, [])
        if not analysts:
            return None

        # Find analyst with lowest workload
        min_workload = float("inf")
        selected = analysts[0]

        for analyst in analysts:
            workload = self.workloads.get(analyst, 0)
            if workload < min_workload:
                min_workload = workload
                selected = analyst

        # Update workload
        self.workloads[selected] = self.workloads.get(selected, 0) + 1

        return selected


class AlertTriageService:
    """Complete alert triage service."""

    def __init__(
        self,
        classifier: AlertClassifier,
        scorer: PriorityScorer,
        decision_engine: TriageDecisionEngine,
        router: AnalystRouter,
    ):
        self.classifier = classifier
        self.scorer = scorer
        self.decision_engine = decision_engine
        self.router = router
        self.processed_alerts: list[TriageResult] = []

    async def triage(self, alert: Alert) -> TriageResult:
        """Triage an alert."""
        start_time = time.time()

        # Classify
        classification = self.classifier.classify(alert)

        # Score
        priority = self.scorer.score(alert, classification)

        # Decide
        decision, actions = self.decision_engine.decide(classification, priority)

        # Route (if needed)
        analyst = None
        if decision in [TriageDecision.ESCALATE, TriageDecision.INVESTIGATE]:
            analyst = self.router.route(priority.queue)

        processing_time = int((time.time() - start_time) * 1000)

        result = TriageResult(
            alert_id=alert.alert_id,
            classification=classification,
            priority=priority,
            decision=decision,
            recommended_actions=actions,
            assigned_analyst=analyst,
            processing_time_ms=processing_time,
        )

        self.processed_alerts.append(result)
        return result

    async def batch_triage(self, alerts: list[Alert]) -> list[TriageResult]:
        """Triage multiple alerts."""
        results = []
        for alert in alerts:
            result = await self.triage(alert)
            results.append(result)
        return results


# Fixtures
@pytest.fixture
def classifier():
    return AlertClassifier()


@pytest.fixture
def scorer():
    return PriorityScorer()


@pytest.fixture
def decision_engine():
    return TriageDecisionEngine()


@pytest.fixture
def router():
    return AnalystRouter()


@pytest.fixture
def triage_service(classifier, scorer, decision_engine, router):
    return AlertTriageService(classifier, scorer, decision_engine, router)


@pytest.fixture
def malware_alert():
    return Alert(
        alert_id="alert-001",
        title="Malware Detection: Emotet Trojan",
        description="Emotet trojan detected on workstation. Malicious process execution observed.",
        source="edr",
        raw_severity="high",
    )


@pytest.fixture
def phishing_alert():
    return Alert(
        alert_id="alert-002",
        title="Phishing Email Detected",
        description="User clicked on phishing link attempting credential theft",
        source="email",
        raw_severity="medium",
    )


@pytest.fixture
def ransomware_alert():
    return Alert(
        alert_id="alert-003",
        title="Ransomware Activity Detected",
        description="Critical ransomware encryption activity detected. Files being encrypted.",
        source="edr",
        raw_severity="critical",
    )


@pytest.fixture
def benign_alert():
    return Alert(
        alert_id="alert-004",
        title="Test Alert - False Positive",
        description="This is a test alert from security scanner for demo purposes",
        source="scanner",
        raw_severity="low",
    )


# Test cases
class TestAlertClassifier:
    """Tests for AlertClassifier."""

    def test_classify_malware(self, classifier, malware_alert):
        """Test malware classification."""
        result = classifier.classify(malware_alert)

        assert result.category == AlertCategory.MALWARE
        assert result.severity == AlertSeverity.HIGH
        assert result.is_true_positive is True
        assert result.confidence > 0.7

    def test_classify_phishing(self, classifier, phishing_alert):
        """Test phishing classification."""
        result = classifier.classify(phishing_alert)

        assert result.category == AlertCategory.PHISHING
        assert result.confidence > 0.6

    def test_classify_ransomware(self, classifier, ransomware_alert):
        """Test ransomware classification."""
        result = classifier.classify(ransomware_alert)

        assert result.category == AlertCategory.RANSOMWARE
        assert result.severity == AlertSeverity.CRITICAL
        assert "T1486" in result.mitre_techniques

    def test_detect_false_positive(self, classifier, benign_alert):
        """Test false positive detection."""
        result = classifier.classify(benign_alert)

        assert result.is_true_positive is False
        assert result.fp_probability > 0.3

    def test_unknown_category(self, classifier):
        """Test unknown category classification."""
        alert = Alert(
            alert_id="test",
            title="Generic Alert",
            description="Something happened on the network",
            source="unknown",
            raw_severity="medium",
        )

        result = classifier.classify(alert)

        assert result.category == AlertCategory.UNKNOWN
        assert result.confidence < 0.5


class TestPriorityScorer:
    """Tests for PriorityScorer."""

    def test_high_priority_scoring(self, classifier, scorer, ransomware_alert):
        """Test high priority scoring."""
        classification = classifier.classify(ransomware_alert)
        priority = scorer.score(ransomware_alert, classification)

        assert priority.score >= 70
        assert priority.queue.startswith("tier1")

    def test_low_priority_scoring(self, classifier, scorer, benign_alert):
        """Test low priority scoring."""
        classification = classifier.classify(benign_alert)
        priority = scorer.score(benign_alert, classification)

        assert priority.score < 50
        assert "review" in priority.queue or "low" in priority.queue

    def test_scoring_factors(self, classifier, scorer, malware_alert):
        """Test scoring factors are recorded."""
        classification = classifier.classify(malware_alert)
        priority = scorer.score(malware_alert, classification)

        assert "severity" in priority.factors
        assert "category" in priority.factors
        assert "confidence" in priority.factors

    def test_queue_assignment(self, classifier, scorer):
        """Test queue assignment based on score."""
        alerts = [
            Alert("1", "Critical breach", "Critical", "edr", "critical"),
            Alert("2", "Medium alert", "Medium", "siem", "medium"),
            Alert("3", "Low info", "Info", "scanner", "low"),
        ]

        queues = []
        for alert in alerts:
            classification = classifier.classify(alert)
            priority = scorer.score(alert, classification)
            queues.append(priority.queue)

        # Higher severity should get higher tier queue
        assert "tier1" in queues[0] or "critical" in queues[0]


class TestTriageDecisionEngine:
    """Tests for TriageDecisionEngine."""

    def test_escalate_decision(self, decision_engine):
        """Test escalation decision."""
        classification = ClassificationResult(
            category=AlertCategory.RANSOMWARE,
            severity=AlertSeverity.CRITICAL,
            confidence=0.95,
            is_true_positive=True,
            fp_probability=0.05,
        )
        priority = PriorityScore(score=90, queue="tier1-critical")

        decision, actions = decision_engine.decide(classification, priority)

        assert decision == TriageDecision.ESCALATE
        assert any("Notify" in a for a in actions)

    def test_close_decision(self, decision_engine):
        """Test close decision for false positive."""
        classification = ClassificationResult(
            category=AlertCategory.UNKNOWN,
            severity=AlertSeverity.LOW,
            confidence=0.3,
            is_true_positive=False,
            fp_probability=0.8,
        )
        priority = PriorityScore(score=15, queue="tier3-review")

        decision, actions = decision_engine.decide(classification, priority)

        assert decision == TriageDecision.CLOSE
        assert any("false positive" in a for a in actions)

    def test_automate_decision(self, decision_engine):
        """Test automation decision."""
        classification = ClassificationResult(
            category=AlertCategory.MALWARE,
            severity=AlertSeverity.MEDIUM,
            confidence=0.85,
            is_true_positive=True,
            fp_probability=0.1,
        )
        priority = PriorityScore(score=55, queue="tier2-medium")

        decision, actions = decision_engine.decide(classification, priority)

        assert decision == TriageDecision.AUTOMATE
        assert any("playbook" in a for a in actions)


class TestAnalystRouter:
    """Tests for AnalystRouter."""

    def test_route_to_analyst(self, router):
        """Test routing to analyst."""
        analyst = router.route("tier1-high")

        assert analyst is not None
        assert analyst.startswith("analyst")

    def test_workload_balancing(self, router):
        """Test workload balancing."""
        # Route multiple alerts
        analysts = []
        for _ in range(6):
            analyst = router.route("tier1-high")
            analysts.append(analyst)

        # Should distribute across analysts
        unique = set(analysts)
        assert len(unique) >= 2  # At least 2 different analysts

    def test_unknown_queue(self, router):
        """Test routing with unknown queue."""
        analyst = router.route("unknown-queue")
        assert analyst is None


class TestAlertTriageService:
    """Tests for AlertTriageService."""

    @pytest.mark.asyncio
    async def test_triage_malware(self, triage_service, malware_alert):
        """Test triaging malware alert."""
        result = await triage_service.triage(malware_alert)

        assert result.alert_id == malware_alert.alert_id
        assert result.classification.category == AlertCategory.MALWARE
        assert result.priority.score > 50
        assert result.processing_time_ms >= 0

    @pytest.mark.asyncio
    async def test_triage_ransomware_escalation(self, triage_service, ransomware_alert):
        """Test ransomware alert escalation."""
        result = await triage_service.triage(ransomware_alert)

        assert result.decision == TriageDecision.ESCALATE
        assert result.assigned_analyst is not None

    @pytest.mark.asyncio
    async def test_triage_false_positive_closure(self, triage_service, benign_alert):
        """Test false positive closure."""
        result = await triage_service.triage(benign_alert)

        assert result.decision == TriageDecision.CLOSE
        assert result.classification.is_true_positive is False

    @pytest.mark.asyncio
    async def test_batch_triage(self, triage_service, malware_alert, phishing_alert):
        """Test batch triaging."""
        alerts = [malware_alert, phishing_alert]
        results = await triage_service.batch_triage(alerts)

        assert len(results) == 2
        assert all(r.classification is not None for r in results)

    @pytest.mark.asyncio
    async def test_high_volume_triage(self, triage_service):
        """Test high volume alert triaging."""
        alerts = [
            Alert(
                alert_id=f"alert-{i}",
                title=f"Test Alert {i}",
                description="Malware detected" if i % 2 == 0 else "Network anomaly",
                source="edr",
                raw_severity="medium",
            )
            for i in range(100)
        ]

        start = time.time()
        results = await triage_service.batch_triage(alerts)
        elapsed = time.time() - start

        assert len(results) == 100
        assert elapsed < 2.0  # Should process 100 alerts in under 2 seconds

    @pytest.mark.asyncio
    async def test_triage_metrics(self, triage_service, malware_alert, phishing_alert):
        """Test triage service tracks processed alerts."""
        await triage_service.triage(malware_alert)
        await triage_service.triage(phishing_alert)

        assert len(triage_service.processed_alerts) == 2


class TestEndToEndTriage:
    """End-to-end triage tests."""

    @pytest.mark.asyncio
    async def test_complete_triage_workflow(self, triage_service):
        """Test complete triage workflow with various alerts."""
        alerts = [
            Alert("1", "Ransomware Detected", "Critical ransomware encryption", "edr", "critical"),
            Alert("2", "Phishing Link", "User clicked phishing link", "email", "medium"),
            Alert("3", "Test Alert", "This is a test demo", "scanner", "low"),
            Alert("4", "Malware Alert", "Trojan malware detected", "av", "high"),
        ]

        results = await triage_service.batch_triage(alerts)

        # Verify appropriate decisions
        assert results[0].decision == TriageDecision.ESCALATE  # Ransomware
        assert results[2].decision == TriageDecision.CLOSE  # Test/FP

        # Verify analyst assignment for escalated alerts
        escalated = [r for r in results if r.decision == TriageDecision.ESCALATE]
        assert all(r.assigned_analyst is not None for r in escalated)

        # Verify recommended actions exist
        assert all(len(r.recommended_actions) > 0 for r in results)
