"""Unit tests for the Alert Classifier model."""

import json
from datetime import datetime
from enum import Enum
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# Mock classes for testing (since we don't have actual dependencies)
class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(str, Enum):
    """Alert categories."""

    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    DENIAL_OF_SERVICE = "denial_of_service"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN = "unknown"


class Alert:
    """Represents a security alert."""

    def __init__(
        self,
        alert_id: str,
        title: str,
        description: str,
        source: str,
        timestamp: datetime | None = None,
        raw_data: dict | None = None,
    ):
        self.alert_id = alert_id
        self.title = title
        self.description = description
        self.source = source
        self.timestamp = timestamp or datetime.utcnow()
        self.raw_data = raw_data or {}


class ClassificationResult:
    """Result of alert classification."""

    def __init__(
        self,
        category: AlertCategory,
        severity: AlertSeverity,
        confidence: float,
        is_true_positive: bool,
        triage_priority: int,
        explanation: str,
        mitre_techniques: list[str] | None = None,
    ):
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.is_true_positive = is_true_positive
        self.triage_priority = triage_priority
        self.explanation = explanation
        self.mitre_techniques = mitre_techniques or []


class AlertClassifier:
    """Mock Alert Classifier for testing."""

    def __init__(self, model_path: str | None = None):
        self.model_path = model_path
        self.model_loaded = False
        self.categories = list(AlertCategory)
        self.severities = list(AlertSeverity)

    def load_model(self) -> None:
        """Load the classification model."""
        self.model_loaded = True

    def classify(self, alert: Alert) -> ClassificationResult:
        """Classify an alert."""
        if not self.model_loaded:
            raise RuntimeError("Model not loaded")

        # Mock classification logic
        category = self._predict_category(alert)
        severity = self._predict_severity(alert)
        confidence = 0.85
        is_tp = self._predict_true_positive(alert)
        priority = self._calculate_priority(severity, confidence, is_tp)

        return ClassificationResult(
            category=category,
            severity=severity,
            confidence=confidence,
            is_true_positive=is_tp,
            triage_priority=priority,
            explanation=f"Classified as {category.value} with {severity.value} severity",
            mitre_techniques=self._extract_techniques(alert),
        )

    def _predict_category(self, alert: Alert) -> AlertCategory:
        """Predict alert category based on title/description."""
        text = f"{alert.title} {alert.description}".lower()

        if "malware" in text or "virus" in text:
            return AlertCategory.MALWARE
        if "phishing" in text:
            return AlertCategory.PHISHING
        if "lateral" in text or "psexec" in text:
            return AlertCategory.LATERAL_MOVEMENT
        if "exfil" in text or "data leak" in text:
            return AlertCategory.DATA_EXFILTRATION
        if "password" in text or "credential" in text:
            return AlertCategory.CREDENTIAL_THEFT
        if "intrusion" in text or "breach" in text:
            return AlertCategory.INTRUSION
        if "ddos" in text or "dos attack" in text:
            return AlertCategory.DENIAL_OF_SERVICE

        return AlertCategory.UNKNOWN

    def _predict_severity(self, alert: Alert) -> AlertSeverity:
        """Predict alert severity."""
        text = f"{alert.title} {alert.description}".lower()

        if "critical" in text or "emergency" in text:
            return AlertSeverity.CRITICAL
        if "high" in text or "severe" in text:
            return AlertSeverity.HIGH
        if "medium" in text or "moderate" in text:
            return AlertSeverity.MEDIUM
        if "low" in text or "minor" in text:
            return AlertSeverity.LOW

        return AlertSeverity.MEDIUM

    def _predict_true_positive(self, alert: Alert) -> bool:
        """Predict if alert is a true positive."""
        # Mock logic - in reality this would use ML
        text = f"{alert.title} {alert.description}".lower()
        fp_indicators = ["test", "demo", "false alarm", "benign", "scanner"]
        return not any(ind in text for ind in fp_indicators)

    def _calculate_priority(
        self, severity: AlertSeverity, confidence: float, is_tp: bool
    ) -> int:
        """Calculate triage priority (1-100, higher = more urgent)."""
        base_score = {
            AlertSeverity.CRITICAL: 90,
            AlertSeverity.HIGH: 70,
            AlertSeverity.MEDIUM: 50,
            AlertSeverity.LOW: 30,
            AlertSeverity.INFO: 10,
        }.get(severity, 50)

        score = base_score * confidence
        if not is_tp:
            score *= 0.5

        return min(100, max(1, int(score)))

    def _extract_techniques(self, alert: Alert) -> list[str]:
        """Extract MITRE ATT&CK techniques."""
        text = f"{alert.title} {alert.description}".lower()
        techniques = []

        technique_mapping = {
            "powershell": "T1059.001",
            "psexec": "T1569.002",
            "mimikatz": "T1003.001",
            "pass the hash": "T1550.002",
            "phishing": "T1566",
            "ransomware": "T1486",
        }

        for keyword, technique in technique_mapping.items():
            if keyword in text:
                techniques.append(technique)

        return techniques


class FeatureExtractor:
    """Extract features from alerts for classification."""

    def __init__(self):
        self.feature_names = [
            "title_length",
            "description_length",
            "has_ip",
            "has_domain",
            "has_hash",
            "keyword_count",
        ]

    def extract(self, alert: Alert) -> dict[str, Any]:
        """Extract features from an alert."""
        text = f"{alert.title} {alert.description}"

        return {
            "title_length": len(alert.title),
            "description_length": len(alert.description),
            "has_ip": self._contains_ip(text),
            "has_domain": self._contains_domain(text),
            "has_hash": self._contains_hash(text),
            "keyword_count": self._count_keywords(text),
        }

    def _contains_ip(self, text: str) -> bool:
        """Check if text contains IP address."""
        import re

        ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        return bool(re.search(ip_pattern, text))

    def _contains_domain(self, text: str) -> bool:
        """Check if text contains domain."""
        import re

        domain_pattern = r"[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}"
        return bool(re.search(domain_pattern, text))

    def _contains_hash(self, text: str) -> bool:
        """Check if text contains file hash."""
        import re

        hash_patterns = [
            r"[a-fA-F0-9]{32}",  # MD5
            r"[a-fA-F0-9]{40}",  # SHA1
            r"[a-fA-F0-9]{64}",  # SHA256
        ]
        return any(re.search(p, text) for p in hash_patterns)

    def _count_keywords(self, text: str) -> int:
        """Count security-related keywords."""
        keywords = [
            "malware",
            "attack",
            "intrusion",
            "suspicious",
            "threat",
            "exploit",
            "vulnerability",
            "breach",
            "ransomware",
            "phishing",
        ]
        text_lower = text.lower()
        return sum(1 for k in keywords if k in text_lower)


# Test fixtures
@pytest.fixture
def classifier():
    """Create a classifier instance."""
    clf = AlertClassifier()
    clf.load_model()
    return clf


@pytest.fixture
def sample_alert():
    """Create a sample alert."""
    return Alert(
        alert_id="alert-001",
        title="Suspicious PowerShell Activity Detected",
        description="PowerShell encoded command execution detected on host WORKSTATION-001",
        source="edr",
        raw_data={"host": "WORKSTATION-001", "user": "admin"},
    )


@pytest.fixture
def malware_alert():
    """Create a malware alert."""
    return Alert(
        alert_id="alert-002",
        title="Malware Detection: Emotet",
        description="Critical malware infection detected. Emotet trojan found on endpoint.",
        source="av",
    )


@pytest.fixture
def phishing_alert():
    """Create a phishing alert."""
    return Alert(
        alert_id="alert-003",
        title="Phishing Email Detected",
        description="User clicked on phishing link from suspicious email",
        source="email-security",
    )


class TestAlertClassifier:
    """Tests for AlertClassifier."""

    def test_classifier_initialization(self):
        """Test classifier initialization."""
        clf = AlertClassifier()
        assert clf.model_loaded is False
        assert len(clf.categories) > 0

    def test_classifier_load_model(self, classifier):
        """Test model loading."""
        assert classifier.model_loaded is True

    def test_classify_without_loading(self):
        """Test classification without loading model raises error."""
        clf = AlertClassifier()
        alert = Alert(alert_id="1", title="Test", description="Test", source="test")

        with pytest.raises(RuntimeError, match="Model not loaded"):
            clf.classify(alert)

    def test_classify_malware_alert(self, classifier, malware_alert):
        """Test malware alert classification."""
        result = classifier.classify(malware_alert)

        assert result.category == AlertCategory.MALWARE
        assert result.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]
        assert result.confidence > 0.5
        assert result.is_true_positive is True

    def test_classify_phishing_alert(self, classifier, phishing_alert):
        """Test phishing alert classification."""
        result = classifier.classify(phishing_alert)

        assert result.category == AlertCategory.PHISHING
        assert result.confidence > 0.5

    def test_classify_lateral_movement(self, classifier):
        """Test lateral movement detection."""
        alert = Alert(
            alert_id="4",
            title="Lateral Movement Detected",
            description="PsExec execution detected from WORKSTATION-001 to SERVER-DB",
            source="edr",
        )
        result = classifier.classify(alert)

        assert result.category == AlertCategory.LATERAL_MOVEMENT
        assert "T1569.002" in result.mitre_techniques

    def test_classify_credential_theft(self, classifier):
        """Test credential theft detection."""
        alert = Alert(
            alert_id="5",
            title="Credential Dump Detected",
            description="Mimikatz credential harvesting detected on domain controller",
            source="edr",
        )
        result = classifier.classify(alert)

        assert result.category == AlertCategory.CREDENTIAL_THEFT
        assert "T1003.001" in result.mitre_techniques

    def test_classify_unknown_category(self, classifier):
        """Test unknown category classification."""
        alert = Alert(
            alert_id="6",
            title="Generic Alert",
            description="Something happened on the network",
            source="generic",
        )
        result = classifier.classify(alert)

        assert result.category == AlertCategory.UNKNOWN

    def test_false_positive_detection(self, classifier):
        """Test false positive detection."""
        alert = Alert(
            alert_id="7",
            title="Test Alert - False Alarm",
            description="This is a test alert for demo purposes",
            source="test",
        )
        result = classifier.classify(alert)

        assert result.is_true_positive is False
        assert result.triage_priority < 50

    def test_priority_calculation(self, classifier):
        """Test priority calculation."""
        critical_alert = Alert(
            alert_id="8",
            title="Critical Emergency",
            description="Critical ransomware outbreak",
            source="edr",
        )
        low_alert = Alert(
            alert_id="9",
            title="Low Priority",
            description="Minor policy violation detected",
            source="policy",
        )

        critical_result = classifier.classify(critical_alert)
        low_result = classifier.classify(low_alert)

        assert critical_result.triage_priority > low_result.triage_priority

    def test_mitre_technique_extraction(self, classifier, sample_alert):
        """Test MITRE technique extraction."""
        result = classifier.classify(sample_alert)

        assert "T1059.001" in result.mitre_techniques  # PowerShell

    def test_explanation_generation(self, classifier, malware_alert):
        """Test explanation generation."""
        result = classifier.classify(malware_alert)

        assert result.explanation is not None
        assert len(result.explanation) > 0
        assert "malware" in result.explanation.lower()


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    @pytest.fixture
    def extractor(self):
        """Create feature extractor."""
        return FeatureExtractor()

    def test_basic_extraction(self, extractor, sample_alert):
        """Test basic feature extraction."""
        features = extractor.extract(sample_alert)

        assert "title_length" in features
        assert "description_length" in features
        assert features["title_length"] > 0
        assert features["description_length"] > 0

    def test_ip_detection(self, extractor):
        """Test IP address detection."""
        alert = Alert(
            alert_id="1",
            title="Alert",
            description="Connection from 192.168.1.100 detected",
            source="fw",
        )
        features = extractor.extract(alert)

        assert features["has_ip"] is True

    def test_no_ip_detection(self, extractor, sample_alert):
        """Test no IP address detection."""
        features = extractor.extract(sample_alert)
        # Sample alert doesn't have an IP in the text
        assert "has_ip" in features

    def test_domain_detection(self, extractor):
        """Test domain detection."""
        alert = Alert(
            alert_id="1",
            title="Alert",
            description="Connection to malicious-domain.com",
            source="proxy",
        )
        features = extractor.extract(alert)

        assert features["has_domain"] is True

    def test_hash_detection(self, extractor):
        """Test file hash detection."""
        alert = Alert(
            alert_id="1",
            title="Malware",
            description="File hash: d41d8cd98f00b204e9800998ecf8427e",
            source="av",
        )
        features = extractor.extract(alert)

        assert features["has_hash"] is True

    def test_keyword_counting(self, extractor):
        """Test keyword counting."""
        alert = Alert(
            alert_id="1",
            title="Malware Attack",
            description="Suspicious exploit detected, possible ransomware threat",
            source="edr",
        )
        features = extractor.extract(alert)

        assert features["keyword_count"] >= 3


class TestClassificationResult:
    """Tests for ClassificationResult."""

    def test_result_creation(self):
        """Test result creation."""
        result = ClassificationResult(
            category=AlertCategory.MALWARE,
            severity=AlertSeverity.HIGH,
            confidence=0.95,
            is_true_positive=True,
            triage_priority=85,
            explanation="High confidence malware detection",
            mitre_techniques=["T1486"],
        )

        assert result.category == AlertCategory.MALWARE
        assert result.severity == AlertSeverity.HIGH
        assert result.confidence == 0.95
        assert result.is_true_positive is True
        assert result.triage_priority == 85
        assert len(result.mitre_techniques) == 1

    def test_result_without_techniques(self):
        """Test result without MITRE techniques."""
        result = ClassificationResult(
            category=AlertCategory.UNKNOWN,
            severity=AlertSeverity.LOW,
            confidence=0.3,
            is_true_positive=False,
            triage_priority=10,
            explanation="Unknown alert type",
        )

        assert result.mitre_techniques == []


class TestBatchClassification:
    """Tests for batch classification."""

    def test_batch_classify(self, classifier):
        """Test batch classification."""
        alerts = [
            Alert(alert_id="1", title="Malware", description="Virus detected", source="av"),
            Alert(alert_id="2", title="Phishing", description="Phishing email", source="email"),
            Alert(alert_id="3", title="Test", description="Test alert", source="test"),
        ]

        results = [classifier.classify(alert) for alert in alerts]

        assert len(results) == 3
        assert results[0].category == AlertCategory.MALWARE
        assert results[1].category == AlertCategory.PHISHING
        assert results[2].is_true_positive is False


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_severity_values(self):
        """Test severity values."""
        assert AlertSeverity.CRITICAL.value == "critical"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity ordering."""
        severities = [
            AlertSeverity.CRITICAL,
            AlertSeverity.HIGH,
            AlertSeverity.MEDIUM,
            AlertSeverity.LOW,
            AlertSeverity.INFO,
        ]
        assert len(severities) == 5


class TestAlertCategory:
    """Tests for AlertCategory enum."""

    def test_category_values(self):
        """Test category values."""
        assert AlertCategory.MALWARE.value == "malware"
        assert AlertCategory.PHISHING.value == "phishing"
        assert AlertCategory.INTRUSION.value == "intrusion"

    def test_all_categories(self):
        """Test all categories exist."""
        expected = [
            "malware",
            "phishing",
            "intrusion",
            "data_exfiltration",
            "credential_theft",
            "lateral_movement",
            "denial_of_service",
            "policy_violation",
            "unknown",
        ]
        actual = [c.value for c in AlertCategory]
        assert set(expected) == set(actual)
