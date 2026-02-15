"""Unit tests for DGA (Domain Generation Algorithm) detection."""

import math
import re
from collections import Counter
from typing import NamedTuple

import pytest


class DGAResult(NamedTuple):
    """Result of DGA detection."""

    domain: str
    is_dga: bool
    confidence: float
    features: dict
    explanation: str


class DGADetector:
    """Domain Generation Algorithm detector."""

    def __init__(self):
        self.entropy_threshold = 3.5
        self.consonant_ratio_threshold = 0.65
        self.digit_ratio_threshold = 0.3
        self.max_consonant_sequence = 5
        self.min_domain_length = 5

        # Common TLDs
        self.tlds = {
            "com",
            "net",
            "org",
            "info",
            "biz",
            "io",
            "co",
            "xyz",
            "top",
        }

        # Common legitimate patterns
        self.legitimate_patterns = [
            r"^www\.",
            r"^mail\.",
            r"^cdn\.",
            r"^api\.",
            r"^static\.",
        ]

        # Vowels and consonants
        self.vowels = set("aeiou")
        self.consonants = set("bcdfghjklmnpqrstvwxyz")
        self.digits = set("0123456789")

    def detect(self, domain: str) -> DGAResult:
        """Detect if a domain is DGA-generated."""
        domain = domain.lower().strip()

        # Extract domain name without TLD
        domain_name = self._extract_domain_name(domain)

        if not domain_name or len(domain_name) < self.min_domain_length:
            return DGAResult(
                domain=domain,
                is_dga=False,
                confidence=0.0,
                features={},
                explanation="Domain too short for analysis",
            )

        # Extract features
        features = self._extract_features(domain_name)

        # Calculate DGA score
        score = self._calculate_score(features)
        is_dga = score > 0.5
        confidence = score

        explanation = self._generate_explanation(features, is_dga)

        return DGAResult(
            domain=domain,
            is_dga=is_dga,
            confidence=confidence,
            features=features,
            explanation=explanation,
        )

    def _extract_domain_name(self, domain: str) -> str:
        """Extract the domain name part (without TLD and subdomain)."""
        # Remove common prefixes
        for pattern in self.legitimate_patterns:
            domain = re.sub(pattern, "", domain)

        # Split by dots
        parts = domain.split(".")

        # Remove TLD
        if len(parts) > 1 and parts[-1] in self.tlds:
            parts = parts[:-1]

        # Get the main domain part
        if parts:
            return parts[-1] if len(parts) > 1 else parts[0]

        return domain

    def _extract_features(self, domain: str) -> dict:
        """Extract features from domain name."""
        return {
            "length": len(domain),
            "entropy": self._calculate_entropy(domain),
            "vowel_ratio": self._calculate_vowel_ratio(domain),
            "consonant_ratio": self._calculate_consonant_ratio(domain),
            "digit_ratio": self._calculate_digit_ratio(domain),
            "max_consonant_sequence": self._max_consonant_sequence(domain),
            "has_digits": any(c in self.digits for c in domain),
            "unique_char_ratio": len(set(domain)) / len(domain),
            "bigram_diversity": self._bigram_diversity(domain),
        }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    def _calculate_vowel_ratio(self, text: str) -> float:
        """Calculate ratio of vowels."""
        if not text:
            return 0.0
        vowel_count = sum(1 for c in text if c in self.vowels)
        return vowel_count / len(text)

    def _calculate_consonant_ratio(self, text: str) -> float:
        """Calculate ratio of consonants."""
        if not text:
            return 0.0
        consonant_count = sum(1 for c in text if c in self.consonants)
        return consonant_count / len(text)

    def _calculate_digit_ratio(self, text: str) -> float:
        """Calculate ratio of digits."""
        if not text:
            return 0.0
        digit_count = sum(1 for c in text if c in self.digits)
        return digit_count / len(text)

    def _max_consonant_sequence(self, text: str) -> int:
        """Find maximum consecutive consonants."""
        max_seq = 0
        current_seq = 0

        for char in text:
            if char in self.consonants:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 0

        return max_seq

    def _bigram_diversity(self, text: str) -> float:
        """Calculate bigram diversity."""
        if len(text) < 2:
            return 0.0

        bigrams = [text[i : i + 2] for i in range(len(text) - 1)]
        unique_bigrams = len(set(bigrams))
        return unique_bigrams / len(bigrams)

    def _calculate_score(self, features: dict) -> float:
        """Calculate DGA score based on features."""
        score = 0.0
        weights = {
            "entropy": 0.25,
            "consonant_ratio": 0.2,
            "digit_ratio": 0.15,
            "max_consonant_sequence": 0.15,
            "unique_char_ratio": 0.1,
            "bigram_diversity": 0.15,
        }

        # Entropy score (higher = more suspicious)
        if features["entropy"] > self.entropy_threshold:
            score += weights["entropy"] * min(
                (features["entropy"] - self.entropy_threshold) / 2, 1
            )

        # Consonant ratio (higher = more suspicious)
        if features["consonant_ratio"] > self.consonant_ratio_threshold:
            score += weights["consonant_ratio"]

        # Digit ratio (higher = more suspicious)
        if features["digit_ratio"] > self.digit_ratio_threshold:
            score += weights["digit_ratio"]

        # Max consonant sequence (higher = more suspicious)
        if features["max_consonant_sequence"] > self.max_consonant_sequence:
            score += weights["max_consonant_sequence"]

        # High unique char ratio is suspicious
        if features["unique_char_ratio"] > 0.8:
            score += weights["unique_char_ratio"]

        # High bigram diversity is suspicious
        if features["bigram_diversity"] > 0.9:
            score += weights["bigram_diversity"]

        return min(score, 1.0)

    def _generate_explanation(self, features: dict, is_dga: bool) -> str:
        """Generate human-readable explanation."""
        reasons = []

        if features["entropy"] > self.entropy_threshold:
            reasons.append(f"high entropy ({features['entropy']:.2f})")

        if features["consonant_ratio"] > self.consonant_ratio_threshold:
            reasons.append(f"high consonant ratio ({features['consonant_ratio']:.2f})")

        if features["digit_ratio"] > self.digit_ratio_threshold:
            reasons.append(f"high digit ratio ({features['digit_ratio']:.2f})")

        if features["max_consonant_sequence"] > self.max_consonant_sequence:
            reasons.append(
                f"long consonant sequence ({features['max_consonant_sequence']})"
            )

        if is_dga:
            return f"DGA detected: {', '.join(reasons)}"
        else:
            return "Domain appears legitimate"


# Fixtures
@pytest.fixture
def detector():
    """Create DGA detector instance."""
    return DGADetector()


# Test data
LEGITIMATE_DOMAINS = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "youtube.com",
    "linkedin.com",
]

DGA_DOMAINS = [
    "qxwvtpjklmnrst.com",  # Random consonants
    "8fj3k9d2m5nxyz.net",  # Alphanumeric
    "bcdfghjklmnpqr.org",  # All consonants
    "x7k9m2p4q8r3w.io",  # Mixed with digits
    "zxcvbnmqwertyu.com",  # Keyboard pattern
]


class TestDGADetector:
    """Tests for DGA Detector."""

    def test_detector_initialization(self, detector):
        """Test detector initialization."""
        assert detector.entropy_threshold > 0
        assert detector.consonant_ratio_threshold > 0
        assert len(detector.tlds) > 0

    def test_legitimate_domain_google(self, detector):
        """Test legitimate domain: google.com."""
        result = detector.detect("google.com")

        assert result.is_dga is False
        assert result.confidence < 0.5
        assert result.domain == "google.com"

    def test_legitimate_domain_facebook(self, detector):
        """Test legitimate domain: facebook.com."""
        result = detector.detect("facebook.com")

        assert result.is_dga is False
        assert result.confidence < 0.5

    @pytest.mark.parametrize("domain", LEGITIMATE_DOMAINS)
    def test_legitimate_domains(self, detector, domain):
        """Test various legitimate domains."""
        result = detector.detect(domain)

        assert result.is_dga is False, f"Domain {domain} incorrectly flagged as DGA"

    def test_dga_domain_random_consonants(self, detector):
        """Test DGA domain with random consonants."""
        result = detector.detect("qxwvtpjklmnrst.com")

        assert result.is_dga is True
        assert result.confidence > 0.5
        assert result.features["consonant_ratio"] > 0.5

    def test_dga_domain_alphanumeric(self, detector):
        """Test DGA domain with alphanumeric pattern."""
        result = detector.detect("8fj3k9d2m5nxyz.net")

        assert result.is_dga is True
        assert result.features["has_digits"] is True

    @pytest.mark.parametrize("domain", DGA_DOMAINS)
    def test_dga_domains(self, detector, domain):
        """Test various DGA domains."""
        result = detector.detect(domain)

        assert result.is_dga is True, f"Domain {domain} not detected as DGA"

    def test_short_domain_handling(self, detector):
        """Test handling of short domains."""
        result = detector.detect("abc.com")

        assert result.is_dga is False
        assert "too short" in result.explanation.lower()

    def test_subdomain_handling(self, detector):
        """Test subdomain handling."""
        result = detector.detect("www.google.com")

        assert result.is_dga is False
        assert result.domain == "www.google.com"

    def test_features_extraction(self, detector):
        """Test feature extraction."""
        result = detector.detect("testdomain.com")

        assert "length" in result.features
        assert "entropy" in result.features
        assert "vowel_ratio" in result.features
        assert "consonant_ratio" in result.features
        assert "digit_ratio" in result.features

    def test_entropy_calculation(self, detector):
        """Test entropy calculation."""
        low_entropy = detector._calculate_entropy("aaaa")
        high_entropy = detector._calculate_entropy("abcd")

        assert low_entropy < high_entropy

    def test_consonant_ratio(self, detector):
        """Test consonant ratio calculation."""
        all_consonants = detector._calculate_consonant_ratio("bcd")
        mixed = detector._calculate_consonant_ratio("abc")

        assert all_consonants == 1.0
        assert mixed < 1.0

    def test_vowel_ratio(self, detector):
        """Test vowel ratio calculation."""
        all_vowels = detector._calculate_vowel_ratio("aeiou")
        no_vowels = detector._calculate_vowel_ratio("bcd")

        assert all_vowels == 1.0
        assert no_vowels == 0.0

    def test_digit_ratio(self, detector):
        """Test digit ratio calculation."""
        all_digits = detector._calculate_digit_ratio("123")
        no_digits = detector._calculate_digit_ratio("abc")

        assert all_digits == 1.0
        assert no_digits == 0.0

    def test_max_consonant_sequence(self, detector):
        """Test max consonant sequence detection."""
        seq = detector._max_consonant_sequence("abcdfgh")
        assert seq == 5  # dfgh

    def test_bigram_diversity(self, detector):
        """Test bigram diversity calculation."""
        low_div = detector._bigram_diversity("aaaa")
        high_div = detector._bigram_diversity("abcd")

        assert low_div < high_div

    def test_explanation_generation(self, detector):
        """Test explanation generation."""
        dga_result = detector.detect("qxwvtpjklmnrst.com")
        legit_result = detector.detect("google.com")

        assert "DGA detected" in dga_result.explanation
        assert "legitimate" in legit_result.explanation.lower()


class TestEntropyCalculation:
    """Tests for entropy calculation."""

    @pytest.fixture
    def detector(self):
        return DGADetector()

    def test_empty_string(self, detector):
        """Test entropy of empty string."""
        assert detector._calculate_entropy("") == 0.0

    def test_single_char(self, detector):
        """Test entropy of single character repeated."""
        assert detector._calculate_entropy("aaaa") == 0.0

    def test_max_entropy(self, detector):
        """Test entropy of uniform distribution."""
        # Each character appears once
        entropy = detector._calculate_entropy("abcd")
        assert entropy == 2.0  # log2(4)

    def test_entropy_increases_with_variety(self, detector):
        """Test that entropy increases with character variety."""
        low = detector._calculate_entropy("aabb")
        high = detector._calculate_entropy("abcd")

        assert low < high


class TestFeatureExtraction:
    """Tests for feature extraction."""

    @pytest.fixture
    def detector(self):
        return DGADetector()

    def test_all_features_present(self, detector):
        """Test all expected features are extracted."""
        features = detector._extract_features("testdomain")

        expected_keys = [
            "length",
            "entropy",
            "vowel_ratio",
            "consonant_ratio",
            "digit_ratio",
            "max_consonant_sequence",
            "has_digits",
            "unique_char_ratio",
            "bigram_diversity",
        ]

        for key in expected_keys:
            assert key in features

    def test_feature_values_in_range(self, detector):
        """Test feature values are in expected ranges."""
        features = detector._extract_features("test123domain")

        assert features["length"] > 0
        assert 0 <= features["entropy"] <= 10  # Reasonable entropy range
        assert 0 <= features["vowel_ratio"] <= 1
        assert 0 <= features["consonant_ratio"] <= 1
        assert 0 <= features["digit_ratio"] <= 1
        assert features["max_consonant_sequence"] >= 0
        assert isinstance(features["has_digits"], bool)
        assert 0 <= features["unique_char_ratio"] <= 1
        assert 0 <= features["bigram_diversity"] <= 1


class TestDomainNameExtraction:
    """Tests for domain name extraction."""

    @pytest.fixture
    def detector(self):
        return DGADetector()

    def test_simple_domain(self, detector):
        """Test simple domain extraction."""
        name = detector._extract_domain_name("example.com")
        assert name == "example"

    def test_www_prefix(self, detector):
        """Test www prefix removal."""
        name = detector._extract_domain_name("www.example.com")
        assert name == "example"

    def test_subdomain(self, detector):
        """Test subdomain handling."""
        name = detector._extract_domain_name("mail.example.com")
        assert name == "example"

    def test_multiple_subdomains(self, detector):
        """Test multiple subdomain handling."""
        name = detector._extract_domain_name("a.b.c.example.com")
        assert name == "example"


class TestBatchDetection:
    """Tests for batch DGA detection."""

    @pytest.fixture
    def detector(self):
        return DGADetector()

    def test_batch_detection(self, detector):
        """Test batch detection of domains."""
        domains = LEGITIMATE_DOMAINS + DGA_DOMAINS
        results = [detector.detect(d) for d in domains]

        assert len(results) == len(domains)

        # Check legitimate domains are not flagged
        legit_results = results[: len(LEGITIMATE_DOMAINS)]
        assert all(not r.is_dga for r in legit_results)

        # Check DGA domains are flagged
        dga_results = results[len(LEGITIMATE_DOMAINS) :]
        assert all(r.is_dga for r in dga_results)

    def test_detection_performance(self, detector):
        """Test detection performance with many domains."""
        import time

        domains = LEGITIMATE_DOMAINS * 100

        start = time.time()
        results = [detector.detect(d) for d in domains]
        elapsed = time.time() - start

        assert len(results) == len(domains)
        assert elapsed < 1.0  # Should complete in under 1 second
