"""Feature extraction for DGA detection."""

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

import numpy as np
import torch

from ai.common.logging import LoggerMixin


@dataclass
class DomainStatistics:
    """Statistical features of a domain name."""

    length: int
    num_digits: int
    num_consonants: int
    num_vowels: int
    num_special: int
    digit_ratio: float
    consonant_ratio: float
    vowel_ratio: float
    unique_char_ratio: float
    entropy: float
    consecutive_consonants_max: int
    consecutive_digits_max: int
    has_subdomain: bool
    subdomain_count: int
    tld_length: int
    sld_length: int
    longest_consonant_seq: int
    bigram_variety: float
    trigram_variety: float
    hex_ratio: float


class DomainTokenizer:
    """Tokenize domain names to character sequences."""

    # ASCII printable characters (32-126) + padding (0) + unknown (1)
    PAD_TOKEN = 0
    UNK_TOKEN = 1
    VOCAB_START = 2

    def __init__(self, max_length: int = 63, lowercase: bool = True):
        """Initialize tokenizer.

        Args:
            max_length: Maximum domain length
            lowercase: Convert to lowercase
        """
        self.max_length = max_length
        self.lowercase = lowercase

        # Build character vocabulary
        self.char_to_id: dict[str, int] = {}
        self.id_to_char: dict[int, str] = {
            self.PAD_TOKEN: "<PAD>",
            self.UNK_TOKEN: "<UNK>",
        }

        # Add ASCII printable characters
        for i, char in enumerate(range(32, 127)):
            char_str = chr(char)
            token_id = i + self.VOCAB_START
            self.char_to_id[char_str] = token_id
            self.id_to_char[token_id] = char_str

        self.vocab_size = len(self.id_to_char)

    def tokenize(self, domain: str) -> list[int]:
        """Tokenize a domain name.

        Args:
            domain: Domain name string

        Returns:
            List of token IDs
        """
        if self.lowercase:
            domain = domain.lower()

        # Remove protocol and path if present
        domain = self._extract_domain(domain)

        # Tokenize
        tokens = []
        for char in domain[: self.max_length]:
            token_id = self.char_to_id.get(char, self.UNK_TOKEN)
            tokens.append(token_id)

        # Pad to max length
        while len(tokens) < self.max_length:
            tokens.append(self.PAD_TOKEN)

        return tokens

    def batch_tokenize(
        self,
        domains: list[str],
        return_tensors: bool = True,
    ) -> np.ndarray | torch.Tensor:
        """Tokenize multiple domains.

        Args:
            domains: List of domain names
            return_tensors: Return PyTorch tensors

        Returns:
            Token ID array/tensor [batch, max_length]
        """
        tokens = [self.tokenize(d) for d in domains]
        arr = np.array(tokens, dtype=np.int64)

        if return_tensors:
            return torch.from_numpy(arr)
        return arr

    def _extract_domain(self, domain: str) -> str:
        """Extract domain from URL or clean domain string."""
        # Remove protocol
        if "://" in domain:
            domain = domain.split("://", 1)[1]

        # Remove path, query, fragment
        domain = domain.split("/")[0].split("?")[0].split("#")[0]

        # Remove port
        if ":" in domain:
            domain = domain.rsplit(":", 1)[0]

        return domain.strip()


class DGAFeatureExtractor(LoggerMixin):
    """Extract features from domain names for DGA detection."""

    VOWELS = set("aeiouAEIOU")
    CONSONANTS = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
    HEX_CHARS = set("0123456789abcdefABCDEF")

    # Common TLDs
    COMMON_TLDS = {
        "com", "net", "org", "edu", "gov", "mil", "int",
        "io", "co", "ai", "app", "dev", "cloud", "online",
        "info", "biz", "name", "pro", "xyz", "top", "site",
        "uk", "de", "fr", "jp", "cn", "ru", "br", "in", "au",
    }

    # Known benign domain patterns
    BENIGN_PATTERNS = [
        r"^www\.",
        r"^mail\.",
        r"^api\.",
        r"^cdn\.",
        r"\.(google|microsoft|amazon|apple|facebook)\.",
    ]

    def __init__(self, tokenizer: DomainTokenizer | None = None):
        """Initialize feature extractor.

        Args:
            tokenizer: Optional domain tokenizer
        """
        self.tokenizer = tokenizer or DomainTokenizer()
        self._benign_patterns = [re.compile(p, re.I) for p in self.BENIGN_PATTERNS]

    def extract_statistics(self, domain: str) -> DomainStatistics:
        """Extract statistical features from a domain.

        Args:
            domain: Domain name

        Returns:
            DomainStatistics object
        """
        # Clean domain
        domain_clean = self._clean_domain(domain)
        parts = domain_clean.split(".")

        # Get SLD (second-level domain) and TLD
        if len(parts) >= 2:
            tld = parts[-1]
            sld = parts[-2] if len(parts) > 1 else ""
            subdomains = parts[:-2]
        else:
            tld = ""
            sld = parts[0] if parts else ""
            subdomains = []

        # Character counts for SLD (main domain)
        length = len(sld)
        num_digits = sum(c.isdigit() for c in sld)
        num_consonants = sum(c in self.CONSONANTS for c in sld)
        num_vowels = sum(c in self.VOWELS for c in sld)
        num_special = sum(not c.isalnum() for c in sld)

        # Ratios
        digit_ratio = num_digits / length if length > 0 else 0
        consonant_ratio = num_consonants / length if length > 0 else 0
        vowel_ratio = num_vowels / length if length > 0 else 0
        unique_chars = len(set(sld.lower()))
        unique_char_ratio = unique_chars / length if length > 0 else 0

        # Entropy
        entropy = self._calculate_entropy(sld.lower())

        # Consecutive sequences
        consecutive_consonants = self._max_consecutive(sld, self.CONSONANTS)
        consecutive_digits = self._max_consecutive(sld, set("0123456789"))

        # N-gram variety
        bigram_variety = self._ngram_variety(sld.lower(), 2)
        trigram_variety = self._ngram_variety(sld.lower(), 3)

        # Hex ratio
        hex_chars = sum(c in self.HEX_CHARS for c in sld)
        hex_ratio = hex_chars / length if length > 0 else 0

        return DomainStatistics(
            length=length,
            num_digits=num_digits,
            num_consonants=num_consonants,
            num_vowels=num_vowels,
            num_special=num_special,
            digit_ratio=digit_ratio,
            consonant_ratio=consonant_ratio,
            vowel_ratio=vowel_ratio,
            unique_char_ratio=unique_char_ratio,
            entropy=entropy,
            consecutive_consonants_max=consecutive_consonants,
            consecutive_digits_max=consecutive_digits,
            has_subdomain=len(subdomains) > 0,
            subdomain_count=len(subdomains),
            tld_length=len(tld),
            sld_length=length,
            longest_consonant_seq=consecutive_consonants,
            bigram_variety=bigram_variety,
            trigram_variety=trigram_variety,
            hex_ratio=hex_ratio,
        )

    def extract_features(self, domain: str) -> dict[str, Any]:
        """Extract all features for a domain.

        Args:
            domain: Domain name

        Returns:
            Feature dictionary
        """
        # Get tokens
        tokens = self.tokenizer.tokenize(domain)

        # Get statistics
        stats = self.extract_statistics(domain)

        # Check patterns
        is_likely_benign = self._check_benign_patterns(domain)
        has_common_tld = self._has_common_tld(domain)

        return {
            "tokens": tokens,
            "statistics": stats,
            "is_likely_benign": is_likely_benign,
            "has_common_tld": has_common_tld,
        }

    def to_tensor(
        self,
        features: dict[str, Any],
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Convert features to tensors.

        Args:
            features: Feature dictionary
            device: Target device

        Returns:
            Dictionary of tensors
        """
        device = torch.device(device)
        stats = features["statistics"]

        # Token tensor
        token_tensor = torch.tensor(features["tokens"], dtype=torch.long, device=device)

        # Statistical features tensor
        stat_features = torch.tensor(
            [
                stats.length / 63.0,  # Normalize by max length
                stats.digit_ratio,
                stats.consonant_ratio,
                stats.vowel_ratio,
                stats.unique_char_ratio,
                stats.entropy / 4.0,  # Normalize by max entropy ~4 bits
                stats.consecutive_consonants_max / 10.0,
                stats.consecutive_digits_max / 10.0,
                float(stats.has_subdomain),
                stats.subdomain_count / 5.0,
                stats.tld_length / 10.0,
                stats.bigram_variety,
                stats.trigram_variety,
                stats.hex_ratio,
                float(features["is_likely_benign"]),
                float(features["has_common_tld"]),
            ],
            dtype=torch.float32,
            device=device,
        )

        return {
            "tokens": token_tensor,
            "statistical_features": stat_features,
        }

    def batch_extract(
        self,
        domains: list[str],
        device: str = "cpu",
    ) -> dict[str, torch.Tensor]:
        """Extract features for multiple domains.

        Args:
            domains: List of domain names
            device: Target device

        Returns:
            Batched feature tensors
        """
        features_list = [self.extract_features(d) for d in domains]
        tensors_list = [self.to_tensor(f, device) for f in features_list]

        return {
            "tokens": torch.stack([t["tokens"] for t in tensors_list]),
            "statistical_features": torch.stack(
                [t["statistical_features"] for t in tensors_list]
            ),
        }

    def _clean_domain(self, domain: str) -> str:
        """Clean domain name."""
        # Remove protocol
        if "://" in domain:
            domain = domain.split("://", 1)[1]

        # Remove path/query/fragment
        domain = domain.split("/")[0].split("?")[0].split("#")[0]

        # Remove port
        if ":" in domain:
            domain = domain.rsplit(":", 1)[0]

        return domain.strip().lower()

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def _max_consecutive(self, text: str, char_set: set) -> int:
        """Find maximum consecutive characters from set."""
        max_count = 0
        current_count = 0

        for char in text:
            if char in char_set:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0

        return max_count

    def _ngram_variety(self, text: str, n: int) -> float:
        """Calculate n-gram variety score."""
        if len(text) < n:
            return 0.0

        ngrams = [text[i : i + n] for i in range(len(text) - n + 1)]
        unique_ngrams = len(set(ngrams))
        max_possible = min(len(ngrams), 26**n)

        return unique_ngrams / max_possible if max_possible > 0 else 0.0

    def _check_benign_patterns(self, domain: str) -> bool:
        """Check if domain matches benign patterns."""
        for pattern in self._benign_patterns:
            if pattern.search(domain):
                return True
        return False

    def _has_common_tld(self, domain: str) -> bool:
        """Check if domain has a common TLD."""
        parts = domain.lower().split(".")
        if parts:
            tld = parts[-1]
            return tld in self.COMMON_TLDS
        return False
