"""Data augmentation for alert classification."""

import random
import re
from typing import Any

import numpy as np
import pandas as pd

from common.logging import LoggerMixin


class AlertAugmenter(LoggerMixin):
    """Augmentation strategies for alert data."""

    # Synonyms for common security terms
    SYNONYMS = {
        "malware": ["malicious software", "virus", "trojan", "malicious code"],
        "attack": ["intrusion", "breach", "compromise", "exploit"],
        "suspicious": ["anomalous", "unusual", "abnormal", "atypical"],
        "blocked": ["denied", "prevented", "stopped", "rejected"],
        "allowed": ["permitted", "accepted", "passed", "approved"],
        "connection": ["traffic", "communication", "session", "link"],
        "failed": ["unsuccessful", "rejected", "denied", "invalid"],
        "unauthorized": ["illegal", "forbidden", "prohibited", "illicit"],
        "high": ["elevated", "critical", "severe", "significant"],
        "detected": ["identified", "discovered", "found", "observed"],
    }

    # Common typos/variations
    VARIATIONS = {
        "password": ["passwd", "pwd", "pass"],
        "username": ["user", "userid", "login"],
        "administrator": ["admin", "root", "superuser"],
        "firewall": ["fw", "FW"],
        "network": ["net", "nw"],
    }

    def __init__(
        self,
        synonym_prob: float = 0.3,
        noise_prob: float = 0.1,
        drop_field_prob: float = 0.05,
        numeric_noise_std: float = 0.1,
        seed: int = 42,
    ) -> None:
        """Initialize the augmenter.

        Args:
            synonym_prob: Probability of replacing with synonym
            noise_prob: Probability of adding noise to values
            drop_field_prob: Probability of dropping optional fields
            numeric_noise_std: Standard deviation for numeric noise
            seed: Random seed
        """
        self.synonym_prob = synonym_prob
        self.noise_prob = noise_prob
        self.drop_field_prob = drop_field_prob
        self.numeric_noise_std = numeric_noise_std
        self.rng = random.Random(seed)
        np.random.seed(seed)

    def augment(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Augment a single alert.

        Args:
            alert: Alert dictionary

        Returns:
            Augmented alert dictionary
        """
        augmented = alert.copy()

        # Text augmentation
        for field in ["title", "description", "message"]:
            if field in augmented and augmented[field]:
                augmented[field] = self._augment_text(augmented[field])

        # Numeric augmentation
        for field in ["bytes_sent", "bytes_received", "packet_count"]:
            if field in augmented and augmented[field]:
                augmented[field] = self._augment_numeric(augmented[field])

        # Field dropping
        optional_fields = ["raw_log", "command_line", "url"]
        for field in optional_fields:
            if field in augmented and self.rng.random() < self.drop_field_prob:
                augmented[field] = None

        return augmented

    def augment_batch(
        self,
        df: pd.DataFrame,
        num_augmentations: int = 1,
    ) -> pd.DataFrame:
        """Augment a batch of alerts.

        Args:
            df: DataFrame with alerts
            num_augmentations: Number of augmented copies per alert

        Returns:
            DataFrame with original and augmented alerts
        """
        augmented_rows = []

        for _, row in df.iterrows():
            alert = row.to_dict()

            for _ in range(num_augmentations):
                augmented = self.augment(alert)
                augmented_rows.append(augmented)

        augmented_df = pd.DataFrame(augmented_rows)

        # Combine original and augmented
        result = pd.concat([df, augmented_df], ignore_index=True)

        self.logger.info(
            "augmented_batch",
            original_size=len(df),
            augmented_size=len(result),
            augmentation_factor=num_augmentations,
        )

        return result

    def _augment_text(self, text: str) -> str:
        """Augment text with synonyms and variations.

        Args:
            text: Input text

        Returns:
            Augmented text
        """
        if not text:
            return text

        words = text.split()
        augmented_words = []

        for word in words:
            word_lower = word.lower()

            # Try synonym replacement
            if self.rng.random() < self.synonym_prob:
                if word_lower in self.SYNONYMS:
                    replacement = self.rng.choice(self.SYNONYMS[word_lower])
                    # Preserve case
                    if word[0].isupper():
                        replacement = replacement.capitalize()
                    augmented_words.append(replacement)
                    continue

            # Try variation replacement
            if self.rng.random() < self.synonym_prob:
                for base, variations in self.VARIATIONS.items():
                    if word_lower == base:
                        replacement = self.rng.choice(variations)
                        augmented_words.append(replacement)
                        break
                else:
                    augmented_words.append(word)
                continue

            augmented_words.append(word)

        return " ".join(augmented_words)

    def _augment_numeric(self, value: float | int) -> float | int:
        """Add noise to numeric value.

        Args:
            value: Input value

        Returns:
            Augmented value
        """
        if value == 0:
            return value

        if self.rng.random() < self.noise_prob:
            noise = np.random.normal(0, self.numeric_noise_std * abs(value))
            augmented = value + noise
            # Keep same type and ensure non-negative
            augmented = max(0, augmented)
            if isinstance(value, int):
                return int(round(augmented))
            return augmented

        return value


class MixupAugmenter(LoggerMixin):
    """Mixup augmentation for continuous features."""

    def __init__(self, alpha: float = 0.2) -> None:
        """Initialize mixup augmenter.

        Args:
            alpha: Mixup alpha parameter (higher = more mixing)
        """
        self.alpha = alpha

    def mixup(
        self,
        features1: np.ndarray,
        features2: np.ndarray,
        labels1: np.ndarray,
        labels2: np.ndarray,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Apply mixup augmentation.

        Args:
            features1: First batch of features
            features2: Second batch of features
            labels1: First batch of labels
            labels2: Second batch of labels

        Returns:
            Tuple of (mixed_features, mixed_labels)
        """
        batch_size = features1.shape[0]

        # Sample lambda from beta distribution
        lam = np.random.beta(self.alpha, self.alpha, batch_size)
        lam = np.maximum(lam, 1 - lam)  # Ensure lam >= 0.5

        # Expand lambda for broadcasting
        lam_features = lam.reshape(-1, 1)
        lam_labels = lam.reshape(-1, 1) if labels1.ndim > 1 else lam

        # Mix features and labels
        mixed_features = lam_features * features1 + (1 - lam_features) * features2
        mixed_labels = lam_labels * labels1 + (1 - lam_labels) * labels2

        return mixed_features, mixed_labels


class BackTranslationAugmenter(LoggerMixin):
    """Augmentation via back-translation (placeholder for future implementation)."""

    def __init__(
        self,
        source_lang: str = "en",
        pivot_langs: list[str] | None = None,
    ) -> None:
        """Initialize back-translation augmenter.

        Args:
            source_lang: Source language
            pivot_langs: Languages to translate through
        """
        self.source_lang = source_lang
        self.pivot_langs = pivot_langs or ["de", "fr", "es"]
        self._translator = None

    async def augment(self, text: str) -> str:
        """Augment text via back-translation.

        Args:
            text: Input text

        Returns:
            Back-translated text
        """
        # Placeholder - would use translation API
        # For now, return original
        self.logger.warning("back_translation_not_implemented")
        return text


class ClassBalancer(LoggerMixin):
    """Balance classes in training data."""

    def __init__(
        self,
        strategy: str = "oversample",
        target_ratio: float | None = None,
    ) -> None:
        """Initialize the class balancer.

        Args:
            strategy: Balancing strategy ("oversample", "undersample", "hybrid")
            target_ratio: Target ratio (None = equal distribution)
        """
        self.strategy = strategy
        self.target_ratio = target_ratio

    def balance(
        self,
        df: pd.DataFrame,
        label_column: str,
        augmenter: AlertAugmenter | None = None,
    ) -> pd.DataFrame:
        """Balance classes in DataFrame.

        Args:
            df: Input DataFrame
            label_column: Name of label column
            augmenter: Optional augmenter for oversampling

        Returns:
            Balanced DataFrame
        """
        class_counts = df[label_column].value_counts()
        max_count = class_counts.max()
        min_count = class_counts.min()

        target_count = int(
            max_count if self.strategy == "oversample"
            else min_count if self.strategy == "undersample"
            else (max_count + min_count) / 2
        )

        if self.target_ratio:
            target_count = int(max_count * self.target_ratio)

        balanced_dfs = []

        for label, count in class_counts.items():
            class_df = df[df[label_column] == label]

            if count < target_count:
                # Oversample
                n_needed = target_count - count
                samples = class_df.sample(n=n_needed, replace=True, random_state=42)

                if augmenter:
                    # Apply augmentation to oversampled data
                    augmented_rows = []
                    for _, row in samples.iterrows():
                        augmented = augmenter.augment(row.to_dict())
                        augmented_rows.append(augmented)
                    samples = pd.DataFrame(augmented_rows)

                class_df = pd.concat([class_df, samples], ignore_index=True)

            elif count > target_count:
                # Undersample
                class_df = class_df.sample(n=target_count, random_state=42)

            balanced_dfs.append(class_df)

        result = pd.concat(balanced_dfs, ignore_index=True)
        result = result.sample(frac=1, random_state=42).reset_index(drop=True)

        self.logger.info(
            "balanced_classes",
            original_size=len(df),
            balanced_size=len(result),
            strategy=self.strategy,
        )

        return result
