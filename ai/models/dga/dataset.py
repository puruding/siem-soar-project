"""DGA Dataset - Dataset classes for DGA detection training."""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler

from common.logging import LoggerMixin
from models.dga.features import DGAFeatureExtractor, DomainTokenizer
from models.dga.config import DGATrainingConfig, DGAConfig, DGAFamily


class DGADataset(Dataset, LoggerMixin):
    """Dataset for DGA detection training.

    Supports:
    - Parquet, CSV, and text file formats
    - On-the-fly tokenization and feature extraction
    - Data augmentation (character swapping, subdomain injection)
    - Class balancing via oversampling
    """

    def __init__(
        self,
        data_path: str | Path,
        config: DGAConfig,
        training_config: DGATrainingConfig | None = None,
        transform: callable | None = None,
        augment: bool = False,
    ):
        """Initialize dataset.

        Args:
            data_path: Path to data file
            config: Model configuration
            training_config: Training configuration
            transform: Optional transform function
            augment: Whether to apply data augmentation
        """
        self.data_path = Path(data_path)
        self.config = config
        self.training_config = training_config or DGATrainingConfig()
        self.transform = transform
        self.augment = augment and self.training_config.augment_data

        # Initialize tokenizer and feature extractor
        self.tokenizer = DomainTokenizer(max_length=config.max_domain_length)
        self.feature_extractor = DGAFeatureExtractor(self.tokenizer)

        # Family mapping
        self.family_to_id = {f.value: i for i, f in enumerate(DGAFamily)}

        # Load data
        self.domains: list[str] = []
        self.labels: list[int] = []  # 0=benign, 1=dga
        self.families: list[int] = []  # Family IDs
        self._load_data()

        self.logger.info(
            "dataset_loaded",
            path=str(data_path),
            total=len(self.domains),
            benign=sum(1 for l in self.labels if l == 0),
            dga=sum(1 for l in self.labels if l == 1),
        )

    def _load_data(self) -> None:
        """Load data from file."""
        suffix = self.data_path.suffix.lower()

        if suffix == ".parquet":
            self._load_parquet()
        elif suffix == ".csv":
            self._load_csv()
        elif suffix in (".txt", ".list"):
            self._load_text()
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    def _load_parquet(self) -> None:
        """Load data from parquet file."""
        try:
            import pyarrow.parquet as pq

            table = pq.read_table(self.data_path)
            df = table.to_pandas()

            self.domains = df["domain"].tolist()
            self.labels = df["label"].tolist() if "label" in df.columns else [0] * len(self.domains)

            if "family" in df.columns:
                self.families = [
                    self.family_to_id.get(str(f).lower(), 0)
                    for f in df["family"]
                ]
            else:
                self.families = [0] * len(self.domains)

        except ImportError:
            self.logger.warning("pyarrow_not_available", msg="Trying pandas")
            import pandas as pd
            df = pd.read_parquet(self.data_path)
            self.domains = df["domain"].tolist()
            self.labels = df["label"].tolist() if "label" in df.columns else [0] * len(self.domains)
            self.families = [0] * len(self.domains)

    def _load_csv(self) -> None:
        """Load data from CSV file."""
        import csv

        with open(self.data_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain = row.get("domain", "").strip()
                if not domain:
                    continue

                self.domains.append(domain)

                # Label: 0=benign, 1=dga
                label = row.get("label", "0")
                if isinstance(label, str):
                    label = 1 if label.lower() in ("1", "dga", "malicious", "true") else 0
                self.labels.append(int(label))

                # Family
                family = row.get("family", "unknown").lower()
                self.families.append(self.family_to_id.get(family, 0))

    def _load_text(self) -> None:
        """Load data from text file (one domain per line).

        Format: domain [,label] [,family]
        """
        with open(self.data_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(",")
                domain = parts[0].strip()

                if not domain:
                    continue

                self.domains.append(domain)

                # Label
                label = 0
                if len(parts) > 1:
                    label_str = parts[1].strip().lower()
                    label = 1 if label_str in ("1", "dga", "malicious", "true") else 0
                self.labels.append(label)

                # Family
                family = "unknown"
                if len(parts) > 2:
                    family = parts[2].strip().lower()
                self.families.append(self.family_to_id.get(family, 0))

    def __len__(self) -> int:
        return len(self.domains)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        domain = self.domains[idx]
        label = self.labels[idx]
        family = self.families[idx]

        # Apply augmentation
        if self.augment and random.random() < self.training_config.augment_ratio:
            domain = self._augment_domain(domain, label)

        # Extract features
        features = self.feature_extractor.extract_features(domain)
        tensors = self.feature_extractor.to_tensor(features, "cpu")

        # Apply transform
        if self.transform:
            tensors = self.transform(tensors)

        return {
            "tokens": tensors["tokens"],
            "statistical_features": tensors["statistical_features"],
            "label": torch.tensor(label, dtype=torch.long),
            "family": torch.tensor(family, dtype=torch.long),
            "domain": domain,
        }

    def _augment_domain(self, domain: str, label: int) -> str:
        """Apply data augmentation to domain.

        Args:
            domain: Original domain
            label: Domain label (0=benign, 1=dga)

        Returns:
            Augmented domain
        """
        aug_type = random.choice(["swap", "insert", "delete", "subdomain"])

        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            return domain

        sld = domain_parts[-2]  # Second-level domain
        tld = domain_parts[-1]

        if aug_type == "swap" and len(sld) > 1:
            # Swap two adjacent characters
            i = random.randint(0, len(sld) - 2)
            sld = sld[:i] + sld[i + 1] + sld[i] + sld[i + 2:]

        elif aug_type == "insert":
            # Insert a random character
            char = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            i = random.randint(0, len(sld))
            sld = sld[:i] + char + sld[i:]

        elif aug_type == "delete" and len(sld) > 3:
            # Delete a random character
            i = random.randint(0, len(sld) - 1)
            sld = sld[:i] + sld[i + 1:]

        elif aug_type == "subdomain":
            # Add a random subdomain
            subdomain_len = random.randint(3, 8)
            subdomain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=subdomain_len))
            return f"{subdomain}.{sld}.{tld}"

        # Reconstruct domain
        if len(domain_parts) > 2:
            return ".".join(domain_parts[:-2]) + f".{sld}.{tld}"
        else:
            return f"{sld}.{tld}"

    def get_class_weights(self) -> torch.Tensor:
        """Calculate class weights for imbalanced data.

        Returns:
            Tensor of class weights
        """
        label_counts = np.bincount(self.labels, minlength=2)
        total = sum(label_counts)
        weights = total / (2 * label_counts)
        return torch.tensor(weights, dtype=torch.float32)

    def get_sample_weights(self) -> np.ndarray:
        """Get sample weights for weighted random sampling.

        Returns:
            Array of sample weights
        """
        class_weights = self.get_class_weights().numpy()
        return np.array([class_weights[label] for label in self.labels])


class DGADataLoader(DataLoader):
    """DataLoader wrapper for DGA datasets with custom collation."""

    def __init__(
        self,
        dataset: DGADataset,
        batch_size: int = 64,
        shuffle: bool = True,
        num_workers: int = 4,
        pin_memory: bool = True,
        balance_classes: bool = False,
        **kwargs,
    ):
        """Initialize DataLoader.

        Args:
            dataset: DGA dataset
            batch_size: Batch size
            shuffle: Whether to shuffle
            num_workers: Number of worker processes
            pin_memory: Whether to pin memory
            balance_classes: Use weighted sampling for class balance
            **kwargs: Additional DataLoader arguments
        """
        sampler = None
        if balance_classes:
            weights = dataset.get_sample_weights()
            sampler = WeightedRandomSampler(
                weights=weights,
                num_samples=len(weights),
                replacement=True,
            )
            shuffle = False  # Can't use both shuffle and sampler

        super().__init__(
            dataset,
            batch_size=batch_size,
            shuffle=shuffle,
            num_workers=num_workers,
            pin_memory=pin_memory,
            sampler=sampler,
            collate_fn=self.collate_fn,
            **kwargs,
        )

    @staticmethod
    def collate_fn(batch: list[dict[str, Any]]) -> dict[str, torch.Tensor | list[str]]:
        """Collate batch of samples.

        Args:
            batch: List of sample dictionaries

        Returns:
            Batched tensors
        """
        tokens = torch.stack([item["tokens"] for item in batch])
        statistical_features = torch.stack([item["statistical_features"] for item in batch])
        labels = torch.stack([item["label"] for item in batch])
        families = torch.stack([item["family"] for item in batch])
        domains = [item["domain"] for item in batch]

        return {
            "tokens": tokens,
            "statistical_features": statistical_features,
            "labels": labels,
            "families": families,
            "domains": domains,
        }


def create_dga_dataloaders(
    config: DGAConfig,
    training_config: DGATrainingConfig,
) -> tuple[DGADataLoader, DGADataLoader, DGADataLoader | None]:
    """Create train, validation, and test dataloaders.

    Args:
        config: Model configuration
        training_config: Training configuration

    Returns:
        Tuple of (train_loader, val_loader, test_loader)
    """
    # Create datasets
    train_dataset = DGADataset(
        data_path=training_config.train_data_path,
        config=config,
        training_config=training_config,
        augment=True,
    )

    val_dataset = DGADataset(
        data_path=training_config.val_data_path,
        config=config,
        training_config=training_config,
        augment=False,
    )

    test_dataset = None
    if Path(training_config.test_data_path).exists():
        test_dataset = DGADataset(
            data_path=training_config.test_data_path,
            config=config,
            training_config=training_config,
            augment=False,
        )

    # Create dataloaders
    train_loader = DGADataLoader(
        train_dataset,
        batch_size=training_config.batch_size,
        shuffle=True,
        num_workers=training_config.num_workers,
        pin_memory=training_config.pin_memory,
        balance_classes=training_config.balance_classes,
    )

    val_loader = DGADataLoader(
        val_dataset,
        batch_size=training_config.batch_size,
        shuffle=False,
        num_workers=training_config.num_workers,
        pin_memory=training_config.pin_memory,
    )

    test_loader = None
    if test_dataset:
        test_loader = DGADataLoader(
            test_dataset,
            batch_size=training_config.batch_size,
            shuffle=False,
            num_workers=training_config.num_workers,
            pin_memory=training_config.pin_memory,
        )

    return train_loader, val_loader, test_loader
