"""Data loaders for model training."""

from typing import Any

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader, Sampler

from common.logging import LoggerMixin
from models.classifier.features import FeatureExtractor, TextFeatureBuilder


class AlertDataset(Dataset, LoggerMixin):
    """PyTorch dataset for alert classification."""

    def __init__(
        self,
        data: pd.DataFrame,
        tokenizer: Any,
        feature_extractor: FeatureExtractor,
        text_builder: TextFeatureBuilder,
        max_length: int = 512,
        include_labels: bool = True,
    ) -> None:
        """Initialize the dataset.

        Args:
            data: DataFrame with alert data
            tokenizer: HuggingFace tokenizer
            feature_extractor: Feature extractor instance
            text_builder: Text feature builder
            max_length: Maximum sequence length
            include_labels: Whether to include labels
        """
        self.data = data.reset_index(drop=True)
        self.tokenizer = tokenizer
        self.feature_extractor = feature_extractor
        self.text_builder = text_builder
        self.max_length = max_length
        self.include_labels = include_labels

        self.logger.info(
            "created_dataset",
            size=len(self.data),
            include_labels=include_labels,
        )

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        """Get a single item.

        Args:
            idx: Item index

        Returns:
            Dictionary of tensors
        """
        row = self.data.iloc[idx]
        alert_dict = row.to_dict()

        # Build text representation
        text = self.text_builder.build_text(alert_dict)

        # Tokenize text
        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        item = {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
        }

        # Extract features
        features = self.feature_extractor.extract(alert_dict)
        feature_tensors = self.feature_extractor.to_tensor(features)
        item["numeric_features"] = feature_tensors["numeric_features"]
        item["categorical_features"] = feature_tensors["categorical_features"]

        # Add labels if training
        if self.include_labels:
            item["severity"] = torch.tensor(row.get("severity_encoded", 2), dtype=torch.long)
            item["category"] = torch.tensor(row.get("category_encoded", 11), dtype=torch.long)
            item["is_fp"] = torch.tensor(row.get("is_fp_encoded", 0), dtype=torch.long)
            item["risk_score"] = torch.tensor(row.get("risk_score_normalized", 0.5), dtype=torch.float)

            # Multi-hot MITRE tactics
            mitre_tactics = row.get("mitre_tactics_encoded", [0] * 14)
            if isinstance(mitre_tactics, (list, np.ndarray)):
                item["mitre_tactics"] = torch.tensor(mitre_tactics, dtype=torch.float)
            else:
                item["mitre_tactics"] = torch.zeros(14, dtype=torch.float)

        # Add metadata
        item["alert_id"] = row.get("alert_id", f"alert_{idx}")

        return item


class BalancedSampler(Sampler):
    """Balanced sampler for handling class imbalance."""

    def __init__(
        self,
        labels: np.ndarray,
        num_samples: int | None = None,
        replacement: bool = True,
    ) -> None:
        """Initialize the sampler.

        Args:
            labels: Array of class labels
            num_samples: Number of samples to draw (default: len(labels))
            replacement: Whether to sample with replacement
        """
        self.labels = labels
        self.num_samples = num_samples or len(labels)
        self.replacement = replacement

        # Calculate class weights
        unique, counts = np.unique(labels, return_counts=True)
        class_weights = 1.0 / counts

        # Assign weight to each sample
        self.weights = torch.tensor([class_weights[label] for label in labels])
        self.weights = self.weights / self.weights.sum()

    def __iter__(self):
        return iter(torch.multinomial(
            self.weights,
            self.num_samples,
            replacement=self.replacement,
        ).tolist())

    def __len__(self) -> int:
        return self.num_samples


class AlertDataLoader(LoggerMixin):
    """Factory for creating data loaders."""

    def __init__(
        self,
        tokenizer: Any,
        feature_extractor: FeatureExtractor | None = None,
        text_builder: TextFeatureBuilder | None = None,
        max_length: int = 512,
    ) -> None:
        """Initialize the data loader factory.

        Args:
            tokenizer: HuggingFace tokenizer
            feature_extractor: Feature extractor (created if None)
            text_builder: Text builder (created if None)
            max_length: Maximum sequence length
        """
        self.tokenizer = tokenizer
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self.text_builder = text_builder or TextFeatureBuilder(max_length=max_length)
        self.max_length = max_length

    def create_train_loader(
        self,
        data: pd.DataFrame,
        batch_size: int = 32,
        num_workers: int = 4,
        balance_classes: bool = True,
        pin_memory: bool = True,
    ) -> DataLoader:
        """Create training data loader.

        Args:
            data: Training DataFrame
            batch_size: Batch size
            num_workers: Number of data loading workers
            balance_classes: Whether to use balanced sampling
            pin_memory: Pin memory for faster GPU transfer

        Returns:
            DataLoader for training
        """
        dataset = AlertDataset(
            data,
            self.tokenizer,
            self.feature_extractor,
            self.text_builder,
            self.max_length,
            include_labels=True,
        )

        sampler = None
        shuffle = True

        if balance_classes and "severity_encoded" in data.columns:
            sampler = BalancedSampler(data["severity_encoded"].values)
            shuffle = False

        loader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=shuffle,
            sampler=sampler,
            num_workers=num_workers,
            pin_memory=pin_memory,
            drop_last=True,
            collate_fn=self._collate_fn,
        )

        self.logger.info(
            "created_train_loader",
            dataset_size=len(dataset),
            batch_size=batch_size,
            balanced=balance_classes,
        )

        return loader

    def create_eval_loader(
        self,
        data: pd.DataFrame,
        batch_size: int = 64,
        num_workers: int = 4,
        pin_memory: bool = True,
    ) -> DataLoader:
        """Create evaluation data loader.

        Args:
            data: Evaluation DataFrame
            batch_size: Batch size
            num_workers: Number of data loading workers
            pin_memory: Pin memory for faster GPU transfer

        Returns:
            DataLoader for evaluation
        """
        dataset = AlertDataset(
            data,
            self.tokenizer,
            self.feature_extractor,
            self.text_builder,
            self.max_length,
            include_labels=True,
        )

        loader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
            pin_memory=pin_memory,
            collate_fn=self._collate_fn,
        )

        self.logger.info(
            "created_eval_loader",
            dataset_size=len(dataset),
            batch_size=batch_size,
        )

        return loader

    def create_inference_loader(
        self,
        data: pd.DataFrame,
        batch_size: int = 64,
        num_workers: int = 2,
    ) -> DataLoader:
        """Create inference data loader (no labels).

        Args:
            data: Inference DataFrame
            batch_size: Batch size
            num_workers: Number of data loading workers

        Returns:
            DataLoader for inference
        """
        dataset = AlertDataset(
            data,
            self.tokenizer,
            self.feature_extractor,
            self.text_builder,
            self.max_length,
            include_labels=False,
        )

        loader = DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
            collate_fn=self._collate_fn,
        )

        return loader

    @staticmethod
    def _collate_fn(batch: list[dict[str, Any]]) -> dict[str, torch.Tensor | list]:
        """Collate batch items.

        Args:
            batch: List of items from dataset

        Returns:
            Batched tensors
        """
        result = {}

        # Stack all tensor fields
        tensor_keys = [
            "input_ids", "attention_mask", "numeric_features", "categorical_features",
            "severity", "category", "is_fp", "risk_score", "mitre_tactics"
        ]

        for key in tensor_keys:
            if key in batch[0] and batch[0][key] is not None:
                result[key] = torch.stack([item[key] for item in batch])

        # Collect non-tensor fields
        result["alert_ids"] = [item.get("alert_id", "") for item in batch]

        return result

    @classmethod
    def from_parquet(
        cls,
        train_path: str,
        val_path: str,
        test_path: str,
        tokenizer: Any,
        batch_size: int = 32,
        num_workers: int = 4,
    ) -> tuple[DataLoader, DataLoader, DataLoader]:
        """Create data loaders from parquet files.

        Args:
            train_path: Path to training parquet
            val_path: Path to validation parquet
            test_path: Path to test parquet
            tokenizer: HuggingFace tokenizer
            batch_size: Batch size
            num_workers: Number of workers

        Returns:
            Tuple of (train_loader, val_loader, test_loader)
        """
        train_df = pd.read_parquet(train_path)
        val_df = pd.read_parquet(val_path)
        test_df = pd.read_parquet(test_path)

        loader_factory = cls(tokenizer)

        train_loader = loader_factory.create_train_loader(
            train_df, batch_size, num_workers, balance_classes=True
        )
        val_loader = loader_factory.create_eval_loader(
            val_df, batch_size * 2, num_workers
        )
        test_loader = loader_factory.create_eval_loader(
            test_df, batch_size * 2, num_workers
        )

        return train_loader, val_loader, test_loader
