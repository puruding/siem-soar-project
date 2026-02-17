"""Training script for DGA detection model."""

import os
import random
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
from tqdm import tqdm

from common.logging import LoggerMixin, get_logger
from models.dga.config import DGAConfig, DGATrainingConfig, DGAFamily
from models.dga.model import DGADetectorModel
from models.dga.features import DGAFeatureExtractor, DomainTokenizer


logger = get_logger(__name__)


class DGADataset(Dataset):
    """Dataset for DGA detection training."""

    def __init__(
        self,
        domains: list[str],
        labels: list[int],
        families: list[int] | None = None,
        tokenizer: DomainTokenizer | None = None,
        feature_extractor: DGAFeatureExtractor | None = None,
        augment: bool = False,
        augment_ratio: float = 0.2,
    ):
        """Initialize dataset.

        Args:
            domains: List of domain names
            labels: Binary labels (0=benign, 1=DGA)
            families: DGA family labels
            tokenizer: Domain tokenizer
            feature_extractor: Feature extractor
            augment: Enable data augmentation
            augment_ratio: Augmentation probability
        """
        self.domains = domains
        self.labels = labels
        self.families = families or [0] * len(domains)

        self.tokenizer = tokenizer or DomainTokenizer()
        self.feature_extractor = feature_extractor or DGAFeatureExtractor(self.tokenizer)

        self.augment = augment
        self.augment_ratio = augment_ratio

    def __len__(self) -> int:
        return len(self.domains)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        domain = self.domains[idx]
        label = self.labels[idx]
        family = self.families[idx]

        # Optional augmentation
        if self.augment and random.random() < self.augment_ratio:
            domain = self._augment_domain(domain)

        # Extract features
        features = self.feature_extractor.extract_features(domain)
        tensors = self.feature_extractor.to_tensor(features, "cpu")

        return {
            "tokens": tensors["tokens"],
            "statistical_features": tensors["statistical_features"],
            "label": torch.tensor(label, dtype=torch.long),
            "family": torch.tensor(family, dtype=torch.long),
        }

    def _augment_domain(self, domain: str) -> str:
        """Apply random augmentation to domain."""
        augmentations = [
            self._swap_chars,
            self._insert_char,
            self._delete_char,
            self._change_case,
        ]

        aug_fn = random.choice(augmentations)
        return aug_fn(domain)

    def _swap_chars(self, domain: str) -> str:
        """Swap two adjacent characters."""
        if len(domain) < 2:
            return domain
        chars = list(domain)
        idx = random.randint(0, len(chars) - 2)
        chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
        return "".join(chars)

    def _insert_char(self, domain: str) -> str:
        """Insert a random character."""
        chars = list(domain)
        idx = random.randint(0, len(chars))
        char = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
        chars.insert(idx, char)
        return "".join(chars)

    def _delete_char(self, domain: str) -> str:
        """Delete a random character."""
        if len(domain) < 2:
            return domain
        chars = list(domain)
        idx = random.randint(0, len(chars) - 1)
        del chars[idx]
        return "".join(chars)

    def _change_case(self, domain: str) -> str:
        """Change case of random characters."""
        chars = list(domain)
        for i in range(len(chars)):
            if random.random() < 0.3:
                chars[i] = chars[i].swapcase()
        return "".join(chars)


class DGATrainer(LoggerMixin):
    """Trainer for DGA detection model."""

    def __init__(
        self,
        model_config: DGAConfig,
        training_config: DGATrainingConfig,
    ):
        """Initialize trainer.

        Args:
            model_config: Model configuration
            training_config: Training configuration
        """
        self.model_config = model_config
        self.config = training_config
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Set seed
        self._set_seed(self.config.seed)

        # Initialize tokenizer and feature extractor
        self.tokenizer = DomainTokenizer(max_length=model_config.max_domain_length)
        self.feature_extractor = DGAFeatureExtractor(self.tokenizer)

        # Initialize model
        self.model = DGADetectorModel(model_config).to(self.device)

        # Initialize optimizer
        self.optimizer = optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )

        # Initialize scheduler
        self.scheduler = None  # Set after knowing total steps

        # Metrics tracking
        self.best_metric = 0.0
        self.epochs_without_improvement = 0
        self.global_step = 0

    def _set_seed(self, seed: int) -> None:
        """Set random seed for reproducibility."""
        random.seed(seed)
        np.random.seed(seed)
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)

    def train(
        self,
        train_domains: list[str],
        train_labels: list[int],
        val_domains: list[str],
        val_labels: list[int],
        train_families: list[int] | None = None,
        val_families: list[int] | None = None,
    ) -> dict[str, Any]:
        """Train the model.

        Args:
            train_domains: Training domains
            train_labels: Training labels
            val_domains: Validation domains
            val_labels: Validation labels
            train_families: Training family labels
            val_families: Validation family labels

        Returns:
            Training history
        """
        self.logger.info(
            "starting_training",
            train_size=len(train_domains),
            val_size=len(val_domains),
            device=str(self.device),
        )

        # Create datasets
        train_dataset = DGADataset(
            domains=train_domains,
            labels=train_labels,
            families=train_families,
            tokenizer=self.tokenizer,
            feature_extractor=self.feature_extractor,
            augment=self.config.augment_data,
            augment_ratio=self.config.augment_ratio,
        )

        val_dataset = DGADataset(
            domains=val_domains,
            labels=val_labels,
            families=val_families,
            tokenizer=self.tokenizer,
            feature_extractor=self.feature_extractor,
            augment=False,
        )

        # Create data loaders
        if self.config.balance_classes:
            # Compute class weights for balanced sampling
            class_counts = np.bincount(train_labels)
            class_weights = 1.0 / class_counts
            sample_weights = [class_weights[label] for label in train_labels]
            sampler = WeightedRandomSampler(
                weights=sample_weights,
                num_samples=len(train_labels),
                replacement=True,
            )
            train_loader = DataLoader(
                train_dataset,
                batch_size=self.config.batch_size,
                sampler=sampler,
                num_workers=self.config.num_workers,
                pin_memory=self.config.pin_memory,
            )
        else:
            train_loader = DataLoader(
                train_dataset,
                batch_size=self.config.batch_size,
                shuffle=True,
                num_workers=self.config.num_workers,
                pin_memory=self.config.pin_memory,
            )

        val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size * 2,
            shuffle=False,
            num_workers=self.config.num_workers,
            pin_memory=self.config.pin_memory,
        )

        # Setup scheduler
        total_steps = len(train_loader) * self.config.max_epochs
        self.scheduler = optim.lr_scheduler.OneCycleLR(
            self.optimizer,
            max_lr=self.config.learning_rate,
            total_steps=total_steps,
            pct_start=0.1,
        )

        # Class weights for loss
        class_counts = np.bincount(train_labels)
        class_weights = torch.tensor(
            [1.0 / c for c in class_counts],
            dtype=torch.float32,
            device=self.device,
        )

        # Training loop
        history = {
            "train_loss": [],
            "val_loss": [],
            "val_accuracy": [],
            "val_f1": [],
            "val_precision": [],
            "val_recall": [],
        }

        for epoch in range(self.config.max_epochs):
            # Train epoch
            train_loss = self._train_epoch(train_loader, class_weights)

            # Validate
            val_metrics = self._validate(val_loader)

            # Update history
            history["train_loss"].append(train_loss)
            history["val_loss"].append(val_metrics["loss"])
            history["val_accuracy"].append(val_metrics["accuracy"])
            history["val_f1"].append(val_metrics["f1"])
            history["val_precision"].append(val_metrics["precision"])
            history["val_recall"].append(val_metrics["recall"])

            self.logger.info(
                "epoch_completed",
                epoch=epoch + 1,
                train_loss=f"{train_loss:.4f}",
                val_loss=f"{val_metrics['loss']:.4f}",
                val_f1=f"{val_metrics['f1']:.4f}",
                val_accuracy=f"{val_metrics['accuracy']:.4f}",
            )

            # Save best model
            current_metric = val_metrics[self.config.early_stopping_metric.replace("val_", "")]
            if current_metric > self.best_metric:
                self.best_metric = current_metric
                self.epochs_without_improvement = 0
                self._save_checkpoint("best_model.pt", val_metrics)
            else:
                self.epochs_without_improvement += 1

            # Early stopping
            if (
                self.config.early_stopping
                and self.epochs_without_improvement >= self.config.early_stopping_patience
            ):
                self.logger.info(
                    "early_stopping",
                    epochs_without_improvement=self.epochs_without_improvement,
                )
                break

            # Save periodic checkpoint
            if (epoch + 1) % 5 == 0:
                self._save_checkpoint(f"checkpoint_epoch_{epoch + 1}.pt", val_metrics)

        # Save final model
        self._save_checkpoint("final_model.pt", val_metrics)

        return history

    def _train_epoch(
        self,
        train_loader: DataLoader,
        class_weights: torch.Tensor,
    ) -> float:
        """Train for one epoch.

        Args:
            train_loader: Training data loader
            class_weights: Class weights for loss

        Returns:
            Average training loss
        """
        self.model.train()
        total_loss = 0.0
        num_batches = 0

        pbar = tqdm(train_loader, desc="Training")
        for batch in pbar:
            # Move to device
            tokens = batch["tokens"].to(self.device)
            statistical_features = batch["statistical_features"].to(self.device)
            labels = batch["label"].to(self.device)
            families = batch["family"].to(self.device)

            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(
                tokens=tokens,
                statistical_features=statistical_features,
            )

            # Compute loss
            losses = self.model.compute_loss(
                outputs=outputs,
                labels=labels,
                family_labels=families,
                class_weights=class_weights,
            )

            # Backward pass
            losses["total_loss"].backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

            self.optimizer.step()
            self.scheduler.step()

            # Update metrics
            total_loss += losses["total_loss"].item()
            num_batches += 1
            self.global_step += 1

            pbar.set_postfix({"loss": f"{losses['total_loss'].item():.4f}"})

        return total_loss / num_batches

    def _validate(self, val_loader: DataLoader) -> dict[str, float]:
        """Validate the model.

        Args:
            val_loader: Validation data loader

        Returns:
            Validation metrics
        """
        self.model.eval()
        total_loss = 0.0
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in val_loader:
                tokens = batch["tokens"].to(self.device)
                statistical_features = batch["statistical_features"].to(self.device)
                labels = batch["label"].to(self.device)

                outputs = self.model(
                    tokens=tokens,
                    statistical_features=statistical_features,
                )

                loss = nn.functional.cross_entropy(outputs["logits"], labels)
                total_loss += loss.item()

                preds = outputs["logits"].argmax(dim=-1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(labels.cpu().numpy())

        # Compute metrics
        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)

        accuracy = (all_preds == all_labels).mean()

        # Precision, recall, F1 for DGA class (label=1)
        tp = ((all_preds == 1) & (all_labels == 1)).sum()
        fp = ((all_preds == 1) & (all_labels == 0)).sum()
        fn = ((all_preds == 0) & (all_labels == 1)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "loss": total_loss / len(val_loader),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    def _save_checkpoint(self, filename: str, metrics: dict[str, float]) -> None:
        """Save model checkpoint.

        Args:
            filename: Checkpoint filename
            metrics: Current metrics
        """
        os.makedirs(self.config.checkpoint_dir, exist_ok=True)
        path = os.path.join(self.config.checkpoint_dir, filename)

        checkpoint = {
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "model_config": self.model_config.model_dump(),
            "training_config": self.config.model_dump(),
            "metrics": metrics,
            "global_step": self.global_step,
        }

        torch.save(checkpoint, path)
        self.logger.info("checkpoint_saved", path=path)


def load_data_from_parquet(path: str) -> tuple[list[str], list[int], list[int]]:
    """Load training data from parquet file.

    Args:
        path: Path to parquet file

    Returns:
        Tuple of (domains, labels, families)
    """
    import pyarrow.parquet as pq

    table = pq.read_table(path)
    df = table.to_pandas()

    domains = df["domain"].tolist()
    labels = df["label"].tolist()
    families = df.get("family", [0] * len(domains)).tolist()

    return domains, labels, families


def main():
    """Main training entry point."""
    model_config = DGAConfig()
    training_config = DGATrainingConfig()

    # Load data
    train_domains, train_labels, train_families = load_data_from_parquet(
        training_config.train_data_path
    )
    val_domains, val_labels, val_families = load_data_from_parquet(
        training_config.val_data_path
    )

    # Train
    trainer = DGATrainer(model_config, training_config)
    history = trainer.train(
        train_domains=train_domains,
        train_labels=train_labels,
        val_domains=val_domains,
        val_labels=val_labels,
        train_families=train_families,
        val_families=val_families,
    )

    print("Training complete!")
    print(f"Best F1: {trainer.best_metric:.4f}")


if __name__ == "__main__":
    main()
