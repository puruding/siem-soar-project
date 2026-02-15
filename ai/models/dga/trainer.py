"""DGA Trainer - Training pipeline for DGA detection models."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.cuda.amp import GradScaler, autocast
from tqdm import tqdm

from common.logging import LoggerMixin
from models.dga.config import DGAConfig, DGATrainingConfig
from models.dga.model import DGADetectorModel
from models.dga.dataset import DGADataLoader


class DGAMetrics:
    """Metrics computation for DGA detection."""

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset accumulated metrics."""
        self.predictions = []
        self.labels = []
        self.family_predictions = []
        self.family_labels = []

    def update(
        self,
        predictions: torch.Tensor,
        labels: torch.Tensor,
        family_predictions: torch.Tensor | None = None,
        family_labels: torch.Tensor | None = None,
    ):
        """Update metrics with batch results."""
        self.predictions.extend(predictions.cpu().numpy())
        self.labels.extend(labels.cpu().numpy())

        if family_predictions is not None:
            self.family_predictions.extend(family_predictions.cpu().numpy())
        if family_labels is not None:
            self.family_labels.extend(family_labels.cpu().numpy())

    def compute(self) -> dict[str, float]:
        """Compute all metrics."""
        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            roc_auc_score,
            confusion_matrix,
        )

        predictions = np.array(self.predictions)
        labels = np.array(self.labels)

        metrics = {}

        # Binary classification metrics
        metrics["accuracy"] = accuracy_score(labels, predictions)
        metrics["precision"] = precision_score(labels, predictions, zero_division=0)
        metrics["recall"] = recall_score(labels, predictions, zero_division=0)
        metrics["f1"] = f1_score(labels, predictions, zero_division=0)

        # Confusion matrix
        cm = confusion_matrix(labels, predictions)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            metrics["true_positive_rate"] = tp / (tp + fn) if (tp + fn) > 0 else 0
            metrics["true_negative_rate"] = tn / (tn + fp) if (tn + fp) > 0 else 0
            metrics["false_positive_rate"] = fp / (fp + tn) if (fp + tn) > 0 else 0

        # Family classification metrics
        if self.family_predictions and self.family_labels:
            family_preds = np.array(self.family_predictions)
            family_labels = np.array(self.family_labels)

            # Only compute for DGA samples
            dga_mask = np.array(self.labels) == 1
            if dga_mask.sum() > 0:
                metrics["family_accuracy"] = accuracy_score(
                    family_labels[dga_mask],
                    family_preds[dga_mask],
                )

        return metrics


class EarlyStopping:
    """Early stopping handler."""

    def __init__(
        self,
        patience: int = 5,
        mode: str = "max",
        min_delta: float = 0.001,
    ):
        """Initialize early stopping.

        Args:
            patience: Number of epochs to wait
            mode: 'max' or 'min' for metric optimization
            min_delta: Minimum change to qualify as improvement
        """
        self.patience = patience
        self.mode = mode
        self.min_delta = min_delta
        self.counter = 0
        self.best_score = None
        self.should_stop = False

    def step(self, score: float) -> bool:
        """Check if training should stop.

        Args:
            score: Current metric value

        Returns:
            True if should stop
        """
        if self.best_score is None:
            self.best_score = score
            return False

        if self.mode == "max":
            improved = score > self.best_score + self.min_delta
        else:
            improved = score < self.best_score - self.min_delta

        if improved:
            self.best_score = score
            self.counter = 0
        else:
            self.counter += 1
            if self.counter >= self.patience:
                self.should_stop = True

        return self.should_stop


class DGATrainer(LoggerMixin):
    """Trainer for DGA detection models.

    Features:
    - Multi-task learning (binary classification + family classification)
    - Mixed precision training (AMP)
    - Learning rate scheduling with warmup
    - Early stopping
    - Checkpoint management
    - WandB integration (optional)
    """

    def __init__(
        self,
        model: DGADetectorModel,
        config: DGAConfig,
        training_config: DGATrainingConfig,
    ):
        """Initialize trainer.

        Args:
            model: DGA detector model
            config: Model configuration
            training_config: Training configuration
        """
        self.model = model
        self.config = config
        self.training_config = training_config

        # Device setup
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = self.model.to(self.device)

        # Mixed precision
        self.use_amp = torch.cuda.is_available()
        self.scaler = GradScaler() if self.use_amp else None

        # Metrics tracker
        self.metrics = DGAMetrics()

        # Early stopping
        if training_config.early_stopping:
            self.early_stopping = EarlyStopping(
                patience=training_config.early_stopping_patience,
                mode=training_config.early_stopping_mode,
            )
        else:
            self.early_stopping = None

        # State
        self.current_epoch = 0
        self.global_step = 0
        self.best_metric = float("-inf")
        self.training_history: list[dict] = []

        # Create output directories
        Path(training_config.output_dir).mkdir(parents=True, exist_ok=True)
        Path(training_config.checkpoint_dir).mkdir(parents=True, exist_ok=True)

        self.logger.info(
            "trainer_initialized",
            device=str(self.device),
            use_amp=self.use_amp,
        )

    def train(
        self,
        train_loader: DGADataLoader,
        val_loader: DGADataLoader,
        class_weights: torch.Tensor | None = None,
    ) -> dict[str, Any]:
        """Run full training loop.

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            class_weights: Optional class weights for imbalanced data

        Returns:
            Training history
        """
        # Create optimizer
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.training_config.learning_rate,
            weight_decay=self.training_config.weight_decay,
        )

        # Create scheduler
        num_training_steps = len(train_loader) * self.training_config.max_epochs
        scheduler = self._create_scheduler(optimizer, num_training_steps)

        # Move class weights to device
        if class_weights is not None:
            class_weights = class_weights.to(self.device)

        self.logger.info(
            "training_started",
            epochs=self.training_config.max_epochs,
            train_samples=len(train_loader.dataset),
            val_samples=len(val_loader.dataset),
        )

        for epoch in range(self.training_config.max_epochs):
            self.current_epoch = epoch

            # Training epoch
            train_metrics = self._train_epoch(
                train_loader, optimizer, scheduler, class_weights
            )

            # Validation
            val_metrics = self._validate(val_loader, class_weights)

            # Log metrics
            epoch_metrics = {
                "epoch": epoch,
                "train_loss": train_metrics["loss"],
                "val_loss": val_metrics["loss"],
                "val_accuracy": val_metrics["accuracy"],
                "val_f1": val_metrics["f1"],
                "val_recall": val_metrics["recall"],
                "val_precision": val_metrics["precision"],
            }
            self.training_history.append(epoch_metrics)

            self.logger.info("epoch_completed", **epoch_metrics)

            # Check for best model
            metric_value = val_metrics[self.training_config.early_stopping_metric.replace("val_", "")]
            if metric_value > self.best_metric:
                self.best_metric = metric_value
                self._save_best_model()

            # Early stopping
            if self.early_stopping:
                if self.early_stopping.step(metric_value):
                    self.logger.info("early_stopping", epoch=epoch, best_metric=self.best_metric)
                    break

            # Periodic checkpoint
            if (epoch + 1) % 5 == 0:
                self._save_checkpoint(epoch)

        # Final checkpoint
        self._save_checkpoint(self.current_epoch, is_final=True)

        return {
            "history": self.training_history,
            "best_metric": self.best_metric,
            "final_epoch": self.current_epoch,
        }

    def _train_epoch(
        self,
        train_loader: DGADataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: Any,
        class_weights: torch.Tensor | None,
    ) -> dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0.0
        num_batches = 0

        progress = tqdm(train_loader, desc=f"Epoch {self.current_epoch}")

        for batch in progress:
            # Move to device
            tokens = batch["tokens"].to(self.device)
            statistical_features = batch["statistical_features"].to(self.device)
            labels = batch["labels"].to(self.device)
            families = batch["families"].to(self.device)

            # Forward pass with AMP
            with autocast(enabled=self.use_amp):
                outputs = self.model(
                    tokens=tokens,
                    statistical_features=statistical_features,
                )

                losses = self.model.compute_loss(
                    outputs=outputs,
                    labels=labels,
                    family_labels=families if self.config.predict_family else None,
                    class_weights=class_weights,
                )
                loss = losses["total_loss"]

            # Backward pass
            optimizer.zero_grad()

            if self.use_amp and self.scaler:
                self.scaler.scale(loss).backward()
                self.scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                self.scaler.step(optimizer)
                self.scaler.update()
            else:
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()

            scheduler.step()

            total_loss += loss.item()
            num_batches += 1
            self.global_step += 1

            progress.set_postfix({"loss": f"{loss.item():.4f}"})

        return {"loss": total_loss / num_batches}

    @torch.no_grad()
    def _validate(
        self,
        val_loader: DGADataLoader,
        class_weights: torch.Tensor | None,
    ) -> dict[str, float]:
        """Run validation."""
        self.model.eval()
        self.metrics.reset()
        total_loss = 0.0
        num_batches = 0

        for batch in val_loader:
            tokens = batch["tokens"].to(self.device)
            statistical_features = batch["statistical_features"].to(self.device)
            labels = batch["labels"].to(self.device)
            families = batch["families"].to(self.device)

            outputs = self.model(
                tokens=tokens,
                statistical_features=statistical_features,
            )

            losses = self.model.compute_loss(
                outputs=outputs,
                labels=labels,
                family_labels=families if self.config.predict_family else None,
                class_weights=class_weights,
            )

            total_loss += losses["total_loss"].item()
            num_batches += 1

            # Collect predictions
            predictions = outputs["logits"].argmax(dim=-1)
            family_predictions = None
            if "family_logits" in outputs:
                family_predictions = outputs["family_logits"].argmax(dim=-1)

            self.metrics.update(
                predictions=predictions,
                labels=labels,
                family_predictions=family_predictions,
                family_labels=families,
            )

        metrics = self.metrics.compute()
        metrics["loss"] = total_loss / num_batches

        return metrics

    def _create_scheduler(
        self,
        optimizer: torch.optim.Optimizer,
        num_training_steps: int,
    ) -> Any:
        """Create learning rate scheduler with warmup."""
        from torch.optim.lr_scheduler import OneCycleLR

        return OneCycleLR(
            optimizer,
            max_lr=self.training_config.learning_rate,
            total_steps=num_training_steps,
            pct_start=self.training_config.warmup_steps / num_training_steps,
            anneal_strategy="cos",
        )

    def _save_best_model(self) -> None:
        """Save the best model."""
        path = Path(self.training_config.output_dir) / "best_model.pt"
        torch.save({
            "model_state_dict": self.model.state_dict(),
            "config": self.config.model_dump(),
            "best_metric": self.best_metric,
            "epoch": self.current_epoch,
        }, path)
        self.logger.info("best_model_saved", path=str(path), metric=self.best_metric)

    def _save_checkpoint(self, epoch: int, is_final: bool = False) -> None:
        """Save training checkpoint."""
        name = "final_checkpoint.pt" if is_final else f"checkpoint_epoch_{epoch}.pt"
        path = Path(self.training_config.checkpoint_dir) / name

        torch.save({
            "model_state_dict": self.model.state_dict(),
            "config": self.config.model_dump(),
            "training_config": self.training_config.model_dump(),
            "epoch": epoch,
            "global_step": self.global_step,
            "best_metric": self.best_metric,
            "history": self.training_history,
        }, path)

        self.logger.info("checkpoint_saved", path=str(path))

    def load_checkpoint(self, path: str) -> None:
        """Load training checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)

        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.current_epoch = checkpoint.get("epoch", 0)
        self.global_step = checkpoint.get("global_step", 0)
        self.best_metric = checkpoint.get("best_metric", float("-inf"))
        self.training_history = checkpoint.get("history", [])

        self.logger.info("checkpoint_loaded", path=path, epoch=self.current_epoch)

    def evaluate(
        self,
        test_loader: DGADataLoader,
        threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Evaluate model on test set.

        Args:
            test_loader: Test data loader
            threshold: Classification threshold

        Returns:
            Evaluation metrics
        """
        self.model.eval()
        self.metrics.reset()

        all_probs = []
        all_labels = []
        all_domains = []

        with torch.no_grad():
            for batch in tqdm(test_loader, desc="Evaluating"):
                tokens = batch["tokens"].to(self.device)
                statistical_features = batch["statistical_features"].to(self.device)
                labels = batch["labels"].to(self.device)

                outputs = self.model(
                    tokens=tokens,
                    statistical_features=statistical_features,
                )

                probs = F.softmax(outputs["logits"], dim=-1)
                predictions = (probs[:, 1] > threshold).long()

                self.metrics.update(predictions, labels)

                all_probs.extend(probs[:, 1].cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
                all_domains.extend(batch["domains"])

        metrics = self.metrics.compute()

        # Calculate AUC
        try:
            from sklearn.metrics import roc_auc_score
            metrics["auc"] = roc_auc_score(all_labels, all_probs)
        except:
            metrics["auc"] = 0.0

        # Find optimal threshold
        best_f1 = 0
        best_threshold = 0.5
        for t in np.arange(0.3, 0.9, 0.05):
            preds = (np.array(all_probs) > t).astype(int)
            from sklearn.metrics import f1_score
            f1 = f1_score(all_labels, preds)
            if f1 > best_f1:
                best_f1 = f1
                best_threshold = t

        metrics["optimal_threshold"] = best_threshold
        metrics["optimal_f1"] = best_f1

        self.logger.info("evaluation_complete", **metrics)

        return metrics
