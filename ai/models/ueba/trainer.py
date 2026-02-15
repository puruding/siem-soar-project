"""UEBA Trainer - Training pipeline for UEBA anomaly detection models."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.cuda.amp import GradScaler, autocast
from torch.utils.data import DataLoader, TensorDataset
from tqdm import tqdm

from common.logging import LoggerMixin
from models.ueba.model import UEBAModel, UEBAConfig


class UEBATrainingConfig:
    """Training configuration for UEBA model."""

    def __init__(
        self,
        # Basic settings
        max_epochs: int = 100,
        batch_size: int = 64,
        learning_rate: float = 1e-4,
        weight_decay: float = 1e-5,
        # Scheduler
        scheduler_type: str = "cosine",
        warmup_epochs: int = 5,
        # Early stopping
        early_stopping: bool = True,
        early_stopping_patience: int = 10,
        early_stopping_metric: str = "val_loss",
        # Regularization
        reconstruction_weight: float = 1.0,
        latent_reg_weight: float = 0.01,
        consistency_weight: float = 0.1,
        # Data
        validation_split: float = 0.15,
        # Output
        output_dir: str = "outputs/ueba",
        checkpoint_dir: str = "outputs/ueba/checkpoints",
        # Hardware
        num_workers: int = 4,
        use_amp: bool = True,
    ):
        self.max_epochs = max_epochs
        self.batch_size = batch_size
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.scheduler_type = scheduler_type
        self.warmup_epochs = warmup_epochs
        self.early_stopping = early_stopping
        self.early_stopping_patience = early_stopping_patience
        self.early_stopping_metric = early_stopping_metric
        self.reconstruction_weight = reconstruction_weight
        self.latent_reg_weight = latent_reg_weight
        self.consistency_weight = consistency_weight
        self.validation_split = validation_split
        self.output_dir = output_dir
        self.checkpoint_dir = checkpoint_dir
        self.num_workers = num_workers
        self.use_amp = use_amp and torch.cuda.is_available()


class EarlyStopping:
    """Early stopping handler for training."""

    def __init__(self, patience: int = 10, mode: str = "min", min_delta: float = 1e-4):
        self.patience = patience
        self.mode = mode
        self.min_delta = min_delta
        self.counter = 0
        self.best_score = None
        self.should_stop = False

    def step(self, score: float) -> bool:
        """Check if training should stop."""
        if self.best_score is None:
            self.best_score = score
            return False

        if self.mode == "min":
            improved = score < self.best_score - self.min_delta
        else:
            improved = score > self.best_score + self.min_delta

        if improved:
            self.best_score = score
            self.counter = 0
        else:
            self.counter += 1
            if self.counter >= self.patience:
                self.should_stop = True

        return self.should_stop


class UEBATrainer(LoggerMixin):
    """Trainer for UEBA anomaly detection models.

    Features:
    - Reconstruction-based training for autoencoders
    - Temporal consistency loss
    - Mixed precision training
    - Adaptive threshold calibration
    - Early stopping
    - Checkpoint management
    """

    def __init__(
        self,
        model: UEBAModel,
        config: UEBAConfig,
        training_config: UEBATrainingConfig | None = None,
    ):
        """Initialize trainer.

        Args:
            model: UEBA model to train
            config: Model configuration
            training_config: Training configuration
        """
        self.model = model
        self.config = config
        self.training_config = training_config or UEBATrainingConfig()

        # Device setup
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = self.model.to(self.device)

        # Mixed precision
        self.use_amp = self.training_config.use_amp
        self.scaler = GradScaler() if self.use_amp else None

        # Early stopping
        if self.training_config.early_stopping:
            self.early_stopping = EarlyStopping(
                patience=self.training_config.early_stopping_patience,
                mode="min" if "loss" in self.training_config.early_stopping_metric else "max",
            )
        else:
            self.early_stopping = None

        # State
        self.current_epoch = 0
        self.global_step = 0
        self.best_loss = float("inf")
        self.training_history: list[dict] = []

        # Create output directories
        Path(self.training_config.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.training_config.checkpoint_dir).mkdir(parents=True, exist_ok=True)

        self.logger.info(
            "ueba_trainer_initialized",
            device=str(self.device),
            use_amp=self.use_amp,
        )

    def train(
        self,
        train_data: torch.Tensor,
        val_data: torch.Tensor | None = None,
    ) -> dict[str, Any]:
        """Run full training loop.

        Args:
            train_data: Training sequences (n_samples, seq_len, input_dim)
            val_data: Validation sequences (optional, split from train if None)

        Returns:
            Training history and metrics
        """
        # Split validation if not provided
        if val_data is None:
            n_val = int(len(train_data) * self.training_config.validation_split)
            indices = torch.randperm(len(train_data))
            val_indices = indices[:n_val]
            train_indices = indices[n_val:]
            val_data = train_data[val_indices]
            train_data = train_data[train_indices]

        # Create data loaders
        train_dataset = TensorDataset(train_data)
        val_dataset = TensorDataset(val_data)

        train_loader = DataLoader(
            train_dataset,
            batch_size=self.training_config.batch_size,
            shuffle=True,
            num_workers=self.training_config.num_workers,
            pin_memory=True,
        )

        val_loader = DataLoader(
            val_dataset,
            batch_size=self.training_config.batch_size,
            shuffle=False,
            num_workers=self.training_config.num_workers,
            pin_memory=True,
        )

        # Create optimizer
        optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.training_config.learning_rate,
            weight_decay=self.training_config.weight_decay,
        )

        # Create scheduler
        scheduler = self._create_scheduler(optimizer, len(train_loader))

        self.logger.info(
            "ueba_training_started",
            epochs=self.training_config.max_epochs,
            train_samples=len(train_data),
            val_samples=len(val_data),
        )

        for epoch in range(self.training_config.max_epochs):
            self.current_epoch = epoch

            # Training epoch
            train_metrics = self._train_epoch(train_loader, optimizer, scheduler)

            # Validation
            val_metrics = self._validate(val_loader)

            # Log metrics
            epoch_metrics = {
                "epoch": epoch,
                "train_loss": train_metrics["loss"],
                "train_recon_loss": train_metrics["recon_loss"],
                "val_loss": val_metrics["loss"],
                "val_recon_loss": val_metrics["recon_loss"],
            }
            self.training_history.append(epoch_metrics)

            self.logger.info("ueba_epoch_completed", **epoch_metrics)

            # Check for best model
            if val_metrics["loss"] < self.best_loss:
                self.best_loss = val_metrics["loss"]
                self._save_best_model()

            # Early stopping
            if self.early_stopping:
                metric_value = val_metrics["loss"]
                if self.early_stopping.step(metric_value):
                    self.logger.info(
                        "ueba_early_stopping",
                        epoch=epoch,
                        best_loss=self.best_loss,
                    )
                    break

            # Periodic checkpoint
            if (epoch + 1) % 10 == 0:
                self._save_checkpoint(epoch)

        # Calibrate anomaly threshold
        self._calibrate_threshold(train_data)

        # Final checkpoint
        self._save_checkpoint(self.current_epoch, is_final=True)

        return {
            "history": self.training_history,
            "best_loss": self.best_loss,
            "final_epoch": self.current_epoch,
        }

    def _train_epoch(
        self,
        train_loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: Any,
    ) -> dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0.0
        total_recon_loss = 0.0
        num_batches = 0

        progress = tqdm(train_loader, desc=f"UEBA Epoch {self.current_epoch}")

        for batch in progress:
            sequences = batch[0].to(self.device)

            with autocast(enabled=self.use_amp):
                # Forward pass
                reconstructed, latent = self.model(sequences)

                # Reconstruction loss
                recon_loss = F.mse_loss(reconstructed, sequences)

                # Latent regularization
                latent_reg = self.training_config.latent_reg_weight * (latent ** 2).mean()

                # Temporal consistency loss
                consistency_loss = self._temporal_consistency_loss(latent)

                # Total loss
                loss = (
                    self.training_config.reconstruction_weight * recon_loss +
                    latent_reg +
                    self.training_config.consistency_weight * consistency_loss
                )

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
            total_recon_loss += recon_loss.item()
            num_batches += 1
            self.global_step += 1

            progress.set_postfix({"loss": f"{loss.item():.4f}"})

        return {
            "loss": total_loss / num_batches,
            "recon_loss": total_recon_loss / num_batches,
        }

    @torch.no_grad()
    def _validate(self, val_loader: DataLoader) -> dict[str, float]:
        """Run validation."""
        self.model.eval()
        total_loss = 0.0
        total_recon_loss = 0.0
        all_errors = []
        num_batches = 0

        for batch in val_loader:
            sequences = batch[0].to(self.device)

            reconstructed, latent = self.model(sequences)

            # Reconstruction loss
            recon_loss = F.mse_loss(reconstructed, sequences)

            # Per-sample errors for statistics
            per_sample_error = F.mse_loss(
                reconstructed, sequences, reduction="none"
            ).mean(dim=(1, 2))
            all_errors.extend(per_sample_error.cpu().numpy())

            # Latent regularization
            latent_reg = self.training_config.latent_reg_weight * (latent ** 2).mean()

            loss = recon_loss + latent_reg

            total_loss += loss.item()
            total_recon_loss += recon_loss.item()
            num_batches += 1

        # Update running statistics
        errors_tensor = torch.tensor(all_errors)
        self.model.update_statistics(errors_tensor)

        return {
            "loss": total_loss / num_batches,
            "recon_loss": total_recon_loss / num_batches,
            "error_mean": float(np.mean(all_errors)),
            "error_std": float(np.std(all_errors)),
        }

    def _temporal_consistency_loss(self, latent: torch.Tensor) -> torch.Tensor:
        """Calculate temporal consistency loss for latent representations.

        Encourages smooth transitions in latent space for sequential data.

        Args:
            latent: Latent representations (batch, latent_dim)

        Returns:
            Consistency loss
        """
        # Simple L2 difference between consecutive samples in batch
        if latent.size(0) < 2:
            return torch.tensor(0.0, device=latent.device)

        diff = latent[1:] - latent[:-1]
        return (diff ** 2).mean()

    def _calibrate_threshold(self, data: torch.Tensor) -> None:
        """Calibrate anomaly detection threshold on training data."""
        self.model.eval()

        # Process in batches
        all_scores = []
        batch_size = self.training_config.batch_size

        with torch.no_grad():
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size].to(self.device)
                scores = self.model.compute_anomaly_score(batch, normalize=False)
                all_scores.extend(scores.cpu().numpy())

        all_scores = np.array(all_scores)

        # Set threshold at configured percentile
        threshold = np.percentile(all_scores, self.config.anomaly_threshold * 100)
        self.model.set_threshold(threshold)

        self.logger.info(
            "ueba_threshold_calibrated",
            percentile=self.config.anomaly_threshold * 100,
            threshold=threshold,
            score_mean=float(np.mean(all_scores)),
            score_std=float(np.std(all_scores)),
        )

    def _create_scheduler(
        self,
        optimizer: torch.optim.Optimizer,
        steps_per_epoch: int,
    ) -> Any:
        """Create learning rate scheduler."""
        from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts, OneCycleLR

        total_steps = steps_per_epoch * self.training_config.max_epochs
        warmup_steps = steps_per_epoch * self.training_config.warmup_epochs

        if self.training_config.scheduler_type == "cosine":
            return OneCycleLR(
                optimizer,
                max_lr=self.training_config.learning_rate,
                total_steps=total_steps,
                pct_start=warmup_steps / total_steps,
                anneal_strategy="cos",
            )
        else:
            return CosineAnnealingWarmRestarts(
                optimizer,
                T_0=steps_per_epoch * 10,
                T_mult=2,
            )

    def _save_best_model(self) -> None:
        """Save the best model."""
        path = Path(self.training_config.output_dir) / "best_ueba_model.pt"
        torch.save({
            "model_state_dict": self.model.state_dict(),
            "config": self.config.model_dump(),
            "best_loss": self.best_loss,
            "epoch": self.current_epoch,
            "threshold": self.model.reconstruction_threshold.item(),
        }, path)
        self.logger.info("ueba_best_model_saved", path=str(path))

    def _save_checkpoint(self, epoch: int, is_final: bool = False) -> None:
        """Save training checkpoint."""
        name = "final_checkpoint.pt" if is_final else f"checkpoint_epoch_{epoch}.pt"
        path = Path(self.training_config.checkpoint_dir) / name

        torch.save({
            "model_state_dict": self.model.state_dict(),
            "config": self.config.model_dump(),
            "epoch": epoch,
            "global_step": self.global_step,
            "best_loss": self.best_loss,
            "history": self.training_history,
        }, path)

    def load_checkpoint(self, path: str) -> None:
        """Load training checkpoint."""
        checkpoint = torch.load(path, map_location=self.device)

        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.current_epoch = checkpoint.get("epoch", 0)
        self.global_step = checkpoint.get("global_step", 0)
        self.best_loss = checkpoint.get("best_loss", float("inf"))
        self.training_history = checkpoint.get("history", [])

        self.logger.info("ueba_checkpoint_loaded", path=path)

    def evaluate(
        self,
        test_data: torch.Tensor,
        test_labels: torch.Tensor | None = None,
    ) -> dict[str, Any]:
        """Evaluate model on test data.

        Args:
            test_data: Test sequences
            test_labels: Optional ground truth labels (0=normal, 1=anomaly)

        Returns:
            Evaluation metrics
        """
        self.model.eval()
        test_data = test_data.to(self.device)

        with torch.no_grad():
            is_anomaly, scores = self.model.detect_anomalies(test_data)

        scores_np = scores.cpu().numpy()
        predictions = is_anomaly.cpu().numpy()

        metrics = {
            "total_samples": len(test_data),
            "anomalies_detected": int(predictions.sum()),
            "anomaly_rate": float(predictions.mean()),
            "score_mean": float(np.mean(scores_np)),
            "score_std": float(np.std(scores_np)),
            "score_min": float(np.min(scores_np)),
            "score_max": float(np.max(scores_np)),
            "threshold": self.model.reconstruction_threshold.item(),
        }

        # If labels provided, calculate classification metrics
        if test_labels is not None:
            labels_np = test_labels.numpy()

            from sklearn.metrics import (
                accuracy_score,
                precision_score,
                recall_score,
                f1_score,
                roc_auc_score,
            )

            metrics["accuracy"] = accuracy_score(labels_np, predictions)
            metrics["precision"] = precision_score(labels_np, predictions, zero_division=0)
            metrics["recall"] = recall_score(labels_np, predictions, zero_division=0)
            metrics["f1"] = f1_score(labels_np, predictions, zero_division=0)

            try:
                metrics["auc"] = roc_auc_score(labels_np, scores_np)
            except:
                metrics["auc"] = 0.0

        self.logger.info("ueba_evaluation_complete", **metrics)

        return metrics
