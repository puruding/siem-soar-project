"""Training loop for alert classification models."""

import os
import time
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
from torch.cuda.amp import GradScaler, autocast
from torch.utils.data import DataLoader
from tqdm import tqdm

from common.logging import LoggerMixin
from models.classifier.architecture import AlertClassifierModel
from models.classifier.config import ClassifierConfig, TrainingConfig
from training.optimizer import create_optimizer, create_scheduler
from training.metrics import ClassificationMetrics
from training.callbacks import Callback, CallbackList


class AlertClassifierTrainer(LoggerMixin):
    """Trainer for alert classification models."""

    def __init__(
        self,
        model: AlertClassifierModel,
        config: ClassifierConfig,
        training_config: TrainingConfig,
        callbacks: list[Callback] | None = None,
    ) -> None:
        """Initialize the trainer.

        Args:
            model: Model to train
            config: Model configuration
            training_config: Training configuration
            callbacks: List of callbacks
        """
        self.model = model
        self.config = config
        self.training_config = training_config
        self.callbacks = CallbackList(callbacks or [])

        # Device setup
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.model = self.model.to(self.device)

        # Mixed precision
        self.use_amp = config.fp16 and torch.cuda.is_available()
        self.scaler = GradScaler() if self.use_amp else None

        # Distributed training
        self.is_distributed = training_config.distributed
        self.world_size = training_config.world_size
        self.local_rank = int(os.environ.get("LOCAL_RANK", 0))

        if self.is_distributed:
            self._setup_distributed()

        # Metrics tracker
        self.metrics = ClassificationMetrics()

        # State
        self.current_epoch = 0
        self.global_step = 0
        self.best_metric = float("-inf")

        self.logger.info(
            "trainer_initialized",
            device=str(self.device),
            use_amp=self.use_amp,
            is_distributed=self.is_distributed,
        )

    def _setup_distributed(self) -> None:
        """Setup distributed training."""
        import torch.distributed as dist
        from torch.nn.parallel import DistributedDataParallel as DDP

        if not dist.is_initialized():
            dist.init_process_group(
                backend=self.training_config.backend,
                world_size=self.world_size,
            )

        self.device = torch.device(f"cuda:{self.local_rank}")
        torch.cuda.set_device(self.device)
        self.model = self.model.to(self.device)
        self.model = DDP(self.model, device_ids=[self.local_rank])

        self.logger.info(
            "distributed_setup",
            world_size=self.world_size,
            local_rank=self.local_rank,
        )

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
    ) -> dict[str, Any]:
        """Run full training loop.

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader

        Returns:
            Dictionary with training history
        """
        # Create optimizer and scheduler
        optimizer = create_optimizer(
            self.model,
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )

        num_training_steps = len(train_loader) * self.config.max_epochs
        scheduler = create_scheduler(
            optimizer,
            num_training_steps=num_training_steps,
            warmup_ratio=self.config.warmup_ratio,
        )

        # Callbacks
        self.callbacks.on_train_begin({"model": self.model, "config": self.config})

        history = {
            "train_loss": [],
            "val_loss": [],
            "val_metrics": [],
        }

        try:
            for epoch in range(self.config.max_epochs):
                self.current_epoch = epoch

                self.callbacks.on_epoch_begin(epoch)

                # Training epoch
                train_metrics = self._train_epoch(
                    train_loader, optimizer, scheduler
                )
                history["train_loss"].append(train_metrics["loss"])

                # Validation
                val_metrics = self._validate(val_loader)
                history["val_loss"].append(val_metrics["loss"])
                history["val_metrics"].append(val_metrics)

                # Logging
                self.logger.info(
                    "epoch_completed",
                    epoch=epoch,
                    train_loss=train_metrics["loss"],
                    val_loss=val_metrics["loss"],
                    val_f1=val_metrics.get("severity_f1_macro", 0),
                )

                # Callbacks
                epoch_logs = {
                    "epoch": epoch,
                    "train_metrics": train_metrics,
                    "val_metrics": val_metrics,
                }
                self.callbacks.on_epoch_end(epoch, epoch_logs)

                # Check for early stopping
                if self.callbacks.should_stop:
                    self.logger.info("early_stopping_triggered", epoch=epoch)
                    break

        except KeyboardInterrupt:
            self.logger.warning("training_interrupted")

        finally:
            self.callbacks.on_train_end(history)

        return history

    def _train_epoch(
        self,
        train_loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler: Any,
    ) -> dict[str, float]:
        """Train for one epoch.

        Args:
            train_loader: Training data loader
            optimizer: Optimizer
            scheduler: Learning rate scheduler

        Returns:
            Training metrics for the epoch
        """
        self.model.train()
        total_loss = 0.0
        num_batches = 0

        progress_bar = tqdm(
            train_loader,
            desc=f"Epoch {self.current_epoch}",
            disable=self.local_rank != 0,
        )

        for batch in progress_bar:
            self.callbacks.on_batch_begin(self.global_step, batch)

            # Move batch to device
            batch = self._move_batch_to_device(batch)

            # Forward pass with mixed precision
            with autocast(enabled=self.use_amp):
                outputs = self.model(
                    input_ids=batch["input_ids"],
                    attention_mask=batch["attention_mask"],
                    numeric_features=batch.get("numeric_features"),
                    categorical_features=batch.get("categorical_features"),
                )

                labels = {
                    "severity": batch.get("severity"),
                    "category": batch.get("category"),
                    "is_fp": batch.get("is_fp"),
                    "risk_score": batch.get("risk_score"),
                    "mitre_tactics": batch.get("mitre_tactics"),
                }
                labels = {k: v for k, v in labels.items() if v is not None}

                losses = self.model.compute_loss(outputs, labels)
                loss = losses["total_loss"]

            # Backward pass
            optimizer.zero_grad()

            if self.use_amp and self.scaler is not None:
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

            # Update metrics
            total_loss += loss.item()
            num_batches += 1
            self.global_step += 1

            progress_bar.set_postfix({"loss": loss.item()})

            # Callbacks
            batch_logs = {"loss": loss.item(), "lr": scheduler.get_last_lr()[0]}
            self.callbacks.on_batch_end(self.global_step, batch_logs)

            # Periodic logging
            if self.global_step % self.training_config.log_interval == 0:
                self.logger.info(
                    "training_step",
                    step=self.global_step,
                    loss=loss.item(),
                    lr=scheduler.get_last_lr()[0],
                )

        return {"loss": total_loss / num_batches}

    @torch.no_grad()
    def _validate(self, val_loader: DataLoader) -> dict[str, float]:
        """Run validation.

        Args:
            val_loader: Validation data loader

        Returns:
            Validation metrics
        """
        self.model.eval()
        total_loss = 0.0
        num_batches = 0

        all_predictions = {
            "severity": [],
            "category": [],
            "is_fp": [],
        }
        all_labels = {
            "severity": [],
            "category": [],
            "is_fp": [],
        }

        for batch in tqdm(val_loader, desc="Validation", disable=self.local_rank != 0):
            batch = self._move_batch_to_device(batch)

            outputs = self.model(
                input_ids=batch["input_ids"],
                attention_mask=batch["attention_mask"],
                numeric_features=batch.get("numeric_features"),
                categorical_features=batch.get("categorical_features"),
            )

            labels = {
                "severity": batch.get("severity"),
                "category": batch.get("category"),
                "is_fp": batch.get("is_fp"),
                "risk_score": batch.get("risk_score"),
                "mitre_tactics": batch.get("mitre_tactics"),
            }
            labels = {k: v for k, v in labels.items() if v is not None}

            losses = self.model.compute_loss(outputs, labels)
            total_loss += losses["total_loss"].item()
            num_batches += 1

            # Collect predictions
            severity_pred = outputs["severity_logits"].argmax(dim=-1)
            category_pred = outputs["category_logits"].argmax(dim=-1)
            fp_pred = outputs["fp_logits"].argmax(dim=-1)

            all_predictions["severity"].extend(severity_pred.cpu().tolist())
            all_predictions["category"].extend(category_pred.cpu().tolist())
            all_predictions["is_fp"].extend(fp_pred.cpu().tolist())

            all_labels["severity"].extend(batch["severity"].cpu().tolist())
            all_labels["category"].extend(batch["category"].cpu().tolist())
            all_labels["is_fp"].extend(batch["is_fp"].cpu().tolist())

        # Calculate metrics
        metrics = {"loss": total_loss / num_batches}

        # Add classification metrics
        for task in ["severity", "category", "is_fp"]:
            task_metrics = self.metrics.compute(
                all_predictions[task],
                all_labels[task],
                prefix=task,
            )
            metrics.update(task_metrics)

        return metrics

    def _move_batch_to_device(self, batch: dict[str, torch.Tensor]) -> dict[str, torch.Tensor]:
        """Move batch tensors to device.

        Args:
            batch: Batch dictionary

        Returns:
            Batch with tensors on device
        """
        return {
            k: v.to(self.device) if isinstance(v, torch.Tensor) else v
            for k, v in batch.items()
        }

    def save_checkpoint(self, path: str) -> None:
        """Save training checkpoint.

        Args:
            path: Checkpoint path
        """
        checkpoint = {
            "epoch": self.current_epoch,
            "global_step": self.global_step,
            "model_state_dict": self.model.state_dict(),
            "best_metric": self.best_metric,
            "config": self.config.model_dump(),
        }
        torch.save(checkpoint, path)
        self.logger.info("saved_checkpoint", path=path)

    def load_checkpoint(self, path: str) -> None:
        """Load training checkpoint.

        Args:
            path: Checkpoint path
        """
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.current_epoch = checkpoint["epoch"]
        self.global_step = checkpoint["global_step"]
        self.best_metric = checkpoint["best_metric"]
        self.logger.info("loaded_checkpoint", path=path, epoch=self.current_epoch)


class DistributedTrainer(AlertClassifierTrainer):
    """Trainer with advanced distributed training support."""

    def __init__(
        self,
        model: AlertClassifierModel,
        config: ClassifierConfig,
        training_config: TrainingConfig,
        callbacks: list[Callback] | None = None,
    ) -> None:
        """Initialize with distributed setup."""
        # Force distributed
        training_config.distributed = True
        super().__init__(model, config, training_config, callbacks)

    def _get_distributed_sampler(self, dataset: Any) -> Any:
        """Get distributed sampler for dataset."""
        from torch.utils.data.distributed import DistributedSampler

        return DistributedSampler(
            dataset,
            num_replicas=self.world_size,
            rank=self.local_rank,
            shuffle=True,
        )
