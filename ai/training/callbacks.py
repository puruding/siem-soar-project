"""Training callbacks for model checkpointing and logging."""

import os
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import torch

from common.logging import LoggerMixin


class Callback(ABC):
    """Base callback class."""

    def on_train_begin(self, logs: dict[str, Any] | None = None) -> None:
        """Called at the start of training."""
        pass

    def on_train_end(self, logs: dict[str, Any] | None = None) -> None:
        """Called at the end of training."""
        pass

    def on_epoch_begin(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Called at the start of an epoch."""
        pass

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Called at the end of an epoch."""
        pass

    def on_batch_begin(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Called at the start of a batch."""
        pass

    def on_batch_end(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Called at the end of a batch."""
        pass


class CallbackList(LoggerMixin):
    """Container for managing multiple callbacks."""

    def __init__(self, callbacks: list[Callback] | None = None) -> None:
        """Initialize the callback list.

        Args:
            callbacks: List of callbacks
        """
        self.callbacks = callbacks or []
        self.should_stop = False

    def append(self, callback: Callback) -> None:
        """Add a callback."""
        self.callbacks.append(callback)

    def on_train_begin(self, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_train_begin(logs)

    def on_train_end(self, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_train_end(logs)

    def on_epoch_begin(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_epoch_begin(epoch, logs)

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_epoch_end(epoch, logs)
            # Check for early stopping
            if isinstance(callback, EarlyStopping) and callback.stopped:
                self.should_stop = True

    def on_batch_begin(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_batch_begin(batch, logs)

    def on_batch_end(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Dispatch to all callbacks."""
        for callback in self.callbacks:
            callback.on_batch_end(batch, logs)


class ModelCheckpoint(Callback, LoggerMixin):
    """Save model checkpoints during training."""

    def __init__(
        self,
        checkpoint_dir: str,
        monitor: str = "val_loss",
        mode: str = "min",
        save_best_only: bool = True,
        save_weights_only: bool = False,
        verbose: bool = True,
    ) -> None:
        """Initialize the checkpoint callback.

        Args:
            checkpoint_dir: Directory to save checkpoints
            monitor: Metric to monitor
            mode: "min" or "max" for the monitored metric
            save_best_only: Only save when metric improves
            save_weights_only: Only save model weights (not full state)
            verbose: Print checkpoint messages
        """
        self.checkpoint_dir = Path(checkpoint_dir)
        self.monitor = monitor
        self.mode = mode
        self.save_best_only = save_best_only
        self.save_weights_only = save_weights_only
        self.verbose = verbose

        self.best_value = float("inf") if mode == "min" else float("-inf")
        self.model = None

        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def on_train_begin(self, logs: dict[str, Any] | None = None) -> None:
        """Store model reference."""
        if logs and "model" in logs:
            self.model = logs["model"]

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Save checkpoint if metric improved."""
        if logs is None or self.model is None:
            return

        # Get monitored value
        val_metrics = logs.get("val_metrics", {})
        current_value = val_metrics.get(self.monitor)

        if current_value is None:
            self.logger.warning("monitor_not_found", metric=self.monitor)
            return

        # Check if improved
        improved = (
            (self.mode == "min" and current_value < self.best_value) or
            (self.mode == "max" and current_value > self.best_value)
        )

        if improved or not self.save_best_only:
            if improved:
                self.best_value = current_value

            # Save checkpoint
            checkpoint_path = self.checkpoint_dir / f"checkpoint_epoch_{epoch}.pt"

            if self.save_weights_only:
                torch.save(self.model.state_dict(), checkpoint_path)
            else:
                torch.save({
                    "epoch": epoch,
                    "model_state_dict": self.model.state_dict(),
                    "best_value": self.best_value,
                    "metrics": val_metrics,
                }, checkpoint_path)

            # Save best model
            if improved:
                best_path = self.checkpoint_dir / "best_model.pt"
                if self.save_weights_only:
                    torch.save(self.model.state_dict(), best_path)
                else:
                    torch.save({
                        "epoch": epoch,
                        "model_state_dict": self.model.state_dict(),
                        "best_value": self.best_value,
                        "metrics": val_metrics,
                    }, best_path)

            if self.verbose:
                self.logger.info(
                    "checkpoint_saved",
                    epoch=epoch,
                    path=str(checkpoint_path),
                    metric=self.monitor,
                    value=current_value,
                    improved=improved,
                )


class EarlyStopping(Callback, LoggerMixin):
    """Stop training when metric stops improving."""

    def __init__(
        self,
        monitor: str = "val_loss",
        mode: str = "min",
        patience: int = 3,
        min_delta: float = 0.0001,
        verbose: bool = True,
    ) -> None:
        """Initialize early stopping callback.

        Args:
            monitor: Metric to monitor
            mode: "min" or "max" for the monitored metric
            patience: Number of epochs without improvement before stopping
            min_delta: Minimum change to qualify as an improvement
            verbose: Print early stopping messages
        """
        self.monitor = monitor
        self.mode = mode
        self.patience = patience
        self.min_delta = min_delta
        self.verbose = verbose

        self.best_value = float("inf") if mode == "min" else float("-inf")
        self.counter = 0
        self.stopped = False

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Check for early stopping."""
        if logs is None:
            return

        val_metrics = logs.get("val_metrics", {})
        current_value = val_metrics.get(self.monitor)

        if current_value is None:
            return

        # Check if improved
        if self.mode == "min":
            improved = current_value < (self.best_value - self.min_delta)
        else:
            improved = current_value > (self.best_value + self.min_delta)

        if improved:
            self.best_value = current_value
            self.counter = 0
        else:
            self.counter += 1

            if self.verbose:
                self.logger.info(
                    "early_stopping_counter",
                    epoch=epoch,
                    counter=self.counter,
                    patience=self.patience,
                )

            if self.counter >= self.patience:
                self.stopped = True
                if self.verbose:
                    self.logger.info(
                        "early_stopping_triggered",
                        epoch=epoch,
                        best_value=self.best_value,
                    )


class WandbLogger(Callback, LoggerMixin):
    """Log metrics to Weights & Biases."""

    def __init__(
        self,
        project: str,
        entity: str | None = None,
        name: str | None = None,
        config: dict[str, Any] | None = None,
        log_model: bool = True,
    ) -> None:
        """Initialize W&B logger.

        Args:
            project: W&B project name
            entity: W&B entity (team/username)
            name: Run name
            config: Configuration to log
            log_model: Whether to log model artifacts
        """
        self.project = project
        self.entity = entity
        self.name = name
        self.config = config
        self.log_model = log_model
        self._run = None

    def on_train_begin(self, logs: dict[str, Any] | None = None) -> None:
        """Initialize W&B run."""
        try:
            import wandb

            self._run = wandb.init(
                project=self.project,
                entity=self.entity,
                name=self.name,
                config=self.config,
            )

            if logs and "model" in logs:
                wandb.watch(logs["model"], log="all", log_freq=100)

            self.logger.info(
                "wandb_initialized",
                project=self.project,
                run_id=self._run.id if self._run else None,
            )

        except ImportError:
            self.logger.warning("wandb_not_installed")
        except Exception as e:
            self.logger.error("wandb_init_failed", error=str(e))

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Log epoch metrics to W&B."""
        if self._run is None or logs is None:
            return

        try:
            import wandb

            metrics = {"epoch": epoch}

            # Log training metrics
            train_metrics = logs.get("train_metrics", {})
            for key, value in train_metrics.items():
                if isinstance(value, (int, float)):
                    metrics[f"train/{key}"] = value

            # Log validation metrics
            val_metrics = logs.get("val_metrics", {})
            for key, value in val_metrics.items():
                if isinstance(value, (int, float)):
                    metrics[f"val/{key}"] = value

            wandb.log(metrics)

        except Exception as e:
            self.logger.error("wandb_log_failed", error=str(e))

    def on_batch_end(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Log batch metrics to W&B."""
        if self._run is None or logs is None:
            return

        # Only log every N batches to reduce overhead
        if batch % 100 != 0:
            return

        try:
            import wandb

            metrics = {"step": batch}
            for key, value in logs.items():
                if isinstance(value, (int, float)):
                    metrics[f"train/{key}"] = value

            wandb.log(metrics)

        except Exception as e:
            pass  # Silently ignore batch logging errors

    def on_train_end(self, logs: dict[str, Any] | None = None) -> None:
        """Finish W&B run."""
        if self._run is None:
            return

        try:
            import wandb

            if self.log_model:
                # Log final model as artifact
                # This would require access to model path
                pass

            wandb.finish()
            self.logger.info("wandb_run_finished")

        except Exception as e:
            self.logger.error("wandb_finish_failed", error=str(e))


class MetricsLogger(Callback, LoggerMixin):
    """Log metrics to file and console."""

    def __init__(
        self,
        log_dir: str,
        log_to_console: bool = True,
    ) -> None:
        """Initialize metrics logger.

        Args:
            log_dir: Directory to save metrics
            log_to_console: Whether to log to console
        """
        self.log_dir = Path(log_dir)
        self.log_to_console = log_to_console
        self.history: dict[str, list[float]] = {}

        self.log_dir.mkdir(parents=True, exist_ok=True)

    def on_epoch_end(self, epoch: int, logs: dict[str, Any] | None = None) -> None:
        """Log epoch metrics."""
        if logs is None:
            return

        # Collect metrics
        metrics = {"epoch": epoch}
        for key, value in logs.get("train_metrics", {}).items():
            if isinstance(value, (int, float)):
                metrics[f"train_{key}"] = value
                self.history.setdefault(f"train_{key}", []).append(value)

        for key, value in logs.get("val_metrics", {}).items():
            if isinstance(value, (int, float)):
                metrics[f"val_{key}"] = value
                self.history.setdefault(f"val_{key}", []).append(value)

        # Save to file
        metrics_path = self.log_dir / f"metrics_epoch_{epoch}.json"
        with open(metrics_path, "w") as f:
            json.dump(metrics, f, indent=2)

        # Log to console
        if self.log_to_console:
            self.logger.info("epoch_metrics", **metrics)

    def on_train_end(self, logs: dict[str, Any] | None = None) -> None:
        """Save complete history."""
        history_path = self.log_dir / "training_history.json"
        with open(history_path, "w") as f:
            json.dump(self.history, f, indent=2)
        self.logger.info("training_history_saved", path=str(history_path))


class GradientLogger(Callback, LoggerMixin):
    """Log gradient statistics during training."""

    def __init__(self, log_interval: int = 100) -> None:
        """Initialize gradient logger.

        Args:
            log_interval: Steps between gradient logging
        """
        self.log_interval = log_interval
        self.model = None

    def on_train_begin(self, logs: dict[str, Any] | None = None) -> None:
        """Store model reference."""
        if logs and "model" in logs:
            self.model = logs["model"]

    def on_batch_end(self, batch: int, logs: dict[str, Any] | None = None) -> None:
        """Log gradient statistics."""
        if batch % self.log_interval != 0 or self.model is None:
            return

        grad_norms = []
        for name, param in self.model.named_parameters():
            if param.grad is not None:
                grad_norm = param.grad.data.norm(2).item()
                grad_norms.append(grad_norm)

        if grad_norms:
            import numpy as np
            self.logger.info(
                "gradient_stats",
                step=batch,
                mean=np.mean(grad_norms),
                max=np.max(grad_norms),
                min=np.min(grad_norms),
            )
