"""Model retraining pipeline for continuous learning."""

import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
import torch
from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel
from data.pipeline import AlertDataPipeline, LabelingPipeline
from models.classifier.architecture import AlertClassifierModel
from models.classifier.config import ClassifierConfig, TrainingConfig
from training.trainer import AlertClassifierTrainer
from training.callbacks import ModelCheckpoint, EarlyStopping


class RetrainingConfig(BaseModel):
    """Configuration for model retraining."""

    # Trigger conditions
    min_feedback_samples: int = Field(default=100, description="Min samples before retrain")
    min_days_since_last_train: int = Field(default=7, description="Min days between retrains")
    fp_rate_threshold: float = Field(default=0.3, description="FP rate threshold for urgent retrain")

    # Data selection
    feedback_lookback_days: int = Field(default=30, description="Days of feedback to include")
    include_historical_data: bool = Field(default=True, description="Include historical training data")
    historical_data_weight: float = Field(default=0.3, description="Weight for historical data")

    # Training settings
    learning_rate: float = Field(default=1e-5, description="Fine-tuning learning rate")
    num_epochs: int = Field(default=3, description="Number of fine-tuning epochs")
    batch_size: int = Field(default=16, description="Fine-tuning batch size")

    # Validation
    validation_threshold: float = Field(default=0.8, description="Min F1 for deployment")
    a_b_test_duration_hours: int = Field(default=24, description="A/B test duration")

    # Output
    output_dir: str = Field(default="models/retrained")
    version_prefix: str = Field(default="v")


class RetrainingTrigger(LoggerMixin):
    """Determine when to trigger model retraining."""

    def __init__(self, config: RetrainingConfig) -> None:
        """Initialize the trigger.

        Args:
            config: Retraining configuration
        """
        self.config = config
        self._last_retrain: datetime | None = None

    async def should_retrain(
        self,
        feedback_count: int,
        fp_rate: float | None = None,
    ) -> tuple[bool, str]:
        """Check if retraining should be triggered.

        Args:
            feedback_count: Number of new feedback samples
            fp_rate: Current false positive rate

        Returns:
            Tuple of (should_retrain, reason)
        """
        # Check sample threshold
        if feedback_count < self.config.min_feedback_samples:
            return False, "insufficient_samples"

        # Check time since last retrain
        if self._last_retrain:
            days_since = (datetime.utcnow() - self._last_retrain).days
            if days_since < self.config.min_days_since_last_train:
                # Unless FP rate is high
                if fp_rate is None or fp_rate < self.config.fp_rate_threshold:
                    return False, "too_recent"

        # Check FP rate threshold (urgent retrain)
        if fp_rate is not None and fp_rate > self.config.fp_rate_threshold:
            return True, "high_fp_rate"

        # Regular scheduled retrain
        return True, "scheduled"

    def record_retrain(self) -> None:
        """Record that retraining was performed."""
        self._last_retrain = datetime.utcnow()


class ModelRetrainer(LoggerMixin):
    """Retrain models based on analyst feedback."""

    def __init__(
        self,
        config: RetrainingConfig | None = None,
    ) -> None:
        """Initialize the retrainer.

        Args:
            config: Retraining configuration
        """
        self.config = config or RetrainingConfig()
        self.trigger = RetrainingTrigger(self.config)

        self._data_pipeline: AlertDataPipeline | None = None
        self._labeling_pipeline = LabelingPipeline()

    async def initialize(self) -> None:
        """Initialize data pipelines."""
        from data.pipeline import DataPipelineConfig

        self._data_pipeline = AlertDataPipeline(DataPipelineConfig(
            lookback_days=self.config.feedback_lookback_days,
        ))
        await self._data_pipeline.connect()

    async def retrain(
        self,
        base_model_path: str,
        tokenizer_name: str = "bert-base-uncased",
    ) -> dict[str, Any]:
        """Run retraining pipeline.

        Args:
            base_model_path: Path to base model weights
            tokenizer_name: Name of tokenizer

        Returns:
            Retraining results
        """
        self.logger.info("starting_retrain", base_model=base_model_path)

        # 1. Prepare training data
        train_df, val_df = await self._prepare_training_data()

        if len(train_df) < self.config.min_feedback_samples:
            self.logger.warning(
                "insufficient_training_data",
                count=len(train_df),
                required=self.config.min_feedback_samples,
            )
            return {"status": "skipped", "reason": "insufficient_data"}

        # 2. Load base model
        model_config = ClassifierConfig(
            learning_rate=self.config.learning_rate,
            max_epochs=self.config.num_epochs,
            batch_size=self.config.batch_size,
        )
        model = AlertClassifierModel(model_config)

        # Load base weights
        if os.path.exists(base_model_path):
            checkpoint = torch.load(base_model_path, map_location="cpu")
            if "model_state_dict" in checkpoint:
                model.load_state_dict(checkpoint["model_state_dict"])
            else:
                model.load_state_dict(checkpoint)

        # 3. Create data loaders
        from transformers import AutoTokenizer
        from data.loader import AlertDataLoader

        tokenizer = AutoTokenizer.from_pretrained(tokenizer_name)
        loader_factory = AlertDataLoader(tokenizer)

        train_loader = loader_factory.create_train_loader(
            train_df,
            batch_size=self.config.batch_size,
            balance_classes=True,
        )
        val_loader = loader_factory.create_eval_loader(
            val_df,
            batch_size=self.config.batch_size * 2,
        )

        # 4. Setup trainer
        training_config = TrainingConfig(
            output_dir=self.config.output_dir,
        )

        callbacks = [
            ModelCheckpoint(
                checkpoint_dir=f"{self.config.output_dir}/checkpoints",
                monitor="val_f1_macro",
                mode="max",
            ),
            EarlyStopping(
                monitor="val_f1_macro",
                mode="max",
                patience=2,
            ),
        ]

        trainer = AlertClassifierTrainer(
            model=model,
            config=model_config,
            training_config=training_config,
            callbacks=callbacks,
        )

        # 5. Run training
        history = trainer.train(train_loader, val_loader)

        # 6. Save retrained model
        version = self._generate_version()
        output_path = Path(self.config.output_dir) / version
        output_path.mkdir(parents=True, exist_ok=True)

        trainer.save_checkpoint(str(output_path / "model.pt"))

        # Save config
        import json
        with open(output_path / "config.json", "w") as f:
            json.dump(model_config.model_dump(), f, indent=2)

        self.trigger.record_retrain()

        results = {
            "status": "completed",
            "version": version,
            "output_path": str(output_path),
            "train_samples": len(train_df),
            "val_samples": len(val_df),
            "final_val_loss": history["val_loss"][-1] if history["val_loss"] else None,
            "final_val_metrics": history["val_metrics"][-1] if history["val_metrics"] else {},
        }

        self.logger.info("retrain_completed", **results)
        return results

    async def _prepare_training_data(
        self,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Prepare training data from feedback.

        Returns:
            Tuple of (train_df, val_df)
        """
        # Fetch alerts with feedback
        df = await self._data_pipeline.fetch_training_data()

        # Apply labels
        df = self._labeling_pipeline.label_dataframe(df)

        # Split
        train_size = int(len(df) * 0.9)
        train_df = df.iloc[:train_size].copy()
        val_df = df.iloc[train_size:].copy()

        return train_df, val_df

    def _generate_version(self) -> str:
        """Generate version string."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"{self.config.version_prefix}{timestamp}"


class OnlineLearner(LoggerMixin):
    """Online learning for incremental model updates."""

    def __init__(
        self,
        model: AlertClassifierModel,
        learning_rate: float = 1e-6,
        buffer_size: int = 100,
    ) -> None:
        """Initialize online learner.

        Args:
            model: Model to update
            learning_rate: Learning rate for online updates
            buffer_size: Size of experience buffer
        """
        self.model = model
        self.learning_rate = learning_rate
        self.buffer_size = buffer_size

        self._buffer: list[dict[str, Any]] = []
        self._optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=learning_rate,
        )
        self._update_count = 0

    async def add_experience(
        self,
        alert: dict[str, Any],
        feedback: dict[str, Any],
    ) -> None:
        """Add a learning experience to buffer.

        Args:
            alert: Alert data
            feedback: Analyst feedback
        """
        self._buffer.append({
            "alert": alert,
            "feedback": feedback,
        })

        # Keep buffer at max size
        if len(self._buffer) > self.buffer_size:
            self._buffer.pop(0)

        # Trigger update if buffer is full
        if len(self._buffer) >= self.buffer_size:
            await self._update()

    async def _update(self) -> None:
        """Perform online update."""
        if not self._buffer:
            return

        self.model.train()

        # Prepare batch (simplified)
        # In practice, would use proper tokenization and feature extraction
        self._optimizer.zero_grad()

        # ... perform forward pass and loss computation ...

        self._optimizer.step()
        self._update_count += 1

        self.logger.info(
            "online_update",
            update_count=self._update_count,
            buffer_size=len(self._buffer),
        )

        # Clear buffer
        self._buffer.clear()
