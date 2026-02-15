"""Configuration for alert classifier models."""

from enum import Enum
from typing import Literal

from pydantic import Field

from common.models import BaseModel


class ModelType(str, Enum):
    """Supported model types."""

    TRANSFORMER = "transformer"
    LSTM = "lstm"
    CNN = "cnn"
    HYBRID = "hybrid"


class ClassifierConfig(BaseModel):
    """Configuration for the alert classifier model."""

    # Model architecture
    model_type: ModelType = Field(default=ModelType.TRANSFORMER)
    hidden_size: int = Field(default=768, description="Hidden layer size")
    num_attention_heads: int = Field(default=12, description="Number of attention heads")
    num_hidden_layers: int = Field(default=6, description="Number of transformer layers")
    intermediate_size: int = Field(default=3072, description="FFN intermediate size")
    hidden_dropout_prob: float = Field(default=0.1, description="Dropout probability")
    attention_probs_dropout_prob: float = Field(default=0.1)
    max_position_embeddings: int = Field(default=512, description="Maximum sequence length")
    vocab_size: int = Field(default=30522, description="Vocabulary size")

    # Classification heads
    num_severity_classes: int = Field(default=5, description="Number of severity levels")
    num_category_classes: int = Field(default=12, description="Number of alert categories")
    num_mitre_tactics: int = Field(default=14, description="Number of MITRE ATT&CK tactics")
    num_mitre_techniques: int = Field(default=200, description="Number of MITRE techniques")

    # Multi-task learning
    severity_weight: float = Field(default=1.0, description="Loss weight for severity")
    category_weight: float = Field(default=1.0, description="Loss weight for category")
    mitre_weight: float = Field(default=0.5, description="Loss weight for MITRE mapping")
    fp_weight: float = Field(default=1.5, description="Loss weight for FP detection")

    # Training settings
    learning_rate: float = Field(default=2e-5, description="Initial learning rate")
    warmup_ratio: float = Field(default=0.1, description="Warmup ratio")
    weight_decay: float = Field(default=0.01, description="Weight decay")
    max_epochs: int = Field(default=10, description="Maximum training epochs")
    batch_size: int = Field(default=32, description="Training batch size")
    gradient_accumulation_steps: int = Field(default=1)
    fp16: bool = Field(default=True, description="Use mixed precision")

    # Inference settings
    inference_batch_size: int = Field(default=64, description="Inference batch size")
    confidence_threshold: float = Field(default=0.5, description="Min confidence threshold")
    use_ensemble: bool = Field(default=False, description="Use model ensemble")

    # Feature settings
    use_numeric_features: bool = Field(default=True, description="Include numeric features")
    use_categorical_features: bool = Field(default=True)
    use_temporal_features: bool = Field(default=True)
    numeric_feature_dim: int = Field(default=32, description="Numeric feature dimension")
    categorical_feature_dim: int = Field(default=64)


class TrainingConfig(BaseModel):
    """Configuration for model training."""

    # Paths
    train_data_path: str = Field(default="data/train.parquet")
    val_data_path: str = Field(default="data/val.parquet")
    test_data_path: str = Field(default="data/test.parquet")
    output_dir: str = Field(default="output/classifier")
    checkpoint_dir: str = Field(default="checkpoints/classifier")

    # Training parameters
    seed: int = Field(default=42, description="Random seed")
    num_workers: int = Field(default=4, description="Data loader workers")
    pin_memory: bool = Field(default=True, description="Pin memory for DataLoader")
    persistent_workers: bool = Field(default=True)

    # Distributed training
    distributed: bool = Field(default=False, description="Enable distributed training")
    world_size: int = Field(default=1, description="Number of GPUs")
    backend: Literal["nccl", "gloo"] = Field(default="nccl")

    # Logging
    log_interval: int = Field(default=100, description="Steps between logging")
    eval_interval: int = Field(default=500, description="Steps between evaluation")
    save_interval: int = Field(default=1000, description="Steps between checkpoints")
    wandb_project: str = Field(default="siem-alert-classifier")
    wandb_entity: str | None = Field(default=None)

    # Early stopping
    early_stopping: bool = Field(default=True)
    early_stopping_patience: int = Field(default=3)
    early_stopping_metric: str = Field(default="val_f1_macro")
    early_stopping_mode: Literal["min", "max"] = Field(default="max")


class InferenceConfig(BaseModel):
    """Configuration for model inference."""

    # Model loading
    model_path: str = Field(description="Path to model weights")
    device: str = Field(default="cuda:0", description="Inference device")
    quantize: bool = Field(default=False, description="Use INT8 quantization")

    # Batching
    max_batch_size: int = Field(default=64, description="Maximum batch size")
    batch_timeout_ms: int = Field(default=50, description="Max wait for batching")
    max_queue_size: int = Field(default=1000, description="Max pending requests")

    # Caching
    enable_cache: bool = Field(default=True, description="Enable result caching")
    cache_ttl_seconds: int = Field(default=300, description="Cache TTL in seconds")
    cache_max_size: int = Field(default=10000, description="Max cached results")

    # Performance
    num_threads: int = Field(default=4, description="Number of CPU threads")
    use_flash_attention: bool = Field(default=True, description="Use Flash Attention 2")
    compile_model: bool = Field(default=True, description="Use torch.compile")
