"""Configuration for DGA detection models."""

from enum import Enum
from typing import Literal

from pydantic import Field

from common.models import BaseModel


class DGAFamily(str, Enum):
    """Known DGA families."""

    UNKNOWN = "unknown"
    CONFICKER = "conficker"
    CRYPTOLOCKER = "cryptolocker"
    DYRE = "dyre"
    EMOTET = "emotet"
    GAMEOVER = "gameover"
    LOCKY = "locky"
    MATSNU = "matsnu"
    MUROFET = "murofet"
    NECURS = "necurs"
    NEWGOZ = "newgoz"
    NYMAIM = "nymaim"
    PADCRYPT = "padcrypt"
    PROSLIKEFAN = "proslikefan"
    PUSHDO = "pushdo"
    PYKSPA = "pykspa"
    QADARS = "qadars"
    RAMDO = "ramdo"
    RAMNIT = "ramnit"
    RANBYUS = "ranbyus"
    ROVNIX = "rovnix"
    SHIFU = "shifu"
    SIMDA = "simda"
    SUPPOBOX = "suppobox"
    SYMMI = "symmi"
    TEMPEDREVE = "tempedreve"
    TINBA = "tinba"
    VAWTRAK = "vawtrak"


class DGAModelType(str, Enum):
    """DGA model architecture types."""

    LSTM = "lstm"
    CNN = "cnn"
    HYBRID = "hybrid"  # LSTM + CNN
    TRANSFORMER = "transformer"


class DGAConfig(BaseModel):
    """Configuration for DGA detection model."""

    # Model architecture
    model_type: DGAModelType = Field(default=DGAModelType.HYBRID)

    # Embedding settings
    vocab_size: int = Field(default=128, description="ASCII character vocabulary")
    embedding_dim: int = Field(default=64, description="Character embedding dimension")
    max_domain_length: int = Field(default=63, description="Maximum domain length")

    # LSTM settings
    lstm_hidden_size: int = Field(default=128, description="LSTM hidden size")
    lstm_num_layers: int = Field(default=2, description="Number of LSTM layers")
    lstm_bidirectional: bool = Field(default=True, description="Use bidirectional LSTM")
    lstm_dropout: float = Field(default=0.3, description="LSTM dropout")

    # CNN settings
    cnn_filters: list[int] = Field(
        default=[64, 128, 256],
        description="CNN filter sizes for different kernel widths",
    )
    cnn_kernel_sizes: list[int] = Field(
        default=[3, 4, 5],
        description="CNN kernel sizes",
    )
    cnn_dropout: float = Field(default=0.5, description="CNN dropout")

    # Classification head
    hidden_size: int = Field(default=256, description="FC hidden layer size")
    num_classes: int = Field(default=2, description="Binary: DGA or benign")
    num_families: int = Field(
        default=len(DGAFamily),
        description="Number of DGA families for multi-class",
    )
    dropout: float = Field(default=0.5, description="Classifier dropout")

    # Attention (for hybrid model)
    use_attention: bool = Field(default=True, description="Use attention mechanism")
    attention_heads: int = Field(default=4, description="Number of attention heads")

    # Feature augmentation
    use_statistical_features: bool = Field(
        default=True,
        description="Include statistical domain features",
    )
    statistical_feature_dim: int = Field(
        default=16,
        description="Statistical feature dimension",
    )

    # Multi-task learning
    predict_family: bool = Field(
        default=True,
        description="Also predict DGA family (multi-task)",
    )
    family_weight: float = Field(default=0.3, description="Loss weight for family prediction")


class DGATrainingConfig(BaseModel):
    """Configuration for DGA model training."""

    # Paths
    train_data_path: str = Field(default="data/dga/train.parquet")
    val_data_path: str = Field(default="data/dga/val.parquet")
    test_data_path: str = Field(default="data/dga/test.parquet")
    output_dir: str = Field(default="output/dga")
    checkpoint_dir: str = Field(default="checkpoints/dga")

    # Training hyperparameters
    seed: int = Field(default=42)
    batch_size: int = Field(default=256, description="Training batch size")
    learning_rate: float = Field(default=1e-3, description="Initial learning rate")
    weight_decay: float = Field(default=1e-4, description="L2 regularization")
    max_epochs: int = Field(default=50, description="Maximum training epochs")
    warmup_steps: int = Field(default=1000, description="LR warmup steps")

    # Data augmentation
    augment_data: bool = Field(default=True, description="Enable data augmentation")
    augment_ratio: float = Field(default=0.2, description="Augmentation ratio")

    # Class balancing
    balance_classes: bool = Field(default=True, description="Balance class weights")
    oversample_minority: bool = Field(default=False, description="Oversample DGA samples")

    # Data loader
    num_workers: int = Field(default=4)
    pin_memory: bool = Field(default=True)

    # Evaluation
    eval_interval: int = Field(default=500, description="Steps between eval")
    save_interval: int = Field(default=1000, description="Steps between saves")

    # Early stopping
    early_stopping: bool = Field(default=True)
    early_stopping_patience: int = Field(default=5)
    early_stopping_metric: str = Field(default="val_f1")
    early_stopping_mode: Literal["min", "max"] = Field(default="max")

    # Logging
    wandb_project: str = Field(default="siem-dga-detector")
    wandb_entity: str | None = Field(default=None)


class DGAInferenceConfig(BaseModel):
    """Configuration for DGA inference."""

    # Model
    model_path: str = Field(description="Path to model weights")
    device: str = Field(default="cuda:0", description="Inference device")

    # Performance
    max_batch_size: int = Field(default=512, description="Maximum batch size")
    batch_timeout_ms: int = Field(default=10, description="Max batch wait time")
    target_latency_ms: float = Field(default=10.0, description="Target latency per domain")

    # Thresholds
    dga_threshold: float = Field(
        default=0.5,
        description="Probability threshold for DGA classification",
    )
    high_confidence_threshold: float = Field(
        default=0.9,
        description="High confidence threshold",
    )

    # Caching
    enable_cache: bool = Field(default=True, description="Cache results")
    cache_ttl_seconds: int = Field(default=3600, description="Cache TTL (1 hour)")
    cache_max_size: int = Field(default=100000, description="Max cached domains")

    # Optimization
    use_onnx: bool = Field(default=False, description="Use ONNX Runtime")
    quantize: bool = Field(default=False, description="Use INT8 quantization")
    compile_model: bool = Field(default=True, description="Use torch.compile")

    # Allowlist/Blocklist
    use_allowlist: bool = Field(default=True, description="Skip allowlisted domains")
    allowlist_path: str | None = Field(default=None, description="Path to allowlist")
    use_blocklist: bool = Field(default=True, description="Auto-flag blocklisted")
    blocklist_path: str | None = Field(default=None, description="Path to blocklist")
