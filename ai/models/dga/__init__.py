"""DGA (Domain Generation Algorithm) Detection models.

This module provides CNN+LSTM based models for detecting algorithmically
generated domain names used by malware for C2 communication.

Key components:
- DGADetector: High-level inference interface
- DGADetectorModel: PyTorch model architecture
- DGAInferenceEngine: Optimized batch inference
- DGATrainer: Training pipeline with multi-task learning
"""

from models.dga.config import (
    DGAConfig,
    DGATrainingConfig,
    DGAInferenceConfig,
    DGAFamily,
    DGAModelType,
)
from models.dga.model import (
    DGADetector,
    DGADetectorModel,
    DGAClassification,
    DGABatchResult,
)
from models.dga.features import (
    DGAFeatureExtractor,
    DomainTokenizer,
    DomainStatistics,
)
from models.dga.inference import (
    DGAInferenceEngine,
    LRUCache,
)
from models.dga.dataset import (
    DGADataset,
    DGADataLoader,
    create_dga_dataloaders,
)
from models.dga.trainer import (
    DGATrainer,
)

__all__ = [
    # Config
    "DGAConfig",
    "DGATrainingConfig",
    "DGAInferenceConfig",
    "DGAFamily",
    "DGAModelType",
    # Model
    "DGADetector",
    "DGADetectorModel",
    "DGAClassification",
    "DGABatchResult",
    # Features
    "DGAFeatureExtractor",
    "DomainTokenizer",
    "DomainStatistics",
    # Inference
    "DGAInferenceEngine",
    "LRUCache",
    # Dataset
    "DGADataset",
    "DGADataLoader",
    "create_dga_dataloaders",
    # Training
    "DGATrainer",
]
