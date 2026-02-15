"""UEBA (User and Entity Behavior Analytics) module.

Provides anomaly detection capabilities for user and entity behaviors:
- Autoencoder-based anomaly detection
- Time-series analysis with Transformers
- Behavior profiling and baseline generation
- Real-time scoring and alerting
"""

from .model import UEBAModel, UEBAConfig
from .profile import (
    BehaviorProfile,
    ProfileManager,
    ProfileType,
    ProfileFeatures,
)
from .anomaly import (
    AnomalyDetector,
    AnomalyScore,
    AnomalyType,
    DetectionResult,
)
from .feature_extractor import (
    UEBAFeatureExtractor,
    TemporalFeatures,
    AccessFeatures,
    NetworkFeatures,
)

__all__ = [
    # Core model
    "UEBAModel",
    "UEBAConfig",
    # Profiling
    "BehaviorProfile",
    "ProfileManager",
    "ProfileType",
    "ProfileFeatures",
    # Anomaly detection
    "AnomalyDetector",
    "AnomalyScore",
    "AnomalyType",
    "DetectionResult",
    # Features
    "UEBAFeatureExtractor",
    "TemporalFeatures",
    "AccessFeatures",
    "NetworkFeatures",
]
