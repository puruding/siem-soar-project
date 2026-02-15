"""Model Loader - Handles loading, caching, and serving of ML models."""

from __future__ import annotations

import os
import time
import threading
from enum import Enum
from pathlib import Path
from typing import Any

import torch


class ModelType(str, Enum):
    """Types of models available."""
    DGA = "dga"
    UEBA = "ueba"
    CLUSTERING = "clustering"


class ModelLoader:
    """Manages loading and serving of ML models.

    Features:
    - Lazy loading on first request
    - Thread-safe model access
    - Model versioning support
    - Memory management
    - Load time tracking
    """

    def __init__(
        self,
        model_dir: str | None = None,
        device: str | None = None,
    ):
        """Initialize model loader.

        Args:
            model_dir: Directory containing model files
            device: Device to load models on (auto-detect if None)
        """
        self.model_dir = Path(model_dir or os.environ.get("MODEL_DIR", "models"))
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Model storage
        self._models: dict[ModelType, Any] = {}
        self._model_configs: dict[ModelType, dict] = {}
        self._load_times: dict[ModelType, float] = {}
        self._inference_counts: dict[ModelType, int] = {}
        self._inference_latencies: dict[ModelType, list[float]] = {}

        # Thread safety
        self._locks: dict[ModelType, threading.Lock] = {
            mt: threading.Lock() for mt in ModelType
        }

    def load_model(
        self,
        model_type: ModelType,
        force_reload: bool = False,
    ) -> float:
        """Load a model.

        Args:
            model_type: Type of model to load
            force_reload: Force reload even if already loaded

        Returns:
            Load time in seconds
        """
        with self._locks[model_type]:
            if not force_reload and model_type in self._models:
                return 0.0

            start_time = time.time()

            if model_type == ModelType.DGA:
                self._load_dga_model()
            elif model_type == ModelType.UEBA:
                self._load_ueba_model()
            elif model_type == ModelType.CLUSTERING:
                self._load_clustering_model()

            load_time = time.time() - start_time
            self._load_times[model_type] = load_time
            self._inference_counts[model_type] = 0
            self._inference_latencies[model_type] = []

            return load_time

    def _load_dga_model(self) -> None:
        """Load DGA detection model."""
        from models.dga.config import DGAConfig
        from models.dga.model import DGADetector

        # Load from checkpoint if exists
        model_path = self.model_dir / "dga" / "best_model.pt"

        if model_path.exists():
            checkpoint = torch.load(model_path, map_location=self.device)
            config = DGAConfig(**checkpoint.get("config", {}))
            model = DGADetector(config)
            model.load_checkpoint(str(model_path))
        else:
            # Initialize with default config
            config = DGAConfig()
            model = DGADetector(config)

        model.model.to(self.device)
        model.model.eval()

        self._models[ModelType.DGA] = model
        self._model_configs[ModelType.DGA] = config.model_dump() if hasattr(config, 'model_dump') else vars(config)

    def _load_ueba_model(self) -> None:
        """Load UEBA anomaly detection model."""
        from models.ueba.model import UEBAModel, UEBAConfig, UEBAModelWrapper
        from models.ueba.anomaly import AnomalyDetector
        from models.ueba.profile import ProfileManager

        model_path = self.model_dir / "ueba" / "best_ueba_model.pt"

        if model_path.exists():
            checkpoint = torch.load(model_path, map_location=self.device)
            config = UEBAConfig(**checkpoint.get("config", {}))
            wrapper = UEBAModelWrapper(config, device=self.device)
            wrapper.model.load_state_dict(checkpoint["model_state_dict"])

            if "threshold" in checkpoint:
                wrapper.model.reconstruction_threshold.fill_(checkpoint["threshold"])
        else:
            config = UEBAConfig()
            wrapper = UEBAModelWrapper(config, device=self.device)

        wrapper.model.eval()

        # Create anomaly detector with model
        profile_manager = ProfileManager()
        detector = AnomalyDetector(
            model_wrapper=wrapper,
            profile_manager=profile_manager,
            config=config,
        )

        self._models[ModelType.UEBA] = detector
        self._model_configs[ModelType.UEBA] = config.model_dump()

    def _load_clustering_model(self) -> None:
        """Load alert clustering model."""
        from models.clustering.model import AlertClusteringModel, ClusteringConfig
        from models.clustering.embedder import AlertEmbedder, EmbeddingConfig

        config = ClusteringConfig()

        # Initialize embedder
        embedding_config = EmbeddingConfig()
        embedder = AlertEmbedder(embedding_config)

        # Initialize clustering model
        model = AlertClusteringModel(config)

        self._models[ModelType.CLUSTERING] = model
        self._model_configs[ModelType.CLUSTERING] = config.model_dump()

    def get_model(self, model_type: ModelType) -> Any:
        """Get a loaded model.

        Args:
            model_type: Type of model

        Returns:
            Loaded model instance
        """
        if model_type not in self._models:
            self.load_model(model_type)

        return self._models[model_type]

    def is_loaded(self, model_type: ModelType) -> bool:
        """Check if a model is loaded."""
        return model_type in self._models

    def unload_model(self, model_type: ModelType) -> None:
        """Unload a model to free resources."""
        with self._locks[model_type]:
            if model_type in self._models:
                del self._models[model_type]
                if model_type in self._model_configs:
                    del self._model_configs[model_type]

                # Clear CUDA cache if needed
                if self.device == "cuda":
                    torch.cuda.empty_cache()

    def unload_all(self) -> None:
        """Unload all models."""
        for model_type in ModelType:
            self.unload_model(model_type)

    def record_inference(
        self,
        model_type: ModelType,
        latency_ms: float,
    ) -> None:
        """Record an inference for metrics.

        Args:
            model_type: Type of model
            latency_ms: Inference latency in milliseconds
        """
        if model_type in self._inference_counts:
            self._inference_counts[model_type] += 1
            latencies = self._inference_latencies[model_type]
            latencies.append(latency_ms)
            # Keep only last 1000 latencies
            if len(latencies) > 1000:
                self._inference_latencies[model_type] = latencies[-1000:]

    def get_model_info(self, model_type: ModelType) -> dict[str, Any]:
        """Get information about a model.

        Args:
            model_type: Type of model

        Returns:
            Model information dictionary
        """
        info = {
            "loaded": model_type in self._models,
            "load_time": self._load_times.get(model_type),
            "inference_count": self._inference_counts.get(model_type, 0),
        }

        latencies = self._inference_latencies.get(model_type, [])
        if latencies:
            info["avg_latency_ms"] = sum(latencies) / len(latencies)
            info["p99_latency_ms"] = sorted(latencies)[int(len(latencies) * 0.99)]
        else:
            info["avg_latency_ms"] = 0.0
            info["p99_latency_ms"] = 0.0

        if model_type in self._model_configs:
            info["config"] = self._model_configs[model_type]

        return info

    def get_device(self) -> str:
        """Get the device models are loaded on."""
        return self.device

    def warm_up(
        self,
        model_type: ModelType,
        num_iterations: int = 5,
    ) -> float:
        """Warm up a model with dummy inference.

        Args:
            model_type: Type of model to warm up
            num_iterations: Number of warm-up iterations

        Returns:
            Average warm-up latency in ms
        """
        model = self.get_model(model_type)
        latencies = []

        for _ in range(num_iterations):
            start = time.time()

            if model_type == ModelType.DGA:
                model.predict("example.com")
            elif model_type == ModelType.UEBA:
                import torch
                dummy_data = torch.randn(1, 24, 128).to(self.device)
                model.model_wrapper.predict(dummy_data)
            elif model_type == ModelType.CLUSTERING:
                model.cluster([{"alert_id": "test", "title": "test alert"}])

            latencies.append((time.time() - start) * 1000)

        return sum(latencies) / len(latencies)
