"""Model loading and management."""

import os
import json
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn

from common.logging import LoggerMixin
from models.classifier.architecture import AlertClassifierModel
from models.classifier.config import ClassifierConfig


class ModelLoader(LoggerMixin):
    """Load and manage model artifacts."""

    def __init__(
        self,
        model_dir: str,
        device: str = "cuda" if torch.cuda.is_available() else "cpu",
    ) -> None:
        """Initialize the model loader.

        Args:
            model_dir: Directory containing model artifacts
            device: Device to load models on
        """
        self.model_dir = Path(model_dir)
        self.device = torch.device(device)

        self._models: dict[str, nn.Module] = {}
        self._configs: dict[str, Any] = {}

    async def load_classifier(
        self,
        version: str = "latest",
        quantize: bool = False,
    ) -> AlertClassifierModel:
        """Load the alert classifier model.

        Args:
            version: Model version to load
            quantize: Whether to apply INT8 quantization

        Returns:
            Loaded classifier model
        """
        cache_key = f"classifier_{version}_{quantize}"

        if cache_key in self._models:
            return self._models[cache_key]

        # Resolve version path
        if version == "latest":
            version_path = self._get_latest_version()
        else:
            version_path = self.model_dir / version

        if not version_path.exists():
            raise FileNotFoundError(f"Model version not found: {version_path}")

        # Load config
        config_path = version_path / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config_dict = json.load(f)
            config = ClassifierConfig(**config_dict)
        else:
            config = ClassifierConfig()

        self._configs[cache_key] = config

        # Create model
        model = AlertClassifierModel(config)

        # Load weights
        weights_path = version_path / "model.pt"
        if weights_path.exists():
            checkpoint = torch.load(weights_path, map_location=self.device)
            if "model_state_dict" in checkpoint:
                model.load_state_dict(checkpoint["model_state_dict"])
            else:
                model.load_state_dict(checkpoint)

            self.logger.info(
                "model_loaded",
                version=version,
                path=str(weights_path),
            )
        else:
            self.logger.warning(
                "weights_not_found",
                path=str(weights_path),
            )

        model = model.to(self.device)
        model.eval()

        # Optional quantization
        if quantize:
            model = self._quantize_model(model)

        # Cache model
        self._models[cache_key] = model

        return model

    def _get_latest_version(self) -> Path:
        """Get the latest model version path.

        Returns:
            Path to latest version directory
        """
        # Check for explicit latest pointer
        latest_file = self.model_dir / "latest"
        if latest_file.exists():
            version = latest_file.read_text().strip()
            return self.model_dir / version

        # Find highest version number
        versions = []
        for d in self.model_dir.iterdir():
            if d.is_dir() and d.name.startswith("v"):
                try:
                    version_num = int(d.name[1:])
                    versions.append((version_num, d))
                except ValueError:
                    pass

        if not versions:
            return self.model_dir

        versions.sort(reverse=True)
        return versions[0][1]

    def _quantize_model(self, model: nn.Module) -> nn.Module:
        """Apply INT8 quantization to model.

        Args:
            model: Model to quantize

        Returns:
            Quantized model
        """
        try:
            quantized_model = torch.quantization.quantize_dynamic(
                model,
                {nn.Linear},
                dtype=torch.qint8,
            )
            self.logger.info("model_quantized")
            return quantized_model
        except Exception as e:
            self.logger.warning("quantization_failed", error=str(e))
            return model

    def get_config(self, cache_key: str) -> Any:
        """Get cached model config.

        Args:
            cache_key: Cache key for the model

        Returns:
            Model configuration
        """
        return self._configs.get(cache_key)

    def unload(self, cache_key: str) -> bool:
        """Unload a cached model.

        Args:
            cache_key: Cache key for the model

        Returns:
            True if model was unloaded
        """
        if cache_key in self._models:
            del self._models[cache_key]
            if cache_key in self._configs:
                del self._configs[cache_key]
            torch.cuda.empty_cache()
            self.logger.info("model_unloaded", cache_key=cache_key)
            return True
        return False

    def unload_all(self) -> None:
        """Unload all cached models."""
        self._models.clear()
        self._configs.clear()
        torch.cuda.empty_cache()
        self.logger.info("all_models_unloaded")


class ModelRegistry(LoggerMixin):
    """Registry for tracking model versions and metadata."""

    def __init__(self, registry_path: str) -> None:
        """Initialize the registry.

        Args:
            registry_path: Path to registry file
        """
        self.registry_path = Path(registry_path)
        self._registry: dict[str, Any] = {}
        self._load_registry()

    def _load_registry(self) -> None:
        """Load registry from file."""
        if self.registry_path.exists():
            with open(self.registry_path) as f:
                self._registry = json.load(f)
        else:
            self._registry = {
                "versions": {},
                "latest": None,
                "production": None,
            }

    def _save_registry(self) -> None:
        """Save registry to file."""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.registry_path, "w") as f:
            json.dump(self._registry, f, indent=2)

    def register_version(
        self,
        version: str,
        metadata: dict[str, Any],
    ) -> None:
        """Register a new model version.

        Args:
            version: Version string
            metadata: Version metadata
        """
        self._registry["versions"][version] = {
            **metadata,
            "registered_at": str(Path.ctime(Path.cwd())),
        }
        self._save_registry()
        self.logger.info("version_registered", version=version)

    def set_latest(self, version: str) -> None:
        """Set the latest version.

        Args:
            version: Version to set as latest
        """
        if version not in self._registry["versions"]:
            raise ValueError(f"Version not found: {version}")

        self._registry["latest"] = version
        self._save_registry()
        self.logger.info("latest_updated", version=version)

    def set_production(self, version: str) -> None:
        """Set the production version.

        Args:
            version: Version to set as production
        """
        if version not in self._registry["versions"]:
            raise ValueError(f"Version not found: {version}")

        self._registry["production"] = version
        self._save_registry()
        self.logger.info("production_updated", version=version)

    def get_latest(self) -> str | None:
        """Get the latest version."""
        return self._registry.get("latest")

    def get_production(self) -> str | None:
        """Get the production version."""
        return self._registry.get("production")

    def get_version_metadata(self, version: str) -> dict[str, Any] | None:
        """Get metadata for a version.

        Args:
            version: Version string

        Returns:
            Version metadata or None
        """
        return self._registry["versions"].get(version)

    def list_versions(self) -> list[str]:
        """List all registered versions.

        Returns:
            List of version strings
        """
        return list(self._registry["versions"].keys())


class EnsembleLoader(LoggerMixin):
    """Load and manage model ensembles."""

    def __init__(
        self,
        model_loader: ModelLoader,
    ) -> None:
        """Initialize ensemble loader.

        Args:
            model_loader: Base model loader
        """
        self.model_loader = model_loader
        self._ensembles: dict[str, list[nn.Module]] = {}

    async def load_ensemble(
        self,
        versions: list[str],
        ensemble_name: str,
    ) -> list[AlertClassifierModel]:
        """Load an ensemble of models.

        Args:
            versions: List of version strings
            ensemble_name: Name for the ensemble

        Returns:
            List of loaded models
        """
        models = []
        for version in versions:
            model = await self.model_loader.load_classifier(version)
            models.append(model)

        self._ensembles[ensemble_name] = models
        self.logger.info(
            "ensemble_loaded",
            name=ensemble_name,
            num_models=len(models),
        )
        return models

    def get_ensemble(self, name: str) -> list[nn.Module] | None:
        """Get a loaded ensemble.

        Args:
            name: Ensemble name

        Returns:
            List of models or None
        """
        return self._ensembles.get(name)
