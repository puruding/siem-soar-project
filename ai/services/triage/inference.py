"""Inference engine for alert triage."""

from typing import Any

import numpy as np
import torch
import torch.nn.functional as F

from common.logging import LoggerMixin
from models.classifier.architecture import AlertClassifierModel
from models.classifier.config import ClassifierConfig, InferenceConfig
from models.classifier.features import FeatureExtractor, TextFeatureBuilder
from models.classifier import AlertClassification, AlertSeverity, AlertCategory
from models.priority import PriorityScorer, HybridPriorityScorer, PriorityFeatureExtractor


class InferenceEngine(LoggerMixin):
    """Engine for running model inference."""

    SEVERITY_LABELS = [
        AlertSeverity.INFO,
        AlertSeverity.LOW,
        AlertSeverity.MEDIUM,
        AlertSeverity.HIGH,
        AlertSeverity.CRITICAL,
    ]

    CATEGORY_LABELS = [
        AlertCategory.MALWARE,
        AlertCategory.INTRUSION,
        AlertCategory.DATA_EXFILTRATION,
        AlertCategory.PRIVILEGE_ESCALATION,
        AlertCategory.LATERAL_MOVEMENT,
        AlertCategory.CREDENTIAL_ACCESS,
        AlertCategory.RECONNAISSANCE,
        AlertCategory.COMMAND_AND_CONTROL,
        AlertCategory.IMPACT,
        AlertCategory.POLICY_VIOLATION,
        AlertCategory.ANOMALY,
        AlertCategory.OTHER,
    ]

    MITRE_TACTICS = [
        "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
        "TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040",
        "TA0042", "TA0043"
    ]

    def __init__(
        self,
        config: InferenceConfig,
        model_config: ClassifierConfig | None = None,
    ) -> None:
        """Initialize the inference engine.

        Args:
            config: Inference configuration
            model_config: Model configuration
        """
        self.config = config
        self.model_config = model_config or ClassifierConfig()
        self.device = torch.device(config.device)

        # Models
        self._classifier: AlertClassifierModel | None = None
        self._priority_scorer: HybridPriorityScorer | None = None
        self._tokenizer: Any = None

        # Feature extractors
        self._feature_extractor = FeatureExtractor()
        self._text_builder = TextFeatureBuilder()
        self._priority_feature_extractor = PriorityFeatureExtractor()

        self._is_loaded = False

    async def load_models(self) -> None:
        """Load all models."""
        self.logger.info("loading_models", model_path=self.config.model_path)

        # Load tokenizer
        from transformers import AutoTokenizer
        try:
            self._tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        except Exception as e:
            self.logger.warning("tokenizer_load_failed", error=str(e))
            self._tokenizer = None

        # Load classifier model
        self._classifier = AlertClassifierModel(self.model_config)

        try:
            checkpoint = torch.load(
                self.config.model_path,
                map_location=self.device,
            )
            if "model_state_dict" in checkpoint:
                self._classifier.load_state_dict(checkpoint["model_state_dict"])
            else:
                self._classifier.load_state_dict(checkpoint)
            self.logger.info("classifier_loaded")
        except FileNotFoundError:
            self.logger.warning(
                "model_not_found",
                path=self.config.model_path,
                message="Using randomly initialized model"
            )
        except Exception as e:
            self.logger.error("model_load_failed", error=str(e))

        self._classifier = self._classifier.to(self.device)
        self._classifier.eval()

        # Optional: Compile model for faster inference
        if self.config.compile_model and hasattr(torch, "compile"):
            try:
                self._classifier = torch.compile(self._classifier)
                self.logger.info("model_compiled")
            except Exception as e:
                self.logger.warning("model_compile_failed", error=str(e))

        # Load priority scorer
        self._priority_scorer = HybridPriorityScorer(ml_weight=0.7)

        self._is_loaded = True
        self.logger.info("models_loaded", device=str(self.device))

    def _prepare_input(
        self,
        alert: dict[str, Any],
    ) -> dict[str, torch.Tensor]:
        """Prepare model input from alert.

        Args:
            alert: Raw alert dictionary

        Returns:
            Dictionary of input tensors
        """
        # Build text
        text = self._text_builder.build_text(alert)

        # Tokenize
        if self._tokenizer is not None:
            encoding = self._tokenizer(
                text,
                max_length=512,
                padding="max_length",
                truncation=True,
                return_tensors="pt",
            )
            input_ids = encoding["input_ids"].to(self.device)
            attention_mask = encoding["attention_mask"].to(self.device)
        else:
            # Fallback: create dummy input
            input_ids = torch.zeros((1, 512), dtype=torch.long, device=self.device)
            attention_mask = torch.ones((1, 512), dtype=torch.long, device=self.device)

        # Extract features
        features = self._feature_extractor.extract(alert)
        feature_tensors = self._feature_extractor.to_tensor(features, str(self.device))

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "numeric_features": feature_tensors["numeric_features"].unsqueeze(0),
            "categorical_features": feature_tensors["categorical_features"].unsqueeze(0),
        }

    @torch.no_grad()
    async def classify(self, alert: dict[str, Any]) -> AlertClassification:
        """Classify a single alert.

        Args:
            alert: Alert dictionary

        Returns:
            Classification result
        """
        if not self._is_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        # Prepare input
        inputs = self._prepare_input(alert)

        # Run inference
        outputs = self._classifier(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
            numeric_features=inputs["numeric_features"],
            categorical_features=inputs["categorical_features"],
        )

        # Process severity
        severity_probs = F.softmax(outputs["severity_logits"], dim=-1)
        severity_idx = severity_probs.argmax(dim=-1).item()
        severity_conf = severity_probs[0, severity_idx].item()

        # Process category
        category_probs = F.softmax(outputs["category_logits"], dim=-1)
        category_idx = category_probs.argmax(dim=-1).item()
        category_conf = category_probs[0, category_idx].item()

        # Process MITRE tactics
        tactics_probs = outputs["mitre_tactics_probs"][0].cpu().numpy()
        mitre_tactics = [
            self.MITRE_TACTICS[i]
            for i, prob in enumerate(tactics_probs)
            if prob > 0.5
        ]

        # Process MITRE techniques
        techniques_probs = outputs["mitre_techniques_probs"][0].cpu().numpy()
        top_techniques_idx = np.argsort(techniques_probs)[-5:][::-1]
        mitre_techniques = [
            f"T{1000 + idx}"  # Simplified technique IDs
            for idx in top_techniques_idx
            if techniques_probs[idx] > 0.3
        ]

        # Get risk score
        risk_score = outputs["risk_score"][0].item()

        # Build explanation
        explanation = self._build_explanation(
            severity=self.SEVERITY_LABELS[severity_idx],
            severity_conf=severity_conf,
            category=self.CATEGORY_LABELS[category_idx],
            category_conf=category_conf,
            mitre_tactics=mitre_tactics,
        )

        return AlertClassification(
            severity=self.SEVERITY_LABELS[severity_idx],
            severity_confidence=severity_conf,
            category=self.CATEGORY_LABELS[category_idx],
            category_confidence=category_conf,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            risk_score=risk_score,
            explanation=explanation,
        )

    @torch.no_grad()
    async def batch_classify(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[AlertClassification]:
        """Classify multiple alerts in batch.

        Args:
            alerts: List of alert dictionaries

        Returns:
            List of classification results
        """
        if not self._is_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        if not alerts:
            return []

        # Process in mini-batches
        results = []
        batch_size = self.config.max_batch_size

        for i in range(0, len(alerts), batch_size):
            batch = alerts[i:i + batch_size]
            batch_results = await self._classify_batch(batch)
            results.extend(batch_results)

        return results

    async def _classify_batch(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[AlertClassification]:
        """Classify a batch of alerts.

        Args:
            alerts: Batch of alerts

        Returns:
            List of classifications
        """
        # Prepare batch inputs
        batch_inputs = [self._prepare_input(alert) for alert in alerts]

        # Stack tensors
        input_ids = torch.cat([b["input_ids"] for b in batch_inputs], dim=0)
        attention_mask = torch.cat([b["attention_mask"] for b in batch_inputs], dim=0)
        numeric_features = torch.cat([b["numeric_features"] for b in batch_inputs], dim=0)
        categorical_features = torch.cat([b["categorical_features"] for b in batch_inputs], dim=0)

        # Run inference
        outputs = self._classifier(
            input_ids=input_ids,
            attention_mask=attention_mask,
            numeric_features=numeric_features,
            categorical_features=categorical_features,
        )

        # Process outputs
        results = []
        for i in range(len(alerts)):
            severity_probs = F.softmax(outputs["severity_logits"][i], dim=-1)
            severity_idx = severity_probs.argmax().item()

            category_probs = F.softmax(outputs["category_logits"][i], dim=-1)
            category_idx = category_probs.argmax().item()

            tactics_probs = outputs["mitre_tactics_probs"][i].cpu().numpy()
            mitre_tactics = [
                self.MITRE_TACTICS[j]
                for j, prob in enumerate(tactics_probs)
                if prob > 0.5
            ]

            result = AlertClassification(
                severity=self.SEVERITY_LABELS[severity_idx],
                severity_confidence=severity_probs[severity_idx].item(),
                category=self.CATEGORY_LABELS[category_idx],
                category_confidence=category_probs[category_idx].item(),
                mitre_tactics=mitre_tactics,
                mitre_techniques=[],
                risk_score=outputs["risk_score"][i].item(),
                explanation=f"Classified as {self.SEVERITY_LABELS[severity_idx].value} {self.CATEGORY_LABELS[category_idx].value}",
            )
            results.append(result)

        return results

    async def compute_priority(
        self,
        alert: dict[str, Any],
        classification: AlertClassification | None = None,
    ) -> dict[str, Any]:
        """Compute priority score for an alert.

        Args:
            alert: Alert dictionary
            classification: Optional pre-computed classification

        Returns:
            Priority scoring result
        """
        # Merge classification into alert for scoring
        if classification:
            alert = {
                **alert,
                "severity": classification.severity.value,
                "category": classification.category.value,
                "confidence": classification.severity_confidence,
            }

        return self._priority_scorer.score(alert)

    def _build_explanation(
        self,
        severity: AlertSeverity,
        severity_conf: float,
        category: AlertCategory,
        category_conf: float,
        mitre_tactics: list[str],
    ) -> str:
        """Build human-readable explanation.

        Args:
            severity: Classified severity
            severity_conf: Severity confidence
            category: Classified category
            category_conf: Category confidence
            mitre_tactics: Mapped MITRE tactics

        Returns:
            Explanation string
        """
        parts = [
            f"Alert classified as {severity.value} severity ({severity_conf:.0%} confidence)",
            f"in category {category.value} ({category_conf:.0%} confidence).",
        ]

        if mitre_tactics:
            parts.append(f"Mapped to MITRE ATT&CK tactics: {', '.join(mitre_tactics)}.")

        return " ".join(parts)


class ModelVersionManager(LoggerMixin):
    """Manage model versions for inference."""

    def __init__(self, model_registry_path: str) -> None:
        """Initialize version manager.

        Args:
            model_registry_path: Path to model registry
        """
        self.registry_path = model_registry_path
        self._versions: dict[str, str] = {}
        self._current_version: str | None = None

    async def get_latest_version(self) -> str | None:
        """Get the latest model version.

        Returns:
            Latest version string or None
        """
        import os
        import json

        registry_file = os.path.join(self.registry_path, "registry.json")
        if not os.path.exists(registry_file):
            return None

        with open(registry_file) as f:
            registry = json.load(f)

        return registry.get("latest_version")

    async def load_version(
        self,
        version: str,
        engine: InferenceEngine,
    ) -> bool:
        """Load a specific model version.

        Args:
            version: Version to load
            engine: Inference engine to load into

        Returns:
            True if loaded successfully
        """
        import os

        model_path = os.path.join(self.registry_path, version, "model.pt")
        if not os.path.exists(model_path):
            self.logger.error("version_not_found", version=version)
            return False

        engine.config.model_path = model_path
        await engine.load_models()

        self._current_version = version
        self.logger.info("version_loaded", version=version)
        return True
