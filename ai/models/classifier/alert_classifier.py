"""Alert classification model for severity and category prediction."""

from enum import Enum
from typing import Any

import torch
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertCategory(str, Enum):
    """Alert category types."""

    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_ACCESS = "credential_access"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY = "anomaly"
    OTHER = "other"


class AlertClassification(BaseModel):
    """Result of alert classification."""

    severity: AlertSeverity = Field(description="Predicted severity level")
    severity_confidence: float = Field(ge=0, le=1, description="Confidence score for severity")
    category: AlertCategory = Field(description="Predicted category")
    category_confidence: float = Field(ge=0, le=1, description="Confidence score for category")
    mitre_tactics: list[str] = Field(default_factory=list, description="Mapped MITRE ATT&CK tactics")
    mitre_techniques: list[str] = Field(default_factory=list, description="Mapped MITRE ATT&CK techniques")
    risk_score: float = Field(ge=0, le=100, description="Calculated risk score")
    explanation: str = Field(description="Human-readable classification explanation")
    is_false_positive: bool = Field(default=False, description="Whether predicted as false positive")
    fp_confidence: float = Field(default=0.0, ge=0, le=1, description="FP prediction confidence")


class AlertClassifier(LoggerMixin):
    """ML-based alert classifier.

    Uses transformer models to classify alerts by severity and category,
    with MITRE ATT&CK mapping and false positive detection.
    """

    SEVERITY_LABELS = [
        AlertSeverity.INFO,
        AlertSeverity.LOW,
        AlertSeverity.MEDIUM,
        AlertSeverity.HIGH,
        AlertSeverity.CRITICAL,
    ]

    CATEGORY_LABELS = list(AlertCategory)

    MITRE_TACTICS = [
        "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
        "TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040",
        "TA0042", "TA0043"
    ]

    def __init__(
        self,
        model_path: str | None = None,
        device: str = "cpu",
    ) -> None:
        """Initialize the classifier.

        Args:
            model_path: Path to the trained model weights
            device: Device to run inference on ("cpu" or "cuda")
        """
        self.model_path = model_path
        self.device = torch.device(device)
        self._model = None
        self._tokenizer = None
        self._feature_extractor = None
        self._text_builder = None
        self._is_loaded = False

    async def load_model(self) -> None:
        """Load the classification model and tokenizer."""
        from models.classifier.architecture import AlertClassifierModel
        from models.classifier.config import ClassifierConfig
        from models.classifier.features import FeatureExtractor, TextFeatureBuilder

        self.logger.info("loading_model", model_path=self.model_path, device=str(self.device))

        # Initialize feature extractors
        self._feature_extractor = FeatureExtractor()
        self._text_builder = TextFeatureBuilder()

        # Load tokenizer
        try:
            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        except Exception as e:
            self.logger.warning("tokenizer_load_failed", error=str(e))
            self._tokenizer = None

        # Initialize and load model
        config = ClassifierConfig()
        self._model = AlertClassifierModel(config)

        if self.model_path:
            try:
                checkpoint = torch.load(self.model_path, map_location=self.device)
                if "model_state_dict" in checkpoint:
                    self._model.load_state_dict(checkpoint["model_state_dict"])
                else:
                    self._model.load_state_dict(checkpoint)
                self.logger.info("model_weights_loaded")
            except FileNotFoundError:
                self.logger.warning("model_not_found", path=self.model_path)
            except Exception as e:
                self.logger.error("model_load_error", error=str(e))

        self._model = self._model.to(self.device)
        self._model.eval()
        self._is_loaded = True

        self.logger.info("model_loaded", device=str(self.device))

    async def classify(self, alert: dict[str, Any]) -> AlertClassification:
        """Classify an alert.

        Args:
            alert: Alert data containing title, description, source, etc.

        Returns:
            Classification result with severity, category, and explanations
        """
        self.logger.debug("classifying_alert", alert_id=alert.get("id"))

        if not self._is_loaded:
            # Return fallback classification if model not loaded
            return self._fallback_classification(alert)

        try:
            # Prepare input
            inputs = self._prepare_input(alert)

            # Run inference
            with torch.no_grad():
                outputs = self._model(
                    input_ids=inputs["input_ids"],
                    attention_mask=inputs["attention_mask"],
                    numeric_features=inputs.get("numeric_features"),
                    categorical_features=inputs.get("categorical_features"),
                )

            # Process outputs
            return self._process_outputs(outputs)

        except Exception as e:
            self.logger.error("classification_failed", error=str(e))
            return self._fallback_classification(alert)

    async def batch_classify(
        self, alerts: list[dict[str, Any]]
    ) -> list[AlertClassification]:
        """Classify multiple alerts in batch.

        Args:
            alerts: List of alert data dictionaries

        Returns:
            List of classification results
        """
        self.logger.info("batch_classifying", count=len(alerts))

        if not self._is_loaded or not alerts:
            return [self._fallback_classification(a) for a in alerts]

        try:
            # Prepare batch inputs
            batch_inputs = [self._prepare_input(alert) for alert in alerts]

            # Stack tensors
            input_ids = torch.cat([b["input_ids"] for b in batch_inputs], dim=0)
            attention_mask = torch.cat([b["attention_mask"] for b in batch_inputs], dim=0)
            numeric_features = torch.cat([b["numeric_features"] for b in batch_inputs], dim=0)
            categorical_features = torch.cat([b["categorical_features"] for b in batch_inputs], dim=0)

            # Run inference
            with torch.no_grad():
                outputs = self._model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    numeric_features=numeric_features,
                    categorical_features=categorical_features,
                )

            # Process each result
            results = []
            for i in range(len(alerts)):
                result = self._process_single_output(outputs, i)
                results.append(result)

            return results

        except Exception as e:
            self.logger.error("batch_classification_failed", error=str(e))
            return [self._fallback_classification(a) for a in alerts]

    def _prepare_input(self, alert: dict[str, Any]) -> dict[str, torch.Tensor]:
        """Prepare model input from alert data."""
        # Build text
        text = self._text_builder.build_text(alert)

        # Tokenize
        if self._tokenizer:
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

    def _process_outputs(self, outputs: dict[str, torch.Tensor]) -> AlertClassification:
        """Process model outputs into classification result."""
        return self._process_single_output(outputs, 0)

    def _process_single_output(
        self, outputs: dict[str, torch.Tensor], idx: int
    ) -> AlertClassification:
        """Process a single output from batch."""
        import torch.nn.functional as F

        # Severity
        severity_probs = F.softmax(outputs["severity_logits"][idx], dim=-1)
        severity_idx = severity_probs.argmax().item()
        severity_conf = severity_probs[severity_idx].item()

        # Category
        category_probs = F.softmax(outputs["category_logits"][idx], dim=-1)
        category_idx = category_probs.argmax().item()
        category_conf = category_probs[category_idx].item()

        # MITRE tactics
        tactics_probs = outputs["mitre_tactics_probs"][idx].cpu().numpy()
        mitre_tactics = [
            self.MITRE_TACTICS[i]
            for i, prob in enumerate(tactics_probs)
            if prob > 0.5
        ]

        # MITRE techniques
        mitre_techniques = []

        # FP detection
        fp_probs = F.softmax(outputs["fp_logits"][idx], dim=-1)
        is_fp = fp_probs[1].item() > 0.5
        fp_conf = fp_probs[1].item() if is_fp else fp_probs[0].item()

        # Risk score
        risk_score = outputs["risk_score"][idx].item()

        # Build explanation
        severity = self.SEVERITY_LABELS[severity_idx]
        category = self.CATEGORY_LABELS[category_idx]

        explanation = (
            f"Alert classified as {severity.value} severity ({severity_conf:.0%} confidence) "
            f"in category {category.value} ({category_conf:.0%} confidence)."
        )
        if mitre_tactics:
            explanation += f" MITRE ATT&CK: {', '.join(mitre_tactics)}."
        if is_fp:
            explanation += f" Likely false positive ({fp_conf:.0%} confidence)."

        return AlertClassification(
            severity=severity,
            severity_confidence=severity_conf,
            category=category,
            category_confidence=category_conf,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            risk_score=risk_score,
            explanation=explanation,
            is_false_positive=is_fp,
            fp_confidence=fp_conf,
        )

    def _fallback_classification(self, alert: dict[str, Any]) -> AlertClassification:
        """Return fallback classification when model unavailable."""
        # Simple rule-based fallback
        severity = AlertSeverity.MEDIUM
        category = AlertCategory.ANOMALY

        title = (alert.get("title") or "").lower()
        description = (alert.get("description") or "").lower()
        text = f"{title} {description}"

        # Severity heuristics
        if any(w in text for w in ["critical", "ransomware", "breach"]):
            severity = AlertSeverity.CRITICAL
        elif any(w in text for w in ["malware", "intrusion", "exploit"]):
            severity = AlertSeverity.HIGH
        elif any(w in text for w in ["suspicious", "anomaly"]):
            severity = AlertSeverity.MEDIUM
        elif any(w in text for w in ["info", "audit", "log"]):
            severity = AlertSeverity.LOW

        # Category heuristics
        if "malware" in text:
            category = AlertCategory.MALWARE
        elif "intrusion" in text:
            category = AlertCategory.INTRUSION
        elif "scan" in text or "recon" in text:
            category = AlertCategory.RECONNAISSANCE

        return AlertClassification(
            severity=severity,
            severity_confidence=0.5,
            category=category,
            category_confidence=0.5,
            mitre_tactics=[],
            mitre_techniques=[],
            risk_score=50.0,
            explanation="Classification based on rule-based fallback (model unavailable).",
            is_false_positive=False,
            fp_confidence=0.5,
        )
