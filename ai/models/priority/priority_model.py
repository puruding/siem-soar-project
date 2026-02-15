"""Priority scoring model for risk-based alert prioritization."""

from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class PriorityConfig(BaseModel):
    """Configuration for priority scoring model."""

    # Input dimensions
    hidden_size: int = Field(default=256, description="Hidden layer size")
    num_numeric_features: int = Field(default=32, description="Number of numeric features")
    num_categorical_features: int = Field(default=16)
    embedding_dim: int = Field(default=32, description="Categorical embedding dimension")

    # Model architecture
    num_layers: int = Field(default=3, description="Number of hidden layers")
    dropout: float = Field(default=0.2, description="Dropout rate")
    use_batch_norm: bool = Field(default=True, description="Use batch normalization")

    # Output
    output_type: str = Field(default="score", description="score or ordinal")
    num_ordinal_classes: int = Field(default=5, description="For ordinal regression")

    # Factor weights (for rule-based component)
    asset_weight: float = Field(default=0.25, description="Asset criticality weight")
    threat_weight: float = Field(default=0.35, description="Threat severity weight")
    confidence_weight: float = Field(default=0.20, description="Detection confidence weight")
    context_weight: float = Field(default=0.20, description="Context/environmental weight")


class PriorityScorer(nn.Module, LoggerMixin):
    """Neural network for priority scoring."""

    def __init__(self, config: PriorityConfig) -> None:
        """Initialize the priority scorer.

        Args:
            config: Model configuration
        """
        super().__init__()
        self.config = config

        # Categorical embeddings
        self.severity_embedding = nn.Embedding(5, config.embedding_dim)
        self.category_embedding = nn.Embedding(12, config.embedding_dim)
        self.asset_criticality_embedding = nn.Embedding(5, config.embedding_dim)

        # Feature processing
        total_input_dim = (
            config.num_numeric_features +
            config.embedding_dim * 3  # Three categorical embeddings
        )

        # MLP layers
        layers = []
        input_dim = total_input_dim

        for i in range(config.num_layers):
            layers.append(nn.Linear(input_dim, config.hidden_size))
            if config.use_batch_norm:
                layers.append(nn.BatchNorm1d(config.hidden_size))
            layers.append(nn.GELU())
            layers.append(nn.Dropout(config.dropout))
            input_dim = config.hidden_size

        self.feature_mlp = nn.Sequential(*layers)

        # Output head
        if config.output_type == "score":
            self.output_head = nn.Sequential(
                nn.Linear(config.hidden_size, config.hidden_size // 2),
                nn.GELU(),
                nn.Linear(config.hidden_size // 2, 1),
                nn.Sigmoid(),
            )
        else:
            # Ordinal regression
            self.output_head = nn.Linear(config.hidden_size, config.num_ordinal_classes)

        # Factor attention (for explainability)
        self.factor_attention = nn.Sequential(
            nn.Linear(config.hidden_size, 4),  # 4 factors
            nn.Softmax(dim=-1),
        )

    def forward(
        self,
        numeric_features: torch.Tensor,
        severity: torch.Tensor,
        category: torch.Tensor,
        asset_criticality: torch.Tensor,
    ) -> dict[str, torch.Tensor]:
        """Forward pass.

        Args:
            numeric_features: [batch, num_numeric_features]
            severity: Severity class IDs [batch]
            category: Category class IDs [batch]
            asset_criticality: Asset criticality IDs [batch]

        Returns:
            Dictionary with score and factor weights
        """
        # Get categorical embeddings
        severity_emb = self.severity_embedding(severity)
        category_emb = self.category_embedding(category)
        asset_emb = self.asset_criticality_embedding(asset_criticality)

        # Concatenate all features
        features = torch.cat([
            numeric_features,
            severity_emb,
            category_emb,
            asset_emb,
        ], dim=-1)

        # Process through MLP
        hidden = self.feature_mlp(features)

        # Get output score
        if self.config.output_type == "score":
            score = self.output_head(hidden).squeeze(-1) * 100  # Scale to 0-100
        else:
            # Ordinal regression
            logits = self.output_head(hidden)
            # Convert to cumulative probabilities for ordinal
            probs = torch.sigmoid(logits)
            score = (probs.sum(dim=-1) / self.config.num_ordinal_classes) * 100

        # Get factor attention weights (for explainability)
        factor_weights = self.factor_attention(hidden)

        return {
            "priority_score": score,
            "factor_weights": factor_weights,
            "hidden": hidden,
        }

    @torch.no_grad()
    def predict(
        self,
        numeric_features: torch.Tensor,
        severity: torch.Tensor,
        category: torch.Tensor,
        asset_criticality: torch.Tensor,
    ) -> dict[str, Any]:
        """Make priority predictions.

        Args:
            numeric_features: [batch, num_numeric_features]
            severity: Severity class IDs [batch]
            category: Category class IDs [batch]
            asset_criticality: Asset criticality IDs [batch]

        Returns:
            Priority scores and explanations
        """
        self.eval()
        outputs = self.forward(numeric_features, severity, category, asset_criticality)

        factor_names = ["asset_risk", "threat_severity", "confidence", "context"]
        factor_weights = outputs["factor_weights"].cpu().numpy()

        # Build explanations
        explanations = []
        for i, weights in enumerate(factor_weights):
            top_factor_idx = np.argmax(weights)
            explanations.append(
                f"Primary factor: {factor_names[top_factor_idx]} ({weights[top_factor_idx]:.2%})"
            )

        return {
            "priority_score": outputs["priority_score"].cpu().numpy(),
            "factor_weights": factor_weights,
            "factor_names": factor_names,
            "explanations": explanations,
        }


class HybridPriorityScorer(LoggerMixin):
    """Hybrid rule-based and ML priority scorer."""

    def __init__(
        self,
        ml_model: PriorityScorer | None = None,
        config: PriorityConfig | None = None,
        ml_weight: float = 0.7,
    ) -> None:
        """Initialize hybrid scorer.

        Args:
            ml_model: Trained ML model
            config: Configuration for rule-based weights
            ml_weight: Weight for ML component (1-ml_weight for rules)
        """
        self.ml_model = ml_model
        self.config = config or PriorityConfig()
        self.ml_weight = ml_weight
        self.rule_weight = 1 - ml_weight

    def calculate_rule_based_score(
        self,
        alert: dict[str, Any],
    ) -> tuple[float, dict[str, float]]:
        """Calculate rule-based priority score.

        Args:
            alert: Alert data dictionary

        Returns:
            Tuple of (score, factor_breakdown)
        """
        # Asset criticality factor (0-100)
        asset_criticality = alert.get("asset_criticality", 2)  # Default medium
        asset_score = asset_criticality / 4 * 100  # 0-4 scale

        # Threat severity factor (0-100)
        severity_map = {"critical": 100, "high": 80, "medium": 50, "low": 25, "info": 10}
        severity = alert.get("severity", "medium")
        threat_score = severity_map.get(severity.lower(), 50)

        # Detection confidence factor (0-100)
        confidence = alert.get("confidence", 0.75) * 100

        # Context factor (0-100) - based on aggregations
        context_signals = []

        # High alert velocity
        alert_count_1h = alert.get("src_ip_alert_count_1h", 0)
        if alert_count_1h > 10:
            context_signals.append(80)
        elif alert_count_1h > 5:
            context_signals.append(60)
        else:
            context_signals.append(30)

        # Known bad reputation
        if alert.get("src_ip_is_known_bad", False):
            context_signals.append(90)
        if alert.get("dst_ip_is_known_bad", False):
            context_signals.append(85)

        # External to internal traffic
        if alert.get("is_external_to_internal", False):
            context_signals.append(70)

        context_score = np.mean(context_signals) if context_signals else 50

        # Weighted combination
        final_score = (
            self.config.asset_weight * asset_score +
            self.config.threat_weight * threat_score +
            self.config.confidence_weight * confidence +
            self.config.context_weight * context_score
        )

        factor_breakdown = {
            "asset_risk": asset_score,
            "threat_severity": threat_score,
            "confidence": confidence,
            "context": context_score,
        }

        return final_score, factor_breakdown

    def score(
        self,
        alert: dict[str, Any],
        ml_features: dict[str, torch.Tensor] | None = None,
    ) -> dict[str, Any]:
        """Calculate combined priority score.

        Args:
            alert: Alert data dictionary
            ml_features: Pre-extracted ML features

        Returns:
            Priority score with explanations
        """
        # Rule-based score
        rule_score, rule_factors = self.calculate_rule_based_score(alert)

        result = {
            "rule_score": rule_score,
            "rule_factors": rule_factors,
        }

        # ML score if model available
        if self.ml_model is not None and ml_features is not None:
            ml_outputs = self.ml_model.predict(**ml_features)
            ml_score = float(ml_outputs["priority_score"][0])

            # Combine scores
            final_score = (
                self.ml_weight * ml_score +
                self.rule_weight * rule_score
            )

            result.update({
                "ml_score": ml_score,
                "ml_factors": dict(zip(
                    ml_outputs["factor_names"],
                    ml_outputs["factor_weights"][0].tolist()
                )),
                "final_score": final_score,
            })
        else:
            result["final_score"] = rule_score

        # Add priority level
        score = result["final_score"]
        if score >= 80:
            result["priority_level"] = "critical"
        elif score >= 60:
            result["priority_level"] = "high"
        elif score >= 40:
            result["priority_level"] = "medium"
        elif score >= 20:
            result["priority_level"] = "low"
        else:
            result["priority_level"] = "info"

        # Build explanation
        top_factor = max(rule_factors.items(), key=lambda x: x[1])
        result["explanation"] = (
            f"Priority score {score:.1f}/100 ({result['priority_level']}). "
            f"Primary factor: {top_factor[0]} ({top_factor[1]:.1f})"
        )

        return result

    async def batch_score(
        self,
        alerts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Score multiple alerts.

        Args:
            alerts: List of alert dictionaries

        Returns:
            List of priority results
        """
        return [self.score(alert) for alert in alerts]
