"""Learning-to-Rank models for alert prioritization."""

from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RankingConfig(BaseModel):
    """Configuration for ranking model."""

    # Model architecture
    hidden_size: int = Field(default=256)
    num_layers: int = Field(default=3)
    dropout: float = Field(default=0.2)
    input_dim: int = Field(default=128, description="Input feature dimension")

    # Training
    margin: float = Field(default=1.0, description="Margin for pairwise loss")
    sigma: float = Field(default=1.0, description="Sigma for listwise loss")

    # Loss type
    loss_type: str = Field(
        default="listwise",
        description="pairwise, listwise, or lambdarank"
    )


class AlertRanker(nn.Module, LoggerMixin):
    """Learning-to-Rank model for alert ordering."""

    def __init__(self, config: RankingConfig) -> None:
        """Initialize the ranker.

        Args:
            config: Model configuration
        """
        super().__init__()
        self.config = config

        # Feature encoder
        layers = []
        input_dim = config.input_dim

        for i in range(config.num_layers):
            layers.extend([
                nn.Linear(input_dim, config.hidden_size),
                nn.BatchNorm1d(config.hidden_size),
                nn.GELU(),
                nn.Dropout(config.dropout),
            ])
            input_dim = config.hidden_size

        self.encoder = nn.Sequential(*layers)

        # Score head
        self.score_head = nn.Sequential(
            nn.Linear(config.hidden_size, config.hidden_size // 2),
            nn.GELU(),
            nn.Linear(config.hidden_size // 2, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        """Compute ranking scores.

        Args:
            features: Input features [batch, input_dim]

        Returns:
            Ranking scores [batch]
        """
        hidden = self.encoder(features)
        scores = self.score_head(hidden).squeeze(-1)
        return scores

    def pairwise_loss(
        self,
        scores_i: torch.Tensor,
        scores_j: torch.Tensor,
        labels: torch.Tensor,
    ) -> torch.Tensor:
        """Compute pairwise ranking loss (RankNet style).

        Args:
            scores_i: Scores for first items [batch]
            scores_j: Scores for second items [batch]
            labels: 1 if i > j, -1 if i < j [batch]

        Returns:
            Pairwise loss
        """
        diff = scores_i - scores_j
        loss = torch.log1p(torch.exp(-labels * diff))
        return loss.mean()

    def listwise_loss(
        self,
        scores: torch.Tensor,
        relevance: torch.Tensor,
    ) -> torch.Tensor:
        """Compute listwise ranking loss (ListMLE).

        Args:
            scores: Predicted scores [batch, list_size]
            relevance: Ground truth relevance [batch, list_size]

        Returns:
            Listwise loss
        """
        # Sort by relevance (descending)
        sorted_indices = relevance.argsort(dim=-1, descending=True)
        sorted_scores = torch.gather(scores, dim=-1, index=sorted_indices)

        # ListMLE loss
        max_score = sorted_scores.max(dim=-1, keepdim=True)[0]
        sorted_scores = sorted_scores - max_score  # Numerical stability

        log_cumsum = torch.logcumsumexp(sorted_scores.flip(dims=[-1]), dim=-1).flip(dims=[-1])
        loss = (log_cumsum - sorted_scores).mean()

        return loss

    def lambdarank_loss(
        self,
        scores: torch.Tensor,
        relevance: torch.Tensor,
        k: int = 10,
    ) -> torch.Tensor:
        """Compute LambdaRank loss with NDCG optimization.

        Args:
            scores: Predicted scores [batch, list_size]
            relevance: Ground truth relevance [batch, list_size]
            k: Cutoff for NDCG

        Returns:
            LambdaRank loss
        """
        batch_size, list_size = scores.shape

        # Compute ideal DCG
        sorted_relevance, _ = relevance.sort(dim=-1, descending=True)
        position_discount = 1.0 / torch.log2(
            torch.arange(2, list_size + 2, device=scores.device).float()
        )
        ideal_dcg = (sorted_relevance[:, :k] * position_discount[:k]).sum(dim=-1)
        ideal_dcg = ideal_dcg.clamp(min=1e-10)

        # Compute pairwise lambda gradients
        score_diff = scores.unsqueeze(-1) - scores.unsqueeze(-2)  # [batch, list, list]
        rel_diff = relevance.unsqueeze(-1) - relevance.unsqueeze(-2)

        # Only consider pairs where relevance differs
        pair_mask = (rel_diff > 0).float()

        # Sigmoid of score difference
        pairwise_prob = torch.sigmoid(self.config.sigma * score_diff)

        # Delta NDCG (simplified)
        delta_ndcg = torch.abs(rel_diff) / ideal_dcg.unsqueeze(-1).unsqueeze(-1)

        # Lambda loss
        loss = pair_mask * delta_ndcg * torch.log(pairwise_prob + 1e-10)
        loss = -loss.sum() / (pair_mask.sum() + 1e-10)

        return loss

    def compute_loss(
        self,
        features: torch.Tensor,
        relevance: torch.Tensor,
    ) -> torch.Tensor:
        """Compute ranking loss.

        Args:
            features: Input features [batch, list_size, input_dim]
            relevance: Ground truth relevance [batch, list_size]

        Returns:
            Ranking loss
        """
        batch_size, list_size, _ = features.shape

        # Get scores for all items
        features_flat = features.view(-1, self.config.input_dim)
        scores_flat = self.forward(features_flat)
        scores = scores_flat.view(batch_size, list_size)

        if self.config.loss_type == "pairwise":
            # Sample pairs from each list
            total_loss = 0
            num_pairs = 0

            for i in range(list_size):
                for j in range(i + 1, list_size):
                    labels = torch.sign(relevance[:, i] - relevance[:, j])
                    valid_mask = labels != 0

                    if valid_mask.sum() > 0:
                        loss = self.pairwise_loss(
                            scores[valid_mask, i],
                            scores[valid_mask, j],
                            labels[valid_mask],
                        )
                        total_loss += loss
                        num_pairs += 1

            return total_loss / max(num_pairs, 1)

        elif self.config.loss_type == "listwise":
            return self.listwise_loss(scores, relevance)

        elif self.config.loss_type == "lambdarank":
            return self.lambdarank_loss(scores, relevance)

        else:
            raise ValueError(f"Unknown loss type: {self.config.loss_type}")

    @torch.no_grad()
    def rank(
        self,
        features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Rank items by predicted scores.

        Args:
            features: Input features [batch, input_dim] or [num_items, input_dim]

        Returns:
            Tuple of (scores, ranks)
        """
        self.eval()
        scores = self.forward(features)
        ranks = scores.argsort(descending=True)
        return scores, ranks


class NDCGEvaluator(LoggerMixin):
    """Evaluate ranking quality using NDCG."""

    def __init__(self, k_values: list[int] | None = None) -> None:
        """Initialize evaluator.

        Args:
            k_values: Values of k for NDCG@k
        """
        self.k_values = k_values or [1, 3, 5, 10, 20]

    def dcg_at_k(
        self,
        relevance: np.ndarray,
        k: int,
    ) -> float:
        """Compute DCG@k.

        Args:
            relevance: Relevance scores in predicted order
            k: Cutoff

        Returns:
            DCG@k score
        """
        relevance = relevance[:k]
        positions = np.arange(1, len(relevance) + 1)
        discounts = np.log2(positions + 1)
        return (relevance / discounts).sum()

    def ndcg_at_k(
        self,
        relevance: np.ndarray,
        k: int,
    ) -> float:
        """Compute NDCG@k.

        Args:
            relevance: Relevance scores in predicted order
            k: Cutoff

        Returns:
            NDCG@k score
        """
        dcg = self.dcg_at_k(relevance, k)
        ideal_relevance = np.sort(relevance)[::-1]
        idcg = self.dcg_at_k(ideal_relevance, k)
        return dcg / idcg if idcg > 0 else 0.0

    def evaluate(
        self,
        predicted_scores: np.ndarray,
        true_relevance: np.ndarray,
    ) -> dict[str, float]:
        """Evaluate ranking quality.

        Args:
            predicted_scores: Predicted ranking scores
            true_relevance: Ground truth relevance

        Returns:
            Dictionary of NDCG metrics
        """
        # Sort by predicted scores (descending)
        order = np.argsort(predicted_scores)[::-1]
        sorted_relevance = true_relevance[order]

        metrics = {}
        for k in self.k_values:
            metrics[f"ndcg@{k}"] = self.ndcg_at_k(sorted_relevance, k)

        # Mean Reciprocal Rank
        relevant_positions = np.where(sorted_relevance > 0)[0]
        if len(relevant_positions) > 0:
            metrics["mrr"] = 1.0 / (relevant_positions[0] + 1)
        else:
            metrics["mrr"] = 0.0

        # Mean Average Precision
        precisions = []
        relevant_count = 0
        for i, rel in enumerate(sorted_relevance):
            if rel > 0:
                relevant_count += 1
                precisions.append(relevant_count / (i + 1))
        metrics["map"] = np.mean(precisions) if precisions else 0.0

        return metrics


class AlertQueueRanker(LoggerMixin):
    """Ranker for analyst alert queue optimization."""

    def __init__(
        self,
        ranker: AlertRanker | None = None,
        priority_scorer: Any = None,
    ) -> None:
        """Initialize queue ranker.

        Args:
            ranker: Trained LTR model
            priority_scorer: Priority scoring model
        """
        self.ranker = ranker
        self.priority_scorer = priority_scorer

    def rank_queue(
        self,
        alerts: list[dict[str, Any]],
        features: torch.Tensor | None = None,
    ) -> list[dict[str, Any]]:
        """Rank a queue of alerts.

        Args:
            alerts: List of alert dictionaries
            features: Pre-extracted features for LTR model

        Returns:
            Sorted alerts with rank information
        """
        if len(alerts) == 0:
            return []

        scores = []

        # Use LTR model if available
        if self.ranker is not None and features is not None:
            with torch.no_grad():
                model_scores = self.ranker.forward(features).cpu().numpy()
                scores = model_scores.tolist()

        # Fallback to priority scorer
        elif self.priority_scorer is not None:
            for alert in alerts:
                result = self.priority_scorer.score(alert)
                scores.append(result["final_score"])

        # Fallback to rule-based
        else:
            for alert in alerts:
                score = self._calculate_simple_score(alert)
                scores.append(score)

        # Add scores and sort
        for alert, score in zip(alerts, scores):
            alert["_rank_score"] = score

        ranked_alerts = sorted(alerts, key=lambda x: x["_rank_score"], reverse=True)

        # Add rank position
        for i, alert in enumerate(ranked_alerts):
            alert["_rank_position"] = i + 1

        return ranked_alerts

    def _calculate_simple_score(self, alert: dict[str, Any]) -> float:
        """Simple rule-based scoring fallback.

        Args:
            alert: Alert dictionary

        Returns:
            Simple priority score
        """
        score = 50.0

        # Severity adjustment
        severity_map = {"critical": 40, "high": 30, "medium": 15, "low": 5, "info": 0}
        severity = alert.get("severity", "medium")
        score += severity_map.get(severity.lower(), 15)

        # Asset criticality
        criticality = alert.get("asset_criticality", 2)
        score += criticality * 5

        # Alert frequency
        alert_count = alert.get("src_ip_alert_count_1h", 0)
        if alert_count > 10:
            score += 10
        elif alert_count > 5:
            score += 5

        return min(100.0, score)
