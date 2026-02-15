"""Model architecture for alert classification."""

import math
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from common.logging import LoggerMixin
from models.classifier.config import ClassifierConfig


class PositionalEncoding(nn.Module):
    """Positional encoding for transformer models."""

    def __init__(self, d_model: int, max_len: int = 512, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create positional encodings
        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))

        pe = torch.zeros(1, max_len, d_model)
        pe[0, :, 0::2] = torch.sin(position * div_term)
        pe[0, :, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Add positional encoding to input."""
        x = x + self.pe[:, :x.size(1)]
        return self.dropout(x)


class MultiHeadSelfAttention(nn.Module):
    """Multi-head self-attention with optional flash attention."""

    def __init__(
        self,
        hidden_size: int,
        num_heads: int,
        dropout: float = 0.1,
        use_flash_attention: bool = True,
    ):
        super().__init__()
        assert hidden_size % num_heads == 0

        self.hidden_size = hidden_size
        self.num_heads = num_heads
        self.head_dim = hidden_size // num_heads
        self.use_flash_attention = use_flash_attention

        self.q_proj = nn.Linear(hidden_size, hidden_size)
        self.k_proj = nn.Linear(hidden_size, hidden_size)
        self.v_proj = nn.Linear(hidden_size, hidden_size)
        self.out_proj = nn.Linear(hidden_size, hidden_size)

        self.dropout = nn.Dropout(dropout)
        self.scale = math.sqrt(self.head_dim)

    def forward(
        self,
        hidden_states: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Forward pass with optional flash attention."""
        batch_size, seq_len, _ = hidden_states.shape

        # Project Q, K, V
        query = self.q_proj(hidden_states)
        key = self.k_proj(hidden_states)
        value = self.v_proj(hidden_states)

        # Reshape for multi-head attention
        query = query.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        key = key.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)
        value = value.view(batch_size, seq_len, self.num_heads, self.head_dim).transpose(1, 2)

        # Use Flash Attention 2 if available and enabled
        if self.use_flash_attention and hasattr(F, "scaled_dot_product_attention"):
            # PyTorch 2.0+ native attention with flash attention backend
            attn_output = F.scaled_dot_product_attention(
                query, key, value,
                attn_mask=attention_mask,
                dropout_p=self.dropout.p if self.training else 0.0,
                is_causal=False,
            )
        else:
            # Standard attention
            attn_weights = torch.matmul(query, key.transpose(-2, -1)) / self.scale

            if attention_mask is not None:
                attn_weights = attn_weights + attention_mask

            attn_weights = F.softmax(attn_weights, dim=-1)
            attn_weights = self.dropout(attn_weights)
            attn_output = torch.matmul(attn_weights, value)

        # Reshape and project output
        attn_output = attn_output.transpose(1, 2).contiguous().view(batch_size, seq_len, -1)
        return self.out_proj(attn_output)


class TransformerBlock(nn.Module):
    """Single transformer encoder block."""

    def __init__(
        self,
        hidden_size: int,
        num_heads: int,
        intermediate_size: int,
        dropout: float = 0.1,
        use_flash_attention: bool = True,
    ):
        super().__init__()

        self.attention = MultiHeadSelfAttention(
            hidden_size, num_heads, dropout, use_flash_attention
        )
        self.norm1 = nn.LayerNorm(hidden_size)
        self.norm2 = nn.LayerNorm(hidden_size)

        self.ffn = nn.Sequential(
            nn.Linear(hidden_size, intermediate_size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(intermediate_size, hidden_size),
            nn.Dropout(dropout),
        )

    def forward(
        self,
        hidden_states: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Forward pass with pre-norm residual connections."""
        # Self-attention with residual
        attn_output = self.attention(self.norm1(hidden_states), attention_mask)
        hidden_states = hidden_states + attn_output

        # FFN with residual
        ffn_output = self.ffn(self.norm2(hidden_states))
        hidden_states = hidden_states + ffn_output

        return hidden_states


class AlertEncoder(nn.Module):
    """Transformer encoder for alert text and features."""

    def __init__(self, config: ClassifierConfig):
        super().__init__()
        self.config = config

        # Token embedding
        self.token_embedding = nn.Embedding(config.vocab_size, config.hidden_size)
        self.position_encoding = PositionalEncoding(
            config.hidden_size,
            config.max_position_embeddings,
            config.hidden_dropout_prob,
        )

        # Transformer layers
        self.layers = nn.ModuleList([
            TransformerBlock(
                config.hidden_size,
                config.num_attention_heads,
                config.intermediate_size,
                config.hidden_dropout_prob,
            )
            for _ in range(config.num_hidden_layers)
        ])

        self.final_norm = nn.LayerNorm(config.hidden_size)

        # Numeric feature projection
        if config.use_numeric_features:
            self.numeric_proj = nn.Sequential(
                nn.Linear(config.numeric_feature_dim, config.hidden_size),
                nn.GELU(),
                nn.Dropout(config.hidden_dropout_prob),
            )

        # Categorical embeddings
        if config.use_categorical_features:
            self.source_type_embedding = nn.Embedding(16, config.categorical_feature_dim)
            self.protocol_embedding = nn.Embedding(16, config.categorical_feature_dim)
            self.action_embedding = nn.Embedding(16, config.categorical_feature_dim)

            self.categorical_proj = nn.Sequential(
                nn.Linear(config.categorical_feature_dim * 3, config.hidden_size),
                nn.GELU(),
                nn.Dropout(config.hidden_dropout_prob),
            )

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        numeric_features: torch.Tensor | None = None,
        categorical_features: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Encode alert data.

        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            numeric_features: Numeric features [batch, num_features]
            categorical_features: Categorical feature IDs [batch, 3]

        Returns:
            Encoded representation [batch, hidden_size]
        """
        batch_size = input_ids.size(0)

        # Token embeddings
        hidden_states = self.token_embedding(input_ids)
        hidden_states = self.position_encoding(hidden_states)

        # Prepare attention mask for transformer
        extended_attention_mask = None
        if attention_mask is not None:
            extended_attention_mask = attention_mask[:, None, None, :]
            extended_attention_mask = (1.0 - extended_attention_mask) * torch.finfo(
                hidden_states.dtype
            ).min

        # Apply transformer layers
        for layer in self.layers:
            hidden_states = layer(hidden_states, extended_attention_mask)

        hidden_states = self.final_norm(hidden_states)

        # Pool to single vector (CLS token or mean pooling)
        if attention_mask is not None:
            # Mean pooling with attention mask
            mask_expanded = attention_mask.unsqueeze(-1).expand(hidden_states.size()).float()
            sum_embeddings = torch.sum(hidden_states * mask_expanded, dim=1)
            sum_mask = mask_expanded.sum(dim=1).clamp(min=1e-9)
            pooled = sum_embeddings / sum_mask
        else:
            pooled = hidden_states.mean(dim=1)

        # Add numeric features
        if numeric_features is not None and self.config.use_numeric_features:
            numeric_proj = self.numeric_proj(numeric_features)
            pooled = pooled + numeric_proj

        # Add categorical features
        if categorical_features is not None and self.config.use_categorical_features:
            source_type_emb = self.source_type_embedding(categorical_features[:, 0])
            protocol_emb = self.protocol_embedding(categorical_features[:, 1])
            action_emb = self.action_embedding(categorical_features[:, 2])

            cat_combined = torch.cat([source_type_emb, protocol_emb, action_emb], dim=-1)
            cat_proj = self.categorical_proj(cat_combined)
            pooled = pooled + cat_proj

        return pooled


class ClassificationHead(nn.Module):
    """Classification head for multi-task learning."""

    def __init__(
        self,
        hidden_size: int,
        num_classes: int,
        dropout: float = 0.1,
        multi_label: bool = False,
    ):
        super().__init__()
        self.multi_label = multi_label

        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, num_classes),
        )

    def forward(self, hidden_states: torch.Tensor) -> torch.Tensor:
        """Forward pass through classification head."""
        logits = self.classifier(hidden_states)
        if self.multi_label:
            return torch.sigmoid(logits)
        return logits


class AlertClassifierModel(nn.Module, LoggerMixin):
    """Complete alert classifier with multi-task heads."""

    def __init__(self, config: ClassifierConfig):
        super().__init__()
        self.config = config

        # Encoder
        self.encoder = AlertEncoder(config)

        # Classification heads
        self.severity_head = ClassificationHead(
            config.hidden_size,
            config.num_severity_classes,
            config.hidden_dropout_prob,
        )

        self.category_head = ClassificationHead(
            config.hidden_size,
            config.num_category_classes,
            config.hidden_dropout_prob,
        )

        self.mitre_tactics_head = ClassificationHead(
            config.hidden_size,
            config.num_mitre_tactics,
            config.hidden_dropout_prob,
            multi_label=True,
        )

        self.mitre_techniques_head = ClassificationHead(
            config.hidden_size,
            config.num_mitre_techniques,
            config.hidden_dropout_prob,
            multi_label=True,
        )

        # False positive detection head
        self.fp_head = ClassificationHead(
            config.hidden_size,
            2,  # Binary: TP or FP
            config.hidden_dropout_prob,
        )

        # Risk score regression head
        self.risk_head = nn.Sequential(
            nn.Linear(config.hidden_size, config.hidden_size // 2),
            nn.GELU(),
            nn.Dropout(config.hidden_dropout_prob),
            nn.Linear(config.hidden_size // 2, 1),
            nn.Sigmoid(),  # Output 0-1, scale to 0-100 later
        )

        # Initialize weights
        self.apply(self._init_weights)

    def _init_weights(self, module: nn.Module) -> None:
        """Initialize weights using Xavier/Glorot initialization."""
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0.0, std=0.02)
        elif isinstance(module, nn.LayerNorm):
            nn.init.ones_(module.weight)
            nn.init.zeros_(module.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        numeric_features: torch.Tensor | None = None,
        categorical_features: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        """Forward pass through all classification heads.

        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            numeric_features: Numeric features [batch, num_features]
            categorical_features: Categorical feature IDs [batch, 3]

        Returns:
            Dictionary with logits/predictions for each task
        """
        # Encode
        hidden_states = self.encoder(
            input_ids, attention_mask, numeric_features, categorical_features
        )

        # Get predictions from all heads
        outputs = {
            "severity_logits": self.severity_head(hidden_states),
            "category_logits": self.category_head(hidden_states),
            "mitre_tactics_probs": self.mitre_tactics_head(hidden_states),
            "mitre_techniques_probs": self.mitre_techniques_head(hidden_states),
            "fp_logits": self.fp_head(hidden_states),
            "risk_score": self.risk_head(hidden_states).squeeze(-1) * 100,  # Scale to 0-100
            "hidden_states": hidden_states,
        }

        return outputs

    def compute_loss(
        self,
        outputs: dict[str, torch.Tensor],
        labels: dict[str, torch.Tensor],
    ) -> dict[str, torch.Tensor]:
        """Compute multi-task loss.

        Args:
            outputs: Model outputs
            labels: Ground truth labels

        Returns:
            Dictionary with individual losses and total loss
        """
        losses = {}

        # Severity classification loss
        if "severity" in labels:
            losses["severity_loss"] = F.cross_entropy(
                outputs["severity_logits"], labels["severity"]
            ) * self.config.severity_weight

        # Category classification loss
        if "category" in labels:
            losses["category_loss"] = F.cross_entropy(
                outputs["category_logits"], labels["category"]
            ) * self.config.category_weight

        # MITRE tactics loss (multi-label BCE)
        if "mitre_tactics" in labels:
            losses["mitre_tactics_loss"] = F.binary_cross_entropy(
                outputs["mitre_tactics_probs"], labels["mitre_tactics"].float()
            ) * self.config.mitre_weight

        # MITRE techniques loss (multi-label BCE)
        if "mitre_techniques" in labels:
            losses["mitre_techniques_loss"] = F.binary_cross_entropy(
                outputs["mitre_techniques_probs"], labels["mitre_techniques"].float()
            ) * self.config.mitre_weight

        # False positive loss (weighted for class imbalance)
        if "is_fp" in labels:
            fp_weight = torch.tensor([1.0, self.config.fp_weight], device=labels["is_fp"].device)
            losses["fp_loss"] = F.cross_entropy(
                outputs["fp_logits"], labels["is_fp"], weight=fp_weight
            )

        # Risk score regression loss
        if "risk_score" in labels:
            losses["risk_loss"] = F.mse_loss(
                outputs["risk_score"], labels["risk_score"]
            )

        # Total loss
        losses["total_loss"] = sum(losses.values())

        return losses

    @torch.no_grad()
    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor | None = None,
        numeric_features: torch.Tensor | None = None,
        categorical_features: torch.Tensor | None = None,
    ) -> dict[str, Any]:
        """Make predictions with confidence scores.

        Args:
            input_ids: Token IDs [batch, seq_len]
            attention_mask: Attention mask [batch, seq_len]
            numeric_features: Numeric features [batch, num_features]
            categorical_features: Categorical feature IDs [batch, 3]

        Returns:
            Predictions with class labels and confidence scores
        """
        self.eval()
        outputs = self.forward(input_ids, attention_mask, numeric_features, categorical_features)

        # Get predictions
        severity_probs = F.softmax(outputs["severity_logits"], dim=-1)
        severity_conf, severity_pred = severity_probs.max(dim=-1)

        category_probs = F.softmax(outputs["category_logits"], dim=-1)
        category_conf, category_pred = category_probs.max(dim=-1)

        fp_probs = F.softmax(outputs["fp_logits"], dim=-1)
        fp_conf, fp_pred = fp_probs.max(dim=-1)

        return {
            "severity": severity_pred.cpu().numpy(),
            "severity_confidence": severity_conf.cpu().numpy(),
            "category": category_pred.cpu().numpy(),
            "category_confidence": category_conf.cpu().numpy(),
            "mitre_tactics": (outputs["mitre_tactics_probs"] > 0.5).cpu().numpy(),
            "mitre_techniques": (outputs["mitre_techniques_probs"] > 0.3).cpu().numpy(),
            "is_false_positive": fp_pred.cpu().numpy(),
            "fp_confidence": fp_conf.cpu().numpy(),
            "risk_score": outputs["risk_score"].cpu().numpy(),
        }
