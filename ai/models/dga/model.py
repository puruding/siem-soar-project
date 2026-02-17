"""DGA Detection Model - LSTM + CNN Hybrid Architecture."""

from enum import Enum
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel
from models.dga.config import DGAConfig, DGAFamily, DGAInferenceConfig
from models.dga.features import DGAFeatureExtractor, DomainTokenizer


class DGAClassification(BaseModel):
    """Result of DGA detection."""

    domain: str = Field(description="Input domain")
    is_dga: bool = Field(description="Whether domain is DGA")
    confidence: float = Field(ge=0, le=1, description="DGA probability")
    family: str = Field(default="unknown", description="Predicted DGA family")
    family_confidence: float = Field(
        default=0.0, ge=0, le=1, description="Family prediction confidence"
    )
    risk_level: str = Field(description="Risk level: low, medium, high, critical")
    features: dict[str, float] = Field(
        default_factory=dict, description="Key domain features"
    )
    explanation: str = Field(description="Human-readable explanation")


class DGABatchResult(BaseModel):
    """Batch DGA detection results."""

    results: list[DGAClassification] = Field(description="Individual results")
    total_count: int = Field(description="Total domains processed")
    dga_count: int = Field(description="Number of DGA domains")
    processing_time_ms: float = Field(description="Processing time")


class CharacterEmbedding(nn.Module):
    """Character-level embedding with optional position encoding."""

    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int,
        max_length: int,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim, padding_idx=0)
        self.position_embedding = nn.Embedding(max_length, embedding_dim)
        self.dropout = nn.Dropout(dropout)
        self.max_length = max_length

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Token IDs [batch, seq_len]

        Returns:
            Embeddings [batch, seq_len, embedding_dim]
        """
        batch_size, seq_len = x.shape

        # Character embeddings
        char_emb = self.embedding(x)

        # Position embeddings
        positions = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(batch_size, -1)
        pos_emb = self.position_embedding(positions)

        # Combine
        embeddings = char_emb + pos_emb
        return self.dropout(embeddings)


class BiLSTMEncoder(nn.Module):
    """Bidirectional LSTM encoder for sequence modeling."""

    def __init__(
        self,
        input_size: int,
        hidden_size: int,
        num_layers: int = 2,
        dropout: float = 0.3,
        bidirectional: bool = True,
    ):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.bidirectional = bidirectional
        self.num_directions = 2 if bidirectional else 1

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0,
            bidirectional=bidirectional,
        )

    def forward(
        self,
        x: torch.Tensor,
        lengths: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Forward pass.

        Args:
            x: Input sequences [batch, seq_len, input_size]
            lengths: Sequence lengths for packing

        Returns:
            outputs: All hidden states [batch, seq_len, hidden_size * num_directions]
            final_hidden: Final hidden state [batch, hidden_size * num_directions]
        """
        if lengths is not None:
            # Pack sequence for efficiency
            packed = nn.utils.rnn.pack_padded_sequence(
                x, lengths.cpu(), batch_first=True, enforce_sorted=False
            )
            outputs, (hidden, _) = self.lstm(packed)
            outputs, _ = nn.utils.rnn.pad_packed_sequence(outputs, batch_first=True)
        else:
            outputs, (hidden, _) = self.lstm(x)

        # Combine forward and backward final hidden states
        if self.bidirectional:
            # hidden: [num_layers * 2, batch, hidden_size]
            # Take last layer's forward and backward
            forward = hidden[-2]  # Last layer forward
            backward = hidden[-1]  # Last layer backward
            final_hidden = torch.cat([forward, backward], dim=-1)
        else:
            final_hidden = hidden[-1]

        return outputs, final_hidden


class CNNEncoder(nn.Module):
    """CNN encoder with multiple kernel sizes for n-gram patterns."""

    def __init__(
        self,
        input_size: int,
        filters: list[int],
        kernel_sizes: list[int],
        dropout: float = 0.5,
    ):
        super().__init__()
        assert len(filters) == len(kernel_sizes)

        self.convs = nn.ModuleList([
            nn.Sequential(
                nn.Conv1d(input_size, f, k, padding=k // 2),
                nn.BatchNorm1d(f),
                nn.ReLU(),
                nn.Dropout(dropout),
            )
            for f, k in zip(filters, kernel_sizes)
        ])

        self.output_size = sum(filters)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Input [batch, seq_len, input_size]

        Returns:
            CNN features [batch, total_filters]
        """
        # Transpose for Conv1d: [batch, input_size, seq_len]
        x = x.transpose(1, 2)

        # Apply each conv layer and global max pool
        conv_outputs = []
        for conv in self.convs:
            out = conv(x)  # [batch, filters, seq_len]
            pooled = F.adaptive_max_pool1d(out, 1).squeeze(-1)  # [batch, filters]
            conv_outputs.append(pooled)

        # Concatenate all filter outputs
        return torch.cat(conv_outputs, dim=-1)


class AttentionLayer(nn.Module):
    """Self-attention layer for sequence weighting."""

    def __init__(self, hidden_size: int, num_heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.attention = nn.MultiheadAttention(
            embed_dim=hidden_size,
            num_heads=num_heads,
            dropout=dropout,
            batch_first=True,
        )
        self.norm = nn.LayerNorm(hidden_size)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Forward pass with self-attention.

        Args:
            x: Input [batch, seq_len, hidden_size]
            mask: Attention mask

        Returns:
            Attention-weighted output [batch, seq_len, hidden_size]
        """
        attn_out, _ = self.attention(x, x, x, key_padding_mask=mask)
        return self.norm(x + attn_out)


class DGADetectorModel(nn.Module, LoggerMixin):
    """Hybrid LSTM + CNN model for DGA detection.

    Architecture:
    1. Character embedding with position encoding
    2. Bidirectional LSTM for sequential patterns
    3. CNN for local n-gram patterns
    4. Optional attention mechanism
    5. Statistical feature fusion
    6. Classification heads (binary + family)
    """

    def __init__(self, config: DGAConfig):
        super().__init__()
        self.config = config

        # Character embedding
        self.embedding = CharacterEmbedding(
            vocab_size=config.vocab_size,
            embedding_dim=config.embedding_dim,
            max_length=config.max_domain_length,
            dropout=config.dropout,
        )

        # LSTM encoder
        lstm_input_size = config.embedding_dim
        self.lstm = BiLSTMEncoder(
            input_size=lstm_input_size,
            hidden_size=config.lstm_hidden_size,
            num_layers=config.lstm_num_layers,
            dropout=config.lstm_dropout,
            bidirectional=config.lstm_bidirectional,
        )

        # CNN encoder
        lstm_output_size = config.lstm_hidden_size * (2 if config.lstm_bidirectional else 1)
        self.cnn = CNNEncoder(
            input_size=lstm_output_size,
            filters=config.cnn_filters,
            kernel_sizes=config.cnn_kernel_sizes,
            dropout=config.cnn_dropout,
        )

        # Optional attention
        if config.use_attention:
            self.attention = AttentionLayer(
                hidden_size=lstm_output_size,
                num_heads=config.attention_heads,
                dropout=config.dropout,
            )
        else:
            self.attention = None

        # Feature fusion
        cnn_output_size = self.cnn.output_size
        combined_size = lstm_output_size + cnn_output_size

        if config.use_statistical_features:
            combined_size += config.statistical_feature_dim

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(combined_size, config.hidden_size),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_size, config.hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(config.dropout),
            nn.Linear(config.hidden_size // 2, config.num_classes),
        )

        # Family classification head (multi-task)
        if config.predict_family:
            self.family_classifier = nn.Sequential(
                nn.Linear(combined_size, config.hidden_size),
                nn.ReLU(),
                nn.Dropout(config.dropout),
                nn.Linear(config.hidden_size, config.num_families),
            )
        else:
            self.family_classifier = None

        # Initialize weights
        self.apply(self._init_weights)

    def _init_weights(self, module: nn.Module) -> None:
        """Initialize weights."""
        if isinstance(module, nn.Linear):
            nn.init.xavier_uniform_(module.weight)
            if module.bias is not None:
                nn.init.zeros_(module.bias)
        elif isinstance(module, nn.Embedding):
            nn.init.normal_(module.weight, mean=0, std=0.02)
            if module.padding_idx is not None:
                module.weight.data[module.padding_idx].zero_()
        elif isinstance(module, nn.LSTM):
            for name, param in module.named_parameters():
                if "weight" in name:
                    nn.init.orthogonal_(param)
                elif "bias" in name:
                    nn.init.zeros_(param)

    def forward(
        self,
        tokens: torch.Tensor,
        statistical_features: torch.Tensor | None = None,
        lengths: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        """Forward pass.

        Args:
            tokens: Token IDs [batch, seq_len]
            statistical_features: Statistical features [batch, stat_dim]
            lengths: Sequence lengths for packing

        Returns:
            Dictionary with logits and features
        """
        batch_size = tokens.size(0)

        # Create attention mask from tokens (padding = 0)
        mask = tokens == 0  # [batch, seq_len]

        # Character embeddings
        embeddings = self.embedding(tokens)  # [batch, seq_len, embed_dim]

        # LSTM encoding
        lstm_outputs, lstm_final = self.lstm(embeddings, lengths)
        # lstm_outputs: [batch, seq_len, lstm_hidden * 2]
        # lstm_final: [batch, lstm_hidden * 2]

        # Optional attention
        if self.attention is not None:
            lstm_outputs = self.attention(lstm_outputs, mask)
            # Use attention-weighted mean as final representation
            attention_mask = (~mask).float().unsqueeze(-1)
            lstm_pooled = (lstm_outputs * attention_mask).sum(dim=1) / attention_mask.sum(dim=1).clamp(min=1)
        else:
            lstm_pooled = lstm_final

        # CNN encoding
        cnn_features = self.cnn(lstm_outputs)  # [batch, cnn_output_size]

        # Combine features
        combined = torch.cat([lstm_pooled, cnn_features], dim=-1)

        if statistical_features is not None and self.config.use_statistical_features:
            combined = torch.cat([combined, statistical_features], dim=-1)

        # Classification
        logits = self.classifier(combined)

        outputs = {
            "logits": logits,
            "features": combined,
        }

        # Family classification
        if self.family_classifier is not None:
            outputs["family_logits"] = self.family_classifier(combined)

        return outputs

    def compute_loss(
        self,
        outputs: dict[str, torch.Tensor],
        labels: torch.Tensor,
        family_labels: torch.Tensor | None = None,
        class_weights: torch.Tensor | None = None,
    ) -> dict[str, torch.Tensor]:
        """Compute loss.

        Args:
            outputs: Model outputs
            labels: Binary labels (0=benign, 1=DGA)
            family_labels: DGA family labels (optional)
            class_weights: Class weights for imbalance

        Returns:
            Dictionary with losses
        """
        losses = {}

        # Binary classification loss
        if class_weights is not None:
            bce_loss = F.cross_entropy(outputs["logits"], labels, weight=class_weights)
        else:
            bce_loss = F.cross_entropy(outputs["logits"], labels)

        losses["binary_loss"] = bce_loss

        # Family classification loss (only for DGA samples)
        if self.family_classifier is not None and family_labels is not None:
            dga_mask = labels == 1
            if dga_mask.any():
                family_loss = F.cross_entropy(
                    outputs["family_logits"][dga_mask],
                    family_labels[dga_mask],
                )
                losses["family_loss"] = family_loss * self.config.family_weight

        # Total loss
        losses["total_loss"] = sum(losses.values())

        return losses


class DGADetector(LoggerMixin):
    """High-level DGA detector for inference."""

    FAMILY_LABELS = list(DGAFamily)

    def __init__(
        self,
        model_path: str | None = None,
        config: DGAConfig | None = None,
        inference_config: DGAInferenceConfig | None = None,
        device: str = "cpu",
    ):
        """Initialize DGA detector.

        Args:
            model_path: Path to model weights
            config: Model configuration
            inference_config: Inference configuration
            device: Inference device
        """
        self.model_path = model_path
        self.config = config or DGAConfig()
        self.inference_config = inference_config
        self.device = torch.device(device)

        self._model: DGADetectorModel | None = None
        self._tokenizer: DomainTokenizer | None = None
        self._feature_extractor: DGAFeatureExtractor | None = None
        self._allowlist: set[str] = set()
        self._blocklist: set[str] = set()
        self._is_loaded = False

    async def load_model(self) -> None:
        """Load the DGA detection model."""
        self.logger.info("loading_dga_model", model_path=self.model_path, device=str(self.device))

        # Initialize tokenizer and feature extractor
        self._tokenizer = DomainTokenizer(max_length=self.config.max_domain_length)
        self._feature_extractor = DGAFeatureExtractor(self._tokenizer)

        # Initialize model
        self._model = DGADetectorModel(self.config)

        if self.model_path:
            try:
                checkpoint = torch.load(self.model_path, map_location=self.device)
                if "model_state_dict" in checkpoint:
                    self._model.load_state_dict(checkpoint["model_state_dict"])
                else:
                    self._model.load_state_dict(checkpoint)
                self.logger.info("dga_model_weights_loaded")
            except FileNotFoundError:
                self.logger.warning("dga_model_not_found", path=self.model_path)
            except Exception as e:
                self.logger.error("dga_model_load_error", error=str(e))

        self._model = self._model.to(self.device)
        self._model.eval()

        # Load allowlist/blocklist
        if self.inference_config:
            await self._load_lists()

        self._is_loaded = True
        self.logger.info("dga_model_loaded", device=str(self.device))

    async def _load_lists(self) -> None:
        """Load allowlist and blocklist."""
        if self.inference_config.use_allowlist and self.inference_config.allowlist_path:
            try:
                with open(self.inference_config.allowlist_path) as f:
                    self._allowlist = {line.strip().lower() for line in f if line.strip()}
                self.logger.info("allowlist_loaded", count=len(self._allowlist))
            except FileNotFoundError:
                self.logger.warning("allowlist_not_found")

        if self.inference_config.use_blocklist and self.inference_config.blocklist_path:
            try:
                with open(self.inference_config.blocklist_path) as f:
                    self._blocklist = {line.strip().lower() for line in f if line.strip()}
                self.logger.info("blocklist_loaded", count=len(self._blocklist))
            except FileNotFoundError:
                self.logger.warning("blocklist_not_found")

    async def detect(self, domain: str) -> DGAClassification:
        """Detect if a domain is DGA-generated.

        Args:
            domain: Domain name to check

        Returns:
            DGA classification result
        """
        if not self._is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        domain_clean = domain.lower().strip()

        # Check allowlist
        if domain_clean in self._allowlist:
            return self._create_benign_result(domain, "Domain is allowlisted")

        # Check blocklist
        if domain_clean in self._blocklist:
            return self._create_dga_result(
                domain,
                confidence=1.0,
                family="unknown",
                explanation="Domain is blocklisted",
            )

        # Extract features
        features = self._feature_extractor.extract_features(domain)
        tensors = self._feature_extractor.to_tensor(features, str(self.device))

        # Run inference
        with torch.no_grad():
            outputs = self._model(
                tokens=tensors["tokens"].unsqueeze(0),
                statistical_features=tensors["statistical_features"].unsqueeze(0),
            )

        # Process outputs
        probs = F.softmax(outputs["logits"], dim=-1)
        dga_prob = probs[0, 1].item()
        is_dga = dga_prob > (
            self.inference_config.dga_threshold if self.inference_config else 0.5
        )

        # Get family prediction if DGA
        family = "unknown"
        family_confidence = 0.0
        if is_dga and "family_logits" in outputs:
            family_probs = F.softmax(outputs["family_logits"], dim=-1)
            family_idx = family_probs.argmax(dim=-1).item()
            family_confidence = family_probs[0, family_idx].item()
            family = self.FAMILY_LABELS[family_idx].value

        # Build explanation
        explanation = self._build_explanation(
            domain=domain,
            is_dga=is_dga,
            confidence=dga_prob,
            features=features,
        )

        # Risk level
        risk_level = self._get_risk_level(dga_prob)

        # Key features for response
        stats = features["statistics"]
        key_features = {
            "entropy": round(stats.entropy, 3),
            "length": stats.length,
            "digit_ratio": round(stats.digit_ratio, 3),
            "consonant_ratio": round(stats.consonant_ratio, 3),
            "unique_char_ratio": round(stats.unique_char_ratio, 3),
        }

        return DGAClassification(
            domain=domain,
            is_dga=is_dga,
            confidence=dga_prob,
            family=family,
            family_confidence=family_confidence,
            risk_level=risk_level,
            features=key_features,
            explanation=explanation,
        )

    async def batch_detect(
        self,
        domains: list[str],
    ) -> DGABatchResult:
        """Detect DGA for multiple domains.

        Args:
            domains: List of domains to check

        Returns:
            Batch detection results
        """
        import time

        if not self._is_loaded:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        start_time = time.perf_counter()
        results = []
        batch_size = self.inference_config.max_batch_size if self.inference_config else 512

        for i in range(0, len(domains), batch_size):
            batch = domains[i : i + batch_size]
            batch_results = await self._detect_batch(batch)
            results.extend(batch_results)

        processing_time = (time.perf_counter() - start_time) * 1000
        dga_count = sum(1 for r in results if r.is_dga)

        return DGABatchResult(
            results=results,
            total_count=len(results),
            dga_count=dga_count,
            processing_time_ms=processing_time,
        )

    async def _detect_batch(
        self,
        domains: list[str],
    ) -> list[DGAClassification]:
        """Detect DGA for a batch of domains."""
        results = []

        # Pre-filter with lists
        to_process = []
        list_results = {}

        for domain in domains:
            domain_clean = domain.lower().strip()
            if domain_clean in self._allowlist:
                list_results[domain] = self._create_benign_result(domain, "Allowlisted")
            elif domain_clean in self._blocklist:
                list_results[domain] = self._create_dga_result(
                    domain, 1.0, "unknown", "Blocklisted"
                )
            else:
                to_process.append(domain)

        # Batch inference
        if to_process:
            features_batch = self._feature_extractor.batch_extract(to_process, str(self.device))

            with torch.no_grad():
                outputs = self._model(
                    tokens=features_batch["tokens"],
                    statistical_features=features_batch["statistical_features"],
                )

            probs = F.softmax(outputs["logits"], dim=-1)
            family_probs = None
            if "family_logits" in outputs:
                family_probs = F.softmax(outputs["family_logits"], dim=-1)

            for idx, domain in enumerate(to_process):
                dga_prob = probs[idx, 1].item()
                is_dga = dga_prob > (
                    self.inference_config.dga_threshold if self.inference_config else 0.5
                )

                family = "unknown"
                family_conf = 0.0
                if is_dga and family_probs is not None:
                    family_idx = family_probs[idx].argmax().item()
                    family_conf = family_probs[idx, family_idx].item()
                    family = self.FAMILY_LABELS[family_idx].value

                results.append(DGAClassification(
                    domain=domain,
                    is_dga=is_dga,
                    confidence=dga_prob,
                    family=family,
                    family_confidence=family_conf,
                    risk_level=self._get_risk_level(dga_prob),
                    features={},
                    explanation=f"{'DGA detected' if is_dga else 'Benign domain'} ({dga_prob:.1%})",
                ))

        # Add list results back
        for domain in domains:
            if domain in list_results:
                results.append(list_results[domain])

        # Reorder to match input
        result_map = {r.domain: r for r in results}
        return [result_map[d] for d in domains]

    def _create_benign_result(self, domain: str, reason: str) -> DGAClassification:
        """Create benign classification result."""
        return DGAClassification(
            domain=domain,
            is_dga=False,
            confidence=0.0,
            family="unknown",
            family_confidence=0.0,
            risk_level="low",
            features={},
            explanation=reason,
        )

    def _create_dga_result(
        self,
        domain: str,
        confidence: float,
        family: str,
        explanation: str,
    ) -> DGAClassification:
        """Create DGA classification result."""
        return DGAClassification(
            domain=domain,
            is_dga=True,
            confidence=confidence,
            family=family,
            family_confidence=0.0,
            risk_level="critical",
            features={},
            explanation=explanation,
        )

    def _get_risk_level(self, probability: float) -> str:
        """Get risk level from DGA probability."""
        if probability >= 0.9:
            return "critical"
        elif probability >= 0.7:
            return "high"
        elif probability >= 0.5:
            return "medium"
        else:
            return "low"

    def _build_explanation(
        self,
        domain: str,
        is_dga: bool,
        confidence: float,
        features: dict[str, Any],
    ) -> str:
        """Build human-readable explanation."""
        stats = features["statistics"]

        if not is_dga:
            return f"Domain '{domain}' appears to be legitimate ({1-confidence:.1%} confidence)."

        reasons = []

        if stats.entropy > 3.5:
            reasons.append(f"high entropy ({stats.entropy:.2f})")

        if stats.consonant_ratio > 0.7:
            reasons.append(f"unusual consonant ratio ({stats.consonant_ratio:.1%})")

        if stats.digit_ratio > 0.3:
            reasons.append(f"high digit ratio ({stats.digit_ratio:.1%})")

        if stats.consecutive_consonants_max > 5:
            reasons.append(f"long consonant sequences ({stats.consecutive_consonants_max})")

        if stats.unique_char_ratio > 0.9:
            reasons.append("high character variety")

        if not reasons:
            reasons.append("pattern analysis")

        reason_str = ", ".join(reasons)
        return f"Domain '{domain}' detected as DGA ({confidence:.1%} confidence). Indicators: {reason_str}."
