"""UEBA Model - Transformer-based Autoencoder for behavior anomaly detection."""

from __future__ import annotations

import math
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class UEBAConfig(BaseModel):
    """Configuration for UEBA model."""

    # Input dimensions
    input_dim: int = Field(default=128, description="Input feature dimension")
    sequence_length: int = Field(default=24, description="Sequence length (hours)")

    # Transformer config
    d_model: int = Field(default=256, description="Model dimension")
    nhead: int = Field(default=8, description="Number of attention heads")
    num_encoder_layers: int = Field(default=4, description="Number of encoder layers")
    num_decoder_layers: int = Field(default=4, description="Number of decoder layers")
    dim_feedforward: int = Field(default=512, description="Feedforward dimension")
    dropout: float = Field(default=0.1, description="Dropout rate")

    # Latent space
    latent_dim: int = Field(default=64, description="Latent space dimension")

    # Training config
    learning_rate: float = Field(default=1e-4, description="Learning rate")
    batch_size: int = Field(default=64, description="Batch size")

    # Anomaly detection
    anomaly_threshold: float = Field(default=0.95, description="Percentile threshold")
    min_samples_for_profile: int = Field(default=168, description="Min samples (1 week hourly)")


class PositionalEncoding(nn.Module):
    """Positional encoding for transformer."""

    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        pe = torch.zeros(max_len, 1, d_model)
        pe[:, 0, 0::2] = torch.sin(position * div_term)
        pe[:, 0, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Add positional encoding to input.

        Args:
            x: Input tensor of shape (seq_len, batch, d_model)

        Returns:
            Tensor with positional encoding added
        """
        x = x + self.pe[:x.size(0)]
        return self.dropout(x)


class TransformerEncoder(nn.Module):
    """Transformer encoder for sequence representation."""

    def __init__(self, config: UEBAConfig):
        super().__init__()
        self.config = config

        # Input projection
        self.input_projection = nn.Linear(config.input_dim, config.d_model)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(
            config.d_model,
            max_len=config.sequence_length,
            dropout=config.dropout,
        )

        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.nhead,
            dim_feedforward=config.dim_feedforward,
            dropout=config.dropout,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=config.num_encoder_layers,
        )

        # Latent projection
        self.latent_projection = nn.Sequential(
            nn.Linear(config.d_model, config.latent_dim * 2),
            nn.LayerNorm(config.latent_dim * 2),
            nn.GELU(),
            nn.Linear(config.latent_dim * 2, config.latent_dim),
        )

    def forward(
        self,
        x: torch.Tensor,
        src_mask: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Encode input sequence to latent space.

        Args:
            x: Input tensor of shape (batch, seq_len, input_dim)
            src_mask: Optional attention mask

        Returns:
            Latent representation of shape (batch, latent_dim)
        """
        # Project input to model dimension
        x = self.input_projection(x)  # (batch, seq_len, d_model)

        # Add positional encoding (needs seq_len first)
        x = x.transpose(0, 1)  # (seq_len, batch, d_model)
        x = self.pos_encoder(x)
        x = x.transpose(0, 1)  # (batch, seq_len, d_model)

        # Transformer encoding
        encoded = self.transformer_encoder(x, src_key_padding_mask=src_mask)

        # Pool to single vector (mean pooling)
        pooled = encoded.mean(dim=1)  # (batch, d_model)

        # Project to latent space
        latent = self.latent_projection(pooled)  # (batch, latent_dim)

        return latent


class TransformerDecoder(nn.Module):
    """Transformer decoder for sequence reconstruction."""

    def __init__(self, config: UEBAConfig):
        super().__init__()
        self.config = config

        # Latent to sequence projection
        self.latent_to_seq = nn.Linear(config.latent_dim, config.d_model * config.sequence_length)

        # Positional encoding
        self.pos_encoder = PositionalEncoding(
            config.d_model,
            max_len=config.sequence_length,
            dropout=config.dropout,
        )

        # Transformer decoder layers (self-attention only for generation)
        decoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.nhead,
            dim_feedforward=config.dim_feedforward,
            dropout=config.dropout,
            batch_first=True,
        )
        self.transformer_decoder = nn.TransformerEncoder(
            decoder_layer,
            num_layers=config.num_decoder_layers,
        )

        # Output projection
        self.output_projection = nn.Sequential(
            nn.Linear(config.d_model, config.d_model),
            nn.LayerNorm(config.d_model),
            nn.GELU(),
            nn.Linear(config.d_model, config.input_dim),
        )

    def forward(self, latent: torch.Tensor) -> torch.Tensor:
        """Decode latent representation to sequence.

        Args:
            latent: Latent tensor of shape (batch, latent_dim)

        Returns:
            Reconstructed sequence of shape (batch, seq_len, input_dim)
        """
        batch_size = latent.size(0)

        # Expand latent to sequence
        seq = self.latent_to_seq(latent)  # (batch, d_model * seq_len)
        seq = seq.view(batch_size, self.config.sequence_length, self.config.d_model)

        # Add positional encoding
        seq = seq.transpose(0, 1)  # (seq_len, batch, d_model)
        seq = self.pos_encoder(seq)
        seq = seq.transpose(0, 1)  # (batch, seq_len, d_model)

        # Transformer decoding
        decoded = self.transformer_decoder(seq)  # (batch, seq_len, d_model)

        # Project to output dimension
        output = self.output_projection(decoded)  # (batch, seq_len, input_dim)

        return output


class UEBAModel(nn.Module, LoggerMixin):
    """Transformer-based Autoencoder for User and Entity Behavior Analytics.

    Architecture:
    - Transformer Encoder: Encodes behavior sequences to latent space
    - Transformer Decoder: Reconstructs sequences from latent space
    - Anomaly detection via reconstruction error

    Features:
    - Temporal attention for time-series patterns
    - Multi-head attention for complex behaviors
    - Reconstruction-based anomaly scoring
    """

    def __init__(self, config: UEBAConfig | None = None):
        super().__init__()
        self.config = config or UEBAConfig()

        # Encoder and decoder
        self.encoder = TransformerEncoder(self.config)
        self.decoder = TransformerDecoder(self.config)

        # Anomaly threshold (learned during training)
        self.register_buffer('reconstruction_threshold', torch.tensor(0.0))
        self.register_buffer('running_mean', torch.tensor(0.0))
        self.register_buffer('running_std', torch.tensor(1.0))

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Forward pass through autoencoder.

        Args:
            x: Input sequence of shape (batch, seq_len, input_dim)
            mask: Optional attention mask

        Returns:
            Tuple of (reconstructed sequence, latent representation)
        """
        # Encode to latent space
        latent = self.encoder(x, mask)

        # Decode back to sequence
        reconstructed = self.decoder(latent)

        return reconstructed, latent

    def compute_reconstruction_error(
        self,
        x: torch.Tensor,
        x_reconstructed: torch.Tensor,
        reduction: str = "mean",
    ) -> torch.Tensor:
        """Compute reconstruction error.

        Args:
            x: Original sequence
            x_reconstructed: Reconstructed sequence
            reduction: Reduction method ('mean', 'sum', 'none')

        Returns:
            Reconstruction error
        """
        # Mean squared error per sample
        mse = F.mse_loss(x_reconstructed, x, reduction='none')

        if reduction == "none":
            return mse.mean(dim=(1, 2))  # Per-sample error
        elif reduction == "sum":
            return mse.sum()
        else:  # mean
            return mse.mean()

    def compute_anomaly_score(
        self,
        x: torch.Tensor,
        normalize: bool = True,
    ) -> torch.Tensor:
        """Compute anomaly score for input sequences.

        Args:
            x: Input sequences of shape (batch, seq_len, input_dim)
            normalize: Whether to normalize scores using running statistics

        Returns:
            Anomaly scores for each sample
        """
        self.eval()
        with torch.no_grad():
            reconstructed, _ = self.forward(x)
            errors = self.compute_reconstruction_error(x, reconstructed, reduction="none")

            if normalize:
                # Z-score normalization
                scores = (errors - self.running_mean) / (self.running_std + 1e-8)
            else:
                scores = errors

        return scores

    def detect_anomalies(
        self,
        x: torch.Tensor,
        threshold: float | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Detect anomalies in input sequences.

        Args:
            x: Input sequences
            threshold: Optional custom threshold (uses learned if None)

        Returns:
            Tuple of (is_anomaly mask, anomaly scores)
        """
        scores = self.compute_anomaly_score(x)
        threshold = threshold if threshold is not None else self.reconstruction_threshold.item()
        is_anomaly = scores > threshold
        return is_anomaly, scores

    def update_statistics(self, errors: torch.Tensor) -> None:
        """Update running statistics for normalization.

        Args:
            errors: Batch of reconstruction errors
        """
        momentum = 0.1
        batch_mean = errors.mean()
        batch_std = errors.std()

        self.running_mean = (1 - momentum) * self.running_mean + momentum * batch_mean
        self.running_std = (1 - momentum) * self.running_std + momentum * batch_std

    def set_threshold(self, percentile_value: float) -> None:
        """Set anomaly threshold based on percentile.

        Args:
            percentile_value: Threshold value at the configured percentile
        """
        self.reconstruction_threshold.fill_(percentile_value)

    def training_step(self, batch: torch.Tensor) -> dict[str, torch.Tensor]:
        """Perform a training step.

        Args:
            batch: Input batch of shape (batch, seq_len, input_dim)

        Returns:
            Dictionary with loss and metrics
        """
        reconstructed, latent = self.forward(batch)

        # Reconstruction loss
        recon_loss = self.compute_reconstruction_error(batch, reconstructed)

        # KL-like regularization on latent (optional)
        latent_reg = 0.01 * (latent ** 2).mean()

        total_loss = recon_loss + latent_reg

        # Update statistics
        with torch.no_grad():
            errors = self.compute_reconstruction_error(batch, reconstructed, reduction="none")
            self.update_statistics(errors)

        return {
            "loss": total_loss,
            "recon_loss": recon_loss,
            "latent_reg": latent_reg,
        }


class UEBAModelWrapper(LoggerMixin):
    """High-level wrapper for UEBA model with training and inference utilities."""

    def __init__(
        self,
        config: UEBAConfig | None = None,
        device: str = "cuda" if torch.cuda.is_available() else "cpu",
    ):
        """Initialize wrapper.

        Args:
            config: Model configuration
            device: Device to use for inference
        """
        self.config = config or UEBAConfig()
        self.device = device
        self.model = UEBAModel(self.config).to(device)
        self.optimizer: torch.optim.Optimizer | None = None

    def train(
        self,
        train_data: torch.Tensor,
        epochs: int = 100,
        validation_data: torch.Tensor | None = None,
    ) -> list[dict[str, float]]:
        """Train the model.

        Args:
            train_data: Training data of shape (n_samples, seq_len, input_dim)
            epochs: Number of training epochs
            validation_data: Optional validation data

        Returns:
            Training history
        """
        self.model.train()
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.config.learning_rate,
        )

        # Create data loader
        dataset = torch.utils.data.TensorDataset(train_data)
        loader = torch.utils.data.DataLoader(
            dataset,
            batch_size=self.config.batch_size,
            shuffle=True,
        )

        history = []
        for epoch in range(epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                batch = batch.to(self.device)

                self.optimizer.zero_grad()
                metrics = self.model.training_step(batch)
                metrics["loss"].backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

                self.optimizer.step()
                epoch_loss += metrics["loss"].item()

            avg_loss = epoch_loss / len(loader)

            # Validation
            val_loss = None
            if validation_data is not None:
                val_loss = self._validate(validation_data)

            self.logger.info(
                "training_epoch",
                epoch=epoch + 1,
                train_loss=avg_loss,
                val_loss=val_loss,
            )

            history.append({
                "epoch": epoch + 1,
                "train_loss": avg_loss,
                "val_loss": val_loss,
            })

        # Set anomaly threshold
        self._calibrate_threshold(train_data)

        return history

    def _validate(self, data: torch.Tensor) -> float:
        """Validate model on data."""
        self.model.eval()
        with torch.no_grad():
            data = data.to(self.device)
            reconstructed, _ = self.model(data)
            loss = self.model.compute_reconstruction_error(data, reconstructed)
        self.model.train()
        return loss.item()

    def _calibrate_threshold(self, data: torch.Tensor) -> None:
        """Calibrate anomaly threshold on training data."""
        self.model.eval()
        with torch.no_grad():
            data = data.to(self.device)
            scores = self.model.compute_anomaly_score(data, normalize=False)
            percentile = self.config.anomaly_threshold * 100
            threshold = torch.quantile(scores, self.config.anomaly_threshold)
            self.model.set_threshold(threshold.item())

        self.logger.info(
            "threshold_calibrated",
            percentile=percentile,
            threshold=threshold.item(),
        )

    def predict(self, data: torch.Tensor) -> dict[str, Any]:
        """Make predictions on new data.

        Args:
            data: Input data of shape (n_samples, seq_len, input_dim)

        Returns:
            Dictionary with predictions
        """
        self.model.eval()
        data = data.to(self.device)

        is_anomaly, scores = self.model.detect_anomalies(data)

        return {
            "is_anomaly": is_anomaly.cpu().numpy(),
            "anomaly_scores": scores.cpu().numpy(),
            "threshold": self.model.reconstruction_threshold.item(),
        }

    def save(self, path: str) -> None:
        """Save model to path."""
        torch.save({
            "config": self.config.model_dump(),
            "model_state": self.model.state_dict(),
        }, path)
        self.logger.info("model_saved", path=path)

    def load(self, path: str) -> None:
        """Load model from path."""
        checkpoint = torch.load(path, map_location=self.device)
        self.config = UEBAConfig(**checkpoint["config"])
        self.model = UEBAModel(self.config).to(self.device)
        self.model.load_state_dict(checkpoint["model_state"])
        self.logger.info("model_loaded", path=path)
