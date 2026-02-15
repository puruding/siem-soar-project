"""Optimizer and scheduler configuration."""

from typing import Any

import torch
import torch.nn as nn
from torch.optim import AdamW, Adam, SGD
from torch.optim.lr_scheduler import (
    CosineAnnealingLR,
    OneCycleLR,
    LinearLR,
    SequentialLR,
)


def create_optimizer(
    model: nn.Module,
    optimizer_type: str = "adamw",
    lr: float = 2e-5,
    weight_decay: float = 0.01,
    betas: tuple[float, float] = (0.9, 0.999),
    eps: float = 1e-8,
    no_decay_params: list[str] | None = None,
) -> torch.optim.Optimizer:
    """Create optimizer with weight decay handling.

    Args:
        model: Model to optimize
        optimizer_type: Type of optimizer ("adamw", "adam", "sgd")
        lr: Learning rate
        weight_decay: Weight decay factor
        betas: Adam beta parameters
        eps: Adam epsilon
        no_decay_params: Parameter names that should not have weight decay

    Returns:
        Configured optimizer
    """
    no_decay_params = no_decay_params or ["bias", "LayerNorm.weight", "layer_norm.weight"]

    # Separate parameters into decay and no-decay groups
    optimizer_grouped_params = [
        {
            "params": [
                p for n, p in model.named_parameters()
                if not any(nd in n for nd in no_decay_params) and p.requires_grad
            ],
            "weight_decay": weight_decay,
        },
        {
            "params": [
                p for n, p in model.named_parameters()
                if any(nd in n for nd in no_decay_params) and p.requires_grad
            ],
            "weight_decay": 0.0,
        },
    ]

    if optimizer_type.lower() == "adamw":
        optimizer = AdamW(
            optimizer_grouped_params,
            lr=lr,
            betas=betas,
            eps=eps,
        )
    elif optimizer_type.lower() == "adam":
        optimizer = Adam(
            optimizer_grouped_params,
            lr=lr,
            betas=betas,
            eps=eps,
        )
    elif optimizer_type.lower() == "sgd":
        optimizer = SGD(
            optimizer_grouped_params,
            lr=lr,
            momentum=0.9,
            nesterov=True,
        )
    else:
        raise ValueError(f"Unknown optimizer type: {optimizer_type}")

    return optimizer


def create_scheduler(
    optimizer: torch.optim.Optimizer,
    num_training_steps: int,
    warmup_ratio: float = 0.1,
    scheduler_type: str = "linear_warmup_cosine",
    num_cycles: float = 0.5,
    min_lr_ratio: float = 0.1,
) -> Any:
    """Create learning rate scheduler.

    Args:
        optimizer: Optimizer instance
        num_training_steps: Total number of training steps
        warmup_ratio: Ratio of warmup steps
        scheduler_type: Type of scheduler
        num_cycles: Number of cosine cycles (for cosine scheduler)
        min_lr_ratio: Minimum LR as ratio of initial LR

    Returns:
        Configured scheduler
    """
    warmup_steps = int(num_training_steps * warmup_ratio)

    if scheduler_type == "linear_warmup_cosine":
        # Linear warmup followed by cosine decay
        warmup_scheduler = LinearLR(
            optimizer,
            start_factor=0.01,
            end_factor=1.0,
            total_iters=warmup_steps,
        )

        cosine_scheduler = CosineAnnealingLR(
            optimizer,
            T_max=num_training_steps - warmup_steps,
            eta_min=optimizer.defaults["lr"] * min_lr_ratio,
        )

        scheduler = SequentialLR(
            optimizer,
            schedulers=[warmup_scheduler, cosine_scheduler],
            milestones=[warmup_steps],
        )

    elif scheduler_type == "one_cycle":
        # One cycle LR policy
        scheduler = OneCycleLR(
            optimizer,
            max_lr=optimizer.defaults["lr"],
            total_steps=num_training_steps,
            pct_start=warmup_ratio,
            anneal_strategy="cos",
            div_factor=25.0,
            final_div_factor=1e4,
        )

    elif scheduler_type == "cosine":
        # Cosine annealing with warm restarts
        from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts

        scheduler = CosineAnnealingWarmRestarts(
            optimizer,
            T_0=num_training_steps // int(1 / num_cycles) if num_cycles > 0 else num_training_steps,
            T_mult=1,
            eta_min=optimizer.defaults["lr"] * min_lr_ratio,
        )

    elif scheduler_type == "linear":
        # Linear decay with warmup
        warmup_scheduler = LinearLR(
            optimizer,
            start_factor=0.01,
            end_factor=1.0,
            total_iters=warmup_steps,
        )

        decay_scheduler = LinearLR(
            optimizer,
            start_factor=1.0,
            end_factor=min_lr_ratio,
            total_iters=num_training_steps - warmup_steps,
        )

        scheduler = SequentialLR(
            optimizer,
            schedulers=[warmup_scheduler, decay_scheduler],
            milestones=[warmup_steps],
        )

    elif scheduler_type == "constant":
        # Constant LR with warmup
        warmup_scheduler = LinearLR(
            optimizer,
            start_factor=0.01,
            end_factor=1.0,
            total_iters=warmup_steps,
        )

        constant_scheduler = LinearLR(
            optimizer,
            start_factor=1.0,
            end_factor=1.0,
            total_iters=num_training_steps - warmup_steps,
        )

        scheduler = SequentialLR(
            optimizer,
            schedulers=[warmup_scheduler, constant_scheduler],
            milestones=[warmup_steps],
        )

    else:
        raise ValueError(f"Unknown scheduler type: {scheduler_type}")

    return scheduler


def get_layer_wise_lr_decay(
    model: nn.Module,
    base_lr: float,
    decay_rate: float = 0.95,
) -> list[dict[str, Any]]:
    """Get layer-wise learning rate decay parameter groups.

    Args:
        model: Model with transformer layers
        base_lr: Base learning rate for top layer
        decay_rate: LR decay rate per layer (lower layers get smaller LR)

    Returns:
        List of parameter groups with decayed learning rates
    """
    param_groups = []
    num_layers = 0

    # Find number of layers
    for name, _ in model.named_parameters():
        if "layer." in name or "layers." in name:
            # Extract layer number
            parts = name.split(".")
            for i, part in enumerate(parts):
                if part in ("layer", "layers") and i + 1 < len(parts):
                    try:
                        layer_num = int(parts[i + 1])
                        num_layers = max(num_layers, layer_num + 1)
                    except ValueError:
                        pass

    # Create parameter groups
    for name, param in model.named_parameters():
        if not param.requires_grad:
            continue

        layer_num = num_layers  # Default to top layer

        # Extract layer number
        if "layer." in name or "layers." in name:
            parts = name.split(".")
            for i, part in enumerate(parts):
                if part in ("layer", "layers") and i + 1 < len(parts):
                    try:
                        layer_num = int(parts[i + 1])
                        break
                    except ValueError:
                        pass

        # Calculate decayed LR
        lr = base_lr * (decay_rate ** (num_layers - layer_num - 1))

        param_groups.append({
            "params": [param],
            "lr": lr,
            "name": name,
        })

    return param_groups
