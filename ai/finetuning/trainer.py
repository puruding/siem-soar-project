"""Korean security domain fine-tuning trainer."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .dataset import SecurityDataset, TrainingExample


class TrainingConfig(BaseModel):
    """Configuration for fine-tuning."""

    # Model
    base_model: str = Field(default="upstage/SOLAR-10.7B-Instruct-v1.0")
    output_dir: str = Field(default="./models/solar-security-ko")

    # LoRA/QLoRA
    use_lora: bool = Field(default=True)
    lora_r: int = Field(default=64)
    lora_alpha: int = Field(default=128)
    lora_dropout: float = Field(default=0.05)
    target_modules: list[str] = Field(
        default_factory=lambda: ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
    )
    use_4bit: bool = Field(default=True, description="Use 4-bit quantization (QLoRA)")

    # Training
    num_epochs: int = Field(default=3)
    batch_size: int = Field(default=4)
    gradient_accumulation_steps: int = Field(default=4)
    learning_rate: float = Field(default=2e-5)
    weight_decay: float = Field(default=0.01)
    warmup_ratio: float = Field(default=0.1)
    max_seq_length: int = Field(default=2048)

    # Optimization
    fp16: bool = Field(default=True)
    bf16: bool = Field(default=False)
    gradient_checkpointing: bool = Field(default=True)
    optim: str = Field(default="paged_adamw_32bit")

    # Evaluation
    eval_steps: int = Field(default=100)
    save_steps: int = Field(default=500)
    logging_steps: int = Field(default=10)
    save_total_limit: int = Field(default=3)

    # Data
    train_split: float = Field(default=0.9)
    seed: int = Field(default=42)


class TrainingMetrics(BaseModel):
    """Training metrics."""

    epoch: int = Field(description="Current epoch")
    step: int = Field(description="Current step")
    train_loss: float = Field(description="Training loss")
    eval_loss: float | None = Field(default=None)
    learning_rate: float | None = Field(default=None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class KoreanSecurityTrainer(LoggerMixin):
    """Trainer for Korean security domain fine-tuning.

    Features:
    - QLoRA fine-tuning for memory efficiency
    - Korean-English bilingual training
    - Security domain specialization
    - Evaluation on security tasks
    """

    # Chat template for SOLAR model
    CHAT_TEMPLATE = """### System:
당신은 보안 분석 전문가입니다. 사용자의 보안 관련 질문에 정확하고 전문적으로 답변하세요.

### User:
{instruction}

{input}

### Assistant:
{output}"""

    def __init__(self, config: TrainingConfig | None = None) -> None:
        """Initialize the trainer.

        Args:
            config: Training configuration
        """
        self.config = config or TrainingConfig()
        self._model = None
        self._tokenizer = None
        self._trainer = None
        self._metrics_history: list[TrainingMetrics] = []

    def prepare_training_data(
        self,
        dataset: SecurityDataset,
    ) -> tuple[Any, Any]:
        """Prepare training data.

        Args:
            dataset: Security dataset

        Returns:
            Tuple of (train_dataset, eval_dataset)
        """
        self.logger.info("preparing_training_data", examples=len(dataset))

        train_examples, eval_examples = dataset.get_train_test_split()

        # Format for training
        train_data = self._format_examples(train_examples)
        eval_data = self._format_examples(eval_examples)

        self.logger.info(
            "data_prepared",
            train_size=len(train_data),
            eval_size=len(eval_data),
        )

        return train_data, eval_data

    def _format_examples(self, examples: list[TrainingExample]) -> list[dict[str, str]]:
        """Format examples for training."""
        formatted = []

        for ex in examples:
            text = self.CHAT_TEMPLATE.format(
                instruction=ex.instruction,
                input=ex.input_text,
                output=ex.output_text,
            )
            formatted.append({"text": text})

        return formatted

    def setup_model(self) -> None:
        """Setup model and tokenizer for training."""
        try:
            import torch
            from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
            from transformers import (
                AutoModelForCausalLM,
                AutoTokenizer,
                BitsAndBytesConfig,
            )
        except ImportError as e:
            raise ImportError(
                "Install: pip install torch transformers peft bitsandbytes accelerate"
            ) from e

        self.logger.info("setting_up_model", model=self.config.base_model)

        # Quantization config for QLoRA
        if self.config.use_4bit:
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
        else:
            bnb_config = None

        # Load model
        self._model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )

        # Load tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(
            self.config.base_model,
            trust_remote_code=True,
        )
        self._tokenizer.pad_token = self._tokenizer.eos_token
        self._tokenizer.padding_side = "right"

        # Prepare for k-bit training
        if self.config.use_4bit:
            self._model = prepare_model_for_kbit_training(self._model)

        # Setup LoRA
        if self.config.use_lora:
            lora_config = LoraConfig(
                r=self.config.lora_r,
                lora_alpha=self.config.lora_alpha,
                lora_dropout=self.config.lora_dropout,
                target_modules=self.config.target_modules,
                bias="none",
                task_type="CAUSAL_LM",
            )
            self._model = get_peft_model(self._model, lora_config)

            # Log trainable parameters
            trainable = sum(p.numel() for p in self._model.parameters() if p.requires_grad)
            total = sum(p.numel() for p in self._model.parameters())
            self.logger.info(
                "lora_setup",
                trainable_params=trainable,
                total_params=total,
                trainable_percent=f"{100 * trainable / total:.2f}%",
            )

    def train(
        self,
        train_data: list[dict[str, str]],
        eval_data: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Train the model.

        Args:
            train_data: Training data
            eval_data: Evaluation data

        Returns:
            Training results
        """
        try:
            from datasets import Dataset
            from transformers import (
                DataCollatorForLanguageModeling,
                Trainer,
                TrainingArguments,
            )
            from trl import SFTTrainer
        except ImportError as e:
            raise ImportError("Install: pip install datasets trl") from e

        if self._model is None or self._tokenizer is None:
            self.setup_model()

        self.logger.info("starting_training", epochs=self.config.num_epochs)

        # Convert to HuggingFace Dataset
        train_dataset = Dataset.from_list(train_data)
        eval_dataset = Dataset.from_list(eval_data) if eval_data else None

        # Training arguments
        training_args = TrainingArguments(
            output_dir=self.config.output_dir,
            num_train_epochs=self.config.num_epochs,
            per_device_train_batch_size=self.config.batch_size,
            gradient_accumulation_steps=self.config.gradient_accumulation_steps,
            learning_rate=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
            warmup_ratio=self.config.warmup_ratio,
            fp16=self.config.fp16,
            bf16=self.config.bf16,
            gradient_checkpointing=self.config.gradient_checkpointing,
            optim=self.config.optim,
            evaluation_strategy="steps" if eval_dataset else "no",
            eval_steps=self.config.eval_steps if eval_dataset else None,
            save_steps=self.config.save_steps,
            logging_steps=self.config.logging_steps,
            save_total_limit=self.config.save_total_limit,
            load_best_model_at_end=eval_dataset is not None,
            report_to=["tensorboard"],
            seed=self.config.seed,
            max_grad_norm=0.3,
            lr_scheduler_type="cosine",
        )

        # Create SFT Trainer
        self._trainer = SFTTrainer(
            model=self._model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            tokenizer=self._tokenizer,
            dataset_text_field="text",
            max_seq_length=self.config.max_seq_length,
            packing=False,
        )

        # Train
        result = self._trainer.train()

        self.logger.info("training_complete", metrics=result.metrics)
        return result.metrics

    def save_model(self, output_dir: str | None = None) -> None:
        """Save the trained model.

        Args:
            output_dir: Output directory
        """
        save_dir = output_dir or self.config.output_dir

        if self._model is None:
            raise ValueError("No model to save")

        self.logger.info("saving_model", output_dir=save_dir)

        # Save adapter
        self._model.save_pretrained(save_dir)

        # Save tokenizer
        if self._tokenizer:
            self._tokenizer.save_pretrained(save_dir)

        # Save config
        config_path = Path(save_dir) / "training_config.json"
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(self.config.model_dump(), f, ensure_ascii=False, indent=2)

        # Save metrics history
        if self._metrics_history:
            metrics_path = Path(save_dir) / "training_metrics.json"
            with open(metrics_path, "w", encoding="utf-8") as f:
                json.dump(
                    [m.model_dump() for m in self._metrics_history],
                    f,
                    ensure_ascii=False,
                    indent=2,
                    default=str,
                )

    def load_model(self, model_dir: str) -> None:
        """Load a fine-tuned model.

        Args:
            model_dir: Model directory
        """
        try:
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError("Install: pip install transformers peft") from e

        self.logger.info("loading_model", model_dir=model_dir)

        # Load config
        config_path = Path(model_dir) / "training_config.json"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                self.config = TrainingConfig(**json.load(f))

        # Load base model
        base_model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            device_map="auto",
            trust_remote_code=True,
        )

        # Load adapter
        self._model = PeftModel.from_pretrained(base_model, model_dir)

        # Load tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(model_dir)

        self.logger.info("model_loaded")

    async def generate(
        self,
        prompt: str,
        max_new_tokens: int = 512,
        temperature: float = 0.3,
    ) -> str:
        """Generate text using the fine-tuned model.

        Args:
            prompt: Input prompt
            max_new_tokens: Maximum tokens to generate
            temperature: Sampling temperature

        Returns:
            Generated text
        """
        if self._model is None or self._tokenizer is None:
            raise ValueError("Model not loaded")

        # Format prompt
        formatted_prompt = f"### User:\n{prompt}\n\n### Assistant:\n"

        # Tokenize
        inputs = self._tokenizer(
            formatted_prompt,
            return_tensors="pt",
            truncation=True,
            max_length=self.config.max_seq_length,
        )
        inputs = {k: v.to(self._model.device) for k, v in inputs.items()}

        # Generate
        outputs = self._model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            do_sample=temperature > 0,
            top_p=0.95,
            pad_token_id=self._tokenizer.pad_token_id,
            eos_token_id=self._tokenizer.eos_token_id,
        )

        # Decode
        generated = self._tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True,
        )

        return generated.strip()


def run_full_training_pipeline(
    dataset: SecurityDataset,
    config: TrainingConfig | None = None,
) -> dict[str, Any]:
    """Run complete training pipeline.

    Args:
        dataset: Training dataset
        config: Training configuration

    Returns:
        Training results
    """
    trainer = KoreanSecurityTrainer(config)

    # Prepare data
    train_data, eval_data = trainer.prepare_training_data(dataset)

    # Setup and train
    trainer.setup_model()
    metrics = trainer.train(train_data, eval_data)

    # Save
    trainer.save_model()

    return metrics
