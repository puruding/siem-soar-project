"""Fine-tuning trainer for NL2SQL model."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TrainingExample(BaseModel):
    """Single training example for NL2SQL."""

    natural_language: str = Field(description="Natural language query")
    sql: str = Field(description="Target SQL query")
    schema_context: str | None = Field(default=None, description="Schema context if needed")
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrainingConfig(BaseModel):
    """Training configuration for NL2SQL fine-tuning."""

    # Model settings
    base_model: str = Field(default="upstage/SOLAR-10.7B-Instruct-v1.0")
    output_dir: str = Field(default="./models/nl2sql-finetuned")

    # LoRA settings
    use_lora: bool = Field(default=True)
    lora_r: int = Field(default=64, description="LoRA rank")
    lora_alpha: int = Field(default=128, description="LoRA alpha")
    lora_dropout: float = Field(default=0.05)
    target_modules: list[str] = Field(
        default_factory=lambda: ["q_proj", "k_proj", "v_proj", "o_proj"]
    )

    # Training hyperparameters
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

    # Data
    train_split: float = Field(default=0.9)
    seed: int = Field(default=42)


@dataclass
class TrainingMetrics:
    """Training metrics and statistics."""

    epoch: int
    step: int
    train_loss: float
    eval_loss: float | None = None
    learning_rate: float | None = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class NL2SQLTrainer(LoggerMixin):
    """Trainer for fine-tuning NL2SQL models.

    Supports:
    - QLoRA fine-tuning for efficient training
    - Custom dataset loading
    - Evaluation metrics for SQL generation
    - Model checkpointing and resuming
    """

    # Chat template for training
    CHAT_TEMPLATE = """### System:
You are an expert SQL analyst. Convert natural language questions into SQL queries.
Use the following database schema:
{schema}

### User:
{question}

### Assistant:
{sql}"""

    def __init__(self, config: TrainingConfig | None = None) -> None:
        """Initialize the trainer.

        Args:
            config: Training configuration
        """
        self.config = config or TrainingConfig()
        self._model = None
        self._tokenizer = None
        self._trainer = None

    def prepare_dataset(
        self,
        examples: list[TrainingExample],
        schema_context: str,
    ) -> Any:
        """Prepare dataset for training.

        Args:
            examples: List of training examples
            schema_context: Database schema context

        Returns:
            Prepared dataset
        """
        self.logger.info("preparing_dataset", num_examples=len(examples))

        # Format examples using chat template
        formatted_examples = []
        for ex in examples:
            text = self.CHAT_TEMPLATE.format(
                schema=ex.schema_context or schema_context,
                question=ex.natural_language,
                sql=ex.sql,
            )
            formatted_examples.append({"text": text})

        return formatted_examples

    def load_dataset_from_file(self, filepath: str) -> list[TrainingExample]:
        """Load training examples from file.

        Args:
            filepath: Path to JSON/JSONL file

        Returns:
            List of training examples
        """
        examples = []
        path = Path(filepath)

        if path.suffix == ".jsonl":
            with open(path) as f:
                for line in f:
                    data = json.loads(line)
                    examples.append(TrainingExample(**data))
        elif path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
                for item in data:
                    examples.append(TrainingExample(**item))
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")

        self.logger.info("loaded_dataset", filepath=filepath, count=len(examples))
        return examples

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
            self.logger.error("missing_dependencies", error=str(e))
            raise ImportError(
                "Please install: pip install torch transformers peft bitsandbytes"
            ) from e

        self.logger.info("loading_model", model=self.config.base_model)

        # Quantization config for QLoRA
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
        )

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
            self._model.print_trainable_parameters()

        self.logger.info("model_loaded", trainable_params=self._count_parameters())

    def _count_parameters(self) -> int:
        """Count trainable parameters."""
        if self._model is None:
            return 0
        return sum(p.numel() for p in self._model.parameters() if p.requires_grad)

    def train(
        self,
        train_dataset: Any,
        eval_dataset: Any | None = None,
        callbacks: list[Any] | None = None,
    ) -> dict[str, Any]:
        """Train the model.

        Args:
            train_dataset: Training dataset
            eval_dataset: Evaluation dataset
            callbacks: Training callbacks

        Returns:
            Training results
        """
        try:
            from transformers import (
                DataCollatorForLanguageModeling,
                Trainer,
                TrainingArguments,
            )
        except ImportError as e:
            raise ImportError("Please install transformers") from e

        if self._model is None or self._tokenizer is None:
            self.setup_model()

        self.logger.info("starting_training", epochs=self.config.num_epochs)

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
            save_total_limit=3,
            load_best_model_at_end=eval_dataset is not None,
            report_to=["tensorboard"],
            seed=self.config.seed,
        )

        # Data collator
        data_collator = DataCollatorForLanguageModeling(
            tokenizer=self._tokenizer,
            mlm=False,
        )

        # Create trainer
        self._trainer = Trainer(
            model=self._model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=eval_dataset,
            data_collator=data_collator,
            callbacks=callbacks,
        )

        # Train
        result = self._trainer.train()

        self.logger.info("training_complete", metrics=result.metrics)
        return result.metrics

    def save_model(self, output_dir: str | None = None) -> None:
        """Save the trained model.

        Args:
            output_dir: Directory to save model
        """
        save_dir = output_dir or self.config.output_dir

        if self._model is None:
            raise ValueError("No model to save")

        self.logger.info("saving_model", output_dir=save_dir)

        # Save LoRA adapter
        self._model.save_pretrained(save_dir)

        # Save tokenizer
        if self._tokenizer:
            self._tokenizer.save_pretrained(save_dir)

        # Save config
        config_path = Path(save_dir) / "training_config.json"
        with open(config_path, "w") as f:
            json.dump(self.config.model_dump(), f, indent=2)

    def load_model(self, model_dir: str) -> None:
        """Load a fine-tuned model.

        Args:
            model_dir: Directory containing saved model
        """
        try:
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise ImportError("Please install transformers and peft") from e

        self.logger.info("loading_finetuned_model", model_dir=model_dir)

        # Load config
        config_path = Path(model_dir) / "training_config.json"
        if config_path.exists():
            with open(config_path) as f:
                config_data = json.load(f)
                self.config = TrainingConfig(**config_data)

        # Load base model
        base_model = AutoModelForCausalLM.from_pretrained(
            self.config.base_model,
            device_map="auto",
            trust_remote_code=True,
        )

        # Load LoRA adapter
        self._model = PeftModel.from_pretrained(base_model, model_dir)

        # Load tokenizer
        self._tokenizer = AutoTokenizer.from_pretrained(model_dir)

        self.logger.info("model_loaded")


class NL2SQLDatasetGenerator:
    """Generate synthetic training data for NL2SQL."""

    # Template patterns for generating training examples
    QUERY_TEMPLATES = [
        # Count queries
        {
            "nl": "How many {entity} are there?",
            "sql": "SELECT COUNT(*) FROM {table}",
        },
        {
            "nl": "Count all {entity} where {condition_nl}",
            "sql": "SELECT COUNT(*) FROM {table} WHERE {condition_sql}",
        },
        # Aggregation queries
        {
            "nl": "What is the average {metric} by {group}?",
            "sql": "SELECT {group_col}, AVG({metric_col}) FROM {table} GROUP BY {group_col}",
        },
        # Time-based queries
        {
            "nl": "Show {entity} from the last {time_period}",
            "sql": "SELECT * FROM {table} WHERE {time_col} > now() - INTERVAL {time_interval}",
        },
        # Top N queries
        {
            "nl": "What are the top {n} {entity} by {metric}?",
            "sql": "SELECT * FROM {table} ORDER BY {metric_col} DESC LIMIT {n}",
        },
        # Filter queries
        {
            "nl": "Find all {entity} with {condition_nl}",
            "sql": "SELECT * FROM {table} WHERE {condition_sql}",
        },
    ]

    # SIEM-specific query templates
    SIEM_TEMPLATES = [
        {
            "nl": "Show all critical alerts from today",
            "sql": "SELECT * FROM alerts WHERE severity = 'critical' AND created_at >= today()",
        },
        {
            "nl": "Which IP addresses have the most failed login attempts?",
            "sql": "SELECT source_ip, COUNT(*) as attempts FROM events WHERE event_type = 'authentication' AND status = 'failed' GROUP BY source_ip ORDER BY attempts DESC LIMIT 10",
        },
        {
            "nl": "Show events from suspicious IP {ip}",
            "sql": "SELECT * FROM events WHERE source_ip = '{ip}' ORDER BY timestamp DESC",
        },
        {
            "nl": "How many alerts per severity level this week?",
            "sql": "SELECT severity, COUNT(*) FROM alerts WHERE created_at >= today() - 7 GROUP BY severity",
        },
        {
            "nl": "Find all cases assigned to {user}",
            "sql": "SELECT * FROM cases WHERE assignee_id = (SELECT user_id FROM users WHERE username = '{user}')",
        },
        {
            "nl": "Show network traffic to port {port} in the last hour",
            "sql": "SELECT * FROM events WHERE dest_port = {port} AND timestamp > now() - INTERVAL 1 HOUR",
        },
    ]

    def __init__(self) -> None:
        """Initialize the generator."""
        pass

    def generate_examples(
        self,
        num_examples: int = 1000,
        include_siem: bool = True,
    ) -> list[TrainingExample]:
        """Generate synthetic training examples.

        Args:
            num_examples: Number of examples to generate
            include_siem: Include SIEM-specific examples

        Returns:
            List of training examples
        """
        examples = []

        # Add SIEM-specific examples
        if include_siem:
            for template in self.SIEM_TEMPLATES:
                examples.append(TrainingExample(
                    natural_language=template["nl"],
                    sql=template["sql"],
                    metadata={"source": "siem_template"},
                ))

        # In practice, this would generate more diverse examples
        # using the templates with various parameter combinations

        return examples[:num_examples]
