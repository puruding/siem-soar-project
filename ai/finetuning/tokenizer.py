"""Extended tokenizer for Korean security domain."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TokenizerConfig(BaseModel):
    """Configuration for tokenizer extension."""

    base_tokenizer: str = Field(default="upstage/SOLAR-10.7B-Instruct-v1.0")
    add_special_tokens: bool = Field(default=True)
    add_security_tokens: bool = Field(default=True)
    max_length: int = Field(default=2048)


class ExtendedTokenizer(LoggerMixin):
    """Extended tokenizer with Korean security domain tokens.

    Features:
    - Korean security terminology tokens
    - Special tokens for structured output
    - Efficient tokenization for security data
    """

    # Korean security domain tokens to add
    SECURITY_TOKENS = [
        # Severity
        "[심각]", "[높음]", "[중간]", "[낮음]",
        "[CRITICAL]", "[HIGH]", "[MEDIUM]", "[LOW]",

        # Status
        "[신규]", "[진행중]", "[완료]", "[거짓양성]",
        "[NEW]", "[IN_PROGRESS]", "[RESOLVED]", "[FALSE_POSITIVE]",

        # Incident types
        "[악성코드]", "[피싱]", "[무차별대입]", "[데이터유출]", "[랜섬웨어]",
        "[MALWARE]", "[PHISHING]", "[BRUTE_FORCE]", "[DATA_BREACH]", "[RANSOMWARE]",

        # Entities
        "[IP]", "[DOMAIN]", "[HASH]", "[URL]", "[EMAIL]", "[CVE]", "[USER]", "[HOST]",

        # MITRE ATT&CK
        "[TACTIC]", "[TECHNIQUE]", "[전술]", "[기술]",

        # Sections
        "[요약]", "[상세]", "[권장사항]", "[타임라인]", "[IOC]",
        "[SUMMARY]", "[DETAIL]", "[RECOMMENDATION]", "[TIMELINE]",

        # Actions
        "[격리]", "[차단]", "[조사]", "[복구]",
        "[ISOLATE]", "[BLOCK]", "[INVESTIGATE]", "[RECOVER]",
    ]

    def __init__(self, config: TokenizerConfig | None = None) -> None:
        """Initialize the tokenizer.

        Args:
            config: Tokenizer configuration
        """
        self.config = config or TokenizerConfig()
        self._tokenizer = None
        self._added_tokens: list[str] = []

    def load_base_tokenizer(self) -> None:
        """Load the base tokenizer."""
        try:
            from transformers import AutoTokenizer
        except ImportError as e:
            raise ImportError("Install: pip install transformers") from e

        self.logger.info("loading_tokenizer", base=self.config.base_tokenizer)

        self._tokenizer = AutoTokenizer.from_pretrained(
            self.config.base_tokenizer,
            trust_remote_code=True,
        )

        # Ensure padding token
        if self._tokenizer.pad_token is None:
            self._tokenizer.pad_token = self._tokenizer.eos_token

    def extend_vocabulary(self, additional_tokens: list[str] | None = None) -> int:
        """Extend vocabulary with security tokens.

        Args:
            additional_tokens: Additional tokens to add

        Returns:
            Number of tokens added
        """
        if self._tokenizer is None:
            self.load_base_tokenizer()

        tokens_to_add = []

        # Add security tokens if configured
        if self.config.add_security_tokens:
            for token in self.SECURITY_TOKENS:
                if token not in self._tokenizer.get_vocab():
                    tokens_to_add.append(token)

        # Add custom tokens
        if additional_tokens:
            for token in additional_tokens:
                if token not in self._tokenizer.get_vocab():
                    tokens_to_add.append(token)

        # Add to tokenizer
        if tokens_to_add:
            num_added = self._tokenizer.add_tokens(tokens_to_add)
            self._added_tokens.extend(tokens_to_add)
            self.logger.info("tokens_added", count=num_added)
            return num_added

        return 0

    def resize_model_embeddings(self, model: Any) -> None:
        """Resize model embeddings after adding tokens.

        Args:
            model: The model to resize
        """
        if self._tokenizer is None:
            raise ValueError("Tokenizer not loaded")

        model.resize_token_embeddings(len(self._tokenizer))
        self.logger.info("embeddings_resized", vocab_size=len(self._tokenizer))

    def tokenize(
        self,
        text: str,
        max_length: int | None = None,
        truncation: bool = True,
        padding: bool = True,
    ) -> dict[str, Any]:
        """Tokenize text.

        Args:
            text: Text to tokenize
            max_length: Maximum length
            truncation: Whether to truncate
            padding: Whether to pad

        Returns:
            Tokenized output
        """
        if self._tokenizer is None:
            self.load_base_tokenizer()

        max_length = max_length or self.config.max_length

        return self._tokenizer(
            text,
            max_length=max_length,
            truncation=truncation,
            padding=padding if padding else False,
            return_tensors="pt",
        )

    def decode(
        self,
        token_ids: list[int],
        skip_special_tokens: bool = True,
    ) -> str:
        """Decode token IDs to text.

        Args:
            token_ids: Token IDs to decode
            skip_special_tokens: Whether to skip special tokens

        Returns:
            Decoded text
        """
        if self._tokenizer is None:
            self.load_base_tokenizer()

        return self._tokenizer.decode(
            token_ids,
            skip_special_tokens=skip_special_tokens,
        )

    def get_vocab_size(self) -> int:
        """Get vocabulary size."""
        if self._tokenizer is None:
            self.load_base_tokenizer()
        return len(self._tokenizer)

    def save(self, output_dir: str) -> None:
        """Save tokenizer to directory.

        Args:
            output_dir: Output directory
        """
        if self._tokenizer is None:
            raise ValueError("Tokenizer not loaded")

        path = Path(output_dir)
        path.mkdir(parents=True, exist_ok=True)

        self._tokenizer.save_pretrained(output_dir)

        # Save added tokens list
        added_tokens_path = path / "added_security_tokens.json"
        with open(added_tokens_path, "w", encoding="utf-8") as f:
            json.dump(self._added_tokens, f, ensure_ascii=False, indent=2)

        self.logger.info("tokenizer_saved", output_dir=output_dir)

    def load(self, tokenizer_dir: str) -> None:
        """Load tokenizer from directory.

        Args:
            tokenizer_dir: Tokenizer directory
        """
        try:
            from transformers import AutoTokenizer
        except ImportError as e:
            raise ImportError("Install: pip install transformers") from e

        self._tokenizer = AutoTokenizer.from_pretrained(
            tokenizer_dir,
            trust_remote_code=True,
        )

        # Load added tokens list
        added_tokens_path = Path(tokenizer_dir) / "added_security_tokens.json"
        if added_tokens_path.exists():
            with open(added_tokens_path, encoding="utf-8") as f:
                self._added_tokens = json.load(f)

        self.logger.info("tokenizer_loaded", vocab_size=len(self._tokenizer))

    @property
    def tokenizer(self) -> Any:
        """Get underlying tokenizer."""
        if self._tokenizer is None:
            self.load_base_tokenizer()
        return self._tokenizer


def create_security_tokenizer(
    base_model: str = "upstage/SOLAR-10.7B-Instruct-v1.0",
    additional_tokens: list[str] | None = None,
) -> ExtendedTokenizer:
    """Create and configure a security domain tokenizer.

    Args:
        base_model: Base model for tokenizer
        additional_tokens: Additional tokens to add

    Returns:
        Configured ExtendedTokenizer
    """
    config = TokenizerConfig(base_tokenizer=base_model)
    tokenizer = ExtendedTokenizer(config)
    tokenizer.load_base_tokenizer()
    tokenizer.extend_vocabulary(additional_tokens)
    return tokenizer
