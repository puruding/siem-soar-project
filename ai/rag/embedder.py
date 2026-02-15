"""Text embedding for RAG pipeline."""

from __future__ import annotations

import asyncio
import hashlib
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class EmbeddingModel(str, Enum):
    """Supported embedding models."""

    BGE_M3 = "bge-m3"
    BGE_LARGE = "bge-large-en-v1.5"
    KO_SROBERTA = "ko-sroberta"
    E5_LARGE = "e5-large-v2"
    MULTILINGUAL = "multilingual-e5-large"


class EmbeddingConfig(BaseModel):
    """Configuration for text embedding."""

    model: EmbeddingModel = Field(default=EmbeddingModel.BGE_M3)
    batch_size: int = Field(default=32, description="Batch size for embedding")
    max_length: int = Field(default=512, description="Maximum text length")
    normalize: bool = Field(default=True, description="Normalize embeddings")
    prefix: str = Field(default="", description="Query prefix for some models")
    cache_enabled: bool = Field(default=True, description="Enable embedding cache")


class TextEmbedder(LoggerMixin):
    """Text embedding service for RAG.

    Features:
    - Multiple model support
    - Batch embedding
    - Caching for repeated texts
    - Korean language support
    - Async operation
    """

    # Model-specific prefixes
    MODEL_PREFIXES = {
        EmbeddingModel.E5_LARGE: "query: ",
        EmbeddingModel.MULTILINGUAL: "query: ",
    }

    # Model dimensions
    MODEL_DIMENSIONS = {
        EmbeddingModel.BGE_M3: 1024,
        EmbeddingModel.BGE_LARGE: 1024,
        EmbeddingModel.KO_SROBERTA: 768,
        EmbeddingModel.E5_LARGE: 1024,
        EmbeddingModel.MULTILINGUAL: 1024,
    }

    def __init__(
        self,
        embedding_endpoint: str | None = None,
        config: EmbeddingConfig | None = None,
    ) -> None:
        """Initialize the embedder.

        Args:
            embedding_endpoint: Text embedding API endpoint
            config: Embedding configuration
        """
        self.embedding_endpoint = embedding_endpoint or "http://localhost:8082"
        self.config = config or EmbeddingConfig()

        self._client: httpx.AsyncClient | None = None

        # Embedding cache
        self._cache: dict[str, list[float]] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    @property
    def dimension(self) -> int:
        """Get embedding dimension for current model."""
        return self.MODEL_DIMENSIONS.get(self.config.model, 1024)

    async def embed(self, text: str) -> list[float]:
        """Embed a single text.

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        # Check cache
        cache_key = self._get_cache_key(text)
        if self.config.cache_enabled and cache_key in self._cache:
            self._cache_hits += 1
            return self._cache[cache_key]

        self._cache_misses += 1

        # Add prefix if needed
        text = self._add_prefix(text)

        # Truncate if needed
        text = text[:self.config.max_length * 4]  # Approximate token limit

        # Get embedding
        embedding = await self._call_embedding_api([text])

        # Cache result
        if self.config.cache_enabled:
            self._cache[cache_key] = embedding[0]

        return embedding[0]

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts in batches.

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        self.logger.info("embedding_batch", count=len(texts))

        results: list[list[float] | None] = [None] * len(texts)
        texts_to_embed: list[tuple[int, str]] = []

        # Check cache first
        for i, text in enumerate(texts):
            cache_key = self._get_cache_key(text)
            if self.config.cache_enabled and cache_key in self._cache:
                results[i] = self._cache[cache_key]
                self._cache_hits += 1
            else:
                texts_to_embed.append((i, text))
                self._cache_misses += 1

        # Embed uncached texts in batches
        if texts_to_embed:
            for batch_start in range(0, len(texts_to_embed), self.config.batch_size):
                batch_end = batch_start + self.config.batch_size
                batch = texts_to_embed[batch_start:batch_end]

                batch_texts = [self._add_prefix(t) for _, t in batch]
                batch_texts = [t[:self.config.max_length * 4] for t in batch_texts]

                embeddings = await self._call_embedding_api(batch_texts)

                for (original_idx, text), embedding in zip(batch, embeddings):
                    results[original_idx] = embedding
                    if self.config.cache_enabled:
                        cache_key = self._get_cache_key(text)
                        self._cache[cache_key] = embedding

        return results

    async def embed_query(self, query: str) -> list[float]:
        """Embed a search query with appropriate prefix.

        Args:
            query: Search query

        Returns:
            Query embedding
        """
        # Use query-specific prefix if model supports it
        original_prefix = self.config.prefix
        if self.config.model in self.MODEL_PREFIXES:
            self.config.prefix = self.MODEL_PREFIXES[self.config.model]

        embedding = await self.embed(query)

        self.config.prefix = original_prefix
        return embedding

    async def embed_document(self, document: str) -> list[float]:
        """Embed a document for indexing.

        Args:
            document: Document text

        Returns:
            Document embedding
        """
        # Documents typically don't need prefix
        original_prefix = self.config.prefix
        self.config.prefix = ""

        embedding = await self.embed(document)

        self.config.prefix = original_prefix
        return embedding

    async def _call_embedding_api(self, texts: list[str]) -> list[list[float]]:
        """Call embedding API.

        Args:
            texts: Texts to embed

        Returns:
            Embedding vectors
        """
        client = await self._get_client()

        # Text Embeddings Inference API format
        response = await client.post(
            f"{self.embedding_endpoint}/embed",
            json={"inputs": texts, "truncate": True},
        )
        response.raise_for_status()

        data = response.json()

        # Handle different response formats
        if isinstance(data, list):
            embeddings = data
        elif isinstance(data, dict):
            embeddings = data.get("embeddings", data.get("data", []))
        else:
            raise ValueError(f"Unexpected embedding response format: {type(data)}")

        # Normalize if configured
        if self.config.normalize:
            embeddings = [self._normalize_vector(e) for e in embeddings]

        return embeddings

    def _normalize_vector(self, vector: list[float]) -> list[float]:
        """Normalize vector to unit length."""
        norm = sum(x * x for x in vector) ** 0.5
        if norm > 0:
            return [x / norm for x in vector]
        return vector

    def _add_prefix(self, text: str) -> str:
        """Add model-specific prefix."""
        if self.config.prefix:
            return f"{self.config.prefix}{text}"
        return text

    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        # Include model in key
        key_text = f"{self.config.model.value}:{text}"
        return hashlib.md5(key_text.encode()).hexdigest()

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self._cache_hits + self._cache_misses
        hit_rate = self._cache_hits / total if total > 0 else 0.0

        return {
            "cache_size": len(self._cache),
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate": hit_rate,
        }

    def clear_cache(self) -> None:
        """Clear embedding cache."""
        self._cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0


async def compute_similarity(
    embedder: TextEmbedder,
    text1: str,
    text2: str,
) -> float:
    """Compute cosine similarity between two texts.

    Args:
        embedder: TextEmbedder instance
        text1: First text
        text2: Second text

    Returns:
        Cosine similarity score
    """
    embeddings = await embedder.embed_batch([text1, text2])
    return cosine_similarity(embeddings[0], embeddings[1])


def cosine_similarity(vec1: list[float], vec2: list[float]) -> float:
    """Calculate cosine similarity between vectors."""
    if len(vec1) != len(vec2):
        return 0.0

    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = sum(a * a for a in vec1) ** 0.5
    norm2 = sum(b * b for b in vec2) ** 0.5

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return dot_product / (norm1 * norm2)
