"""Document reranker for RAG pipeline."""

from __future__ import annotations

from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RerankerModel(str, Enum):
    """Supported reranker models."""

    BGE_RERANKER_V2 = "bge-reranker-v2-m3"
    BGE_RERANKER_BASE = "bge-reranker-base"
    MS_MARCO = "ms-marco-MiniLM"
    COHERE = "rerank-multilingual-v2.0"


class RerankerConfig(BaseModel):
    """Configuration for reranking."""

    model: RerankerModel = Field(default=RerankerModel.BGE_RERANKER_V2)
    top_k: int = Field(default=5, description="Number of documents to return")
    max_length: int = Field(default=512, description="Maximum text length")
    batch_size: int = Field(default=32, description="Batch size for reranking")
    normalize_scores: bool = Field(default=True)


class RerankResult(BaseModel):
    """Reranking result for a document."""

    index: int = Field(description="Original index in input list")
    score: float = Field(description="Reranking score")
    content: str = Field(description="Document content")


class DocumentReranker(LoggerMixin):
    """Cross-encoder reranker for improved retrieval.

    Features:
    - Cross-encoder scoring for query-document pairs
    - Batch processing for efficiency
    - Score normalization
    - Multiple model support
    """

    def __init__(
        self,
        reranker_endpoint: str | None = None,
        config: RerankerConfig | None = None,
    ) -> None:
        """Initialize the reranker.

        Args:
            reranker_endpoint: Reranker API endpoint
            config: Reranker configuration
        """
        self.reranker_endpoint = reranker_endpoint or "http://localhost:8083"
        self.config = config or RerankerConfig()

        self._client: httpx.AsyncClient | None = None

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

    async def rerank(
        self,
        query: str,
        documents: list[str],
        top_k: int | None = None,
    ) -> list[RerankResult]:
        """Rerank documents based on query relevance.

        Args:
            query: Search query
            documents: List of document texts
            top_k: Number of top documents to return

        Returns:
            List of reranking results ordered by score
        """
        top_k = top_k or self.config.top_k

        self.logger.info(
            "reranking_documents",
            query_length=len(query),
            num_documents=len(documents),
            top_k=top_k,
        )

        if not documents:
            return []

        if len(documents) == 1:
            return [RerankResult(index=0, score=1.0, content=documents[0])]

        # Truncate documents if needed
        truncated_docs = [doc[:self.config.max_length * 4] for doc in documents]

        # Rerank in batches
        all_scores = []
        for batch_start in range(0, len(truncated_docs), self.config.batch_size):
            batch_end = batch_start + self.config.batch_size
            batch_docs = truncated_docs[batch_start:batch_end]

            batch_scores = await self._call_reranker(query, batch_docs)
            all_scores.extend(batch_scores)

        # Normalize scores if configured
        if self.config.normalize_scores:
            all_scores = self._normalize_scores(all_scores)

        # Build results with original indices
        results = [
            RerankResult(index=i, score=score, content=documents[i])
            for i, score in enumerate(all_scores)
        ]

        # Sort by score descending
        results.sort(key=lambda x: x.score, reverse=True)

        return results[:top_k]

    async def _call_reranker(self, query: str, documents: list[str]) -> list[float]:
        """Call reranker API.

        Args:
            query: Search query
            documents: Documents to rerank

        Returns:
            List of relevance scores
        """
        client = await self._get_client()

        # Text Embeddings Inference rerank API format
        response = await client.post(
            f"{self.reranker_endpoint}/rerank",
            json={
                "query": query,
                "texts": documents,
                "truncate": True,
            },
        )
        response.raise_for_status()

        data = response.json()

        # Handle different response formats
        if isinstance(data, list):
            if isinstance(data[0], dict):
                # Format: [{"score": 0.9, "index": 0}, ...]
                scores = [0.0] * len(documents)
                for item in data:
                    scores[item.get("index", 0)] = item.get("score", 0.0)
                return scores
            else:
                # Format: [0.9, 0.8, ...]
                return data
        elif isinstance(data, dict):
            return data.get("scores", [0.0] * len(documents))

        raise ValueError(f"Unexpected reranker response format: {type(data)}")

    def _normalize_scores(self, scores: list[float]) -> list[float]:
        """Normalize scores to [0, 1] range."""
        if not scores:
            return scores

        min_score = min(scores)
        max_score = max(scores)

        if max_score == min_score:
            return [0.5] * len(scores)

        return [(s - min_score) / (max_score - min_score) for s in scores]

    async def rerank_with_metadata(
        self,
        query: str,
        documents: list[dict[str, Any]],
        content_key: str = "content",
        top_k: int | None = None,
    ) -> list[dict[str, Any]]:
        """Rerank documents with metadata preservation.

        Args:
            query: Search query
            documents: List of document dicts with metadata
            content_key: Key for document content
            top_k: Number of top documents to return

        Returns:
            Reranked documents with scores added
        """
        contents = [doc.get(content_key, "") for doc in documents]
        results = await self.rerank(query, contents, top_k)

        # Build output with original metadata
        reranked_docs = []
        for result in results:
            doc = documents[result.index].copy()
            doc["rerank_score"] = result.score
            doc["original_index"] = result.index
            reranked_docs.append(doc)

        return reranked_docs


class RecursiveReranker(DocumentReranker):
    """Reranker with recursive refinement for large document sets."""

    def __init__(
        self,
        reranker_endpoint: str | None = None,
        config: RerankerConfig | None = None,
        first_stage_k: int = 50,
    ) -> None:
        """Initialize recursive reranker.

        Args:
            reranker_endpoint: Reranker API endpoint
            config: Reranker configuration
            first_stage_k: Number of candidates for first stage
        """
        super().__init__(reranker_endpoint, config)
        self.first_stage_k = first_stage_k

    async def rerank(
        self,
        query: str,
        documents: list[str],
        top_k: int | None = None,
    ) -> list[RerankResult]:
        """Rerank with two-stage refinement for large sets.

        Args:
            query: Search query
            documents: List of document texts
            top_k: Number of top documents to return

        Returns:
            List of reranking results
        """
        top_k = top_k or self.config.top_k

        # If small enough, use single-stage reranking
        if len(documents) <= self.first_stage_k:
            return await super().rerank(query, documents, top_k)

        self.logger.info(
            "recursive_reranking",
            num_documents=len(documents),
            first_stage_k=self.first_stage_k,
        )

        # First stage: Get top candidates
        first_stage_results = await super().rerank(query, documents, self.first_stage_k)

        # Second stage: Refine with full attention
        candidate_texts = [r.content for r in first_stage_results]
        candidate_indices = [r.index for r in first_stage_results]

        second_stage_results = await super().rerank(query, candidate_texts, top_k)

        # Map back to original indices
        final_results = []
        for result in second_stage_results:
            original_index = candidate_indices[result.index]
            final_results.append(RerankResult(
                index=original_index,
                score=result.score,
                content=documents[original_index],
            ))

        return final_results
