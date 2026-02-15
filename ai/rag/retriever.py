"""Document retriever for RAG pipeline."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class RetrievalMethod(str, Enum):
    """Retrieval methods."""

    DENSE = "dense"  # Vector similarity
    SPARSE = "sparse"  # BM25/keyword
    HYBRID = "hybrid"  # Combined


class DocumentType(str, Enum):
    """Document types in knowledge base."""

    RUNBOOK = "runbook"
    PLAYBOOK = "playbook"
    POLICY = "policy"
    THREAT_INTEL = "threat_intel"
    INCIDENT_REPORT = "incident_report"
    PROCEDURE = "procedure"
    KNOWLEDGE_ARTICLE = "knowledge_article"


class RetrievedDocument(BaseModel):
    """Retrieved document with metadata."""

    doc_id: str = Field(description="Document ID")
    content: str = Field(description="Document content or chunk")
    doc_type: DocumentType = Field(description="Document type")
    title: str = Field(description="Document title")
    score: float = Field(ge=0, le=1, description="Relevance score")
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(default="", description="Source system")
    chunk_index: int | None = Field(default=None, description="Chunk index if chunked")
    total_chunks: int | None = Field(default=None, description="Total chunks in document")
    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)


class RetrieverConfig(BaseModel):
    """Configuration for document retrieval."""

    method: RetrievalMethod = Field(default=RetrievalMethod.HYBRID)
    top_k: int = Field(default=5, description="Number of documents to retrieve")
    min_score: float = Field(default=0.5, ge=0, le=1)
    doc_types: list[DocumentType] | None = Field(default=None, description="Filter by doc types")
    rerank: bool = Field(default=True, description="Apply reranking")
    rerank_top_k: int = Field(default=20, description="Candidates for reranking")
    include_metadata: bool = Field(default=True)


class DocumentRetriever(LoggerMixin):
    """Retrieves relevant documents for RAG.

    Features:
    - Dense retrieval using embeddings
    - Sparse retrieval using BM25
    - Hybrid search combining both
    - Multi-stage retrieval with reranking
    - Filtering by document type and metadata
    """

    def __init__(
        self,
        embedding_endpoint: str | None = None,
        vector_db_endpoint: str | None = None,
        reranker_endpoint: str | None = None,
    ) -> None:
        """Initialize the retriever.

        Args:
            embedding_endpoint: Text embedding API endpoint
            vector_db_endpoint: Vector database endpoint (Qdrant)
            reranker_endpoint: Reranker API endpoint
        """
        self.embedding_endpoint = embedding_endpoint or "http://localhost:8082"
        self.vector_db_endpoint = vector_db_endpoint or "http://localhost:6333"
        self.reranker_endpoint = reranker_endpoint or "http://localhost:8083"

        self._client: httpx.AsyncClient | None = None

        # Collection name in vector DB
        self.collection_name = "security_knowledge"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def retrieve(
        self,
        query: str,
        config: RetrieverConfig | None = None,
    ) -> list[RetrievedDocument]:
        """Retrieve relevant documents for a query.

        Args:
            query: Search query
            config: Retrieval configuration

        Returns:
            List of relevant documents ordered by score
        """
        config = config or RetrieverConfig()

        self.logger.info(
            "retrieving_documents",
            query_length=len(query),
            method=config.method,
            top_k=config.top_k,
        )

        # Get candidates based on method
        if config.method == RetrievalMethod.DENSE:
            candidates = await self._dense_retrieve(query, config)
        elif config.method == RetrievalMethod.SPARSE:
            candidates = await self._sparse_retrieve(query, config)
        else:  # HYBRID
            dense_results = await self._dense_retrieve(query, config)
            sparse_results = await self._sparse_retrieve(query, config)
            candidates = self._merge_results(dense_results, sparse_results)

        # Apply document type filter
        if config.doc_types:
            candidates = [c for c in candidates if c.doc_type in config.doc_types]

        # Apply minimum score filter
        candidates = [c for c in candidates if c.score >= config.min_score]

        # Rerank if enabled
        if config.rerank and len(candidates) > 1:
            candidates = await self._rerank(query, candidates, config.top_k)
        else:
            candidates.sort(key=lambda x: x.score, reverse=True)
            candidates = candidates[:config.top_k]

        return candidates

    async def _dense_retrieve(
        self,
        query: str,
        config: RetrieverConfig,
    ) -> list[RetrievedDocument]:
        """Retrieve using dense vector similarity."""
        client = await self._get_client()

        # Get query embedding
        embedding_response = await client.post(
            f"{self.embedding_endpoint}/embed",
            json={"inputs": query, "truncate": True},
        )
        embedding_response.raise_for_status()

        embedding_data = embedding_response.json()
        query_vector = embedding_data[0] if isinstance(embedding_data, list) else embedding_data.get("embeddings", [[]])[0]

        # Build filter
        filter_conditions = None
        if config.doc_types:
            filter_conditions = {
                "must": [
                    {
                        "key": "doc_type",
                        "match": {"any": [dt.value for dt in config.doc_types]}
                    }
                ]
            }

        # Search in Qdrant
        search_response = await client.post(
            f"{self.vector_db_endpoint}/collections/{self.collection_name}/points/search",
            json={
                "vector": query_vector,
                "limit": config.rerank_top_k if config.rerank else config.top_k,
                "with_payload": True,
                "filter": filter_conditions,
            },
        )
        search_response.raise_for_status()

        results = search_response.json().get("result", [])

        # Convert to RetrievedDocument
        documents = []
        for result in results:
            payload = result.get("payload", {})
            documents.append(RetrievedDocument(
                doc_id=str(result.get("id")),
                content=payload.get("content", ""),
                doc_type=DocumentType(payload.get("doc_type", "knowledge_article")),
                title=payload.get("title", ""),
                score=result.get("score", 0.0),
                metadata=payload.get("metadata", {}),
                source=payload.get("source", ""),
                chunk_index=payload.get("chunk_index"),
                total_chunks=payload.get("total_chunks"),
            ))

        return documents

    async def _sparse_retrieve(
        self,
        query: str,
        config: RetrieverConfig,
    ) -> list[RetrievedDocument]:
        """Retrieve using sparse (BM25) matching."""
        client = await self._get_client()

        # Build filter
        filter_conditions = None
        if config.doc_types:
            filter_conditions = {
                "must": [
                    {
                        "key": "doc_type",
                        "match": {"any": [dt.value for dt in config.doc_types]}
                    }
                ]
            }

        # Qdrant sparse search (using text index)
        # Note: This requires a text index to be configured
        search_response = await client.post(
            f"{self.vector_db_endpoint}/collections/{self.collection_name}/points/scroll",
            json={
                "filter": {
                    "must": [
                        {
                            "key": "content",
                            "match": {"text": query}
                        }
                    ] + (filter_conditions.get("must", []) if filter_conditions else [])
                },
                "limit": config.rerank_top_k if config.rerank else config.top_k,
                "with_payload": True,
            },
        )
        search_response.raise_for_status()

        results = search_response.json().get("result", {}).get("points", [])

        # Convert to RetrievedDocument with BM25-like scoring
        documents = []
        query_terms = set(query.lower().split())

        for result in results:
            payload = result.get("payload", {})
            content = payload.get("content", "").lower()

            # Simple term frequency score
            content_terms = set(content.split())
            matching_terms = query_terms & content_terms
            score = len(matching_terms) / (len(query_terms) + 1)

            documents.append(RetrievedDocument(
                doc_id=str(result.get("id")),
                content=payload.get("content", ""),
                doc_type=DocumentType(payload.get("doc_type", "knowledge_article")),
                title=payload.get("title", ""),
                score=score,
                metadata=payload.get("metadata", {}),
                source=payload.get("source", ""),
                chunk_index=payload.get("chunk_index"),
                total_chunks=payload.get("total_chunks"),
            ))

        return documents

    def _merge_results(
        self,
        dense_results: list[RetrievedDocument],
        sparse_results: list[RetrievedDocument],
        dense_weight: float = 0.7,
    ) -> list[RetrievedDocument]:
        """Merge dense and sparse results using reciprocal rank fusion."""
        merged: dict[str, RetrievedDocument] = {}
        k = 60  # RRF constant

        # Add dense results
        for rank, doc in enumerate(dense_results):
            doc.score = 1 / (k + rank + 1)
            merged[doc.doc_id] = doc

        # Add/merge sparse results
        sparse_weight = 1 - dense_weight
        for rank, doc in enumerate(sparse_results):
            sparse_score = 1 / (k + rank + 1)
            if doc.doc_id in merged:
                # RRF fusion
                merged[doc.doc_id].score += sparse_score
            else:
                doc.score = sparse_score * sparse_weight
                merged[doc.doc_id] = doc

        return list(merged.values())

    async def _rerank(
        self,
        query: str,
        documents: list[RetrievedDocument],
        top_k: int,
    ) -> list[RetrievedDocument]:
        """Rerank documents using cross-encoder."""
        client = await self._get_client()

        # Prepare pairs for reranker
        pairs = [[query, doc.content[:512]] for doc in documents]

        try:
            response = await client.post(
                f"{self.reranker_endpoint}/rerank",
                json={
                    "query": query,
                    "texts": [doc.content[:512] for doc in documents],
                    "truncate": True,
                },
            )
            response.raise_for_status()

            scores = response.json()
            # Handle different response formats
            if isinstance(scores, list):
                if isinstance(scores[0], dict):
                    scores = [s.get("score", 0) for s in scores]
            elif isinstance(scores, dict):
                scores = scores.get("scores", [0] * len(documents))

            # Update scores
            for doc, score in zip(documents, scores):
                doc.score = score

        except Exception as e:
            self.logger.warning("rerank_failed", error=str(e))
            # Keep original scores

        # Sort and return top_k
        documents.sort(key=lambda x: x.score, reverse=True)
        return documents[:top_k]

    async def retrieve_for_context(
        self,
        incident_context: dict[str, Any],
        config: RetrieverConfig | None = None,
    ) -> list[RetrievedDocument]:
        """Retrieve documents relevant to incident context.

        Args:
            incident_context: Incident data for context-aware retrieval
            config: Retrieval configuration

        Returns:
            Relevant documents for incident
        """
        config = config or RetrieverConfig()

        # Build query from context
        query_parts = []

        if title := incident_context.get("title"):
            query_parts.append(title)

        if description := incident_context.get("description"):
            query_parts.append(description[:200])

        if incident_type := incident_context.get("incident_type"):
            query_parts.append(f"incident type: {incident_type}")

        if mitre_tactics := incident_context.get("mitre_tactics"):
            query_parts.append(f"MITRE tactics: {', '.join(mitre_tactics)}")

        query = " ".join(query_parts)

        # Prioritize runbooks and procedures
        if not config.doc_types:
            config.doc_types = [
                DocumentType.RUNBOOK,
                DocumentType.PLAYBOOK,
                DocumentType.PROCEDURE,
                DocumentType.KNOWLEDGE_ARTICLE,
            ]

        return await self.retrieve(query, config)

    async def get_document(self, doc_id: str) -> RetrievedDocument | None:
        """Get a specific document by ID.

        Args:
            doc_id: Document ID

        Returns:
            Document or None if not found
        """
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.vector_db_endpoint}/collections/{self.collection_name}/points/{doc_id}",
            )
            response.raise_for_status()

            result = response.json().get("result")
            if not result:
                return None

            payload = result.get("payload", {})
            return RetrievedDocument(
                doc_id=str(result.get("id")),
                content=payload.get("content", ""),
                doc_type=DocumentType(payload.get("doc_type", "knowledge_article")),
                title=payload.get("title", ""),
                score=1.0,
                metadata=payload.get("metadata", {}),
                source=payload.get("source", ""),
            )

        except Exception as e:
            self.logger.warning("get_document_failed", doc_id=doc_id, error=str(e))
            return None

    async def batch_retrieve(
        self,
        queries: list[str],
        config: RetrieverConfig | None = None,
    ) -> list[list[RetrievedDocument]]:
        """Retrieve documents for multiple queries in parallel.

        Args:
            queries: List of queries
            config: Retrieval configuration

        Returns:
            List of document lists for each query
        """
        config = config or RetrieverConfig()

        tasks = [self.retrieve(query, config) for query in queries]
        return await asyncio.gather(*tasks)
