"""Vector indexer for RAG pipeline."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .chunker import DocumentChunk, TextChunker, ChunkConfig
from .embedder import TextEmbedder, EmbeddingConfig


class IndexStatus(str, Enum):
    """Index operation status."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class IndexConfig(BaseModel):
    """Configuration for vector indexing."""

    collection_name: str = Field(default="security_knowledge")
    vector_size: int = Field(default=1024, description="Embedding dimension")
    distance_metric: str = Field(default="Cosine", description="Distance metric")
    on_disk: bool = Field(default=True, description="Store vectors on disk")
    hnsw_m: int = Field(default=16, description="HNSW M parameter")
    hnsw_ef_construct: int = Field(default=100, description="HNSW ef_construct")
    enable_quantization: bool = Field(default=False, description="Enable scalar quantization")


class IndexResult(BaseModel):
    """Result of indexing operation."""

    status: IndexStatus = Field(description="Operation status")
    documents_indexed: int = Field(default=0)
    chunks_indexed: int = Field(default=0)
    errors: list[str] = Field(default_factory=list)
    duration_ms: int = Field(default=0)


class VectorIndexer(LoggerMixin):
    """Vector database indexer for RAG.

    Features:
    - Document chunking and embedding
    - Qdrant vector database integration
    - Batch indexing with progress
    - Collection management
    - Index statistics
    """

    def __init__(
        self,
        vector_db_endpoint: str | None = None,
        embedder: TextEmbedder | None = None,
        chunker: TextChunker | None = None,
        config: IndexConfig | None = None,
    ) -> None:
        """Initialize the indexer.

        Args:
            vector_db_endpoint: Qdrant endpoint
            embedder: Text embedder instance
            chunker: Text chunker instance
            config: Index configuration
        """
        self.vector_db_endpoint = vector_db_endpoint or "http://localhost:6333"
        self.embedder = embedder or TextEmbedder()
        self.chunker = chunker or TextChunker()
        self.config = config or IndexConfig()

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(120.0),
            )
        return self._client

    async def close(self) -> None:
        """Close resources."""
        if self._client:
            await self._client.aclose()
            self._client = None
        await self.embedder.close()

    async def create_collection(self, recreate: bool = False) -> bool:
        """Create vector collection in Qdrant.

        Args:
            recreate: Delete and recreate if exists

        Returns:
            True if created successfully
        """
        client = await self._get_client()

        # Check if collection exists
        try:
            response = await client.get(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}"
            )
            exists = response.status_code == 200

            if exists and not recreate:
                self.logger.info("collection_exists", name=self.config.collection_name)
                return True

            if exists and recreate:
                # Delete existing collection
                await client.delete(
                    f"{self.vector_db_endpoint}/collections/{self.config.collection_name}"
                )
                self.logger.info("collection_deleted", name=self.config.collection_name)

        except Exception as e:
            self.logger.warning("collection_check_failed", error=str(e))

        # Create collection
        collection_config = {
            "vectors": {
                "size": self.config.vector_size,
                "distance": self.config.distance_metric,
                "on_disk": self.config.on_disk,
            },
            "hnsw_config": {
                "m": self.config.hnsw_m,
                "ef_construct": self.config.hnsw_ef_construct,
            },
        }

        if self.config.enable_quantization:
            collection_config["quantization_config"] = {
                "scalar": {
                    "type": "int8",
                    "quantile": 0.99,
                    "always_ram": True,
                }
            }

        try:
            response = await client.put(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}",
                json=collection_config,
            )
            response.raise_for_status()
            self.logger.info("collection_created", name=self.config.collection_name)
            return True

        except Exception as e:
            self.logger.error("collection_create_failed", error=str(e))
            return False

    async def index_document(
        self,
        doc_id: str,
        content: str,
        metadata: dict[str, Any],
    ) -> IndexResult:
        """Index a single document.

        Args:
            doc_id: Document ID
            content: Document content
            metadata: Document metadata

        Returns:
            Indexing result
        """
        start_time = datetime.utcnow()

        # Chunk document
        chunks = self.chunker.chunk_document(doc_id, content, metadata)

        if not chunks:
            return IndexResult(
                status=IndexStatus.FAILED,
                errors=["No chunks generated from document"],
            )

        # Embed chunks
        chunk_texts = [chunk.content for chunk in chunks]
        embeddings = await self.embedder.embed_batch(chunk_texts)

        # Index to vector DB
        errors = await self._upsert_vectors(chunks, embeddings)

        duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        if errors:
            return IndexResult(
                status=IndexStatus.PARTIAL if len(errors) < len(chunks) else IndexStatus.FAILED,
                documents_indexed=1 if len(errors) < len(chunks) else 0,
                chunks_indexed=len(chunks) - len(errors),
                errors=errors,
                duration_ms=duration,
            )

        return IndexResult(
            status=IndexStatus.SUCCESS,
            documents_indexed=1,
            chunks_indexed=len(chunks),
            duration_ms=duration,
        )

    async def index_documents(
        self,
        documents: list[dict[str, Any]],
        content_key: str = "content",
        id_key: str = "id",
        batch_size: int = 10,
    ) -> IndexResult:
        """Index multiple documents.

        Args:
            documents: List of documents to index
            content_key: Key for document content
            id_key: Key for document ID
            batch_size: Documents per batch

        Returns:
            Aggregated indexing result
        """
        start_time = datetime.utcnow()

        self.logger.info("indexing_documents", count=len(documents))

        total_docs = 0
        total_chunks = 0
        all_errors = []

        for batch_start in range(0, len(documents), batch_size):
            batch_end = batch_start + batch_size
            batch = documents[batch_start:batch_end]

            # Process batch in parallel
            tasks = []
            for doc in batch:
                doc_id = str(doc.get(id_key, uuid.uuid4()))
                content = doc.get(content_key, "")
                metadata = {k: v for k, v in doc.items() if k not in [content_key]}

                if content:
                    tasks.append(self.index_document(doc_id, content, metadata))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    all_errors.append(str(result))
                elif isinstance(result, IndexResult):
                    total_docs += result.documents_indexed
                    total_chunks += result.chunks_indexed
                    all_errors.extend(result.errors)

        duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        if all_errors:
            status = IndexStatus.PARTIAL if total_docs > 0 else IndexStatus.FAILED
        else:
            status = IndexStatus.SUCCESS

        return IndexResult(
            status=status,
            documents_indexed=total_docs,
            chunks_indexed=total_chunks,
            errors=all_errors[:100],  # Limit error count
            duration_ms=duration,
        )

    async def _upsert_vectors(
        self,
        chunks: list[DocumentChunk],
        embeddings: list[list[float]],
    ) -> list[str]:
        """Upsert vectors to Qdrant.

        Args:
            chunks: Document chunks
            embeddings: Chunk embeddings

        Returns:
            List of errors (empty if successful)
        """
        client = await self._get_client()

        points = []
        for chunk, embedding in zip(chunks, embeddings):
            point = {
                "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, chunk.chunk_id)),
                "vector": embedding,
                "payload": {
                    "chunk_id": chunk.chunk_id,
                    "doc_id": chunk.doc_id,
                    "content": chunk.content,
                    "chunk_index": chunk.chunk_index,
                    "total_chunks": chunk.total_chunks,
                    **chunk.metadata,
                },
            }
            points.append(point)

        try:
            response = await client.put(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}/points",
                json={"points": points},
                params={"wait": "true"},
            )
            response.raise_for_status()
            return []

        except Exception as e:
            self.logger.error("upsert_failed", error=str(e))
            return [str(e)]

    async def delete_document(self, doc_id: str) -> bool:
        """Delete a document and its chunks from index.

        Args:
            doc_id: Document ID to delete

        Returns:
            True if deleted successfully
        """
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}/points/delete",
                json={
                    "filter": {
                        "must": [
                            {"key": "doc_id", "match": {"value": doc_id}}
                        ]
                    }
                },
            )
            response.raise_for_status()
            self.logger.info("document_deleted", doc_id=doc_id)
            return True

        except Exception as e:
            self.logger.error("delete_failed", doc_id=doc_id, error=str(e))
            return False

    async def get_collection_stats(self) -> dict[str, Any]:
        """Get collection statistics.

        Returns:
            Collection statistics
        """
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}"
            )
            response.raise_for_status()

            data = response.json().get("result", {})
            return {
                "name": self.config.collection_name,
                "vectors_count": data.get("vectors_count", 0),
                "points_count": data.get("points_count", 0),
                "indexed_vectors_count": data.get("indexed_vectors_count", 0),
                "status": data.get("status", "unknown"),
                "config": data.get("config", {}),
            }

        except Exception as e:
            self.logger.error("stats_failed", error=str(e))
            return {"error": str(e)}

    async def optimize(self) -> bool:
        """Optimize the collection for search.

        Returns:
            True if optimization triggered successfully
        """
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.vector_db_endpoint}/collections/{self.config.collection_name}/index",
                json={"wait": False},
            )
            response.raise_for_status()
            self.logger.info("optimization_triggered")
            return True

        except Exception as e:
            self.logger.error("optimize_failed", error=str(e))
            return False


async def build_knowledge_base(
    indexer: VectorIndexer,
    documents: list[dict[str, Any]],
    recreate: bool = False,
) -> IndexResult:
    """Build a complete knowledge base from documents.

    Args:
        indexer: VectorIndexer instance
        documents: Documents to index
        recreate: Recreate collection if exists

    Returns:
        Indexing result
    """
    # Create collection
    if not await indexer.create_collection(recreate=recreate):
        return IndexResult(
            status=IndexStatus.FAILED,
            errors=["Failed to create collection"],
        )

    # Index documents
    result = await indexer.index_documents(documents)

    # Optimize
    if result.status != IndexStatus.FAILED:
        await indexer.optimize()

    return result
