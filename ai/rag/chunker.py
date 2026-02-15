"""Document chunking for RAG pipeline."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ChunkStrategy(str, Enum):
    """Chunking strategies."""

    FIXED_SIZE = "fixed_size"
    SENTENCE = "sentence"
    PARAGRAPH = "paragraph"
    SEMANTIC = "semantic"
    RECURSIVE = "recursive"


class DocumentChunk(BaseModel):
    """A chunk of a document."""

    chunk_id: str = Field(description="Unique chunk ID")
    doc_id: str = Field(description="Parent document ID")
    content: str = Field(description="Chunk content")
    chunk_index: int = Field(description="Index within document")
    total_chunks: int = Field(description="Total chunks in document")
    start_char: int = Field(description="Start character position")
    end_char: int = Field(description="End character position")
    metadata: dict[str, Any] = Field(default_factory=dict)
    overlap_prev: bool = Field(default=False, description="Has overlap with previous chunk")
    overlap_next: bool = Field(default=False, description="Has overlap with next chunk")


class ChunkConfig(BaseModel):
    """Configuration for document chunking."""

    strategy: ChunkStrategy = Field(default=ChunkStrategy.RECURSIVE)
    chunk_size: int = Field(default=512, description="Target chunk size in characters")
    chunk_overlap: int = Field(default=50, description="Overlap between chunks")
    min_chunk_size: int = Field(default=100, description="Minimum chunk size")
    max_chunk_size: int = Field(default=1000, description="Maximum chunk size")
    separators: list[str] = Field(
        default_factory=lambda: ["\n\n", "\n", ". ", "! ", "? ", "; ", ", ", " "],
        description="Separators for recursive splitting"
    )
    preserve_sentences: bool = Field(default=True, description="Try to preserve complete sentences")


class TextChunker(LoggerMixin):
    """Text chunking service for RAG.

    Features:
    - Multiple chunking strategies
    - Configurable chunk size and overlap
    - Sentence preservation
    - Metadata propagation
    - Semantic-aware chunking (with headings)
    """

    # Sentence ending patterns
    SENTENCE_ENDINGS = re.compile(r"[.!?]\s+")

    # Heading patterns
    HEADING_PATTERNS = [
        re.compile(r"^#{1,6}\s+.+$", re.MULTILINE),  # Markdown
        re.compile(r"^\d+\.\s+.+$", re.MULTILINE),  # Numbered
        re.compile(r"^[A-Z][A-Z\s]+:?\s*$", re.MULTILINE),  # ALL CAPS
    ]

    def __init__(self, config: ChunkConfig | None = None) -> None:
        """Initialize the chunker.

        Args:
            config: Chunking configuration
        """
        self.config = config or ChunkConfig()

    def chunk_document(
        self,
        doc_id: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> list[DocumentChunk]:
        """Chunk a document into smaller pieces.

        Args:
            doc_id: Document ID
            content: Document content
            metadata: Document metadata to include in chunks

        Returns:
            List of document chunks
        """
        metadata = metadata or {}

        self.logger.info(
            "chunking_document",
            doc_id=doc_id,
            content_length=len(content),
            strategy=self.config.strategy,
        )

        if self.config.strategy == ChunkStrategy.FIXED_SIZE:
            chunks = self._chunk_fixed_size(content)
        elif self.config.strategy == ChunkStrategy.SENTENCE:
            chunks = self._chunk_by_sentence(content)
        elif self.config.strategy == ChunkStrategy.PARAGRAPH:
            chunks = self._chunk_by_paragraph(content)
        elif self.config.strategy == ChunkStrategy.SEMANTIC:
            chunks = self._chunk_semantic(content)
        else:  # RECURSIVE
            chunks = self._chunk_recursive(content, self.config.separators)

        # Build DocumentChunk objects
        total_chunks = len(chunks)
        document_chunks = []

        for i, (text, start, end) in enumerate(chunks):
            chunk_id = self._generate_chunk_id(doc_id, i, text)

            document_chunks.append(DocumentChunk(
                chunk_id=chunk_id,
                doc_id=doc_id,
                content=text,
                chunk_index=i,
                total_chunks=total_chunks,
                start_char=start,
                end_char=end,
                metadata=metadata.copy(),
                overlap_prev=i > 0 and self.config.chunk_overlap > 0,
                overlap_next=i < total_chunks - 1 and self.config.chunk_overlap > 0,
            ))

        return document_chunks

    def _chunk_fixed_size(self, content: str) -> list[tuple[str, int, int]]:
        """Chunk by fixed character size with overlap."""
        chunks = []
        start = 0
        content_length = len(content)

        while start < content_length:
            end = min(start + self.config.chunk_size, content_length)

            # Extend to end of word if possible
            if end < content_length:
                # Find last space within chunk
                last_space = content.rfind(" ", start, end)
                if last_space > start:
                    end = last_space

            chunk_text = content[start:end].strip()

            if len(chunk_text) >= self.config.min_chunk_size:
                chunks.append((chunk_text, start, end))

            # Move start with overlap
            start = end - self.config.chunk_overlap

        return chunks

    def _chunk_by_sentence(self, content: str) -> list[tuple[str, int, int]]:
        """Chunk by sentences, grouping to target size."""
        sentences = self._split_into_sentences(content)
        chunks = []
        current_chunk = []
        current_start = 0
        current_length = 0

        for sentence, start, end in sentences:
            sentence_length = len(sentence)

            # Check if adding this sentence exceeds max size
            if current_length + sentence_length > self.config.max_chunk_size and current_chunk:
                # Save current chunk
                chunk_text = " ".join(current_chunk)
                chunk_end = start
                chunks.append((chunk_text, current_start, chunk_end))

                # Start new chunk with overlap
                if self.config.chunk_overlap > 0 and len(current_chunk) > 1:
                    overlap_sentences = current_chunk[-2:]
                    current_chunk = overlap_sentences + [sentence]
                    current_start = chunk_end - sum(len(s) for s in overlap_sentences) - len(overlap_sentences)
                else:
                    current_chunk = [sentence]
                    current_start = start

                current_length = sum(len(s) for s in current_chunk) + len(current_chunk) - 1
            else:
                current_chunk.append(sentence)
                current_length += sentence_length + 1

        # Add remaining chunk
        if current_chunk:
            chunk_text = " ".join(current_chunk)
            chunks.append((chunk_text, current_start, len(content)))

        return chunks

    def _chunk_by_paragraph(self, content: str) -> list[tuple[str, int, int]]:
        """Chunk by paragraphs, grouping small paragraphs."""
        paragraphs = content.split("\n\n")
        chunks = []
        current_chunk = []
        current_start = 0
        current_length = 0
        position = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                position += 2  # Account for \n\n
                continue

            para_length = len(para)
            para_start = content.find(para, position)
            para_end = para_start + para_length

            # Check if adding this paragraph exceeds max size
            if current_length + para_length > self.config.max_chunk_size and current_chunk:
                # Save current chunk
                chunk_text = "\n\n".join(current_chunk)
                chunks.append((chunk_text, current_start, para_start))

                current_chunk = [para]
                current_start = para_start
                current_length = para_length
            else:
                if not current_chunk:
                    current_start = para_start
                current_chunk.append(para)
                current_length += para_length + 2

            position = para_end

        # Add remaining chunk
        if current_chunk:
            chunk_text = "\n\n".join(current_chunk)
            chunks.append((chunk_text, current_start, len(content)))

        return chunks

    def _chunk_semantic(self, content: str) -> list[tuple[str, int, int]]:
        """Chunk by semantic sections (headings)."""
        sections = self._split_by_headings(content)

        chunks = []
        for section_text, start, end in sections:
            # If section is too large, recursively chunk it
            if len(section_text) > self.config.max_chunk_size:
                sub_chunks = self._chunk_recursive(section_text, self.config.separators)
                for sub_text, sub_start, sub_end in sub_chunks:
                    chunks.append((sub_text, start + sub_start, start + sub_end))
            elif len(section_text) >= self.config.min_chunk_size:
                chunks.append((section_text, start, end))

        # Merge small chunks
        chunks = self._merge_small_chunks(chunks)

        return chunks

    def _chunk_recursive(
        self,
        content: str,
        separators: list[str],
        start_offset: int = 0,
    ) -> list[tuple[str, int, int]]:
        """Recursively chunk using hierarchical separators."""
        if not separators:
            return self._chunk_fixed_size(content)

        separator = separators[0]
        remaining_separators = separators[1:]

        # Split by current separator
        parts = content.split(separator)

        # If content is small enough, return as single chunk
        if len(content) <= self.config.max_chunk_size:
            if len(content) >= self.config.min_chunk_size:
                return [(content.strip(), 0, len(content))]
            return []

        chunks = []
        current_chunk = []
        current_length = 0
        position = 0

        for i, part in enumerate(parts):
            part_with_sep = part + (separator if i < len(parts) - 1 else "")
            part_length = len(part_with_sep)

            if current_length + part_length > self.config.chunk_size and current_chunk:
                # Finalize current chunk
                chunk_text = separator.join(current_chunk)

                if len(chunk_text) > self.config.max_chunk_size:
                    # Need to split further
                    sub_chunks = self._chunk_recursive(chunk_text, remaining_separators)
                    chunks.extend(sub_chunks)
                elif len(chunk_text) >= self.config.min_chunk_size:
                    chunks.append((chunk_text, position - len(chunk_text), position))

                current_chunk = [part]
                current_length = len(part)
            else:
                current_chunk.append(part)
                current_length += part_length

            position += part_length

        # Handle remaining content
        if current_chunk:
            chunk_text = separator.join(current_chunk)
            if len(chunk_text) > self.config.max_chunk_size:
                sub_chunks = self._chunk_recursive(chunk_text, remaining_separators)
                chunks.extend(sub_chunks)
            elif len(chunk_text) >= self.config.min_chunk_size:
                chunks.append((chunk_text, position - len(chunk_text), position))

        return chunks

    def _split_into_sentences(self, content: str) -> list[tuple[str, int, int]]:
        """Split content into sentences."""
        sentences = []
        position = 0

        for match in self.SENTENCE_ENDINGS.finditer(content):
            end = match.end()
            sentence = content[position:end].strip()
            if sentence:
                sentences.append((sentence, position, end))
            position = end

        # Add remaining content
        if position < len(content):
            remaining = content[position:].strip()
            if remaining:
                sentences.append((remaining, position, len(content)))

        return sentences

    def _split_by_headings(self, content: str) -> list[tuple[str, int, int]]:
        """Split content by headings."""
        # Find all heading positions
        heading_positions = []
        for pattern in self.HEADING_PATTERNS:
            for match in pattern.finditer(content):
                heading_positions.append(match.start())

        heading_positions = sorted(set(heading_positions))

        if not heading_positions:
            return [(content, 0, len(content))]

        # Split at headings
        sections = []
        for i, start in enumerate(heading_positions):
            end = heading_positions[i + 1] if i + 1 < len(heading_positions) else len(content)
            section = content[start:end].strip()
            if section:
                sections.append((section, start, end))

        # Add content before first heading
        if heading_positions[0] > 0:
            pre_content = content[:heading_positions[0]].strip()
            if pre_content:
                sections.insert(0, (pre_content, 0, heading_positions[0]))

        return sections

    def _merge_small_chunks(
        self,
        chunks: list[tuple[str, int, int]],
    ) -> list[tuple[str, int, int]]:
        """Merge chunks that are too small."""
        if not chunks:
            return chunks

        merged = []
        current_text = ""
        current_start = 0
        current_end = 0

        for text, start, end in chunks:
            if not current_text:
                current_text = text
                current_start = start
                current_end = end
            elif len(current_text) + len(text) <= self.config.max_chunk_size:
                current_text = f"{current_text}\n\n{text}"
                current_end = end
            else:
                if len(current_text) >= self.config.min_chunk_size:
                    merged.append((current_text, current_start, current_end))
                current_text = text
                current_start = start
                current_end = end

        # Add remaining
        if current_text and len(current_text) >= self.config.min_chunk_size:
            merged.append((current_text, current_start, current_end))

        return merged

    def _generate_chunk_id(self, doc_id: str, index: int, content: str) -> str:
        """Generate unique chunk ID."""
        hash_input = f"{doc_id}:{index}:{content[:100]}"
        return f"{doc_id}-chunk-{hashlib.md5(hash_input.encode()).hexdigest()[:8]}"

    def estimate_chunks(self, content_length: int) -> int:
        """Estimate number of chunks for given content length.

        Args:
            content_length: Length of content in characters

        Returns:
            Estimated number of chunks
        """
        effective_chunk_size = self.config.chunk_size - self.config.chunk_overlap
        return max(1, (content_length + effective_chunk_size - 1) // effective_chunk_size)
