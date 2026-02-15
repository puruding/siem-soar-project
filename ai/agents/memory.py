"""Agent Memory - Short-term and long-term memory for agents."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class MemoryType(str, Enum):
    """Types of agent memory."""

    SHORT_TERM = "short_term"  # Current execution context
    WORKING = "working"  # Working memory for current task
    EPISODIC = "episodic"  # Past experiences and executions
    SEMANTIC = "semantic"  # Knowledge and facts
    PROCEDURAL = "procedural"  # How to perform tasks


class MemoryImportance(str, Enum):
    """Importance level for memory items."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MemoryItem(BaseModel):
    """A single memory item."""

    memory_id: str = Field(default_factory=lambda: str(uuid4()))
    memory_type: MemoryType = Field(description="Type of memory")
    content: dict[str, Any] = Field(description="Memory content")
    importance: MemoryImportance = Field(default=MemoryImportance.MEDIUM)
    tags: list[str] = Field(default_factory=list)
    embedding: list[float] | None = Field(default=None)
    access_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_accessed: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(default=None)

    @property
    def is_expired(self) -> bool:
        """Check if memory is expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class ConversationMessage(BaseModel):
    """A message in conversation memory."""

    role: str = Field(description="Message role (system/user/assistant/tool)")
    content: str = Field(description="Message content")
    name: str | None = Field(default=None, description="Function/tool name if applicable")
    tool_call_id: str | None = Field(default=None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentMemory(LoggerMixin):
    """Memory system for AI agents.

    Features:
    - Short-term memory for current context
    - Working memory for task state
    - Episodic memory for past experiences
    - Semantic memory for knowledge
    - Memory retrieval with importance-based ranking
    """

    def __init__(
        self,
        agent_id: str,
        short_term_capacity: int = 100,
        working_capacity: int = 50,
        episodic_capacity: int = 1000,
    ) -> None:
        """Initialize agent memory.

        Args:
            agent_id: ID of the agent
            short_term_capacity: Max short-term memory items
            working_capacity: Max working memory items
            episodic_capacity: Max episodic memory items
        """
        self.agent_id = agent_id
        self._short_term_capacity = short_term_capacity
        self._working_capacity = working_capacity
        self._episodic_capacity = episodic_capacity

        # Memory stores
        self._short_term: deque[MemoryItem] = deque(maxlen=short_term_capacity)
        self._working: dict[str, MemoryItem] = {}
        self._episodic: list[MemoryItem] = []
        self._semantic: dict[str, MemoryItem] = {}
        self._procedural: dict[str, MemoryItem] = {}

        # Conversation history
        self._conversations: dict[str, list[ConversationMessage]] = {}
        self._current_conversation: str | None = None

    def add(
        self,
        content: dict[str, Any],
        memory_type: MemoryType,
        importance: MemoryImportance = MemoryImportance.MEDIUM,
        tags: list[str] | None = None,
        ttl_seconds: int | None = None,
        key: str | None = None,
    ) -> str:
        """Add a memory item.

        Args:
            content: Memory content
            memory_type: Type of memory
            importance: Importance level
            tags: Optional tags for retrieval
            ttl_seconds: Time-to-live in seconds
            key: Optional key for semantic/procedural memory

        Returns:
            Memory ID
        """
        expires_at = None
        if ttl_seconds:
            expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

        item = MemoryItem(
            memory_type=memory_type,
            content=content,
            importance=importance,
            tags=tags or [],
            expires_at=expires_at,
        )

        if memory_type == MemoryType.SHORT_TERM:
            self._short_term.append(item)

        elif memory_type == MemoryType.WORKING:
            if len(self._working) >= self._working_capacity:
                self._evict_working_memory()
            self._working[key or item.memory_id] = item

        elif memory_type == MemoryType.EPISODIC:
            if len(self._episodic) >= self._episodic_capacity:
                self._evict_episodic_memory()
            self._episodic.append(item)

        elif memory_type == MemoryType.SEMANTIC:
            if key:
                self._semantic[key] = item
            else:
                self._semantic[item.memory_id] = item

        elif memory_type == MemoryType.PROCEDURAL:
            if key:
                self._procedural[key] = item
            else:
                self._procedural[item.memory_id] = item

        self.logger.debug(
            "memory_added",
            agent_id=self.agent_id,
            memory_type=memory_type.value,
            memory_id=item.memory_id,
        )

        return item.memory_id

    def get(self, memory_id: str) -> MemoryItem | None:
        """Get a memory item by ID."""
        # Search in all stores
        for store in [self._semantic, self._procedural, self._working]:
            if memory_id in store:
                item = store[memory_id]
                item.access_count += 1
                item.last_accessed = datetime.utcnow()
                return item

        # Search in lists
        for item in list(self._short_term) + self._episodic:
            if item.memory_id == memory_id:
                item.access_count += 1
                item.last_accessed = datetime.utcnow()
                return item

        return None

    def retrieve(
        self,
        query: str | None = None,
        memory_type: MemoryType | None = None,
        tags: list[str] | None = None,
        limit: int = 10,
        min_importance: MemoryImportance | None = None,
    ) -> list[MemoryItem]:
        """Retrieve memories based on criteria.

        Args:
            query: Optional search query
            memory_type: Filter by memory type
            tags: Filter by tags
            limit: Maximum items to return
            min_importance: Minimum importance level

        Returns:
            List of matching memories
        """
        candidates = []

        # Collect candidates from appropriate stores
        if memory_type is None or memory_type == MemoryType.SHORT_TERM:
            candidates.extend(self._short_term)

        if memory_type is None or memory_type == MemoryType.WORKING:
            candidates.extend(self._working.values())

        if memory_type is None or memory_type == MemoryType.EPISODIC:
            candidates.extend(self._episodic)

        if memory_type is None or memory_type == MemoryType.SEMANTIC:
            candidates.extend(self._semantic.values())

        if memory_type is None or memory_type == MemoryType.PROCEDURAL:
            candidates.extend(self._procedural.values())

        # Filter by expiry
        candidates = [c for c in candidates if not c.is_expired]

        # Filter by tags
        if tags:
            candidates = [
                c for c in candidates
                if any(tag in c.tags for tag in tags)
            ]

        # Filter by importance
        if min_importance:
            importance_order = [
                MemoryImportance.LOW,
                MemoryImportance.MEDIUM,
                MemoryImportance.HIGH,
                MemoryImportance.CRITICAL,
            ]
            min_idx = importance_order.index(min_importance)
            candidates = [
                c for c in candidates
                if importance_order.index(c.importance) >= min_idx
            ]

        # Score and rank candidates
        scored = []
        for item in candidates:
            score = self._calculate_relevance(item, query)
            scored.append((item, score))

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        # Update access counts
        result = []
        for item, _ in scored[:limit]:
            item.access_count += 1
            item.last_accessed = datetime.utcnow()
            result.append(item)

        return result

    def _calculate_relevance(
        self,
        item: MemoryItem,
        query: str | None = None,
    ) -> float:
        """Calculate relevance score for a memory item."""
        score = 0.0

        # Importance bonus
        importance_scores = {
            MemoryImportance.LOW: 0.1,
            MemoryImportance.MEDIUM: 0.3,
            MemoryImportance.HIGH: 0.5,
            MemoryImportance.CRITICAL: 0.8,
        }
        score += importance_scores.get(item.importance, 0.0)

        # Recency bonus
        age_hours = (datetime.utcnow() - item.created_at).total_seconds() / 3600
        recency_score = max(0, 1 - (age_hours / 24))  # Decay over 24 hours
        score += recency_score * 0.2

        # Access frequency bonus
        if item.access_count > 0:
            score += min(item.access_count / 10, 0.2)

        # Query match bonus (simple text matching)
        if query:
            content_str = str(item.content).lower()
            query_lower = query.lower()
            if query_lower in content_str:
                score += 0.5
            elif any(word in content_str for word in query_lower.split()):
                score += 0.2

        return min(score, 1.0)

    def _evict_working_memory(self) -> None:
        """Evict least important items from working memory."""
        if not self._working:
            return

        # Sort by importance and access
        items = sorted(
            self._working.items(),
            key=lambda x: (
                x[1].importance.value,
                x[1].access_count,
                x[1].last_accessed,
            ),
        )

        # Remove lowest priority
        key_to_remove = items[0][0]
        del self._working[key_to_remove]

    def _evict_episodic_memory(self) -> None:
        """Evict old, low-importance episodic memories."""
        if not self._episodic:
            return

        # Sort by importance, then by age
        self._episodic.sort(
            key=lambda x: (
                x.importance.value,
                -x.created_at.timestamp(),
            ),
        )

        # Remove oldest low-importance
        self._episodic.pop(0)

    # Conversation memory methods

    def start_conversation(self, conversation_id: str | None = None) -> str:
        """Start a new conversation.

        Args:
            conversation_id: Optional conversation ID

        Returns:
            Conversation ID
        """
        conv_id = conversation_id or str(uuid4())
        self._conversations[conv_id] = []
        self._current_conversation = conv_id
        return conv_id

    def add_message(
        self,
        role: str,
        content: str,
        name: str | None = None,
        tool_call_id: str | None = None,
        conversation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a message to conversation memory.

        Args:
            role: Message role
            content: Message content
            name: Function/tool name
            tool_call_id: Tool call ID for function responses
            conversation_id: Conversation ID (uses current if not specified)
            metadata: Additional metadata
        """
        conv_id = conversation_id or self._current_conversation
        if not conv_id:
            conv_id = self.start_conversation()

        if conv_id not in self._conversations:
            self._conversations[conv_id] = []

        message = ConversationMessage(
            role=role,
            content=content,
            name=name,
            tool_call_id=tool_call_id,
            metadata=metadata or {},
        )

        self._conversations[conv_id].append(message)

    def get_messages(
        self,
        conversation_id: str | None = None,
        last_n: int | None = None,
    ) -> list[dict[str, Any]]:
        """Get messages in LangChain/OpenAI format.

        Args:
            conversation_id: Conversation ID
            last_n: Get only last N messages

        Returns:
            Messages in chat format
        """
        conv_id = conversation_id or self._current_conversation
        if not conv_id or conv_id not in self._conversations:
            return []

        messages = self._conversations[conv_id]
        if last_n:
            messages = messages[-last_n:]

        result = []
        for msg in messages:
            entry = {
                "role": msg.role,
                "content": msg.content,
            }
            if msg.name:
                entry["name"] = msg.name
            if msg.tool_call_id:
                entry["tool_call_id"] = msg.tool_call_id
            result.append(entry)

        return result

    def clear_conversation(self, conversation_id: str | None = None) -> None:
        """Clear a conversation."""
        conv_id = conversation_id or self._current_conversation
        if conv_id and conv_id in self._conversations:
            del self._conversations[conv_id]
            if self._current_conversation == conv_id:
                self._current_conversation = None

    def get_context_summary(self, max_length: int = 2000) -> str:
        """Get a summary of current context for LLM.

        Args:
            max_length: Maximum summary length

        Returns:
            Context summary string
        """
        parts = []

        # Recent short-term memories
        recent = list(self._short_term)[-5:]
        if recent:
            parts.append("Recent context:")
            for item in recent:
                parts.append(f"- {str(item.content)[:100]}")

        # Important working memory
        important = [
            item for item in self._working.values()
            if item.importance in [MemoryImportance.HIGH, MemoryImportance.CRITICAL]
        ]
        if important:
            parts.append("\nCritical information:")
            for item in important[:5]:
                parts.append(f"- {str(item.content)[:100]}")

        summary = "\n".join(parts)
        if len(summary) > max_length:
            summary = summary[:max_length - 3] + "..."

        return summary

    def clear_all(self) -> None:
        """Clear all memory."""
        self._short_term.clear()
        self._working.clear()
        self._episodic.clear()
        self._semantic.clear()
        self._procedural.clear()
        self._conversations.clear()
        self._current_conversation = None
        self.logger.info("memory_cleared", agent_id=self.agent_id)

    def get_stats(self) -> dict[str, Any]:
        """Get memory statistics."""
        return {
            "agent_id": self.agent_id,
            "short_term_count": len(self._short_term),
            "short_term_capacity": self._short_term_capacity,
            "working_count": len(self._working),
            "working_capacity": self._working_capacity,
            "episodic_count": len(self._episodic),
            "episodic_capacity": self._episodic_capacity,
            "semantic_count": len(self._semantic),
            "procedural_count": len(self._procedural),
            "conversation_count": len(self._conversations),
            "current_conversation": self._current_conversation,
        }
