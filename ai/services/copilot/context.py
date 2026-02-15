"""Context management for Security Copilot sessions."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ContextType(str, Enum):
    """Types of context items."""

    ALERT = "alert"
    CASE = "case"
    EVENT = "event"
    QUERY_RESULT = "query_result"
    PLAYBOOK = "playbook"
    USER_PREFERENCE = "user_preference"


class ContextItem(BaseModel):
    """Single context item."""

    item_id: str = Field(default_factory=lambda: str(uuid4()))
    context_type: ContextType
    data: dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = Field(default=None)
    priority: int = Field(default=0, description="Higher = more important")


class SessionContext(BaseModel):
    """Session context container."""

    session_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str | None = Field(default=None)
    items: dict[str, ContextItem] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)


class ContextManager(LoggerMixin):
    """Manages context for Copilot sessions.

    Features:
    - Session-scoped context storage
    - Automatic expiration
    - Priority-based context selection
    - Context summarization for LLM
    """

    # Default TTLs by context type
    DEFAULT_TTLS = {
        ContextType.ALERT: timedelta(hours=4),
        ContextType.CASE: timedelta(hours=8),
        ContextType.EVENT: timedelta(hours=2),
        ContextType.QUERY_RESULT: timedelta(minutes=30),
        ContextType.PLAYBOOK: timedelta(hours=4),
        ContextType.USER_PREFERENCE: timedelta(days=30),
    }

    def __init__(self, max_context_items: int = 50) -> None:
        """Initialize context manager.

        Args:
            max_context_items: Maximum context items per session
        """
        self.max_context_items = max_context_items
        self._sessions: dict[str, SessionContext] = {}

    def get_or_create_session(
        self,
        session_id: str | None = None,
        user_id: str | None = None,
    ) -> SessionContext:
        """Get or create a session.

        Args:
            session_id: Existing session ID
            user_id: User ID

        Returns:
            Session context
        """
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            session.last_activity = datetime.utcnow()
            return session

        session = SessionContext(user_id=user_id)
        self._sessions[session.session_id] = session
        return session

    def add_context(
        self,
        session_id: str,
        context_type: ContextType,
        data: dict[str, Any],
        item_id: str | None = None,
        priority: int = 0,
        ttl: timedelta | None = None,
    ) -> str:
        """Add context item to session.

        Args:
            session_id: Session ID
            context_type: Type of context
            data: Context data
            item_id: Optional custom ID
            priority: Item priority
            ttl: Time-to-live

        Returns:
            Context item ID
        """
        session = self._sessions.get(session_id)
        if not session:
            session = self.get_or_create_session(session_id)

        # Calculate expiration
        ttl = ttl or self.DEFAULT_TTLS.get(context_type, timedelta(hours=1))
        expires_at = datetime.utcnow() + ttl

        # Create item
        item = ContextItem(
            item_id=item_id or str(uuid4()),
            context_type=context_type,
            data=data,
            expires_at=expires_at,
            priority=priority,
        )

        # Add to session
        session.items[item.item_id] = item
        session.last_activity = datetime.utcnow()

        # Trim if needed
        self._trim_context(session)

        self.logger.info(
            "context_added",
            session_id=session_id,
            context_type=context_type,
            item_id=item.item_id,
        )

        return item.item_id

    def get_context(
        self,
        session_id: str,
        context_type: ContextType | None = None,
    ) -> list[ContextItem]:
        """Get context items from session.

        Args:
            session_id: Session ID
            context_type: Filter by type

        Returns:
            List of context items
        """
        session = self._sessions.get(session_id)
        if not session:
            return []

        # Clean expired items
        self._clean_expired(session)

        items = list(session.items.values())

        if context_type:
            items = [i for i in items if i.context_type == context_type]

        # Sort by priority (descending) then by created_at (descending)
        items.sort(key=lambda x: (-x.priority, -x.created_at.timestamp()))

        return items

    def remove_context(self, session_id: str, item_id: str) -> bool:
        """Remove a context item.

        Args:
            session_id: Session ID
            item_id: Item ID to remove

        Returns:
            True if removed
        """
        session = self._sessions.get(session_id)
        if session and item_id in session.items:
            del session.items[item_id]
            return True
        return False

    def clear_context(
        self,
        session_id: str,
        context_type: ContextType | None = None,
    ) -> int:
        """Clear context items.

        Args:
            session_id: Session ID
            context_type: Clear only this type (None = all)

        Returns:
            Number of items cleared
        """
        session = self._sessions.get(session_id)
        if not session:
            return 0

        if context_type is None:
            count = len(session.items)
            session.items.clear()
            return count

        items_to_remove = [
            item_id for item_id, item in session.items.items()
            if item.context_type == context_type
        ]

        for item_id in items_to_remove:
            del session.items[item_id]

        return len(items_to_remove)

    def build_context_string(
        self,
        session_id: str,
        max_tokens: int = 1000,
        include_types: list[ContextType] | None = None,
    ) -> str:
        """Build context string for LLM prompt.

        Args:
            session_id: Session ID
            max_tokens: Maximum tokens (approximate)
            include_types: Types to include

        Returns:
            Formatted context string
        """
        items = self.get_context(session_id)

        if include_types:
            items = [i for i in items if i.context_type in include_types]

        if not items:
            return ""

        parts = ["Current Context:"]
        char_limit = max_tokens * 4  # Rough token-to-char ratio

        for item in items:
            if len("\n".join(parts)) > char_limit:
                break

            part = self._format_context_item(item)
            parts.append(part)

        return "\n".join(parts)

    def _format_context_item(self, item: ContextItem) -> str:
        """Format a context item for display."""
        if item.context_type == ContextType.ALERT:
            return f"- Alert: {item.data.get('title', 'N/A')} (Severity: {item.data.get('severity', 'N/A')})"

        elif item.context_type == ContextType.CASE:
            return f"- Case: {item.data.get('title', 'N/A')} (Status: {item.data.get('status', 'N/A')})"

        elif item.context_type == ContextType.EVENT:
            return f"- Event: {item.data.get('event_type', 'N/A')} from {item.data.get('source_ip', 'N/A')}"

        elif item.context_type == ContextType.QUERY_RESULT:
            result_count = len(item.data.get('results', []))
            return f"- Query Result: {result_count} rows"

        elif item.context_type == ContextType.PLAYBOOK:
            return f"- Playbook: {item.data.get('name', 'N/A')}"

        else:
            context_type_val = item.context_type.value if hasattr(item.context_type, 'value') else str(item.context_type)
            return f"- {context_type_val}: {str(item.data)[:100]}"

    def _clean_expired(self, session: SessionContext) -> None:
        """Remove expired context items."""
        now = datetime.utcnow()
        expired = [
            item_id for item_id, item in session.items.items()
            if item.expires_at and item.expires_at < now
        ]

        for item_id in expired:
            del session.items[item_id]

    def _trim_context(self, session: SessionContext) -> None:
        """Trim context to max size."""
        if len(session.items) <= self.max_context_items:
            return

        # Sort by priority and age
        items = list(session.items.items())
        items.sort(key=lambda x: (x[1].priority, x[1].created_at.timestamp()), reverse=True)

        # Keep top items
        keep_ids = {item_id for item_id, _ in items[:self.max_context_items]}
        session.items = {
            item_id: item
            for item_id, item in session.items.items()
            if item_id in keep_ids
        }

    def set_current_alert(self, session_id: str, alert: dict[str, Any]) -> str:
        """Set the current alert being viewed.

        Args:
            session_id: Session ID
            alert: Alert data

        Returns:
            Context item ID
        """
        # Remove previous current alerts
        self.clear_context(session_id, ContextType.ALERT)

        return self.add_context(
            session_id,
            ContextType.ALERT,
            alert,
            priority=10,  # High priority
        )

    def set_current_case(self, session_id: str, case: dict[str, Any]) -> str:
        """Set the current case being viewed.

        Args:
            session_id: Session ID
            case: Case data

        Returns:
            Context item ID
        """
        # Remove previous current cases
        self.clear_context(session_id, ContextType.CASE)

        return self.add_context(
            session_id,
            ContextType.CASE,
            case,
            priority=10,
        )

    def add_query_result(
        self,
        session_id: str,
        query: str,
        results: list[dict[str, Any]],
    ) -> str:
        """Add a query result to context.

        Args:
            session_id: Session ID
            query: SQL query
            results: Query results

        Returns:
            Context item ID
        """
        return self.add_context(
            session_id,
            ContextType.QUERY_RESULT,
            {
                "query": query,
                "results": results[:100],  # Limit stored results
                "total_rows": len(results),
            },
            priority=5,
            ttl=timedelta(minutes=30),
        )

    def get_session_summary(self, session_id: str) -> dict[str, Any]:
        """Get summary of session context.

        Args:
            session_id: Session ID

        Returns:
            Session summary
        """
        session = self._sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        self._clean_expired(session)

        type_counts = {}
        for item in session.items.values():
            type_name = item.context_type.value if hasattr(item.context_type, 'value') else str(item.context_type)
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "total_items": len(session.items),
            "items_by_type": type_counts,
            "created_at": session.created_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
        }

    def cleanup_inactive_sessions(self, max_age: timedelta = timedelta(hours=24)) -> int:
        """Clean up inactive sessions.

        Args:
            max_age: Maximum session age

        Returns:
            Number of sessions removed
        """
        cutoff = datetime.utcnow() - max_age
        to_remove = [
            session_id for session_id, session in self._sessions.items()
            if session.last_activity < cutoff
        ]

        for session_id in to_remove:
            del self._sessions[session_id]

        return len(to_remove)
