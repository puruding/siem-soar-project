"""Collect analyst feedback for model improvement."""

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel


class FeedbackType(str, Enum):
    """Types of analyst feedback."""

    SEVERITY_CORRECTION = "severity_correction"
    CATEGORY_CORRECTION = "category_correction"
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    PRIORITY_ADJUSTMENT = "priority_adjustment"
    MITRE_CORRECTION = "mitre_correction"
    OTHER = "other"


class AnalystFeedback(BaseModel):
    """Analyst feedback on an alert classification."""

    feedback_id: UUID = Field(default_factory=uuid4)
    alert_id: str = Field(description="ID of the alert")
    analyst_id: str = Field(description="ID of the analyst")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    feedback_type: FeedbackType = Field(description="Type of feedback")

    # Original classification
    original_severity: str | None = Field(default=None)
    original_category: str | None = Field(default=None)
    original_priority: float | None = Field(default=None)

    # Corrected values
    corrected_severity: str | None = Field(default=None)
    corrected_category: str | None = Field(default=None)
    corrected_priority: float | None = Field(default=None)
    is_false_positive: bool | None = Field(default=None)

    # MITRE corrections
    mitre_tactics_add: list[str] = Field(default_factory=list)
    mitre_tactics_remove: list[str] = Field(default_factory=list)
    mitre_techniques_add: list[str] = Field(default_factory=list)
    mitre_techniques_remove: list[str] = Field(default_factory=list)

    # Additional context
    notes: str | None = Field(default=None, description="Analyst notes")
    confidence: float = Field(default=1.0, ge=0, le=1, description="Analyst confidence")
    time_spent_seconds: int | None = Field(default=None, description="Time spent on investigation")


class FeedbackCollector(LoggerMixin):
    """Collect and store analyst feedback."""

    def __init__(
        self,
        storage_backend: str = "clickhouse",
    ) -> None:
        """Initialize the feedback collector.

        Args:
            storage_backend: Backend for storing feedback
        """
        self.storage_backend = storage_backend
        self._buffer: list[AnalystFeedback] = []
        self._buffer_lock = asyncio.Lock()
        self._flush_interval = 60  # seconds
        self._max_buffer_size = 100

        # Database connection
        self._client: Any = None

    async def connect(self) -> None:
        """Connect to storage backend."""
        settings = get_settings()

        if self.storage_backend == "clickhouse":
            import clickhouse_connect
            self._client = clickhouse_connect.get_client(
                host=settings.clickhouse_dsn.split("://")[1].split(":")[0],
            )
            await self._ensure_table()

        self.logger.info(
            "feedback_collector_connected",
            backend=self.storage_backend,
        )

    async def _ensure_table(self) -> None:
        """Ensure feedback table exists."""
        if self.storage_backend == "clickhouse":
            self._client.command("""
                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id UUID,
                    alert_id String,
                    analyst_id String,
                    timestamp DateTime64(3),
                    feedback_type String,
                    original_severity Nullable(String),
                    original_category Nullable(String),
                    original_priority Nullable(Float64),
                    corrected_severity Nullable(String),
                    corrected_category Nullable(String),
                    corrected_priority Nullable(Float64),
                    is_false_positive Nullable(UInt8),
                    mitre_tactics_add Array(String),
                    mitre_tactics_remove Array(String),
                    mitre_techniques_add Array(String),
                    mitre_techniques_remove Array(String),
                    notes Nullable(String),
                    confidence Float64,
                    time_spent_seconds Nullable(Int32)
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, alert_id)
                PARTITION BY toYYYYMM(timestamp)
            """)

    async def collect(self, feedback: AnalystFeedback) -> None:
        """Collect a piece of feedback.

        Args:
            feedback: Analyst feedback
        """
        async with self._buffer_lock:
            self._buffer.append(feedback)

            self.logger.info(
                "feedback_collected",
                alert_id=feedback.alert_id,
                feedback_type=feedback.feedback_type,
            )

            if len(self._buffer) >= self._max_buffer_size:
                await self._flush()

    async def _flush(self) -> None:
        """Flush feedback buffer to storage."""
        if not self._buffer:
            return

        feedback_to_flush = self._buffer.copy()
        self._buffer.clear()

        try:
            if self.storage_backend == "clickhouse":
                await self._flush_to_clickhouse(feedback_to_flush)

            self.logger.info(
                "feedback_flushed",
                count=len(feedback_to_flush),
            )
        except Exception as e:
            self.logger.error(
                "feedback_flush_failed",
                error=str(e),
                count=len(feedback_to_flush),
            )
            # Re-add to buffer for retry
            self._buffer.extend(feedback_to_flush)

    async def _flush_to_clickhouse(self, feedback_list: list[AnalystFeedback]) -> None:
        """Flush feedback to ClickHouse.

        Args:
            feedback_list: List of feedback to flush
        """
        rows = []
        for f in feedback_list:
            rows.append([
                str(f.feedback_id),
                f.alert_id,
                f.analyst_id,
                f.timestamp,
                f.feedback_type.value,
                f.original_severity,
                f.original_category,
                f.original_priority,
                f.corrected_severity,
                f.corrected_category,
                f.corrected_priority,
                int(f.is_false_positive) if f.is_false_positive is not None else None,
                f.mitre_tactics_add,
                f.mitre_tactics_remove,
                f.mitre_techniques_add,
                f.mitre_techniques_remove,
                f.notes,
                f.confidence,
                f.time_spent_seconds,
            ])

        self._client.insert(
            "analyst_feedback",
            rows,
            column_names=[
                "feedback_id", "alert_id", "analyst_id", "timestamp",
                "feedback_type", "original_severity", "original_category",
                "original_priority", "corrected_severity", "corrected_category",
                "corrected_priority", "is_false_positive", "mitre_tactics_add",
                "mitre_tactics_remove", "mitre_techniques_add", "mitre_techniques_remove",
                "notes", "confidence", "time_spent_seconds"
            ],
        )

    async def get_feedback_for_alert(
        self, alert_id: str
    ) -> list[AnalystFeedback]:
        """Get all feedback for an alert.

        Args:
            alert_id: Alert ID

        Returns:
            List of feedback
        """
        if self.storage_backend == "clickhouse":
            result = self._client.query(
                "SELECT * FROM analyst_feedback WHERE alert_id = %(alert_id)s ORDER BY timestamp",
                parameters={"alert_id": alert_id},
            )

            feedback_list = []
            for row in result.result_rows:
                feedback_list.append(AnalystFeedback(
                    feedback_id=row[0],
                    alert_id=row[1],
                    analyst_id=row[2],
                    timestamp=row[3],
                    feedback_type=FeedbackType(row[4]),
                    original_severity=row[5],
                    original_category=row[6],
                    original_priority=row[7],
                    corrected_severity=row[8],
                    corrected_category=row[9],
                    corrected_priority=row[10],
                    is_false_positive=bool(row[11]) if row[11] is not None else None,
                    mitre_tactics_add=row[12] or [],
                    mitre_tactics_remove=row[13] or [],
                    mitre_techniques_add=row[14] or [],
                    mitre_techniques_remove=row[15] or [],
                    notes=row[16],
                    confidence=row[17],
                    time_spent_seconds=row[18],
                ))

            return feedback_list

        return []

    async def get_recent_feedback(
        self,
        hours: int = 24,
        feedback_type: FeedbackType | None = None,
    ) -> list[AnalystFeedback]:
        """Get recent feedback.

        Args:
            hours: Hours to look back
            feedback_type: Filter by feedback type

        Returns:
            List of recent feedback
        """
        if self.storage_backend == "clickhouse":
            query = """
                SELECT * FROM analyst_feedback
                WHERE timestamp > now() - INTERVAL %(hours)s HOUR
            """
            params = {"hours": hours}

            if feedback_type:
                query += " AND feedback_type = %(feedback_type)s"
                params["feedback_type"] = feedback_type.value

            query += " ORDER BY timestamp DESC"

            result = self._client.query(query, parameters=params)

            feedback_list = []
            for row in result.result_rows:
                feedback_list.append(AnalystFeedback(
                    feedback_id=row[0],
                    alert_id=row[1],
                    analyst_id=row[2],
                    timestamp=row[3],
                    feedback_type=FeedbackType(row[4]),
                    # ... map other fields
                ))

            return feedback_list

        return []

    async def get_fp_rate_by_rule(
        self,
        days: int = 30,
    ) -> dict[str, float]:
        """Get false positive rates by rule.

        Args:
            days: Days to look back

        Returns:
            Dictionary of rule_id -> FP rate
        """
        if self.storage_backend == "clickhouse":
            result = self._client.query(f"""
                SELECT
                    a.rule_id,
                    count(*) as total,
                    countIf(f.is_false_positive = 1) as fp_count
                FROM alerts a
                INNER JOIN analyst_feedback f ON a.alert_id = f.alert_id
                WHERE a.timestamp > now() - INTERVAL {days} DAY
                GROUP BY a.rule_id
                HAVING total >= 10
                ORDER BY fp_count / total DESC
            """)

            return {
                row[0]: row[2] / row[1] if row[1] > 0 else 0
                for row in result.result_rows
            }

        return {}

    async def close(self) -> None:
        """Close connections and flush remaining feedback."""
        await self._flush()
        if self._client:
            self._client.close()
