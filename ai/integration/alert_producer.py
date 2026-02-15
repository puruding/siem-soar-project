"""Kafka producer for publishing triage results."""

import asyncio
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from kafka import KafkaProducer
from kafka.errors import KafkaError
from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel
from models.classifier import AlertClassification


class ProducerConfig(BaseModel):
    """Configuration for alert producer."""

    # Kafka settings
    bootstrap_servers: list[str] = Field(default_factory=lambda: ["localhost:9092"])
    acks: str = Field(default="all")
    retries: int = Field(default=3)
    batch_size: int = Field(default=16384)
    linger_ms: int = Field(default=10)
    buffer_memory: int = Field(default=33554432)  # 32MB
    compression_type: str = Field(default="gzip")

    # Topics
    classified_topic: str = Field(default="alerts.classified")
    priority_topic: str = Field(default="alerts.priority")
    notification_topic: str = Field(default="alerts.notifications")


class TriageResult(BaseModel):
    """Published triage result."""

    alert_id: str = Field(description="Original alert ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Classification
    severity: str = Field(description="Classified severity")
    severity_confidence: float = Field(description="Severity confidence")
    category: str = Field(description="Classified category")
    category_confidence: float = Field(description="Category confidence")
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Priority
    priority_score: float = Field(description="Priority score 0-100")
    priority_level: str = Field(description="Priority level")
    risk_score: float = Field(description="Risk score 0-100")

    # FP detection
    is_false_positive: bool = Field(default=False)
    fp_confidence: float = Field(default=0.0)

    # Actions
    recommended_actions: list[str] = Field(default_factory=list)
    assigned_to: str | None = Field(default=None)

    # Processing metadata
    processing_time_ms: float = Field(description="Processing time")
    model_version: str = Field(default="unknown")


class AlertProducer(LoggerMixin):
    """Produce triage results to Kafka."""

    def __init__(
        self,
        config: ProducerConfig | None = None,
    ) -> None:
        """Initialize the producer.

        Args:
            config: Producer configuration
        """
        self.config = config or ProducerConfig()
        self._producer: KafkaProducer | None = None
        self._metrics = {
            "messages_sent": 0,
            "bytes_sent": 0,
            "errors": 0,
        }

    async def start(self) -> None:
        """Start the producer."""
        self._producer = KafkaProducer(
            bootstrap_servers=self.config.bootstrap_servers,
            acks=self.config.acks,
            retries=self.config.retries,
            batch_size=self.config.batch_size,
            linger_ms=self.config.linger_ms,
            buffer_memory=self.config.buffer_memory,
            compression_type=self.config.compression_type,
            value_serializer=self._serialize,
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )

        self.logger.info(
            "producer_started",
            bootstrap_servers=self.config.bootstrap_servers,
        )

    async def stop(self) -> None:
        """Stop the producer."""
        if self._producer:
            self._producer.flush()
            self._producer.close()
            self._producer = None

        self.logger.info(
            "producer_stopped",
            metrics=self._metrics,
        )

    def _serialize(self, value: Any) -> bytes:
        """Serialize value to JSON bytes."""

        def default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, UUID):
                return str(obj)
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            return str(obj)

        return json.dumps(value, default=default).encode("utf-8")

    async def publish_result(
        self,
        result: TriageResult,
        key: str | None = None,
    ) -> None:
        """Publish a single triage result.

        Args:
            result: Triage result
            key: Optional partition key
        """
        if not self._producer:
            raise RuntimeError("Producer not started")

        key = key or result.alert_id

        try:
            future = self._producer.send(
                self.config.classified_topic,
                key=key,
                value=result.model_dump(),
            )

            # Don't block, use callback for errors
            future.add_callback(self._on_success)
            future.add_errback(self._on_error)

        except KafkaError as e:
            self.logger.error(
                "publish_failed",
                alert_id=result.alert_id,
                error=str(e),
            )
            self._metrics["errors"] += 1
            raise

    async def publish_batch(
        self,
        results: list[TriageResult],
    ) -> None:
        """Publish a batch of results.

        Args:
            results: List of triage results
        """
        if not self._producer:
            raise RuntimeError("Producer not started")

        for result in results:
            try:
                self._producer.send(
                    self.config.classified_topic,
                    key=result.alert_id,
                    value=result.model_dump(),
                )
            except KafkaError as e:
                self.logger.error(
                    "batch_publish_error",
                    alert_id=result.alert_id,
                    error=str(e),
                )
                self._metrics["errors"] += 1

        # Flush after batch
        self._producer.flush()

        self.logger.debug(
            "batch_published",
            count=len(results),
        )

    async def publish_priority_update(
        self,
        alert_id: str,
        priority_score: float,
        priority_level: str,
        reason: str,
    ) -> None:
        """Publish priority update for an alert.

        Args:
            alert_id: Alert ID
            priority_score: New priority score
            priority_level: New priority level
            reason: Reason for update
        """
        if not self._producer:
            raise RuntimeError("Producer not started")

        message = {
            "alert_id": alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "priority_score": priority_score,
            "priority_level": priority_level,
            "reason": reason,
        }

        self._producer.send(
            self.config.priority_topic,
            key=alert_id,
            value=message,
        )

    async def publish_notification(
        self,
        alert_id: str,
        notification_type: str,
        recipients: list[str],
        message: str,
        severity: str = "medium",
    ) -> None:
        """Publish notification for high-priority alerts.

        Args:
            alert_id: Alert ID
            notification_type: Type of notification
            recipients: List of recipient identifiers
            message: Notification message
            severity: Notification severity
        """
        if not self._producer:
            raise RuntimeError("Producer not started")

        notification = {
            "alert_id": alert_id,
            "timestamp": datetime.utcnow().isoformat(),
            "notification_type": notification_type,
            "recipients": recipients,
            "message": message,
            "severity": severity,
        }

        self._producer.send(
            self.config.notification_topic,
            key=alert_id,
            value=notification,
        )

    def _on_success(self, metadata: Any) -> None:
        """Callback for successful send."""
        self._metrics["messages_sent"] += 1

    def _on_error(self, exception: Exception) -> None:
        """Callback for send error."""
        self.logger.error("send_error", error=str(exception))
        self._metrics["errors"] += 1

    @property
    def metrics(self) -> dict[str, int]:
        """Get producer metrics."""
        return self._metrics.copy()


class AsyncAlertProducer(LoggerMixin):
    """Async Kafka producer using aiokafka."""

    def __init__(
        self,
        config: ProducerConfig | None = None,
    ) -> None:
        """Initialize async producer.

        Args:
            config: Producer configuration
        """
        self.config = config or ProducerConfig()
        self._producer = None

    async def start(self) -> None:
        """Start async producer."""
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError:
            self.logger.error("aiokafka_not_installed")
            return

        self._producer = AIOKafkaProducer(
            bootstrap_servers=",".join(self.config.bootstrap_servers),
            compression_type=self.config.compression_type,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )

        await self._producer.start()
        self.logger.info("async_producer_started")

    async def stop(self) -> None:
        """Stop async producer."""
        if self._producer:
            await self._producer.stop()

    async def publish(
        self,
        topic: str,
        key: str,
        value: dict[str, Any],
    ) -> None:
        """Publish message async.

        Args:
            topic: Target topic
            key: Message key
            value: Message value
        """
        if not self._producer:
            raise RuntimeError("Producer not started")

        await self._producer.send_and_wait(topic, key=key, value=value)
