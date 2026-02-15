"""Kafka consumer for alert processing."""

import asyncio
import json
import signal
from typing import Any, Callable, Coroutine

from kafka import KafkaConsumer
from kafka.errors import KafkaError
from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel


class ConsumerConfig(BaseModel):
    """Configuration for alert consumer."""

    # Kafka settings
    bootstrap_servers: list[str] = Field(default_factory=lambda: ["localhost:9092"])
    group_id: str = Field(default="ai-triage")
    auto_offset_reset: str = Field(default="latest")
    enable_auto_commit: bool = Field(default=False)
    max_poll_records: int = Field(default=100)
    max_poll_interval_ms: int = Field(default=300000)
    session_timeout_ms: int = Field(default=30000)

    # Topics
    alert_topic: str = Field(default="alerts.raw")
    dlq_topic: str = Field(default="alerts.dlq")

    # Processing
    batch_size: int = Field(default=50)
    batch_timeout_ms: int = Field(default=1000)
    max_retries: int = Field(default=3)
    retry_delay_ms: int = Field(default=1000)


class AlertConsumer(LoggerMixin):
    """Consume alerts from Kafka for triage processing."""

    def __init__(
        self,
        config: ConsumerConfig | None = None,
        processor: Callable[[list[dict[str, Any]]], Coroutine[Any, Any, list[dict[str, Any]]]] | None = None,
    ) -> None:
        """Initialize the alert consumer.

        Args:
            config: Consumer configuration
            processor: Async function to process alert batches
        """
        self.config = config or ConsumerConfig()
        self.processor = processor

        self._consumer: KafkaConsumer | None = None
        self._running = False
        self._processed_count = 0
        self._error_count = 0

    async def start(self) -> None:
        """Start consuming alerts."""
        self.logger.info(
            "starting_consumer",
            topic=self.config.alert_topic,
            group_id=self.config.group_id,
        )

        self._consumer = KafkaConsumer(
            self.config.alert_topic,
            bootstrap_servers=self.config.bootstrap_servers,
            group_id=self.config.group_id,
            auto_offset_reset=self.config.auto_offset_reset,
            enable_auto_commit=self.config.enable_auto_commit,
            max_poll_records=self.config.max_poll_records,
            max_poll_interval_ms=self.config.max_poll_interval_ms,
            session_timeout_ms=self.config.session_timeout_ms,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            key_deserializer=lambda m: m.decode("utf-8") if m else None,
        )

        self._running = True

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._shutdown)
            except NotImplementedError:
                # Windows doesn't support add_signal_handler
                pass

        await self._consume_loop()

    def _shutdown(self) -> None:
        """Handle shutdown signal."""
        self.logger.info("shutdown_signal_received")
        self._running = False

    async def stop(self) -> None:
        """Stop consuming."""
        self._running = False

        if self._consumer:
            self._consumer.close()
            self._consumer = None

        self.logger.info(
            "consumer_stopped",
            processed_count=self._processed_count,
            error_count=self._error_count,
        )

    async def _consume_loop(self) -> None:
        """Main consume loop."""
        batch: list[dict[str, Any]] = []
        batch_start_time = asyncio.get_event_loop().time()

        while self._running:
            try:
                # Poll for messages
                records = self._consumer.poll(
                    timeout_ms=100,
                    max_records=self.config.batch_size,
                )

                for topic_partition, messages in records.items():
                    for message in messages:
                        alert = message.value
                        alert["_kafka_metadata"] = {
                            "topic": message.topic,
                            "partition": message.partition,
                            "offset": message.offset,
                            "timestamp": message.timestamp,
                            "key": message.key,
                        }
                        batch.append(alert)

                # Check if we should process the batch
                current_time = asyncio.get_event_loop().time()
                batch_age_ms = (current_time - batch_start_time) * 1000

                should_process = (
                    len(batch) >= self.config.batch_size or
                    (batch and batch_age_ms >= self.config.batch_timeout_ms)
                )

                if should_process and batch:
                    await self._process_batch(batch)
                    batch = []
                    batch_start_time = current_time

                # Small delay to prevent busy loop
                await asyncio.sleep(0.01)

            except KafkaError as e:
                self.logger.error("kafka_error", error=str(e))
                self._error_count += 1
                await asyncio.sleep(1)

            except Exception as e:
                self.logger.error("consume_error", error=str(e))
                self._error_count += 1
                await asyncio.sleep(1)

        # Process remaining batch on shutdown
        if batch:
            await self._process_batch(batch)

    async def _process_batch(
        self, batch: list[dict[str, Any]]
    ) -> None:
        """Process a batch of alerts.

        Args:
            batch: List of alerts to process
        """
        if not self.processor:
            self.logger.warning("no_processor_configured")
            return

        self.logger.debug(
            "processing_batch",
            batch_size=len(batch),
        )

        try:
            # Process alerts
            results = await self.processor(batch)

            # Commit offsets on success
            self._consumer.commit()

            self._processed_count += len(batch)

            self.logger.info(
                "batch_processed",
                batch_size=len(batch),
                total_processed=self._processed_count,
            )

        except Exception as e:
            self.logger.error(
                "batch_processing_failed",
                error=str(e),
                batch_size=len(batch),
            )
            self._error_count += len(batch)

            # Send to DLQ
            await self._send_to_dlq(batch, str(e))

    async def _send_to_dlq(
        self,
        batch: list[dict[str, Any]],
        error: str,
    ) -> None:
        """Send failed alerts to dead letter queue.

        Args:
            batch: Failed alerts
            error: Error message
        """
        # Import producer here to avoid circular dependency
        from kafka import KafkaProducer

        try:
            producer = KafkaProducer(
                bootstrap_servers=self.config.bootstrap_servers,
                value_serializer=lambda m: json.dumps(m).encode("utf-8"),
            )

            for alert in batch:
                dlq_message = {
                    "alert": alert,
                    "error": error,
                    "retry_count": alert.get("_retry_count", 0),
                }
                producer.send(self.config.dlq_topic, dlq_message)

            producer.flush()
            producer.close()

            self.logger.info(
                "alerts_sent_to_dlq",
                count=len(batch),
            )

        except Exception as e:
            self.logger.error(
                "dlq_send_failed",
                error=str(e),
            )


class AsyncAlertConsumer(LoggerMixin):
    """Async Kafka consumer using aiokafka."""

    def __init__(
        self,
        config: ConsumerConfig | None = None,
        processor: Callable[[list[dict[str, Any]]], Coroutine[Any, Any, list[dict[str, Any]]]] | None = None,
    ) -> None:
        """Initialize async consumer.

        Args:
            config: Consumer configuration
            processor: Async batch processor
        """
        self.config = config or ConsumerConfig()
        self.processor = processor

        self._consumer = None
        self._running = False

    async def start(self) -> None:
        """Start async consumer."""
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError:
            self.logger.error("aiokafka_not_installed")
            return

        self._consumer = AIOKafkaConsumer(
            self.config.alert_topic,
            bootstrap_servers=",".join(self.config.bootstrap_servers),
            group_id=self.config.group_id,
            auto_offset_reset=self.config.auto_offset_reset,
            enable_auto_commit=self.config.enable_auto_commit,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )

        await self._consumer.start()
        self._running = True

        self.logger.info(
            "async_consumer_started",
            topic=self.config.alert_topic,
        )

        try:
            await self._consume_loop()
        finally:
            await self._consumer.stop()

    async def stop(self) -> None:
        """Stop async consumer."""
        self._running = False

    async def _consume_loop(self) -> None:
        """Async consume loop."""
        batch = []

        async for message in self._consumer:
            if not self._running:
                break

            alert = message.value
            batch.append(alert)

            if len(batch) >= self.config.batch_size:
                if self.processor:
                    await self.processor(batch)
                await self._consumer.commit()
                batch = []
