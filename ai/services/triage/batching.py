"""Dynamic batching for efficient inference."""

import asyncio
import time
from collections import deque
from typing import Any, Callable, Coroutine, TypeVar

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

T = TypeVar("T")


class BatchConfig(BaseModel):
    """Configuration for dynamic batching."""

    max_batch_size: int = Field(default=64, description="Maximum batch size")
    max_wait_ms: int = Field(default=50, description="Maximum wait time for batching")
    max_queue_size: int = Field(default=1000, description="Maximum queue size")


class PendingRequest:
    """A pending request waiting for batching."""

    def __init__(self, data: Any, request_id: str) -> None:
        """Initialize pending request.

        Args:
            data: Request data
            request_id: Unique request ID
        """
        self.data = data
        self.request_id = request_id
        self.future: asyncio.Future = asyncio.get_event_loop().create_future()
        self.created_at = time.time()


class DynamicBatcher(LoggerMixin):
    """Dynamic batching for inference requests."""

    def __init__(
        self,
        batch_fn: Callable[[list[Any]], Coroutine[Any, Any, list[Any]]],
        config: BatchConfig | None = None,
    ) -> None:
        """Initialize the batcher.

        Args:
            batch_fn: Async function that processes a batch
            config: Batching configuration
        """
        self.batch_fn = batch_fn
        self.config = config or BatchConfig()

        self._queue: deque[PendingRequest] = deque()
        self._lock = asyncio.Lock()
        self._processing = False
        self._task: asyncio.Task | None = None

        # Metrics
        self._total_requests = 0
        self._total_batches = 0
        self._total_latency_ms = 0.0

    async def start(self) -> None:
        """Start the batching loop."""
        self._processing = True
        self._task = asyncio.create_task(self._batch_loop())
        self.logger.info("batcher_started", max_batch=self.config.max_batch_size)

    async def stop(self) -> None:
        """Stop the batching loop."""
        self._processing = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.logger.info("batcher_stopped")

    async def submit(self, data: Any, request_id: str) -> Any:
        """Submit a request for batched processing.

        Args:
            data: Request data
            request_id: Unique request ID

        Returns:
            Processing result
        """
        if len(self._queue) >= self.config.max_queue_size:
            raise RuntimeError("Request queue full")

        request = PendingRequest(data, request_id)

        async with self._lock:
            self._queue.append(request)
            self._total_requests += 1

        # Wait for result
        result = await request.future
        return result

    async def _batch_loop(self) -> None:
        """Main batching loop."""
        while self._processing:
            try:
                await self._process_batch()
            except Exception as e:
                self.logger.error("batch_processing_error", error=str(e))
            await asyncio.sleep(0.001)  # Small delay to prevent busy loop

    async def _process_batch(self) -> None:
        """Process a batch of requests."""
        # Collect batch
        batch: list[PendingRequest] = []
        wait_start = time.time()

        while True:
            # Check if we should process
            elapsed_ms = (time.time() - wait_start) * 1000

            if len(batch) >= self.config.max_batch_size:
                break

            if elapsed_ms >= self.config.max_wait_ms and batch:
                break

            # Try to get more requests
            async with self._lock:
                if self._queue:
                    batch.append(self._queue.popleft())
                elif batch:
                    break
                else:
                    await asyncio.sleep(0.005)
                    continue

        if not batch:
            return

        # Process batch
        batch_start = time.time()

        try:
            inputs = [req.data for req in batch]
            results = await self.batch_fn(inputs)

            # Set results
            for req, result in zip(batch, results):
                if not req.future.done():
                    req.future.set_result(result)

        except Exception as e:
            # Set exceptions for all requests
            for req in batch:
                if not req.future.done():
                    req.future.set_exception(e)

        # Update metrics
        batch_latency = (time.time() - batch_start) * 1000
        self._total_batches += 1
        self._total_latency_ms += batch_latency

        self.logger.debug(
            "batch_processed",
            batch_size=len(batch),
            latency_ms=batch_latency,
        )

    @property
    def metrics(self) -> dict[str, Any]:
        """Get batching metrics."""
        avg_latency = (
            self._total_latency_ms / self._total_batches
            if self._total_batches > 0 else 0
        )
        avg_batch_size = (
            self._total_requests / self._total_batches
            if self._total_batches > 0 else 0
        )

        return {
            "total_requests": self._total_requests,
            "total_batches": self._total_batches,
            "queue_size": len(self._queue),
            "avg_latency_ms": avg_latency,
            "avg_batch_size": avg_batch_size,
        }


class AdaptiveBatcher(DynamicBatcher):
    """Batcher with adaptive batch size based on latency."""

    def __init__(
        self,
        batch_fn: Callable[[list[Any]], Coroutine[Any, Any, list[Any]]],
        config: BatchConfig | None = None,
        target_latency_ms: float = 50.0,
    ) -> None:
        """Initialize adaptive batcher.

        Args:
            batch_fn: Batch processing function
            config: Batching configuration
            target_latency_ms: Target latency for batch processing
        """
        super().__init__(batch_fn, config)
        self.target_latency_ms = target_latency_ms
        self._current_max_batch = config.max_batch_size if config else 64
        self._latency_window: deque[float] = deque(maxlen=100)

    async def _process_batch(self) -> None:
        """Process batch with adaptive sizing."""
        # Collect batch with adaptive limit
        batch: list[PendingRequest] = []
        wait_start = time.time()

        while True:
            elapsed_ms = (time.time() - wait_start) * 1000

            if len(batch) >= self._current_max_batch:
                break

            if elapsed_ms >= self.config.max_wait_ms and batch:
                break

            async with self._lock:
                if self._queue:
                    batch.append(self._queue.popleft())
                elif batch:
                    break
                else:
                    await asyncio.sleep(0.005)
                    continue

        if not batch:
            return

        # Process batch
        batch_start = time.time()

        try:
            inputs = [req.data for req in batch]
            results = await self.batch_fn(inputs)

            for req, result in zip(batch, results):
                if not req.future.done():
                    req.future.set_result(result)

        except Exception as e:
            for req in batch:
                if not req.future.done():
                    req.future.set_exception(e)

        # Update metrics and adapt
        batch_latency = (time.time() - batch_start) * 1000
        self._latency_window.append(batch_latency)
        self._total_batches += 1
        self._total_latency_ms += batch_latency

        # Adapt batch size
        self._adapt_batch_size()

    def _adapt_batch_size(self) -> None:
        """Adapt batch size based on recent latencies."""
        if len(self._latency_window) < 10:
            return

        avg_latency = sum(self._latency_window) / len(self._latency_window)

        if avg_latency > self.target_latency_ms * 1.2:
            # Latency too high, decrease batch size
            self._current_max_batch = max(8, int(self._current_max_batch * 0.9))
        elif avg_latency < self.target_latency_ms * 0.8:
            # Latency low, can increase batch size
            self._current_max_batch = min(
                self.config.max_batch_size,
                int(self._current_max_batch * 1.1)
            )

        self.logger.debug(
            "batch_size_adapted",
            current_max=self._current_max_batch,
            avg_latency_ms=avg_latency,
        )


class PriorityBatcher(LoggerMixin):
    """Batcher with priority queue support."""

    def __init__(
        self,
        batch_fn: Callable[[list[Any]], Coroutine[Any, Any, list[Any]]],
        config: BatchConfig | None = None,
        num_priority_levels: int = 3,
    ) -> None:
        """Initialize priority batcher.

        Args:
            batch_fn: Batch processing function
            config: Batching configuration
            num_priority_levels: Number of priority levels
        """
        self.batch_fn = batch_fn
        self.config = config or BatchConfig()
        self.num_priority_levels = num_priority_levels

        # Priority queues (0 = highest priority)
        self._queues: list[deque[PendingRequest]] = [
            deque() for _ in range(num_priority_levels)
        ]
        self._lock = asyncio.Lock()
        self._processing = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the priority batching loop."""
        self._processing = True
        self._task = asyncio.create_task(self._batch_loop())

    async def stop(self) -> None:
        """Stop the batching loop."""
        self._processing = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def submit(
        self,
        data: Any,
        request_id: str,
        priority: int = 1,
    ) -> Any:
        """Submit a request with priority.

        Args:
            data: Request data
            request_id: Unique request ID
            priority: Priority level (0 = highest)

        Returns:
            Processing result
        """
        priority = min(max(0, priority), self.num_priority_levels - 1)
        request = PendingRequest(data, request_id)

        async with self._lock:
            self._queues[priority].append(request)

        return await request.future

    async def _batch_loop(self) -> None:
        """Main priority batching loop."""
        while self._processing:
            try:
                await self._process_batch()
            except Exception as e:
                self.logger.error("priority_batch_error", error=str(e))
            await asyncio.sleep(0.001)

    async def _process_batch(self) -> None:
        """Process batch from priority queues."""
        batch: list[PendingRequest] = []
        wait_start = time.time()

        while True:
            elapsed_ms = (time.time() - wait_start) * 1000

            if len(batch) >= self.config.max_batch_size:
                break

            if elapsed_ms >= self.config.max_wait_ms and batch:
                break

            # Get from highest priority queue first
            async with self._lock:
                found = False
                for queue in self._queues:
                    if queue:
                        batch.append(queue.popleft())
                        found = True
                        break

                if not found:
                    if batch:
                        break
                    else:
                        await asyncio.sleep(0.005)
                        continue

        if not batch:
            return

        try:
            inputs = [req.data for req in batch]
            results = await self.batch_fn(inputs)

            for req, result in zip(batch, results):
                if not req.future.done():
                    req.future.set_result(result)

        except Exception as e:
            for req in batch:
                if not req.future.done():
                    req.future.set_exception(e)
