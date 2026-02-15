"""Task Scheduler - Schedule and manage agent tasks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TaskPriority(int, Enum):
    """Task priority levels."""

    CRITICAL = 1
    HIGH = 3
    NORMAL = 5
    LOW = 7
    BACKGROUND = 9


class TaskStatus(str, Enum):
    """Task status."""

    PENDING = "pending"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScheduledTask(BaseModel):
    """A scheduled task."""

    task_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(description="Task name")
    task_type: str = Field(description="Type of task")
    priority: TaskPriority = Field(default=TaskPriority.NORMAL)
    status: TaskStatus = Field(default=TaskStatus.PENDING)

    # Scheduling
    scheduled_at: datetime | None = Field(default=None)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)

    # Configuration
    data: dict[str, Any] = Field(default_factory=dict)
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)
    timeout_seconds: int = Field(default=300)

    # Result
    result: dict[str, Any] | None = Field(default=None)
    error: str | None = Field(default=None)


class TaskScheduler(LoggerMixin):
    """Scheduler for agent tasks.

    Features:
    - Priority-based scheduling
    - Delayed execution
    - Retry logic
    - Concurrent task limits
    """

    def __init__(
        self,
        max_concurrent: int = 10,
    ) -> None:
        """Initialize scheduler.

        Args:
            max_concurrent: Max concurrent tasks
        """
        self.max_concurrent = max_concurrent
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._tasks: dict[str, ScheduledTask] = {}
        self._handlers: dict[str, Callable] = {}
        self._running: set[str] = set()
        self._shutdown = False

    def register_handler(
        self,
        task_type: str,
        handler: Callable,
    ) -> None:
        """Register a task handler.

        Args:
            task_type: Type of task
            handler: Async function to handle task
        """
        self._handlers[task_type] = handler
        self.logger.info("handler_registered", task_type=task_type)

    async def schedule(
        self,
        task: ScheduledTask,
        delay_seconds: int = 0,
    ) -> str:
        """Schedule a task.

        Args:
            task: Task to schedule
            delay_seconds: Delay before execution

        Returns:
            Task ID
        """
        if delay_seconds > 0:
            task.scheduled_at = datetime.utcnow() + timedelta(seconds=delay_seconds)
        else:
            task.scheduled_at = datetime.utcnow()

        task.status = TaskStatus.SCHEDULED
        self._tasks[task.task_id] = task

        # Add to priority queue (lower priority number = higher priority)
        await self._queue.put((task.priority.value, task.scheduled_at, task.task_id))

        self.logger.info(
            "task_scheduled",
            task_id=task.task_id,
            priority=task.priority.name,
        )

        return task.task_id

    async def run(self) -> None:
        """Run the scheduler loop."""
        self.logger.info("scheduler_started")

        while not self._shutdown:
            try:
                # Wait for task with timeout
                try:
                    priority, scheduled_at, task_id = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                task = self._tasks.get(task_id)
                if not task or task.status == TaskStatus.CANCELLED:
                    continue

                # Check if scheduled time has arrived
                now = datetime.utcnow()
                if task.scheduled_at and task.scheduled_at > now:
                    # Re-queue for later
                    await self._queue.put((priority, scheduled_at, task_id))
                    await asyncio.sleep(0.1)
                    continue

                # Check concurrent limit
                if len(self._running) >= self.max_concurrent:
                    await self._queue.put((priority, scheduled_at, task_id))
                    await asyncio.sleep(0.1)
                    continue

                # Execute task
                asyncio.create_task(self._execute_task(task))

            except Exception as e:
                self.logger.error("scheduler_error", error=str(e))

        self.logger.info("scheduler_stopped")

    async def _execute_task(self, task: ScheduledTask) -> None:
        """Execute a single task."""
        task.status = TaskStatus.RUNNING
        task.started_at = datetime.utcnow()
        self._running.add(task.task_id)

        self.logger.info("executing_task", task_id=task.task_id)

        try:
            handler = self._handlers.get(task.task_type)
            if not handler:
                raise ValueError(f"No handler for task type: {task.task_type}")

            # Execute with timeout
            result = await asyncio.wait_for(
                handler(task.data),
                timeout=task.timeout_seconds,
            )

            task.status = TaskStatus.COMPLETED
            task.result = result
            task.completed_at = datetime.utcnow()

            self.logger.info("task_completed", task_id=task.task_id)

        except asyncio.TimeoutError:
            task.error = "Task timed out"
            await self._handle_failure(task)

        except Exception as e:
            task.error = str(e)
            await self._handle_failure(task)

        finally:
            self._running.discard(task.task_id)

    async def _handle_failure(self, task: ScheduledTask) -> None:
        """Handle task failure with retry logic."""
        task.retry_count += 1

        if task.retry_count <= task.max_retries:
            self.logger.warning(
                "task_retry",
                task_id=task.task_id,
                retry=task.retry_count,
            )
            # Re-schedule with exponential backoff
            delay = 2 ** task.retry_count
            await self.schedule(task, delay_seconds=delay)
        else:
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            self.logger.error(
                "task_failed",
                task_id=task.task_id,
                error=task.error,
            )

    def cancel(self, task_id: str) -> bool:
        """Cancel a task."""
        task = self._tasks.get(task_id)
        if task and task.status in [TaskStatus.PENDING, TaskStatus.SCHEDULED]:
            task.status = TaskStatus.CANCELLED
            return True
        return False

    def get_task(self, task_id: str) -> ScheduledTask | None:
        """Get task by ID."""
        return self._tasks.get(task_id)

    def get_stats(self) -> dict[str, Any]:
        """Get scheduler statistics."""
        tasks = list(self._tasks.values())
        return {
            "total_tasks": len(tasks),
            "pending": len([t for t in tasks if t.status == TaskStatus.PENDING]),
            "scheduled": len([t for t in tasks if t.status == TaskStatus.SCHEDULED]),
            "running": len(self._running),
            "completed": len([t for t in tasks if t.status == TaskStatus.COMPLETED]),
            "failed": len([t for t in tasks if t.status == TaskStatus.FAILED]),
        }

    async def shutdown(self) -> None:
        """Shutdown scheduler."""
        self._shutdown = True
        # Wait for running tasks
        while self._running:
            await asyncio.sleep(0.5)
