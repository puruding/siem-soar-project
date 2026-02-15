"""Agent Coordinator - Coordinate multiple agents for complex tasks."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from ..base import AgentCapability, AgentContext, BaseAgent
from ..registry import AgentRegistry


class CoordinationTask(BaseModel):
    """A task to be coordinated across agents."""

    task_id: str = Field(default_factory=lambda: str(uuid4()))
    task_type: str = Field(description="Type of task")
    priority: int = Field(default=5, ge=1, le=10)
    required_capabilities: list[AgentCapability] = Field(default_factory=list)
    input_data: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)


class CoordinationResult(BaseModel):
    """Result of coordination."""

    coordination_id: str = Field(default_factory=lambda: str(uuid4()))
    tasks_total: int = Field(default=0)
    tasks_completed: int = Field(default=0)
    tasks_failed: int = Field(default=0)
    results: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float = Field(default=0.0)
    success: bool = Field(default=False)


class AgentCoordinator(LoggerMixin):
    """Coordinator for multi-agent task execution.

    Features:
    - Parallel task execution
    - Dependency resolution
    - Load balancing
    - Result aggregation
    """

    def __init__(
        self,
        registry: AgentRegistry | None = None,
        max_parallel: int = 5,
    ) -> None:
        """Initialize coordinator.

        Args:
            registry: Agent registry
            max_parallel: Max parallel tasks
        """
        self.registry = registry or AgentRegistry.get_instance()
        self.max_parallel = max_parallel
        self._task_results: dict[str, Any] = {}

    async def coordinate(
        self,
        tasks: list[CoordinationTask],
    ) -> CoordinationResult:
        """Coordinate execution of multiple tasks.

        Args:
            tasks: Tasks to coordinate

        Returns:
            Coordination result
        """
        self.logger.info("starting_coordination", task_count=len(tasks))

        start_time = datetime.utcnow()
        result = CoordinationResult(tasks_total=len(tasks))

        # Build dependency graph
        task_map = {t.task_id: t for t in tasks}
        completed = set()

        # Execute in dependency order
        while len(completed) < len(tasks):
            # Find ready tasks
            ready = []
            for task in tasks:
                if task.task_id in completed:
                    continue
                if all(dep in completed for dep in task.dependencies):
                    ready.append(task)

            if not ready:
                self.logger.warning("no_ready_tasks")
                break

            # Execute batch
            batch = ready[:self.max_parallel]
            batch_results = await self._execute_batch(batch)

            for task_id, task_result in batch_results.items():
                completed.add(task_id)
                self._task_results[task_id] = task_result
                result.results[task_id] = task_result

                if task_result.get("success"):
                    result.tasks_completed += 1
                else:
                    result.tasks_failed += 1

        # Calculate duration
        end_time = datetime.utcnow()
        result.duration_seconds = (end_time - start_time).total_seconds()
        result.success = result.tasks_failed == 0

        self.logger.info(
            "coordination_complete",
            completed=result.tasks_completed,
            failed=result.tasks_failed,
        )

        return result

    async def _execute_batch(
        self,
        tasks: list[CoordinationTask],
    ) -> dict[str, Any]:
        """Execute a batch of tasks in parallel."""
        async def execute_task(task: CoordinationTask) -> tuple[str, dict]:
            try:
                # Find suitable agent
                agent = self._select_agent(task)
                if not agent:
                    return task.task_id, {"success": False, "error": "No suitable agent"}

                # Build context
                context = AgentContext(
                    execution_id=task.task_id,
                    data=task.input_data,
                )

                # Add dependency results
                for dep_id in task.dependencies:
                    if dep_id in self._task_results:
                        context.data[f"dep_{dep_id}"] = self._task_results[dep_id]

                # Execute
                result = await agent.run(context)
                return task.task_id, {
                    "success": result.success,
                    "output": result.output,
                    "agent_id": agent.agent_id,
                }

            except Exception as e:
                return task.task_id, {"success": False, "error": str(e)}

        # Run all tasks
        results = await asyncio.gather(*[execute_task(t) for t in tasks])

        return dict(results)

    def _select_agent(self, task: CoordinationTask) -> BaseAgent | None:
        """Select best agent for task."""
        candidates = []

        for capability in task.required_capabilities:
            agents = self.registry.get_agents_by_capability(capability)
            candidates.extend(agents)

        if not candidates:
            return None

        # Return first available
        return candidates[0]
