"""Base agent classes and interfaces for LangGraph-based agents."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Callable, TypeVar
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel, TimestampMixin


class AgentCapability(str, Enum):
    """Capabilities that agents can have."""

    INVESTIGATE = "investigate"
    ANALYZE = "analyze"
    RESPOND = "respond"
    ENRICH = "enrich"
    CONTAIN = "contain"
    REMEDIATE = "remediate"
    NOTIFY = "notify"
    QUERY = "query"
    SUMMARIZE = "summarize"
    PLAN = "plan"
    EXECUTE = "execute"
    VALIDATE = "validate"
    ROLLBACK = "rollback"


class AgentPriority(str, Enum):
    """Agent execution priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AgentStatus(str, Enum):
    """Agent lifecycle status."""

    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentConfig(BaseModel):
    """Configuration for an agent."""

    agent_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(description="Agent name")
    description: str = Field(default="", description="Agent description")
    capabilities: list[AgentCapability] = Field(default_factory=list)
    priority: AgentPriority = Field(default=AgentPriority.NORMAL)
    max_iterations: int = Field(default=10, ge=1, le=100)
    timeout_seconds: int = Field(default=300, ge=10, le=3600)
    retry_count: int = Field(default=3, ge=0, le=10)
    require_approval: bool = Field(default=True)
    auto_approve_low_risk: bool = Field(default=True)
    enabled: bool = Field(default=True)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentContext(BaseModel):
    """Context passed to agent during execution."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    triggered_by: str = Field(default="system", description="Who triggered the agent")
    trigger_type: str = Field(default="manual", description="How agent was triggered")
    parent_execution_id: str | None = Field(default=None)
    alert_id: str | None = Field(default=None)
    case_id: str | None = Field(default=None)
    incident_id: str | None = Field(default=None)
    data: dict[str, Any] = Field(default_factory=dict)
    constraints: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)


class AgentResult(BaseModel):
    """Result from agent execution."""

    execution_id: str = Field(description="Execution ID")
    agent_id: str = Field(description="Agent that produced this result")
    status: AgentStatus = Field(description="Execution status")
    success: bool = Field(default=False)
    output: dict[str, Any] = Field(default_factory=dict)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = Field(default=None)
    metrics: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(description="When execution started")
    completed_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def duration_seconds(self) -> float:
        """Calculate execution duration in seconds."""
        return (self.completed_at - self.started_at).total_seconds()


class AgentStep(BaseModel):
    """A single step in agent execution."""

    step_id: str = Field(default_factory=lambda: str(uuid4()))
    step_number: int = Field(ge=1)
    action: str = Field(description="Action to take")
    reasoning: str = Field(description="Why this action")
    input_data: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] | None = Field(default=None)
    status: AgentStatus = Field(default=AgentStatus.IDLE)
    requires_approval: bool = Field(default=False)
    risk_level: str = Field(default="low")
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    error: str | None = Field(default=None)


class ToolDefinition(BaseModel):
    """Definition of a tool available to agents."""

    name: str = Field(description="Tool name")
    description: str = Field(description="What the tool does")
    parameters: dict[str, Any] = Field(default_factory=dict)
    required_parameters: list[str] = Field(default_factory=list)
    risk_level: str = Field(default="low")
    requires_approval: bool = Field(default=False)
    enabled: bool = Field(default=True)


T = TypeVar("T", bound="BaseAgent")


class BaseAgent(ABC, LoggerMixin):
    """Base class for all LangGraph-based agents.

    Provides common functionality:
    - Configuration management
    - Lifecycle management
    - Tool registration
    - State management integration
    - Logging and metrics
    """

    def __init__(self, config: AgentConfig) -> None:
        """Initialize the agent.

        Args:
            config: Agent configuration
        """
        self.config = config
        self._status = AgentStatus.IDLE
        self._tools: dict[str, tuple[ToolDefinition, Callable]] = {}
        self._current_context: AgentContext | None = None
        self._steps: list[AgentStep] = []
        self._iteration_count = 0

    @property
    def agent_id(self) -> str:
        """Get agent ID."""
        return self.config.agent_id

    @property
    def name(self) -> str:
        """Get agent name."""
        return self.config.name

    @property
    def status(self) -> AgentStatus:
        """Get current status."""
        return self._status

    @property
    def capabilities(self) -> list[AgentCapability]:
        """Get agent capabilities."""
        return self.config.capabilities

    def has_capability(self, capability: AgentCapability) -> bool:
        """Check if agent has a capability."""
        return capability in self.capabilities

    def register_tool(
        self,
        definition: ToolDefinition,
        handler: Callable,
    ) -> None:
        """Register a tool with the agent.

        Args:
            definition: Tool definition
            handler: Async function to execute the tool
        """
        self._tools[definition.name] = (definition, handler)
        self.logger.info(
            "tool_registered",
            agent=self.name,
            tool=definition.name,
        )

    def get_tools(self) -> list[ToolDefinition]:
        """Get all registered tools."""
        return [defn for defn, _ in self._tools.values()]

    async def execute_tool(
        self,
        tool_name: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a registered tool.

        Args:
            tool_name: Name of the tool to execute
            parameters: Tool parameters

        Returns:
            Tool execution result
        """
        if tool_name not in self._tools:
            raise ValueError(f"Tool not found: {tool_name}")

        definition, handler = self._tools[tool_name]

        # Check required parameters
        for param in definition.required_parameters:
            if param not in parameters:
                raise ValueError(f"Missing required parameter: {param}")

        self.logger.info(
            "executing_tool",
            agent=self.name,
            tool=tool_name,
        )

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**parameters)
            else:
                result = handler(**parameters)

            return {"success": True, "result": result}

        except Exception as e:
            self.logger.error(
                "tool_execution_failed",
                agent=self.name,
                tool=tool_name,
                error=str(e),
            )
            return {"success": False, "error": str(e)}

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the agent. Called before first execution."""
        pass

    @abstractmethod
    async def run(self, context: AgentContext) -> AgentResult:
        """Run the agent with given context.

        Args:
            context: Execution context

        Returns:
            Execution result
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources. Called on shutdown."""
        pass

    async def pause(self) -> None:
        """Pause agent execution."""
        if self._status == AgentStatus.RUNNING:
            self._status = AgentStatus.PAUSED
            self.logger.info("agent_paused", agent=self.name)

    async def resume(self) -> None:
        """Resume paused agent."""
        if self._status == AgentStatus.PAUSED:
            self._status = AgentStatus.RUNNING
            self.logger.info("agent_resumed", agent=self.name)

    async def cancel(self) -> None:
        """Cancel agent execution."""
        self._status = AgentStatus.CANCELLED
        self.logger.info("agent_cancelled", agent=self.name)

    def _add_step(self, step: AgentStep) -> None:
        """Add a step to the execution history."""
        self._steps.append(step)

    def _get_steps(self) -> list[AgentStep]:
        """Get all execution steps."""
        return self._steps.copy()

    def _clear_steps(self) -> None:
        """Clear execution steps."""
        self._steps.clear()
        self._iteration_count = 0

    def _check_iteration_limit(self) -> bool:
        """Check if iteration limit is reached."""
        self._iteration_count += 1
        return self._iteration_count <= self.config.max_iterations

    def _create_result(
        self,
        success: bool,
        output: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> AgentResult:
        """Create an agent result."""
        return AgentResult(
            execution_id=self._current_context.execution_id if self._current_context else str(uuid4()),
            agent_id=self.agent_id,
            status=self._status,
            success=success,
            output=output or {},
            actions_taken=[step.model_dump() for step in self._steps],
            error=error,
            metrics={
                "iterations": self._iteration_count,
                "steps_count": len(self._steps),
            },
            started_at=self._current_context.started_at if self._current_context else datetime.utcnow(),
        )


class CompositeAgent(BaseAgent):
    """Agent that composes multiple sub-agents."""

    def __init__(self, config: AgentConfig) -> None:
        """Initialize composite agent."""
        super().__init__(config)
        self._sub_agents: dict[str, BaseAgent] = {}

    def add_sub_agent(self, agent: BaseAgent) -> None:
        """Add a sub-agent."""
        self._sub_agents[agent.agent_id] = agent
        # Inherit capabilities
        for cap in agent.capabilities:
            if cap not in self.config.capabilities:
                self.config.capabilities.append(cap)

    def get_sub_agent(self, agent_id: str) -> BaseAgent | None:
        """Get a sub-agent by ID."""
        return self._sub_agents.get(agent_id)

    def get_sub_agents(self) -> list[BaseAgent]:
        """Get all sub-agents."""
        return list(self._sub_agents.values())

    async def initialize(self) -> None:
        """Initialize all sub-agents."""
        for agent in self._sub_agents.values():
            await agent.initialize()

    async def cleanup(self) -> None:
        """Cleanup all sub-agents."""
        for agent in self._sub_agents.values():
            await agent.cleanup()

    @abstractmethod
    async def run(self, context: AgentContext) -> AgentResult:
        """Run the composite agent."""
        pass
