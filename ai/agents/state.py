"""Agent State Management - State machine and persistence for agents."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Callable, TypedDict
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class AgentState(str, Enum):
    """States in the agent state machine."""

    # Initial states
    PENDING = "pending"
    INITIALIZING = "initializing"

    # Active states
    PLANNING = "planning"
    INVESTIGATING = "investigating"
    ANALYZING = "analyzing"
    EXECUTING = "executing"
    VALIDATING = "validating"

    # Waiting states
    WAITING_DATA = "waiting_data"
    WAITING_APPROVAL = "waiting_approval"
    WAITING_CALLBACK = "waiting_callback"

    # Terminal states
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

    @classmethod
    def terminal_states(cls) -> set[AgentState]:
        """Get terminal states."""
        return {cls.COMPLETED, cls.FAILED, cls.CANCELLED, cls.TIMEOUT}

    @classmethod
    def active_states(cls) -> set[AgentState]:
        """Get active states."""
        return {
            cls.PLANNING,
            cls.INVESTIGATING,
            cls.ANALYZING,
            cls.EXECUTING,
            cls.VALIDATING,
        }

    @classmethod
    def waiting_states(cls) -> set[AgentState]:
        """Get waiting states."""
        return {cls.WAITING_DATA, cls.WAITING_APPROVAL, cls.WAITING_CALLBACK}


class StateTransition(BaseModel):
    """A state transition record."""

    transition_id: str = Field(default_factory=lambda: str(uuid4()))
    from_state: AgentState = Field(description="Previous state")
    to_state: AgentState = Field(description="New state")
    trigger: str = Field(description="What triggered the transition")
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ExecutionState(BaseModel):
    """Complete execution state for an agent run."""

    execution_id: str = Field(description="Execution ID")
    agent_id: str = Field(description="Agent ID")
    current_state: AgentState = Field(default=AgentState.PENDING)
    previous_state: AgentState | None = Field(default=None)

    # Data
    input_data: dict[str, Any] = Field(default_factory=dict)
    working_data: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] = Field(default_factory=dict)

    # Progress
    current_step: int = Field(default=0)
    total_steps: int = Field(default=0)
    steps_completed: list[str] = Field(default_factory=list)

    # History
    transitions: list[StateTransition] = Field(default_factory=list)
    messages: list[dict[str, Any]] = Field(default_factory=list)

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    # Error handling
    error: str | None = Field(default=None)
    retry_count: int = Field(default=0)


class LangGraphState(TypedDict, total=False):
    """State type for LangGraph workflows.

    This is the state that flows through LangGraph nodes.
    """

    # Identifiers
    execution_id: str
    agent_id: str

    # Current phase
    phase: str
    step: int

    # Input/Output
    input: dict[str, Any]
    context: dict[str, Any]
    output: dict[str, Any]

    # Messages for LLM
    messages: list[dict[str, str]]

    # Investigation data
    evidence: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    timeline: list[dict[str, Any]]

    # Analysis data
    root_cause: dict[str, Any] | None
    impact_assessment: dict[str, Any] | None
    threat_classification: dict[str, Any] | None

    # Response data
    action_plan: list[dict[str, Any]]
    actions_executed: list[dict[str, Any]]
    actions_pending: list[dict[str, Any]]

    # Control flow
    should_continue: bool
    requires_approval: bool
    approval_status: str | None

    # Error handling
    error: str | None
    retry_count: int


class StateManager(LoggerMixin):
    """Manager for agent execution state.

    Features:
    - State machine with valid transitions
    - State persistence
    - State history tracking
    - Checkpoint and restore
    """

    # Valid state transitions
    VALID_TRANSITIONS: dict[AgentState, set[AgentState]] = {
        AgentState.PENDING: {AgentState.INITIALIZING, AgentState.CANCELLED},
        AgentState.INITIALIZING: {
            AgentState.PLANNING,
            AgentState.INVESTIGATING,
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.PLANNING: {
            AgentState.INVESTIGATING,
            AgentState.EXECUTING,
            AgentState.WAITING_APPROVAL,
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.INVESTIGATING: {
            AgentState.ANALYZING,
            AgentState.WAITING_DATA,
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.ANALYZING: {
            AgentState.PLANNING,
            AgentState.EXECUTING,
            AgentState.WAITING_APPROVAL,
            AgentState.COMPLETED,
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.EXECUTING: {
            AgentState.VALIDATING,
            AgentState.WAITING_APPROVAL,
            AgentState.WAITING_CALLBACK,
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.VALIDATING: {
            AgentState.COMPLETED,
            AgentState.EXECUTING,  # Retry
            AgentState.FAILED,
            AgentState.CANCELLED,
        },
        AgentState.WAITING_DATA: {
            AgentState.INVESTIGATING,
            AgentState.TIMEOUT,
            AgentState.CANCELLED,
        },
        AgentState.WAITING_APPROVAL: {
            AgentState.EXECUTING,
            AgentState.CANCELLED,
            AgentState.TIMEOUT,
        },
        AgentState.WAITING_CALLBACK: {
            AgentState.VALIDATING,
            AgentState.FAILED,
            AgentState.TIMEOUT,
            AgentState.CANCELLED,
        },
    }

    def __init__(self) -> None:
        """Initialize the state manager."""
        self._states: dict[str, ExecutionState] = {}
        self._checkpoints: dict[str, ExecutionState] = {}
        self._hooks: dict[AgentState, list[Callable]] = {}

    def create_state(
        self,
        execution_id: str,
        agent_id: str,
        input_data: dict[str, Any] | None = None,
    ) -> ExecutionState:
        """Create a new execution state.

        Args:
            execution_id: Unique execution ID
            agent_id: Agent ID
            input_data: Initial input data

        Returns:
            Created execution state
        """
        state = ExecutionState(
            execution_id=execution_id,
            agent_id=agent_id,
            input_data=input_data or {},
        )
        self._states[execution_id] = state
        self.logger.info(
            "state_created",
            execution_id=execution_id,
            agent_id=agent_id,
        )
        return state

    def get_state(self, execution_id: str) -> ExecutionState | None:
        """Get execution state by ID."""
        return self._states.get(execution_id)

    def transition(
        self,
        execution_id: str,
        to_state: AgentState,
        trigger: str = "automatic",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Transition state.

        Args:
            execution_id: Execution ID
            to_state: Target state
            trigger: What triggered the transition
            metadata: Additional metadata

        Returns:
            True if transition was successful
        """
        state = self._states.get(execution_id)
        if not state:
            self.logger.error("state_not_found", execution_id=execution_id)
            return False

        # Check if transition is valid
        current = state.current_state
        if current in AgentState.terminal_states():
            self.logger.warning(
                "cannot_transition_from_terminal",
                execution_id=execution_id,
                current=current.value,
                target=to_state.value,
            )
            return False

        valid_targets = self.VALID_TRANSITIONS.get(current, set())
        if to_state not in valid_targets:
            self.logger.warning(
                "invalid_transition",
                execution_id=execution_id,
                from_state=current.value,
                to_state=to_state.value,
            )
            return False

        # Record transition
        transition = StateTransition(
            from_state=current,
            to_state=to_state,
            trigger=trigger,
            metadata=metadata or {},
        )

        state.previous_state = current
        state.current_state = to_state
        state.transitions.append(transition)
        state.updated_at = datetime.utcnow()

        self.logger.info(
            "state_transitioned",
            execution_id=execution_id,
            from_state=current.value,
            to_state=to_state.value,
            trigger=trigger,
        )

        # Call hooks
        self._call_hooks(to_state, state)

        return True

    def register_hook(
        self,
        state: AgentState,
        callback: Callable[[ExecutionState], None],
    ) -> None:
        """Register a hook for state entry.

        Args:
            state: State to hook
            callback: Callback function
        """
        if state not in self._hooks:
            self._hooks[state] = []
        self._hooks[state].append(callback)

    def _call_hooks(self, state: AgentState, exec_state: ExecutionState) -> None:
        """Call registered hooks for a state."""
        for callback in self._hooks.get(state, []):
            try:
                callback(exec_state)
            except Exception as e:
                self.logger.error(
                    "hook_error",
                    state=state.value,
                    error=str(e),
                )

    def update_working_data(
        self,
        execution_id: str,
        data: dict[str, Any],
        merge: bool = True,
    ) -> None:
        """Update working data.

        Args:
            execution_id: Execution ID
            data: Data to update
            merge: Whether to merge with existing data
        """
        state = self._states.get(execution_id)
        if not state:
            return

        if merge:
            state.working_data.update(data)
        else:
            state.working_data = data

        state.updated_at = datetime.utcnow()

    def add_message(
        self,
        execution_id: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a message to state.

        Args:
            execution_id: Execution ID
            role: Message role (system/user/assistant)
            content: Message content
            metadata: Additional metadata
        """
        state = self._states.get(execution_id)
        if not state:
            return

        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
            **(metadata or {}),
        }
        state.messages.append(message)
        state.updated_at = datetime.utcnow()

    def checkpoint(self, execution_id: str) -> str:
        """Create a checkpoint of current state.

        Args:
            execution_id: Execution ID

        Returns:
            Checkpoint ID
        """
        state = self._states.get(execution_id)
        if not state:
            raise ValueError(f"State not found: {execution_id}")

        checkpoint_id = f"{execution_id}_{len(self._checkpoints)}"
        self._checkpoints[checkpoint_id] = state.model_copy(deep=True)

        self.logger.info(
            "checkpoint_created",
            execution_id=execution_id,
            checkpoint_id=checkpoint_id,
        )

        return checkpoint_id

    def restore(self, checkpoint_id: str) -> ExecutionState | None:
        """Restore state from checkpoint.

        Args:
            checkpoint_id: Checkpoint ID

        Returns:
            Restored state or None
        """
        if checkpoint_id not in self._checkpoints:
            return None

        state = self._checkpoints[checkpoint_id].model_copy(deep=True)
        self._states[state.execution_id] = state

        self.logger.info(
            "state_restored",
            execution_id=state.execution_id,
            checkpoint_id=checkpoint_id,
        )

        return state

    def set_error(self, execution_id: str, error: str) -> None:
        """Set error on state.

        Args:
            execution_id: Execution ID
            error: Error message
        """
        state = self._states.get(execution_id)
        if state:
            state.error = error
            state.updated_at = datetime.utcnow()

    def increment_retry(self, execution_id: str) -> int:
        """Increment retry count.

        Args:
            execution_id: Execution ID

        Returns:
            New retry count
        """
        state = self._states.get(execution_id)
        if state:
            state.retry_count += 1
            state.updated_at = datetime.utcnow()
            return state.retry_count
        return 0

    def complete(
        self,
        execution_id: str,
        output: dict[str, Any] | None = None,
        success: bool = True,
    ) -> None:
        """Mark execution as complete.

        Args:
            execution_id: Execution ID
            output: Output data
            success: Whether execution was successful
        """
        state = self._states.get(execution_id)
        if not state:
            return

        state.output_data = output or {}

        target = AgentState.COMPLETED if success else AgentState.FAILED
        self.transition(execution_id, target, trigger="completion")

    def get_active_executions(self) -> list[ExecutionState]:
        """Get all active executions."""
        return [
            state
            for state in self._states.values()
            if state.current_state not in AgentState.terminal_states()
        ]

    def cleanup_completed(self, max_age_hours: int = 24) -> int:
        """Remove old completed executions.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            Number of removed executions
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0

        for execution_id in list(self._states.keys()):
            state = self._states[execution_id]
            if state.current_state in AgentState.terminal_states():
                if state.updated_at < cutoff:
                    del self._states[execution_id]
                    removed += 1

        if removed:
            self.logger.info("cleaned_up_executions", count=removed)

        return removed
