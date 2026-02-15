"""Agentic AI Service - Autonomous security operations with LangGraph."""

from contextlib import asynccontextmanager
from enum import Enum
from typing import Any

from fastapi import FastAPI
from pydantic import Field

from common import get_logger, get_settings, setup_logging
from common.models import BaseModel, BaseRequest, BaseResponse, HealthResponse

settings = get_settings()
logger = get_logger(__name__)


class AgentState(str, Enum):
    """Agent execution states."""

    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"  # Waiting for human approval
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentTask(BaseModel):
    """A task for the agentic system."""

    task_id: str = Field(description="Unique task identifier")
    objective: str = Field(description="Task objective")
    context: dict[str, Any] = Field(default_factory=dict, description="Task context")
    constraints: list[str] = Field(default_factory=list, description="Execution constraints")
    require_approval: bool = Field(default=True, description="Require human approval for actions")


class AgentStep(BaseModel):
    """A step in agent execution."""

    step_id: str = Field(description="Step identifier")
    action: str = Field(description="Action taken")
    reasoning: str = Field(description="Reasoning for the action")
    result: dict[str, Any] | None = Field(default=None, description="Step result")
    requires_approval: bool = Field(default=False, description="Needs human approval")


class AgentExecution(BaseModel):
    """Agent execution status and results."""

    task_id: str = Field(description="Task ID")
    state: AgentState = Field(description="Current state")
    steps: list[AgentStep] = Field(default_factory=list, description="Execution steps")
    current_step: int = Field(default=0, description="Current step index")
    final_result: dict[str, Any] | None = Field(default=None, description="Final result")
    error: str | None = Field(default=None, description="Error message if failed")


class ExecuteRequest(BaseRequest):
    """Request to execute an agent task."""

    task: AgentTask = Field(description="Task to execute")
    async_execution: bool = Field(default=True, description="Run asynchronously")


class ApprovalRequest(BaseRequest):
    """Request to approve a pending action."""

    task_id: str = Field(description="Task ID")
    step_id: str = Field(description="Step ID to approve")
    approved: bool = Field(description="Whether action is approved")
    feedback: str | None = Field(default=None, description="Optional feedback")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    setup_logging(
        level=settings.log_level,
        format=settings.log_format,
        service_name="ai-agentic",
    )

    logger.info("starting_service", environment=settings.environment)

    yield

    logger.info("shutting_down_service")


app = FastAPI(
    title="Agentic AI Service",
    description="Autonomous security operations with human-in-the-loop",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="ai-agentic",
        version="0.1.0",
    )


@app.post("/api/v1/execute", response_model=BaseResponse[AgentExecution])
async def execute_task(request: ExecuteRequest) -> BaseResponse[AgentExecution]:
    """Execute an agent task."""
    try:
        logger.info("executing_task", task_id=request.task.task_id)

        # TODO: Implement LangGraph-based agent execution
        execution = AgentExecution(
            task_id=request.task.task_id,
            state=AgentState.PENDING,
            steps=[],
        )

        return BaseResponse.success_response(request.request_id, execution)

    except Exception as e:
        logger.error("execution_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@app.get("/api/v1/tasks/{task_id}", response_model=BaseResponse[AgentExecution])
async def get_task_status(task_id: str) -> BaseResponse[AgentExecution]:
    """Get task execution status."""
    # TODO: Implement task status retrieval
    execution = AgentExecution(
        task_id=task_id,
        state=AgentState.RUNNING,
        steps=[],
    )
    return BaseResponse.success_response(request_id=None, data=execution)


@app.post("/api/v1/approve", response_model=BaseResponse[AgentExecution])
async def approve_action(request: ApprovalRequest) -> BaseResponse[AgentExecution]:
    """Approve or reject a pending agent action."""
    try:
        logger.info(
            "processing_approval",
            task_id=request.task_id,
            step_id=request.step_id,
            approved=request.approved,
        )

        # TODO: Implement approval handling
        execution = AgentExecution(
            task_id=request.task_id,
            state=AgentState.RUNNING if request.approved else AgentState.CANCELLED,
            steps=[],
        )

        return BaseResponse.success_response(request.request_id, execution)

    except Exception as e:
        logger.error("approval_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@app.post("/api/v1/cancel/{task_id}")
async def cancel_task(task_id: str) -> BaseResponse[AgentExecution]:
    """Cancel a running task."""
    logger.info("cancelling_task", task_id=task_id)

    # TODO: Implement task cancellation
    execution = AgentExecution(
        task_id=task_id,
        state=AgentState.CANCELLED,
        steps=[],
    )
    return BaseResponse.success_response(request_id=None, data=execution)


def main() -> None:
    """Run the service."""
    import uvicorn

    uvicorn.run(
        "services.agentic.main:app",
        host=settings.host,
        port=8002,  # Different port
        workers=settings.workers,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
