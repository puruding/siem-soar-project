"""Base Pydantic models for AI services."""

from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict, Field


class BaseModel(PydanticBaseModel):
    """Base model with common configuration."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True,
        validate_assignment=True,
        arbitrary_types_allowed=True,
    )


class TimestampMixin(BaseModel):
    """Mixin for models with timestamps."""

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class BaseRequest(BaseModel):
    """Base request model with common fields."""

    request_id: UUID = Field(default_factory=uuid4, description="Unique request ID")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Request timestamp"
    )


T = TypeVar("T")


class BaseResponse(BaseModel, Generic[T]):
    """Base response model with common fields."""

    request_id: UUID = Field(description="Original request ID")
    success: bool = Field(description="Whether the request was successful")
    data: T | None = Field(default=None, description="Response data")
    error: str | None = Field(default=None, description="Error message if failed")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Response timestamp"
    )

    @classmethod
    def success_response(cls, request_id: UUID, data: T) -> "BaseResponse[T]":
        """Create a successful response."""
        return cls(request_id=request_id, success=True, data=data)

    @classmethod
    def error_response(cls, request_id: UUID, error: str) -> "BaseResponse[T]":
        """Create an error response."""
        return cls(request_id=request_id, success=False, error=error)


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response model."""

    items: list[T] = Field(description="List of items")
    total: int = Field(description="Total number of items")
    page: int = Field(ge=1, description="Current page number")
    page_size: int = Field(ge=1, le=100, description="Number of items per page")
    has_next: bool = Field(description="Whether there are more pages")
    has_previous: bool = Field(description="Whether there are previous pages")

    @property
    def total_pages(self) -> int:
        """Calculate total number of pages."""
        return (self.total + self.page_size - 1) // self.page_size


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str = Field(description="Service status")
    service: str = Field(description="Service name")
    version: str = Field(description="Service version")
    checks: dict[str, Any] = Field(
        default_factory=dict, description="Individual health checks"
    )
