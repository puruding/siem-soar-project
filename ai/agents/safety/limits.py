"""Execution Limiter - Rate limiting and resource constraints for agents."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class LimitExceededError(Exception):
    """Raised when a limit is exceeded."""

    def __init__(
        self,
        limit_type: str,
        current: float,
        maximum: float,
        message: str | None = None,
    ):
        self.limit_type = limit_type
        self.current = current
        self.maximum = maximum
        super().__init__(message or f"{limit_type} limit exceeded: {current}/{maximum}")


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""

    name: str = Field(description="Name of the rate limit")
    max_requests: int = Field(description="Maximum requests in window")
    window_seconds: int = Field(default=60, description="Time window in seconds")
    burst_limit: int | None = Field(default=None, description="Max burst size")
    cooldown_seconds: int = Field(default=0, description="Cooldown after limit hit")


class ResourceLimit(BaseModel):
    """Resource usage limit."""

    resource_type: str = Field(description="Type of resource")
    max_usage: float = Field(description="Maximum usage")
    current_usage: float = Field(default=0.0)
    unit: str = Field(default="count")
    reset_interval_seconds: int | None = Field(default=None)
    last_reset: datetime = Field(default_factory=datetime.utcnow)


class ExecutionLimiter(LoggerMixin):
    """Limiter for controlling agent execution rates and resources.

    Features:
    - Rate limiting per action type
    - Resource usage tracking
    - Concurrent execution limits
    - Burst control
    - Cooldown periods
    """

    def __init__(
        self,
        max_concurrent_actions: int = 10,
        max_daily_actions: int = 1000,
        default_rate_limit: int = 100,
    ) -> None:
        """Initialize execution limiter.

        Args:
            max_concurrent_actions: Maximum concurrent actions
            max_daily_actions: Maximum daily actions
            default_rate_limit: Default rate limit per minute
        """
        self.max_concurrent_actions = max_concurrent_actions
        self.max_daily_actions = max_daily_actions
        self.default_rate_limit = default_rate_limit

        self._rate_limits: dict[str, RateLimitConfig] = {}
        self._resource_limits: dict[str, ResourceLimit] = {}
        self._request_history: dict[str, list[datetime]] = defaultdict(list)
        self._concurrent_count = 0
        self._daily_count = 0
        self._daily_reset_time = datetime.utcnow().replace(hour=0, minute=0, second=0)
        self._cooldowns: dict[str, datetime] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent_actions)

        # Register default limits
        self._register_default_limits()

    def _register_default_limits(self) -> None:
        """Register default rate limits."""
        defaults = [
            RateLimitConfig(
                name="isolate_host",
                max_requests=20,
                window_seconds=3600,  # 20 per hour
                burst_limit=5,
            ),
            RateLimitConfig(
                name="disable_account",
                max_requests=50,
                window_seconds=3600,
                burst_limit=10,
            ),
            RateLimitConfig(
                name="block_ip",
                max_requests=200,
                window_seconds=3600,
                burst_limit=50,
            ),
            RateLimitConfig(
                name="execute_playbook",
                max_requests=100,
                window_seconds=3600,
                burst_limit=20,
            ),
            RateLimitConfig(
                name="llm_call",
                max_requests=1000,
                window_seconds=3600,
                burst_limit=100,
                cooldown_seconds=60,
            ),
        ]

        for config in defaults:
            self._rate_limits[config.name] = config

        # Default resource limits
        self._resource_limits = {
            "memory_mb": ResourceLimit(
                resource_type="memory",
                max_usage=4096,  # 4GB
                unit="MB",
            ),
            "cpu_seconds": ResourceLimit(
                resource_type="cpu",
                max_usage=3600,  # 1 hour of CPU time per day
                unit="seconds",
                reset_interval_seconds=86400,
            ),
            "api_calls": ResourceLimit(
                resource_type="api",
                max_usage=10000,
                unit="calls",
                reset_interval_seconds=86400,
            ),
        }

    def register_rate_limit(self, config: RateLimitConfig) -> None:
        """Register a rate limit configuration.

        Args:
            config: Rate limit configuration
        """
        self._rate_limits[config.name] = config
        self.logger.info(
            "rate_limit_registered",
            name=config.name,
            max_requests=config.max_requests,
        )

    def register_resource_limit(self, limit: ResourceLimit) -> None:
        """Register a resource limit.

        Args:
            limit: Resource limit
        """
        self._resource_limits[limit.resource_type] = limit
        self.logger.info(
            "resource_limit_registered",
            resource_type=limit.resource_type,
            max_usage=limit.max_usage,
        )

    async def acquire(
        self,
        action_type: str,
        count: int = 1,
    ) -> bool:
        """Acquire permission to execute an action.

        Args:
            action_type: Type of action
            count: Number of executions requested

        Returns:
            True if acquired, False otherwise

        Raises:
            LimitExceededError: If limits are exceeded
        """
        # Check daily limit
        self._reset_daily_if_needed()
        if self._daily_count + count > self.max_daily_actions:
            raise LimitExceededError(
                "daily_actions",
                self._daily_count,
                self.max_daily_actions,
            )

        # Check cooldown
        if action_type in self._cooldowns:
            if datetime.utcnow() < self._cooldowns[action_type]:
                remaining = (self._cooldowns[action_type] - datetime.utcnow()).seconds
                raise LimitExceededError(
                    "cooldown",
                    remaining,
                    0,
                    f"Action {action_type} in cooldown for {remaining}s",
                )

        # Check rate limit
        if action_type in self._rate_limits:
            config = self._rate_limits[action_type]
            self._check_rate_limit(action_type, config, count)

        # Acquire semaphore for concurrency
        await self._semaphore.acquire()

        # Record request
        now = datetime.utcnow()
        self._request_history[action_type].append(now)
        self._concurrent_count += 1
        self._daily_count += count

        self.logger.debug(
            "limit_acquired",
            action_type=action_type,
            concurrent=self._concurrent_count,
            daily=self._daily_count,
        )

        return True

    def release(self, action_type: str) -> None:
        """Release an acquired permit.

        Args:
            action_type: Type of action
        """
        self._semaphore.release()
        self._concurrent_count = max(0, self._concurrent_count - 1)

        self.logger.debug(
            "limit_released",
            action_type=action_type,
            concurrent=self._concurrent_count,
        )

    def _check_rate_limit(
        self,
        action_type: str,
        config: RateLimitConfig,
        count: int,
    ) -> None:
        """Check if rate limit allows the request."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=config.window_seconds)

        # Clean old requests
        self._request_history[action_type] = [
            ts for ts in self._request_history[action_type]
            if ts > window_start
        ]

        current_count = len(self._request_history[action_type])

        # Check window limit
        if current_count + count > config.max_requests:
            # Trigger cooldown if configured
            if config.cooldown_seconds > 0:
                self._cooldowns[action_type] = now + timedelta(seconds=config.cooldown_seconds)

            raise LimitExceededError(
                f"rate_limit_{action_type}",
                current_count,
                config.max_requests,
            )

        # Check burst limit
        if config.burst_limit:
            burst_window = now - timedelta(seconds=10)  # 10 second burst window
            burst_count = len([
                ts for ts in self._request_history[action_type]
                if ts > burst_window
            ])
            if burst_count + count > config.burst_limit:
                raise LimitExceededError(
                    f"burst_limit_{action_type}",
                    burst_count,
                    config.burst_limit,
                )

    def _reset_daily_if_needed(self) -> None:
        """Reset daily counter if day has changed."""
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        if today_start > self._daily_reset_time:
            self._daily_count = 0
            self._daily_reset_time = today_start
            self.logger.info("daily_limits_reset")

    def track_resource(
        self,
        resource_type: str,
        usage: float,
    ) -> None:
        """Track resource usage.

        Args:
            resource_type: Type of resource
            usage: Amount used

        Raises:
            LimitExceededError: If resource limit exceeded
        """
        limit = self._resource_limits.get(resource_type)
        if not limit:
            return

        # Reset if interval passed
        if limit.reset_interval_seconds:
            elapsed = (datetime.utcnow() - limit.last_reset).total_seconds()
            if elapsed > limit.reset_interval_seconds:
                limit.current_usage = 0
                limit.last_reset = datetime.utcnow()

        # Check limit
        new_usage = limit.current_usage + usage
        if new_usage > limit.max_usage:
            raise LimitExceededError(
                resource_type,
                new_usage,
                limit.max_usage,
                f"Resource {resource_type} would exceed limit: {new_usage}/{limit.max_usage} {limit.unit}",
            )

        limit.current_usage = new_usage

    def get_rate_limit_status(self, action_type: str) -> dict[str, Any]:
        """Get rate limit status for an action type.

        Args:
            action_type: Action type

        Returns:
            Rate limit status
        """
        config = self._rate_limits.get(action_type)
        if not config:
            return {"configured": False}

        now = datetime.utcnow()
        window_start = now - timedelta(seconds=config.window_seconds)

        current_count = len([
            ts for ts in self._request_history.get(action_type, [])
            if ts > window_start
        ])

        cooldown_remaining = 0
        if action_type in self._cooldowns:
            if now < self._cooldowns[action_type]:
                cooldown_remaining = (self._cooldowns[action_type] - now).seconds

        return {
            "configured": True,
            "max_requests": config.max_requests,
            "current_count": current_count,
            "remaining": config.max_requests - current_count,
            "window_seconds": config.window_seconds,
            "burst_limit": config.burst_limit,
            "in_cooldown": cooldown_remaining > 0,
            "cooldown_remaining": cooldown_remaining,
        }

    def get_resource_status(self, resource_type: str) -> dict[str, Any]:
        """Get resource limit status.

        Args:
            resource_type: Resource type

        Returns:
            Resource status
        """
        limit = self._resource_limits.get(resource_type)
        if not limit:
            return {"configured": False}

        time_until_reset = None
        if limit.reset_interval_seconds:
            elapsed = (datetime.utcnow() - limit.last_reset).total_seconds()
            time_until_reset = max(0, limit.reset_interval_seconds - elapsed)

        return {
            "configured": True,
            "max_usage": limit.max_usage,
            "current_usage": limit.current_usage,
            "remaining": limit.max_usage - limit.current_usage,
            "unit": limit.unit,
            "time_until_reset": time_until_reset,
        }

    def get_stats(self) -> dict[str, Any]:
        """Get overall limiter statistics."""
        return {
            "concurrent_actions": self._concurrent_count,
            "max_concurrent": self.max_concurrent_actions,
            "daily_actions": self._daily_count,
            "max_daily": self.max_daily_actions,
            "rate_limits": {
                name: self.get_rate_limit_status(name)
                for name in self._rate_limits
            },
            "resources": {
                name: self.get_resource_status(name)
                for name in self._resource_limits
            },
            "active_cooldowns": len([
                k for k, v in self._cooldowns.items()
                if datetime.utcnow() < v
            ]),
        }

    def reset_all(self) -> None:
        """Reset all limits and counters."""
        self._request_history.clear()
        self._daily_count = 0
        self._cooldowns.clear()

        for limit in self._resource_limits.values():
            limit.current_usage = 0
            limit.last_reset = datetime.utcnow()

        self.logger.info("all_limits_reset")


class LimitContext:
    """Context manager for acquiring and releasing limits."""

    def __init__(
        self,
        limiter: ExecutionLimiter,
        action_type: str,
    ):
        self.limiter = limiter
        self.action_type = action_type
        self._acquired = False

    async def __aenter__(self):
        await self.limiter.acquire(self.action_type)
        self._acquired = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._acquired:
            self.limiter.release(self.action_type)
        return False
