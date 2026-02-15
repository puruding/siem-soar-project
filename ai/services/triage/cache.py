"""Caching layer for inference results."""

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from typing import Any

import redis.asyncio as redis
from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel


class CacheConfig(BaseModel):
    """Configuration for caching."""

    # In-memory cache
    max_memory_items: int = Field(default=10000, description="Max items in memory cache")
    memory_ttl_seconds: int = Field(default=300, description="Memory cache TTL")

    # Redis cache
    use_redis: bool = Field(default=True, description="Use Redis for distributed cache")
    redis_ttl_seconds: int = Field(default=3600, description="Redis cache TTL")
    redis_prefix: str = Field(default="triage:", description="Redis key prefix")


class LRUCache(LoggerMixin):
    """In-memory LRU cache with TTL."""

    def __init__(
        self,
        max_size: int = 10000,
        ttl_seconds: int = 300,
    ) -> None:
        """Initialize the cache.

        Args:
            max_size: Maximum number of items
            ttl_seconds: Time-to-live in seconds
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()

        # Metrics
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> Any | None:
        """Get item from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        async with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None

            value, timestamp = self._cache[key]

            # Check TTL
            if time.time() - timestamp > self.ttl_seconds:
                del self._cache[key]
                self._misses += 1
                return None

            # Move to end (most recently used)
            self._cache.move_to_end(key)
            self._hits += 1
            return value

    async def set(self, key: str, value: Any) -> None:
        """Set item in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        async with self._lock:
            # Remove oldest if at capacity
            while len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)

            self._cache[key] = (value, time.time())
            self._cache.move_to_end(key)

    async def delete(self, key: str) -> bool:
        """Delete item from cache.

        Args:
            key: Cache key

        Returns:
            True if item was deleted
        """
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    async def clear(self) -> None:
        """Clear all items from cache."""
        async with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def metrics(self) -> dict[str, Any]:
        """Get cache metrics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
        }


class RedisCache(LoggerMixin):
    """Redis-based distributed cache."""

    def __init__(
        self,
        redis_url: str,
        prefix: str = "triage:",
        ttl_seconds: int = 3600,
    ) -> None:
        """Initialize Redis cache.

        Args:
            redis_url: Redis connection URL
            prefix: Key prefix for namespacing
            ttl_seconds: Time-to-live in seconds
        """
        self.redis_url = redis_url
        self.prefix = prefix
        self.ttl_seconds = ttl_seconds
        self._client: redis.Redis | None = None

    async def connect(self) -> None:
        """Connect to Redis."""
        self._client = await redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        self.logger.info("redis_connected", url=self.redis_url)

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.close()
            self._client = None

    def _make_key(self, key: str) -> str:
        """Create prefixed key."""
        return f"{self.prefix}{key}"

    async def get(self, key: str) -> Any | None:
        """Get item from Redis.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        if not self._client:
            return None

        try:
            value = await self._client.get(self._make_key(key))
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            self.logger.warning("redis_get_error", key=key, error=str(e))
            return None

    async def set(self, key: str, value: Any) -> None:
        """Set item in Redis.

        Args:
            key: Cache key
            value: Value to cache
        """
        if not self._client:
            return

        try:
            await self._client.setex(
                self._make_key(key),
                self.ttl_seconds,
                json.dumps(value, default=str),
            )
        except Exception as e:
            self.logger.warning("redis_set_error", key=key, error=str(e))

    async def delete(self, key: str) -> bool:
        """Delete item from Redis.

        Args:
            key: Cache key

        Returns:
            True if item was deleted
        """
        if not self._client:
            return False

        try:
            result = await self._client.delete(self._make_key(key))
            return result > 0
        except Exception as e:
            self.logger.warning("redis_delete_error", key=key, error=str(e))
            return False

    async def clear_prefix(self) -> int:
        """Clear all items with the cache prefix.

        Returns:
            Number of items deleted
        """
        if not self._client:
            return 0

        try:
            pattern = f"{self.prefix}*"
            cursor = 0
            deleted = 0

            while True:
                cursor, keys = await self._client.scan(cursor, match=pattern, count=100)
                if keys:
                    deleted += await self._client.delete(*keys)
                if cursor == 0:
                    break

            return deleted
        except Exception as e:
            self.logger.warning("redis_clear_error", error=str(e))
            return 0


class TieredCache(LoggerMixin):
    """Two-tier caching with memory and Redis."""

    def __init__(self, config: CacheConfig | None = None) -> None:
        """Initialize tiered cache.

        Args:
            config: Cache configuration
        """
        self.config = config or CacheConfig()

        # Memory cache (L1)
        self._memory = LRUCache(
            max_size=self.config.max_memory_items,
            ttl_seconds=self.config.memory_ttl_seconds,
        )

        # Redis cache (L2)
        self._redis: RedisCache | None = None
        if self.config.use_redis:
            settings = get_settings()
            self._redis = RedisCache(
                redis_url=settings.redis_url,
                prefix=self.config.redis_prefix,
                ttl_seconds=self.config.redis_ttl_seconds,
            )

    async def connect(self) -> None:
        """Connect to Redis if enabled."""
        if self._redis:
            await self._redis.connect()

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.disconnect()

    async def get(self, key: str) -> Any | None:
        """Get item from tiered cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None
        """
        # Try memory cache first
        value = await self._memory.get(key)
        if value is not None:
            return value

        # Try Redis cache
        if self._redis:
            value = await self._redis.get(key)
            if value is not None:
                # Populate memory cache
                await self._memory.set(key, value)
                return value

        return None

    async def set(self, key: str, value: Any) -> None:
        """Set item in both cache tiers.

        Args:
            key: Cache key
            value: Value to cache
        """
        # Set in memory
        await self._memory.set(key, value)

        # Set in Redis
        if self._redis:
            await self._redis.set(key, value)

    async def delete(self, key: str) -> None:
        """Delete item from both cache tiers.

        Args:
            key: Cache key
        """
        await self._memory.delete(key)
        if self._redis:
            await self._redis.delete(key)

    async def clear(self) -> None:
        """Clear both cache tiers."""
        await self._memory.clear()
        if self._redis:
            await self._redis.clear_prefix()

    @property
    def metrics(self) -> dict[str, Any]:
        """Get combined cache metrics."""
        return {
            "memory": self._memory.metrics,
            "redis_enabled": self._redis is not None,
        }


class ClassificationCache(LoggerMixin):
    """Specialized cache for classification results."""

    def __init__(self, cache: TieredCache) -> None:
        """Initialize classification cache.

        Args:
            cache: Underlying tiered cache
        """
        self._cache = cache

    def _make_alert_key(self, alert: dict[str, Any]) -> str:
        """Create cache key from alert.

        Args:
            alert: Alert dictionary

        Returns:
            Cache key
        """
        # Create deterministic hash from relevant alert fields
        key_fields = [
            alert.get("alert_id", ""),
            alert.get("title", ""),
            alert.get("description", ""),
            alert.get("rule_id", ""),
            alert.get("source_ip", ""),
            alert.get("dest_ip", ""),
        ]

        key_data = "|".join(str(f) for f in key_fields)
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]

    async def get_classification(
        self, alert: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Get cached classification for alert.

        Args:
            alert: Alert dictionary

        Returns:
            Cached classification or None
        """
        key = self._make_alert_key(alert)
        return await self._cache.get(f"classification:{key}")

    async def set_classification(
        self,
        alert: dict[str, Any],
        classification: dict[str, Any],
    ) -> None:
        """Cache classification result.

        Args:
            alert: Alert dictionary
            classification: Classification result
        """
        key = self._make_alert_key(alert)
        await self._cache.set(f"classification:{key}", classification)

    async def invalidate_alert(self, alert: dict[str, Any]) -> None:
        """Invalidate cached classification for alert.

        Args:
            alert: Alert dictionary
        """
        key = self._make_alert_key(alert)
        await self._cache.delete(f"classification:{key}")
