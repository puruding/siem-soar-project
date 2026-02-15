"""Configuration management for AI services."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Service identification
    service_name: str = Field(default="ai-service", description="Service name")
    environment: Literal["development", "staging", "production"] = Field(
        default="development", description="Deployment environment"
    )
    debug: bool = Field(default=False, description="Enable debug mode")

    # Server settings
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    workers: int = Field(default=1, description="Number of worker processes")

    # Database connections
    postgres_dsn: str = Field(
        default="postgresql://localhost:5432/siemsoar",
        description="PostgreSQL connection string",
    )
    clickhouse_dsn: str = Field(
        default="clickhouse://localhost:8123/siemsoar",
        description="ClickHouse connection string",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # Kafka settings
    kafka_brokers: str = Field(
        default="localhost:9092",
        description="Comma-separated Kafka broker addresses",
    )
    kafka_consumer_group: str = Field(
        default="ai-service",
        description="Kafka consumer group ID",
    )

    # AI/ML settings
    model_cache_dir: str = Field(
        default="/tmp/models",
        description="Directory for model cache",
    )
    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        description="Default embedding model",
    )
    llm_model: str = Field(
        default="gpt-4-turbo-preview",
        description="Default LLM model",
    )
    max_tokens: int = Field(default=4096, description="Maximum tokens for LLM")
    temperature: float = Field(default=0.0, description="LLM temperature")

    # API keys (secrets)
    openai_api_key: SecretStr | None = Field(default=None, description="OpenAI API key")
    anthropic_api_key: SecretStr | None = Field(
        default=None, description="Anthropic API key"
    )

    # vLLM settings
    vllm_endpoint: str = Field(
        default="http://localhost:8080",
        description="vLLM inference server endpoint",
    )

    # Vector store settings
    chroma_host: str = Field(default="localhost", description="ChromaDB host")
    chroma_port: int = Field(default=8001, description="ChromaDB port")

    # Observability
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: Literal["json", "text"] = Field(
        default="json", description="Log output format"
    )
    metrics_enabled: bool = Field(default=True, description="Enable Prometheus metrics")
    tracing_enabled: bool = Field(default=False, description="Enable distributed tracing")
    tracing_endpoint: str = Field(
        default="http://localhost:4317",
        description="OpenTelemetry collector endpoint",
    )

    @property
    def kafka_brokers_list(self) -> list[str]:
        """Return Kafka brokers as a list."""
        return [b.strip() for b in self.kafka_brokers.split(",")]


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
