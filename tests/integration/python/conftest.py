"""Pytest configuration for integration tests."""

import asyncio
import os
from typing import Generator

import pytest


# Test configuration from environment variables
def get_service_url(service: str, default_port: int) -> str:
    """Get service URL from environment or use default."""
    env_var = f"{service.upper()}_SERVICE_URL"
    return os.environ.get(env_var, f"http://localhost:{default_port}")


# Service URLs
SERVICE_URLS = {
    "gateway": get_service_url("gateway", 8080),
    "detection": get_service_url("detection", 8081),
    "soar": get_service_url("soar", 8082),
    "case": get_service_url("case", 8083),
    "query": get_service_url("query", 8084),
    "ti": get_service_url("ti", 8085),
    "collector": get_service_url("collector", 8086),
    "pipeline": get_service_url("pipeline", 8087),
    "copilot": get_service_url("copilot", 8000),
    "triage": get_service_url("triage", 8001),
    "agentic": get_service_url("agentic", 8002),
}


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def service_urls() -> dict[str, str]:
    """Provide service URLs to tests."""
    return SERVICE_URLS


@pytest.fixture
def gateway_url() -> str:
    """Gateway service URL."""
    return SERVICE_URLS["gateway"]


@pytest.fixture
def detection_url() -> str:
    """Detection service URL."""
    return SERVICE_URLS["detection"]


@pytest.fixture
def soar_url() -> str:
    """SOAR service URL."""
    return SERVICE_URLS["soar"]


@pytest.fixture
def case_url() -> str:
    """Case service URL."""
    return SERVICE_URLS["case"]


@pytest.fixture
def query_url() -> str:
    """Query service URL."""
    return SERVICE_URLS["query"]


@pytest.fixture
def copilot_url() -> str:
    """Copilot service URL."""
    return SERVICE_URLS["copilot"]


@pytest.fixture
def triage_url() -> str:
    """Triage service URL."""
    return SERVICE_URLS["triage"]


@pytest.fixture
def agentic_url() -> str:
    """Agentic service URL."""
    return SERVICE_URLS["agentic"]


# Markers
def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )


# Skip conditions
def pytest_collection_modifyitems(config, items):
    """Modify test collection based on markers and conditions."""
    # Skip integration tests if SKIP_INTEGRATION is set
    if os.environ.get("SKIP_INTEGRATION", "").lower() == "true":
        skip_integration = pytest.mark.skip(reason="SKIP_INTEGRATION is set")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)

    # Skip e2e tests if SKIP_E2E is set
    if os.environ.get("SKIP_E2E", "").lower() == "true":
        skip_e2e = pytest.mark.skip(reason="SKIP_E2E is set")
        for item in items:
            if "e2e" in item.keywords:
                item.add_marker(skip_e2e)


# Test timeouts
@pytest.fixture
def short_timeout() -> float:
    """Short timeout for quick operations."""
    return float(os.environ.get("TEST_SHORT_TIMEOUT", "10"))


@pytest.fixture
def medium_timeout() -> float:
    """Medium timeout for standard operations."""
    return float(os.environ.get("TEST_MEDIUM_TIMEOUT", "30"))


@pytest.fixture
def long_timeout() -> float:
    """Long timeout for complex operations."""
    return float(os.environ.get("TEST_LONG_TIMEOUT", "120"))
