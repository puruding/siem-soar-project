# Copilot Service Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install PyTorch CPU from pytorch index
RUN pip install --no-cache-dir --target=/app/deps \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install other dependencies from PyPI
RUN pip install --no-cache-dir --target=/app/deps \
    fastapi>=0.109.0 \
    uvicorn[standard]>=0.27.0 \
    pydantic>=2.6.0 \
    pydantic-settings>=2.1.0 \
    httpx>=0.26.0 \
    redis>=5.0.0 \
    structlog>=24.1.0 \
    tenacity>=8.2.0 \
    openai>=1.10.0 \
    langchain>=0.1.0 \
    langchain-core>=0.1.0 \
    transformers>=4.37.0 \
    numpy>=1.26.0 \
    scikit-learn>=1.4.0


# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies from builder
COPY --from=builder /app/deps /usr/local/lib/python3.11/site-packages

# Copy application code
COPY common/ ./common/
COPY models/ ./models/
COPY services/copilot/ ./services/copilot/

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO
ENV ENVIRONMENT=production

# Expose port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Run the service
CMD ["python", "-m", "uvicorn", "services.copilot.main:app", "--host", "0.0.0.0", "--port", "8001"]
