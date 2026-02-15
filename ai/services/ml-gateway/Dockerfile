# ML Gateway Service Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt* ./
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir --target=/app/deps -r requirements.txt; \
    else pip install --no-cache-dir --target=/app/deps \
    fastapi uvicorn pydantic redis torch transformers langchain prometheus-client; fi


# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies from builder
COPY --from=builder /app/deps /usr/local/lib/python3.11/site-packages

# Copy application code
COPY common/ ./common/
COPY models/ ./models/
COPY services/ml-gateway/ ./services/ml_gateway/

# Create model directory
RUN mkdir -p /app/models/dga /app/models/ueba /app/models/clustering

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV MODEL_DIR=/app/models

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the service
CMD ["python", "-m", "uvicorn", "services.ml_gateway.main:app", "--host", "0.0.0.0", "--port", "8080"]
