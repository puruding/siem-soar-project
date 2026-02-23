# OpenTelemetry Implementation - ML Gateway

## Overview
OpenTelemetry distributed tracing has been successfully added to the Python ML Gateway service.

## Changes Made

### 1. Dependencies Added (pyproject.toml)
```toml
"opentelemetry-api>=1.22.0",
"opentelemetry-sdk>=1.22.0",
"opentelemetry-exporter-otlp-proto-grpc>=1.22.0",
"opentelemetry-instrumentation-fastapi>=0.43b0",
"opentelemetry-instrumentation-httpx>=0.43b0",
```

### 2. New Observability Module (common/observability.py)
Created a reusable OpenTelemetry setup module with:
- `init_tracing(service_name: str)` - Initialize OTel with OTLP exporter
- `get_tracer(name: str)` - Get tracer instance
- Resource attributes: service name, version, environment
- B3MultiFormat propagator for trace context propagation
- Graceful fallback on exporter initialization failure

### 3. ML Gateway Integration (services/ml_gateway/main.py)
- Imported `init_tracing` from common module
- Called `init_tracing("ml-gateway")` in lifespan startup
- Instrumented FastAPI app with `FastAPIInstrumentor.instrument_app(app)`
- Updated docstring to mention OpenTelemetry tracing

### 4. Common Module Exports (common/__init__.py)
Exported observability functions:
- `init_tracing`
- `get_tracer`

## Features

### Automatic Instrumentation
FastAPIInstrumentor provides:
- HTTP request/response tracing
- Automatic span creation for each endpoint
- HTTP headers extraction (traceparent, b3, etc.)
- Request/response attribute capture

### Trace Context Propagation
- B3MultiFormat propagator handles incoming traceparent headers from Go services
- Trace context is automatically propagated to downstream HTTP calls (via httpx instrumentation)

### Configuration
Environment variables:
- `OTEL_EXPORTER_OTLP_ENDPOINT` - Jaeger OTLP endpoint (default: "jaeger:4317")
- `ENVIRONMENT` - Deployment environment (default: "development")

### Resource Attributes
Each trace includes:
- `service.name`: "ml-gateway"
- `service.version`: "1.0.0"
- `deployment.environment`: from ENVIRONMENT env var

## Compatibility

### Existing Metrics
- Prometheus metrics remain unchanged
- Both `/metrics` and OTel tracing coexist

### Error Handling
- OTLP exporter failures are logged but don't crash the service
- Service continues to function without tracing if Jaeger is unavailable

## Testing

### Local Testing
```bash
# Start Jaeger (if not running)
docker run -d --name jaeger \
  -e COLLECTOR_OTLP_ENABLED=true \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Set environment
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317

# Run ML Gateway
cd ai
poetry install
poetry run uvicorn services.ml_gateway.main:app --reload

# Make requests
curl http://localhost:8080/health

# View traces
open http://localhost:16686
```

### Kubernetes Deployment
The service will automatically connect to the Jaeger collector at `jaeger:4317` (configured in Helm values).

## Integration with Go Services

### Trace Context Flow
1. Go service (e.g., triage-engine) receives HTTP request
2. Go's OTel middleware extracts/creates trace context
3. Go service calls ML Gateway with traceparent header
4. Python FastAPIInstrumentor extracts traceparent
5. Python creates child span for ML inference
6. Trace shows end-to-end request flow

### Example Trace
```
triage-engine (Go)
└── POST /api/v1/triage/classify (200ms)
    └── ml-gateway (Python)
        └── POST /api/v1/dga/predict (150ms)
            └── Model inference (120ms)
```

## Next Steps

### Custom Spans
To add manual instrumentation for model inference:

```python
from common.observability import get_tracer

tracer = get_tracer(__name__)

with tracer.start_as_current_span("model_inference") as span:
    span.set_attribute("model_type", model_type.value)
    span.set_attribute("batch_size", len(inputs))
    result = model.predict(inputs)
    span.set_attribute("prediction_count", len(result))
```

### Other AI Services
Apply the same pattern to:
- `services/triage/main.py`
- `services/copilot/main.py`
- `services/agentic/main.py`

## References
- [OpenTelemetry Python Docs](https://opentelemetry-python.readthedocs.io/)
- [FastAPI Instrumentation](https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation/fastapi/fastapi.html)
- [OTLP Exporter](https://opentelemetry-python.readthedocs.io/en/latest/exporter/otlp/otlp.html)
