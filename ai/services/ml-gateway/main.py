"""ML Gateway Service - FastAPI application for ML model serving.

This service provides unified endpoints for:
- DGA detection (/api/v1/dga/*)
- UEBA anomaly detection (/api/v1/ueba/*)
- Alert clustering (/api/v1/clustering/*)

Features:
- Model lazy loading with caching
- Batch inference support
- Health checks
- Prometheus metrics
- Request validation
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from services.ml_gateway.models.loader import ModelLoader, ModelType
from services.ml_gateway.routes import dga, ueba, clustering


# Metrics
REQUEST_COUNT = Counter(
    "ml_gateway_requests_total",
    "Total requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "ml_gateway_request_latency_seconds",
    "Request latency",
    ["method", "endpoint"],
)
INFERENCE_LATENCY = Histogram(
    "ml_gateway_inference_latency_seconds",
    "Model inference latency",
    ["model_type"],
)


# Global model loader
model_loader: ModelLoader | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global model_loader

    # Startup: Initialize model loader
    model_loader = ModelLoader()

    # Preload models based on config
    preload_models = ["dga", "ueba", "clustering"]
    for model_name in preload_models:
        try:
            await asyncio.to_thread(
                model_loader.load_model,
                ModelType(model_name),
            )
        except Exception as e:
            print(f"Warning: Failed to preload {model_name}: {e}")

    yield

    # Shutdown: Cleanup
    if model_loader:
        model_loader.unload_all()


# Create FastAPI app
app = FastAPI(
    title="ML Gateway Service",
    description="Unified ML inference API for SIEM-SOAR platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for metrics
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Middleware to track request metrics."""
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code,
    ).inc()
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.url.path,
    ).observe(duration)

    return response


# Include routers
app.include_router(dga.router, prefix="/api/v1/dga", tags=["DGA Detection"])
app.include_router(ueba.router, prefix="/api/v1/ueba", tags=["UEBA Anomaly Detection"])
app.include_router(clustering.router, prefix="/api/v1/clustering", tags=["Alert Clustering"])


# Health and status endpoints
class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(description="Service status")
    models_loaded: dict[str, bool] = Field(description="Model load status")
    uptime_seconds: float = Field(description="Service uptime")


_start_time = time.time()


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Check service health."""
    global model_loader

    models_loaded = {}
    if model_loader:
        for model_type in ModelType:
            models_loaded[model_type.value] = model_loader.is_loaded(model_type)

    return HealthResponse(
        status="healthy",
        models_loaded=models_loaded,
        uptime_seconds=time.time() - _start_time,
    )


@app.get("/ready")
async def readiness_check():
    """Check if service is ready to accept requests."""
    global model_loader

    if model_loader is None:
        raise HTTPException(status_code=503, detail="Model loader not initialized")

    # Check if at least one model is loaded
    for model_type in ModelType:
        if model_loader.is_loaded(model_type):
            return {"status": "ready"}

    raise HTTPException(status_code=503, detail="No models loaded")


@app.get("/metrics")
async def metrics():
    """Expose Prometheus metrics."""
    from starlette.responses import Response
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


class ModelStatusResponse(BaseModel):
    """Model status response."""
    model_type: str
    loaded: bool
    load_time: float | None
    inference_count: int
    avg_latency_ms: float


@app.get("/api/v1/models/status")
async def get_model_status() -> list[ModelStatusResponse]:
    """Get status of all models."""
    global model_loader

    if model_loader is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    statuses = []
    for model_type in ModelType:
        info = model_loader.get_model_info(model_type)
        statuses.append(ModelStatusResponse(
            model_type=model_type.value,
            loaded=info.get("loaded", False),
            load_time=info.get("load_time"),
            inference_count=info.get("inference_count", 0),
            avg_latency_ms=info.get("avg_latency_ms", 0.0),
        ))

    return statuses


class ModelLoadRequest(BaseModel):
    """Request to load/reload a model."""
    model_type: str = Field(description="Model type to load")
    force_reload: bool = Field(default=False, description="Force reload even if loaded")


@app.post("/api/v1/models/load")
async def load_model(request: ModelLoadRequest) -> dict[str, Any]:
    """Load or reload a model."""
    global model_loader

    if model_loader is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        model_type = ModelType(request.model_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid model type: {request.model_type}. Valid types: {[t.value for t in ModelType]}",
        )

    try:
        load_time = await asyncio.to_thread(
            model_loader.load_model,
            model_type,
            force_reload=request.force_reload,
        )
        return {
            "status": "loaded",
            "model_type": model_type.value,
            "load_time_seconds": load_time,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")


@app.post("/api/v1/models/unload")
async def unload_model(model_type: str) -> dict[str, Any]:
    """Unload a model to free resources."""
    global model_loader

    if model_loader is None:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        mt = ModelType(model_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid model type: {model_type}")

    model_loader.unload_model(mt)
    return {"status": "unloaded", "model_type": model_type}


# Error handlers
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content={"error": "validation_error", "detail": str(exc)},
    )


@app.exception_handler(Exception)
async def general_error_handler(request: Request, exc: Exception):
    """Handle general errors."""
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error", "detail": str(exc)},
    )


def get_model_loader() -> ModelLoader:
    """Get the global model loader instance."""
    global model_loader
    if model_loader is None:
        raise RuntimeError("Model loader not initialized")
    return model_loader


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "services.ml_gateway.main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        workers=1,
    )
