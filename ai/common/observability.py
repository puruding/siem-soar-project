"""OpenTelemetry observability setup for AI services."""

import os
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.propagate import set_global_textmap
from opentelemetry.propagators.b3 import B3MultiFormat


def init_tracing(service_name: str) -> None:
    """Initialize OpenTelemetry tracing.

    Args:
        service_name: Name of the service for tracing.
    """
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "jaeger:4317")

    resource = Resource.create({
        ResourceAttributes.SERVICE_NAME: service_name,
        ResourceAttributes.SERVICE_VERSION: "1.0.0",
        ResourceAttributes.DEPLOYMENT_ENVIRONMENT: os.getenv("ENVIRONMENT", "development"),
    })

    provider = TracerProvider(resource=resource)

    try:
        exporter = OTLPSpanExporter(
            endpoint=endpoint,
            insecure=True,
        )
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
    except Exception as e:
        print(f"Warning: Failed to initialize OTLP exporter: {e}")

    trace.set_tracer_provider(provider)
    set_global_textmap(B3MultiFormat())

    print(f"OpenTelemetry initialized for {service_name} -> {endpoint}")


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer instance."""
    return trace.get_tracer(name)
