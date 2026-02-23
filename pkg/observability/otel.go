package observability

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// Config holds observability configuration
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string // e.g., "jaeger:4317"
	MetricsPort    int    // e.g., 9090
}

// DefaultConfig returns default observability config from environment
func DefaultConfig(serviceName string) Config {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "jaeger:4317"
	}

	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	return Config{
		ServiceName:    serviceName,
		ServiceVersion: "1.0.0",
		Environment:    env,
		OTLPEndpoint:   endpoint,
		MetricsPort:    9090,
	}
}

// Provider holds initialized OTel providers
type Provider struct {
	TracerProvider     *trace.TracerProvider
	MeterProvider      *metric.MeterProvider
	PrometheusExporter *prometheus.Exporter
}

// Init initializes OpenTelemetry with tracing and metrics
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			semconv.DeploymentEnvironment(cfg.Environment),
		),
	)
	if err != nil {
		return nil, err
	}

	// Strip http:// or https:// prefix from endpoint if present
	endpoint := cfg.OTLPEndpoint
	if strings.HasPrefix(endpoint, "http://") {
		endpoint = strings.TrimPrefix(endpoint, "http://")
	} else if strings.HasPrefix(endpoint, "https://") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}

	// Initialize trace exporter (OTLP to Jaeger)
	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		slog.Warn("failed to create trace exporter, tracing disabled", "error", err)
		// Continue without tracing
	}

	// Create TracerProvider with configurable sampling
	var tp *trace.TracerProvider
	if traceExporter != nil {
		// Get sampling rate from environment (default: 1.0 = sample everything)
		samplingRate := 1.0
		if rateStr := os.Getenv("OTEL_SAMPLING_RATE"); rateStr != "" {
			if rate, err := strconv.ParseFloat(rateStr, 64); err == nil {
				samplingRate = rate
				slog.Info("using custom sampling rate", "rate", samplingRate)
			} else {
				slog.Warn("invalid OTEL_SAMPLING_RATE, using default", "value", rateStr, "error", err)
			}
		}

		// Configure sampler based on rate
		var sampler trace.Sampler
		if samplingRate >= 1.0 {
			sampler = trace.AlwaysSample()
		} else if samplingRate <= 0.0 {
			sampler = trace.NeverSample()
		} else {
			// Use parent-based sampling with ratio for production
			sampler = trace.ParentBased(trace.TraceIDRatioBased(samplingRate))
		}

		tp = trace.NewTracerProvider(
			trace.WithBatcher(traceExporter,
				trace.WithBatchTimeout(5*time.Second),
				trace.WithMaxExportBatchSize(512),
			),
			trace.WithResource(res),
			trace.WithSampler(sampler),
		)
		otel.SetTracerProvider(tp)
	}

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Initialize Prometheus exporter for metrics
	promExporter, err := prometheus.New()
	if err != nil {
		slog.Warn("failed to create prometheus exporter", "error", err)
	}

	var mp *metric.MeterProvider
	if promExporter != nil {
		mp = metric.NewMeterProvider(
			metric.WithReader(promExporter),
			metric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
	}

	slog.Info("OpenTelemetry initialized",
		"service", cfg.ServiceName,
		"otlp_endpoint", cfg.OTLPEndpoint,
		"tracing", traceExporter != nil,
		"metrics", promExporter != nil,
	)

	return &Provider{
		TracerProvider:     tp,
		MeterProvider:      mp,
		PrometheusExporter: promExporter,
	}, nil
}

// Shutdown gracefully shuts down the provider
func (p *Provider) Shutdown(ctx context.Context) {
	if p.TracerProvider != nil {
		if err := p.TracerProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown tracer provider", "error", err)
		}
	}
	if p.MeterProvider != nil {
		if err := p.MeterProvider.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown meter provider", "error", err)
		}
	}
}
