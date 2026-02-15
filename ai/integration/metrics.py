"""Prometheus metrics for triage service."""

import time
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TriageMetrics(BaseModel):
    """Metrics for alert triage operations."""

    # Counters
    alerts_processed: int = Field(default=0)
    alerts_classified: int = Field(default=0)
    alerts_failed: int = Field(default=0)
    false_positives_detected: int = Field(default=0)
    critical_alerts: int = Field(default=0)
    high_alerts: int = Field(default=0)

    # Latency tracking (in seconds)
    total_processing_time: float = Field(default=0.0)
    total_inference_time: float = Field(default=0.0)

    # Model metrics
    model_version: str = Field(default="unknown")
    model_load_time: float = Field(default=0.0)

    # Confidence metrics
    total_severity_confidence: float = Field(default=0.0)
    total_category_confidence: float = Field(default=0.0)


class MetricsCollector(LoggerMixin):
    """Collect and expose Prometheus metrics."""

    def __init__(self, enable_prometheus: bool = True) -> None:
        """Initialize metrics collector.

        Args:
            enable_prometheus: Whether to enable Prometheus metrics
        """
        self.enable_prometheus = enable_prometheus
        self._metrics = TriageMetrics()

        # Prometheus metrics (if available)
        self._prom_metrics: dict[str, Any] = {}

        if enable_prometheus:
            self._init_prometheus()

    def _init_prometheus(self) -> None:
        """Initialize Prometheus metrics."""
        try:
            from prometheus_client import Counter, Histogram, Gauge, Info

            # Counters
            self._prom_metrics["alerts_processed"] = Counter(
                "triage_alerts_processed_total",
                "Total number of alerts processed",
                ["status"],
            )

            self._prom_metrics["alerts_by_severity"] = Counter(
                "triage_alerts_by_severity_total",
                "Alerts by severity level",
                ["severity"],
            )

            self._prom_metrics["alerts_by_category"] = Counter(
                "triage_alerts_by_category_total",
                "Alerts by category",
                ["category"],
            )

            self._prom_metrics["false_positives"] = Counter(
                "triage_false_positives_total",
                "Number of false positives detected",
            )

            # Histograms
            self._prom_metrics["processing_latency"] = Histogram(
                "triage_processing_latency_seconds",
                "Alert processing latency",
                buckets=[0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0],
            )

            self._prom_metrics["inference_latency"] = Histogram(
                "triage_inference_latency_seconds",
                "Model inference latency",
                buckets=[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25],
            )

            self._prom_metrics["batch_size"] = Histogram(
                "triage_batch_size",
                "Processing batch size",
                buckets=[1, 5, 10, 25, 50, 100, 200],
            )

            # Gauges
            self._prom_metrics["priority_score"] = Histogram(
                "triage_priority_score",
                "Alert priority scores",
                buckets=[10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
            )

            self._prom_metrics["confidence_score"] = Histogram(
                "triage_confidence_score",
                "Classification confidence scores",
                buckets=[0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99],
            )

            self._prom_metrics["queue_size"] = Gauge(
                "triage_queue_size",
                "Current queue size",
            )

            self._prom_metrics["model_info"] = Info(
                "triage_model",
                "Model information",
            )

            self.logger.info("prometheus_metrics_initialized")

        except ImportError:
            self.logger.warning("prometheus_client_not_installed")
            self.enable_prometheus = False

    def record_alert_processed(
        self,
        severity: str,
        category: str,
        is_false_positive: bool,
        priority_score: float,
        severity_confidence: float,
        category_confidence: float,
        processing_time_seconds: float,
        inference_time_seconds: float,
    ) -> None:
        """Record metrics for a processed alert.

        Args:
            severity: Classified severity
            category: Classified category
            is_false_positive: Whether detected as FP
            priority_score: Priority score
            severity_confidence: Severity confidence
            category_confidence: Category confidence
            processing_time_seconds: Total processing time
            inference_time_seconds: Model inference time
        """
        # Update internal metrics
        self._metrics.alerts_processed += 1
        self._metrics.alerts_classified += 1
        self._metrics.total_processing_time += processing_time_seconds
        self._metrics.total_inference_time += inference_time_seconds
        self._metrics.total_severity_confidence += severity_confidence
        self._metrics.total_category_confidence += category_confidence

        if is_false_positive:
            self._metrics.false_positives_detected += 1

        if severity == "critical":
            self._metrics.critical_alerts += 1
        elif severity == "high":
            self._metrics.high_alerts += 1

        # Update Prometheus metrics
        if self.enable_prometheus:
            self._prom_metrics["alerts_processed"].labels(status="success").inc()
            self._prom_metrics["alerts_by_severity"].labels(severity=severity).inc()
            self._prom_metrics["alerts_by_category"].labels(category=category).inc()

            if is_false_positive:
                self._prom_metrics["false_positives"].inc()

            self._prom_metrics["processing_latency"].observe(processing_time_seconds)
            self._prom_metrics["inference_latency"].observe(inference_time_seconds)
            self._prom_metrics["priority_score"].observe(priority_score)
            self._prom_metrics["confidence_score"].observe(severity_confidence)

    def record_alert_failed(self, error_type: str) -> None:
        """Record a failed alert processing.

        Args:
            error_type: Type of error
        """
        self._metrics.alerts_failed += 1

        if self.enable_prometheus:
            self._prom_metrics["alerts_processed"].labels(status="error").inc()

    def record_batch(self, batch_size: int) -> None:
        """Record batch processing.

        Args:
            batch_size: Size of processed batch
        """
        if self.enable_prometheus:
            self._prom_metrics["batch_size"].observe(batch_size)

    def set_queue_size(self, size: int) -> None:
        """Update current queue size.

        Args:
            size: Current queue size
        """
        if self.enable_prometheus:
            self._prom_metrics["queue_size"].set(size)

    def set_model_info(self, version: str, load_time: float) -> None:
        """Set model information.

        Args:
            version: Model version
            load_time: Model load time in seconds
        """
        self._metrics.model_version = version
        self._metrics.model_load_time = load_time

        if self.enable_prometheus:
            self._prom_metrics["model_info"].info({
                "version": version,
                "load_time": str(load_time),
            })

    def get_summary(self) -> dict[str, Any]:
        """Get metrics summary.

        Returns:
            Dictionary of metrics
        """
        metrics = self._metrics.model_dump()

        # Calculate averages
        if self._metrics.alerts_processed > 0:
            metrics["avg_processing_time_ms"] = (
                self._metrics.total_processing_time / self._metrics.alerts_processed * 1000
            )
            metrics["avg_inference_time_ms"] = (
                self._metrics.total_inference_time / self._metrics.alerts_processed * 1000
            )
            metrics["avg_severity_confidence"] = (
                self._metrics.total_severity_confidence / self._metrics.alerts_processed
            )
            metrics["avg_category_confidence"] = (
                self._metrics.total_category_confidence / self._metrics.alerts_processed
            )
            metrics["fp_rate"] = (
                self._metrics.false_positives_detected / self._metrics.alerts_processed
            )
            metrics["error_rate"] = (
                self._metrics.alerts_failed /
                (self._metrics.alerts_processed + self._metrics.alerts_failed)
            )

        return metrics


class LatencyTracker:
    """Context manager for tracking operation latency."""

    def __init__(self, metrics_collector: MetricsCollector, operation: str) -> None:
        """Initialize latency tracker.

        Args:
            metrics_collector: Metrics collector
            operation: Operation name
        """
        self.collector = metrics_collector
        self.operation = operation
        self.start_time: float | None = None
        self.duration: float = 0.0

    def __enter__(self) -> "LatencyTracker":
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.start_time is not None:
            self.duration = time.perf_counter() - self.start_time

    async def __aenter__(self) -> "LatencyTracker":
        self.start_time = time.perf_counter()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.start_time is not None:
            self.duration = time.perf_counter() - self.start_time
