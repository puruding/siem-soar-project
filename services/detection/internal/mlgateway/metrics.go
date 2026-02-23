// Package mlgateway provides HTTP client for ML Gateway service.
package mlgateway

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds Prometheus metrics for ML Gateway client.
type Metrics struct {
	triageRequests *prometheus.CounterVec
	triageDuration *prometheus.HistogramVec
	cacheHits      prometheus.Counter
	cacheMisses    prometheus.Counter
}

var (
	// triageRequests tracks total triage requests by status.
	triageRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "triage_requests_total",
			Help:      "Total number of ML triage requests by status (success, error, circuit_open)",
		},
		[]string{"status"},
	)

	// triageDuration tracks triage request latency.
	triageDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "triage_duration_seconds",
			Help:      "ML triage request duration in seconds",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
		[]string{"operation"},
	)

	// circuitState tracks circuit breaker state.
	// 0 = closed, 1 = half-open, 2 = open
	circuitState = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "circuit_breaker_state",
			Help:      "Circuit breaker state (0=closed, 1=half-open, 2=open)",
		},
		[]string{"name"},
	)

	// cacheHits tracks cache hits.
	cacheHits = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "cache_hits_total",
			Help:      "Total number of ML triage cache hits",
		},
	)

	// cacheMisses tracks cache misses.
	cacheMisses = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "cache_misses_total",
			Help:      "Total number of ML triage cache misses",
		},
	)

	// mlEnrichmentEnabled tracks if ML enrichment is enabled.
	mlEnrichmentEnabled = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "enrichment_enabled",
			Help:      "Whether ML enrichment is enabled (1) or disabled (0)",
		},
	)

	// batchSize tracks batch request sizes.
	batchSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "batch_size",
			Help:      "Size of batch triage requests",
			Buckets:   []float64{1, 5, 10, 25, 50, 100, 250, 500},
		},
	)

	// riskScoreDistribution tracks distribution of risk scores.
	riskScoreDistribution = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "risk_score_distribution",
			Help:      "Distribution of ML risk scores",
			Buckets:   []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		},
	)

	// falsePositiveRate tracks false positive rate.
	falsePositiveRate = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "false_positive_total",
			Help:      "Total number of alerts classified as false positive vs true positive",
		},
		[]string{"classification"},
	)

	// priorityDistribution tracks priority distribution.
	priorityDistribution = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "detection",
			Subsystem: "mlgateway",
			Name:      "priority_distribution_total",
			Help:      "Distribution of alert priorities assigned by ML",
		},
		[]string{"priority"},
	)
)

// NewMetrics creates a new Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		triageRequests: triageRequests,
		triageDuration: triageDuration,
		cacheHits:      cacheHits,
		cacheMisses:    cacheMisses,
	}
}

// RecordTriageResult records metrics for a triage result.
func RecordTriageResult(analysis *MLAnalysis) {
	if analysis == nil {
		return
	}

	// Record risk score distribution
	riskScoreDistribution.Observe(analysis.RiskScore)

	// Record false positive classification
	if analysis.IsFalsePositive {
		falsePositiveRate.WithLabelValues("false_positive").Inc()
	} else {
		falsePositiveRate.WithLabelValues("true_positive").Inc()
	}

	// Record priority distribution
	if analysis.Priority != "" {
		priorityDistribution.WithLabelValues(analysis.Priority).Inc()
	}
}

// RecordBatchSize records the size of a batch request.
func RecordBatchSize(size int) {
	batchSize.Observe(float64(size))
}

// SetMLEnrichmentEnabled sets the ML enrichment enabled gauge.
func SetMLEnrichmentEnabled(enabled bool) {
	if enabled {
		mlEnrichmentEnabled.Set(1)
	} else {
		mlEnrichmentEnabled.Set(0)
	}
}

// GetCircuitBreakerStateGauge returns the circuit breaker state gauge for a given name.
func GetCircuitBreakerStateGauge(name string) prometheus.Gauge {
	return circuitState.WithLabelValues(name)
}
