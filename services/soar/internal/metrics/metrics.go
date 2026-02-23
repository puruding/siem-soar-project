// Package metrics provides Prometheus metrics for SOAR service.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// soar_trigger_duration_seconds - time from alert to SOAR trigger
	SOARTriggerDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "soar_trigger_duration_seconds",
			Help:    "Duration of SOAR playbook trigger in seconds",
			Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0},
		},
	)

	// soar_execution_duration_seconds - total playbook execution time
	SOARExecutionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "soar_execution_duration_seconds",
			Help:    "Duration of SOAR playbook execution in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0},
		},
		[]string{"playbook_name", "status"},
	)

	// soar_playbook_executions_total - total execution count
	SOARPlaybookExecutionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "soar_playbook_executions_total",
			Help: "Total number of SOAR playbook executions",
		},
		[]string{"playbook_name", "status"},
	)

	// pipeline_duration_seconds - end-to-end pipeline latency
	PipelineDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "pipeline_duration_seconds",
			Help:    "End-to-end pipeline duration from alert to completion in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0},
		},
	)
)

// RecordTriggerDuration records the duration from alert to SOAR trigger.
func RecordTriggerDuration(duration time.Duration) {
	SOARTriggerDuration.Observe(duration.Seconds())
}

// RecordExecutionDuration records playbook execution duration.
func RecordExecutionDuration(playbookName string, duration time.Duration, success bool) {
	status := "success"
	if !success {
		status = "failed"
	}
	SOARExecutionDuration.WithLabelValues(playbookName, status).Observe(duration.Seconds())
	SOARPlaybookExecutionsTotal.WithLabelValues(playbookName, status).Inc()
}

// RecordPipelineDuration records end-to-end pipeline duration.
func RecordPipelineDuration(duration time.Duration) {
	PipelineDuration.Observe(duration.Seconds())
}

// PrometheusMetricsRecorder implements MetricsRecorder interface with Prometheus.
type PrometheusMetricsRecorder struct{}

// NewPrometheusMetricsRecorder creates a new Prometheus metrics recorder.
func NewPrometheusMetricsRecorder() *PrometheusMetricsRecorder {
	return &PrometheusMetricsRecorder{}
}

// RecordExecution records playbook execution metrics.
func (r *PrometheusMetricsRecorder) RecordExecution(playbook string, duration time.Duration, success bool) {
	RecordExecutionDuration(playbook, duration, success)
}

// RecordConnectorCall records connector call metrics.
func (r *PrometheusMetricsRecorder) RecordConnectorCall(connector, action string, duration time.Duration, success bool) {
	// Can add connector-specific metrics here if needed
}

// RecordError records error metrics.
func (r *PrometheusMetricsRecorder) RecordError(component, errorType string) {
	// Can add error metrics here if needed
}

// IncrementCounter increments a named counter with labels.
func (r *PrometheusMetricsRecorder) IncrementCounter(name string, labels map[string]string) {
	// Can add generic counter support here if needed
}
