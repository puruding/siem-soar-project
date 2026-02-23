# Grafana Dashboards for SIEM-SOAR Platform

This directory contains Grafana dashboard JSON files for monitoring the Detection → ML → SOAR automation pipeline.

## Dashboard Overview

### 1. **pipeline_latency.json** - Detection-ML-SOAR Pipeline
**Purpose**: Monitor end-to-end latency and phase breakdown of the automation chain.

**Key Panels**:
- **End-to-End Pipeline Latency (p99)**: Tracks p99, p95, and p50 latency for the complete automation flow
  - Alert thresholds: Yellow at 0.5s, Red at 1s
- **Phase Breakdown**: Stacked view of individual phase latencies
  - Detection → ML
  - ML → SOAR Trigger
  - SOAR Execution
- **Circuit Breaker Status**: Real-time state of ML Gateway circuit breaker (CLOSED/HALF-OPEN/OPEN)
- **Circuit Breaker Opens (5m)**: Count of circuit opens in 5-minute window
- **Request Rate by Service**: Request throughput for each service
- **Error Rate**: HTTP 5xx error rates by service (threshold: >1% yellow, >5% red)
- **ML Cache Hit Rate**: Percentage of ML requests served from cache
- **SOAR Playbook Executions (5m)**: Total playbook executions in 5-minute window

**Prometheus Metrics Used**:
```promql
# Latency metrics
pipeline_duration_seconds_bucket
detection_ml_call_duration_seconds_bucket
soar_trigger_duration_seconds_bucket
soar_execution_duration_seconds_bucket

# Circuit breaker
circuit_breaker_state{name="ml-gateway"}
circuit_breaker_opens_total{name="ml-gateway"}

# Request/error metrics
http_requests_total
http_requests_total{status=~"5.."}

# Cache metrics
ml_cache_hits_total
ml_cache_requests_total

# SOAR metrics
soar_playbook_executions_total
```

**UID**: `pipeline-latency`

---

### 2. **ml_gateway_metrics.json** - ML Gateway Metrics
**Purpose**: Monitor ML model inference performance, cache efficiency, and model health.

**Key Panels**:
- **ML Request Rate by Model Type**: Throughput for DGA, UEBA, and Clustering models
- **ML Inference Latency**: p99/p95/p50 latency breakdown by model type
  - Alert thresholds: Yellow at 0.2s, Red at 0.5s
- **Cache Hit Rate**: Gauge showing ML cache efficiency (target: >70%)
- **Cache Hits vs Misses**: Time series comparison
- **Model Load Status**: Pie chart showing loaded vs not-loaded models
- **Model Memory Usage**: Memory consumption by model
- **ML Error Rate by Model**: Error percentage per model type
- **ML Predictions by Model (5m)**: Distribution of predictions across models

**Prometheus Metrics Used**:
```promql
# Request metrics
ml_gateway_requests_total{model_type}
ml_gateway_requests_total{status="error"}

# Inference latency
ml_inference_duration_seconds_bucket

# Cache metrics
ml_cache_hits_total
ml_cache_misses_total
ml_cache_requests_total

# Model health
ml_model_loaded_status
ml_model_memory_bytes

# Predictions
ml_predictions_total{model_type, prediction}
```

**UID**: `ml-gateway-metrics`

---

### 3. **soar_execution.json** - SOAR Execution
**Purpose**: Monitor SOAR playbook executions, success rates, and Temporal workflow health.

**Key Panels**:
- **Playbook Execution Rate**: Execution throughput by playbook name
- **Execution Status Distribution**: Pie chart (completed/failed/running/pending_approval)
- **Playbook Success Rate**: Gauge showing completion ratio (target: >95%)
- **Playbook Execution Duration**: p99/p95/p50 latency by playbook
  - Alert thresholds: Yellow at 30s, Red at 60s
- **Pending Approvals**: Count of playbooks awaiting human approval
- **Currently Running Executions**: Real-time execution count
- **Execution Outcomes (5m)**: Stacked time series of completed/failed executions
- **Playbook Node Executions (5m)**: Bar chart showing individual node executions
- **Temporal Workflow Queue Depth**: Queue backlog by task queue
- **Dead Letter Queue Messages**: DLQ messages grouped by failure reason

**Prometheus Metrics Used**:
```promql
# Execution metrics
soar_playbook_executions_total{playbook_name, status}
soar_playbook_executions_current{status}

# Duration
soar_playbook_duration_seconds_bucket{playbook_name}

# Approval workflow
soar_pending_approvals_count

# Node-level metrics
soar_playbook_node_executions_total{playbook_name, node_name}

# Temporal metrics
soar_temporal_workflow_queue_depth{task_queue}

# DLQ
soar_dlq_messages_total{reason}
```

**UID**: `soar-execution`

---

## Dashboard Configuration

All dashboards use the following settings:

| Setting | Value |
|---------|-------|
| **Auto-refresh** | 10 seconds |
| **Time range** | Last 1 hour (default) |
| **Timezone** | Browser timezone |
| **Theme** | Dark |
| **Datasource** | Prometheus (UID: `prometheus`) |

---

## Provisioning

Dashboards are automatically provisioned via Grafana's file-based provisioning:

**Provisioning Config**: `../provisioning/dashboards/dashboards.yaml`

```yaml
apiVersion: 1
providers:
  - name: 'SIEM Dashboards'
    orgId: 1
    folder: 'SIEM-SOAR'
    folderUid: 'siem-soar'
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
```

**Docker Volume Mapping**:
```yaml
volumes:
  - ./dashboards:/var/lib/grafana/dashboards:ro
  - ./provisioning:/etc/grafana/provisioning:ro
```

---

## Required Prometheus Metrics

To use these dashboards, ensure the following metrics are exported:

### Detection Service (Go)
```go
// Histogram for ML call duration
detection_ml_call_duration_seconds_bucket

// Histogram for overall pipeline duration
pipeline_duration_seconds_bucket
```

### ML Gateway (Python)
```python
# Request counter with labels
ml_gateway_requests_total{model_type, status}

# Inference duration histogram
ml_inference_duration_seconds_bucket{model_type}

# Cache metrics
ml_cache_hits_total
ml_cache_misses_total
ml_cache_requests_total

# Model health
ml_model_loaded_status{model_name}
ml_model_memory_bytes{model_name}

# Predictions counter
ml_predictions_total{model_type, prediction}
```

### SOAR Service (Go)
```go
// Trigger duration histogram
soar_trigger_duration_seconds_bucket

// Execution duration histogram
soar_execution_duration_seconds_bucket
soar_playbook_duration_seconds_bucket{playbook_name}

// Execution counters
soar_playbook_executions_total{playbook_name, status}
soar_playbook_executions_current{status}

// Approval gauge
soar_pending_approvals_count

// Node executions
soar_playbook_node_executions_total{playbook_name, node_name}

// Temporal metrics
soar_temporal_workflow_queue_depth{task_queue}

// DLQ
soar_dlq_messages_total{reason}
```

### Shared Metrics (All Services)
```go
// HTTP metrics
http_requests_total{service, method, status}

// Circuit breaker
circuit_breaker_state{name}
circuit_breaker_opens_total{name}
```

---

## Alert Rules

These dashboards include visual thresholds. For active alerting, configure Prometheus Alertmanager rules:

```yaml
groups:
  - name: siem-soar-pipeline
    interval: 30s
    rules:
      - alert: HighPipelineLatency
        expr: histogram_quantile(0.99, sum(rate(pipeline_duration_seconds_bucket[5m])) by (le)) > 1
        for: 2m
        annotations:
          summary: "Pipeline p99 latency exceeds 1 second"

      - alert: MLGatewayDown
        expr: circuit_breaker_state{name="ml-gateway"} == 2
        for: 1m
        annotations:
          summary: "ML Gateway circuit breaker is OPEN"

      - alert: SOARLowSuccessRate
        expr: |
          sum(rate(soar_playbook_executions_total{status="completed"}[5m]))
          /
          sum(rate(soar_playbook_executions_total[5m])) < 0.95
        for: 5m
        annotations:
          summary: "SOAR success rate below 95%"
```

---

## Customization

To modify dashboards:

1. **Edit in Grafana UI** (if `editable: true` in provisioning config)
2. **Export JSON** via Share → Export → Save to file
3. **Replace file** in this directory
4. **Restart Grafana** to reload changes

Or edit JSON directly using Grafana's [dashboard JSON model](https://grafana.com/docs/grafana/latest/dashboards/json-model/).

---

## Related Documentation

- [Design Document](../../../../siem-soar-strategy/13_추가요구사항/01_Detection-ML-SOAR_자동화_체인_구축.md) - Section 4.3.5
- [Prometheus Metrics Guide](../prometheus/README.md)
- [Grafana Provisioning](../provisioning/README.md)

---

**Created**: 2024-02-22
**Version**: 1.0.0
**Maintained by**: SIEM Platform Team
