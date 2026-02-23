# SIEM-SOAR Observability Guide

Complete guide for monitoring and observing the SIEM-SOAR platform using Prometheus, Grafana, and Jaeger.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Getting Started](#getting-started)
- [Accessing Dashboards](#accessing-dashboards)
- [Metrics Reference](#metrics-reference)
- [Tracing Guide](#tracing-guide)
- [Alerts Configuration](#alerts-configuration)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Overview

The SIEM-SOAR platform includes a comprehensive observability stack that provides:

- **Distributed Tracing**: End-to-end request tracing across microservices using Jaeger
- **Metrics Collection**: Prometheus scrapes metrics from all services
- **Visualization**: Grafana dashboards for real-time monitoring
- **Log Aggregation**: Centralized logging with structured logs
- **Alerting**: Automated alerts based on metrics thresholds

### Key Metrics

| Metric | Purpose | Threshold |
|--------|---------|-----------|
| Service Availability | HTTP request success rate | > 99.5% |
| P99 Latency | 99th percentile response time | < 1 second |
| Error Rate | Percentage of failed requests | < 0.5% |
| Event Processing Throughput | Events per second | > 100K EPS |
| Data Freshness | Time since last event processed | < 30 seconds |
| Queue Depth | Messages pending in Kafka | < 10K |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SIEM-SOAR Services                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Gateway  │  │Detection │  │   SOAR   │  │   Query  │   │
│  │ (Traces) │  │ (Traces) │  │ (Traces) │  │ (Traces) │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │             │             │           │
│       └─────────────┴─────────────┴─────────────┘           │
│                     │                                        │
│              OTLP gRPC & HTTP                               │
└──────────────────────┼──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
   │  Jaeger  │   │Prometheus│   │ Services │
   │  Traces  │   │ Metrics  │   │ Metrics  │
   │  (UI)    │   │  (TSDB)  │   │ Endpoint │
   └────┬─────┘   └────┬─────┘   └──────────┘
        │              │
        │         ┌────┴─────┐
        │         │           │
        │    ┌────▼───┐   ┌───▼────┐
        │    │Grafana │   │ Alerts │
        │    │Dashboards  │ Rules  │
        │    └────────┘   └────────┘
        │
    ┌───▼─────┐
    │  Admin  │
    │   UI    │
    └─────────┘
```

### Data Flow

1. **Services** generate spans and metrics
2. **OTLP Exporters** in services send traces to Jaeger and metrics to Prometheus
3. **Jaeger** receives traces, indexes them, and provides UI
4. **Prometheus** scrapes metrics endpoints and stores time-series data
5. **Grafana** queries Prometheus for visualization
6. **Alert Manager** evaluates rules and sends notifications

---

## Components

### Jaeger - Distributed Tracing

**Purpose**: Understand service dependencies, identify bottlenecks, and debug issues

- **Image**: `jaegertracing/all-in-one:1.53`
- **UI Port**: `16686` (http://localhost:16686)
- **OTLP gRPC Port**: `4317`
- **OTLP HTTP Port**: `4318`
- **Features**:
  - Trace sampling and storage
  - Service dependency graph
  - Span analysis
  - Trace search with advanced filters

### Prometheus - Metrics Aggregation

**Purpose**: Collect, store, and query time-series metrics

- **Image**: `prom/prometheus:v2.48.0`
- **Web UI Port**: `9090` (http://localhost:9090)
- **Scrape Interval**: 15 seconds
- **Retention**: 15 days
- **Metrics Scraped**:
  - All SIEM services on port `9090`
  - OTEL Collector on port `8888`
  - Jaeger metrics on port `14269`

### Grafana - Visualization

**Purpose**: Create dashboards and alerts for monitoring

- **Image**: `grafana/grafana:10.2.0`
- **Web UI Port**: `3001` (http://localhost:3001)
- **Default Credentials**: `admin:admin`
- **Features**:
  - Pre-configured Prometheus data source
  - Ready-to-use dashboards
  - Alert rules configured
  - User management

### OpenTelemetry Collector

**Purpose**: Receive, process, and forward telemetry data

- **Image**: `otel/opentelemetry-collector-contrib:0.91.0`
- **OTLP gRPC Port**: `4319` (internal routing)
- **OTLP HTTP Port**: `4320` (internal routing)
- **Prometheus Export**: `8888`
- **Features**:
  - Span processing and enrichment
  - Metric transformation
  - Batch processing
  - Multiple exporters

---

## Getting Started

### Prerequisites

- Docker and Docker Compose installed
- 16GB RAM (minimum 8GB)
- 50GB free disk space

### Starting the Stack

1. **Start all services** (including observability stack):

```bash
cd /path/to/siem-soar-project
docker-compose up -d
```

2. **Wait for services to be ready** (2-3 minutes):

```bash
docker-compose ps
```

3. **Verify observability stack**:

```bash
./scripts/observability/verify-observability.sh
```

Expected output:

```
=== SIEM-SOAR Observability Stack Verification ===
✓ siem-jaeger is running
✓ siem-prometheus is running
✓ siem-grafana is running
✓ Jaeger UI is accessible (http://localhost:16686)
✓ Prometheus UI is accessible (http://localhost:9090)
✓ Grafana UI is accessible (http://localhost:3001)
✓ Observability stack verification completed successfully!
```

### Troubleshooting Startup

If containers fail to start:

```bash
# Check container logs
docker-compose logs siem-jaeger
docker-compose logs siem-prometheus
docker-compose logs siem-grafana

# Verify network connectivity
docker network ls
docker inspect siem-network

# Restart services
docker-compose restart siem-jaeger siem-prometheus siem-grafana
```

---

## Accessing Dashboards

### Jaeger UI

Access distributed traces and service dependencies:

```
URL: http://localhost:16686
```

**Key Features**:

- **Service Search**: Select a service from dropdown to view its traces
- **Search**: Filter by time range, operation, tags, and duration
- **Service Graph**: Visualize service dependencies and error rates
- **Trace Details**: Examine individual spans with timing and errors

**Example Queries**:

```
Service: gateway
Operation: POST /alerts
Tags: http.status_code=500
Duration: >100ms
```

### Prometheus UI

Access metrics and run queries:

```
URL: http://localhost:9090
```

**Key Sections**:

- **Alerts**: View active alerts and their status
- **Targets**: See all monitored endpoints and their health
- **Graphs**: Run PromQL queries and visualize results
- **Status**: Configuration, flags, and build info

**Example Queries**:

```promql
# Service availability
rate(http_requests_total{status=~"2.."}[5m]) / rate(http_requests_total[5m])

# P99 latency
histogram_quantile(0.99, rate(http_duration_seconds_bucket[5m]))

# Alert processing rate
rate(alerts_processed_total[1m])
```

### Grafana UI

Access pre-built dashboards:

```
URL: http://localhost:3001
User: admin
Password: admin
```

**Step 1: Change Default Password**

1. Click user icon (top right)
2. Select "Change password"
3. Enter new password
4. Click "Change password"

**Step 2: Configure Data Source**

1. Go to Configuration → Data Sources
2. Click "Prometheus"
3. Verify URL: `http://siem-prometheus:9090`
4. Click "Save & Test"

**Step 3: Import Dashboards**

Pre-configured dashboards are provisioned automatically:

| Dashboard | Purpose |
|-----------|---------|
| SIEM-SOAR Overview | System-wide health and throughput |
| Service Health | Per-service metrics and errors |
| Data Pipeline | Event processing and latency |
| Detection Engine | Rule execution and alerts |
| SOAR Workflows | Temporal workflow metrics |
| Database Performance | ClickHouse and PostgreSQL metrics |
| Infrastructure | CPU, memory, disk utilization |

---

## Metrics Reference

### HTTP Service Metrics

All SIEM services expose Prometheus metrics on port `9090/metrics`:

#### Request Metrics

```promql
# Request rate (requests/second)
rate(http_requests_total[5m])

# Request latency (seconds)
histogram_quantile(0.95, http_duration_seconds_bucket)

# Status code distribution
http_requests_total by (status)

# Error rate
rate(http_requests_total{status=~"5.."}[5m])
```

#### Common Labels

- `service`: Service name (gateway, detection, soar, etc.)
- `method`: HTTP method (GET, POST, etc.)
- `path`: API path (e.g., /alerts, /detections)
- `status`: HTTP status code

### SIEM-Specific Metrics

#### Event Processing

```promql
# Events ingested per second
rate(events_ingested_total[1m])

# Alert generation rate
rate(alerts_generated_total[1m])

# Average event latency (ms)
avg(events_processing_latency_ms)

# Queue depth
kafka_consumer_lag_sum
```

#### Detection Engine

```promql
# Rule execution count
detection_rules_executed_total

# Detection latency
detection_processing_latency_seconds

# False positive rate
detection_false_positives_total / detection_alerts_total
```

#### SOAR Workflows

```promql
# Workflow execution count
temporal_workflow_execution_total

# Workflow latency
temporal_workflow_latency_seconds

# Failed workflows
temporal_workflow_failed_total
```

#### AI Services

```promql
# Model inference latency
ml_inference_latency_seconds

# Model accuracy
ml_model_accuracy

# Cache hit rate
ml_cache_hits_total / ml_cache_requests_total
```

### System Metrics

```promql
# Node memory usage
node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes

# Node CPU usage
rate(node_cpu_seconds_total[5m])

# Disk usage
node_filesystem_avail_bytes / node_filesystem_size_bytes

# Network I/O
rate(node_network_receive_bytes_total[5m])
```

---

## Tracing Guide

### Understanding Traces

A trace represents a complete request flow through your system:

```
Trace ID: 8448eb211c80319c

  Span 1: gateway.POST /alerts
  ├─ Start: 12:00:00.000
  ├─ End: 12:00:00.100
  ├─ Duration: 100ms
  └─ Spans: [detection-span, enrichment-span]

     Span 1.1: detection.CheckRules
     ├─ Start: 12:00:00.010
     ├─ End: 12:00:00.050
     └─ Duration: 40ms

     Span 1.2: enricher.EnrichAlert
     ├─ Start: 12:00:00.050
     ├─ End: 12:00:00.090
     └─ Duration: 40ms
```

### Viewing Traces in Jaeger

1. Open Jaeger UI: http://localhost:16686
2. Select Service: e.g., "gateway"
3. (Optional) Select Operation: e.g., "POST /alerts"
4. Set time range and click "Find Traces"
5. Click a trace to view details

### Analyzing Span Timing

**Critical Path**: The longest sequence of child spans

```
Total Time: 100ms
├─ gateway (100ms) ← Critical path
│  ├─ auth (10ms)
│  ├─ detection (40ms) ← Critical path
│  │  └─ rule_execution (35ms) ← Bottleneck
│  └─ enrichment (40ms)
```

### Adding Custom Spans

Services can add custom spans to trace important operations:

**Go Example**:

```go
import "go.opentelemetry.io/otel"

ctx, span := otel.Tracer("my-service").Start(ctx, "my-operation")
defer span.End()

span.AddEvent("processing_started")
span.SetAttributes(attribute.String("user_id", userID))

// Do work...

span.AddEvent("processing_complete")
```

**Python Example**:

```python
from opentelemetry import trace

tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("my_operation") as span:
    span.set_attribute("user_id", user_id)
    # Do work...
    span.add_event("processing_complete")
```

---

## Alerts Configuration

### Pre-configured Alert Rules

Alert rules are defined in Prometheus and evaluated continuously:

| Alert | Condition | Severity |
|-------|-----------|----------|
| ServiceDown | Service unavailable for 5 min | Critical |
| HighErrorRate | Error rate > 5% for 5 min | Warning |
| HighLatency | P99 latency > 2 sec for 10 min | Warning |
| QueueBacklog | Kafka queue depth > 50K | Warning |
| LowDiskSpace | Available disk < 10% | Warning |
| HighMemoryUsage | Memory usage > 90% | Warning |

### Viewing Active Alerts

**In Prometheus**:

1. Navigate to Alerts: http://localhost:9090/alerts
2. See active and inactive alerts
3. View rule definitions and evaluation times

**In Grafana**:

1. Go to Alerting → Alerts
2. See alert history and status
3. Configure notification channels

### Creating Custom Alerts

**Add to prometheus.yml**:

```yaml
groups:
  - name: siem-custom
    interval: 1m
    rules:
      # Alert when detection latency exceeds threshold
      - alert: DetectionLatencyHigh
        expr: |
          histogram_quantile(0.99,
            rate(detection_processing_latency_seconds_bucket[5m])
          ) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Detection latency is high ({{ $value }}s)"
          description: "99th percentile detection latency exceeds 1 second"
```

### Setting Notification Channels

Configure how alerts are sent:

1. In Grafana, go to Alerting → Notification Channels
2. Add channel (Email, Slack, PagerDuty, etc.)
3. In Alert Rule, select the notification channel
4. Test notification

**Example: Slack Integration**

```
1. Create Slack webhook: https://api.slack.com/incoming-webhooks
2. In Grafana: Add Notification Channel
3. Type: Slack
4. Webhook URL: <your-webhook-url>
5. Channel: #security-alerts
6. Username: SIEM-SOAR Bot
```

---

## Troubleshooting

### Jaeger Issues

#### Traces Not Appearing

**Problem**: Generated spans don't appear in Jaeger UI

**Solutions**:

1. **Verify service is sending traces**:

```bash
# Check service logs for OTLP errors
docker-compose logs siem-gateway | grep -i otel
docker-compose logs siem-detection | grep -i otel
```

2. **Verify OTLP endpoint is reachable**:

```bash
curl -v http://localhost:4318/v1/health
```

3. **Check service environment variables**:

```bash
docker-compose exec siem-gateway env | grep OTEL
```

Expected:
```
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_SERVICE_NAME=gateway
OTEL_TRACES_EXPORTER=otlp
```

4. **Verify Jaeger is running and healthy**:

```bash
docker-compose logs siem-jaeger
curl http://localhost:16686/api/services
```

#### High Memory Usage

**Problem**: Jaeger container consuming excessive memory

**Solutions**:

1. **Adjust sampling rate** in service config:

```yaml
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1  # Sample 10% of traces
```

2. **Increase Jaeger memory limit** in docker-compose.yml:

```yaml
jaeger:
  mem_limit: 2g  # Increase from default
```

### Prometheus Issues

#### No Metrics Data

**Problem**: Prometheus shows no data for queries

**Solutions**:

1. **Check scrape targets**:

```
Visit http://localhost:9090/targets
Verify all services show "UP"
```

2. **Verify service metrics endpoints**:

```bash
curl http://localhost:9090/metrics      # Prometheus itself
curl http://localhost:8888/metrics      # OTEL Collector
```

3. **Check Prometheus logs**:

```bash
docker-compose logs siem-prometheus | tail -50
```

4. **Verify prometheus.yml configuration**:

```bash
cat infra/monitoring/docker/prometheus.yml
```

#### High Disk Usage

**Problem**: Prometheus data consuming excessive disk space

**Solutions**:

1. **Reduce retention period** in docker-compose.yml:

```yaml
command:
  - '--storage.tsdb.retention.time=7d'  # Change from 15d
```

2. **Reduce scrape frequency**:

```yaml
global:
  scrape_interval: 30s  # Change from 15s
```

3. **Manual cleanup**:

```bash
# Backup existing data
docker-compose exec siem-prometheus tar czf /prometheus/backup.tar.gz /prometheus/wal

# Restart Prometheus (clears WAL)
docker-compose restart siem-prometheus
```

### Grafana Issues

#### Cannot Connect to Prometheus

**Problem**: Grafana shows "Error reading Prometheus"

**Solutions**:

1. **Verify data source URL**:

```
Configuration → Data Sources → Prometheus
URL should be: http://siem-prometheus:9090
(Not localhost)
```

2. **Check network connectivity**:

```bash
docker-compose exec siem-grafana curl http://siem-prometheus:9090
```

3. **Verify Prometheus is running**:

```bash
docker-compose ps | grep prometheus
docker-compose logs siem-prometheus
```

#### Default Password Not Working

**Problem**: Cannot login with admin:admin

**Solutions**:

1. **Reset admin password**:

```bash
docker-compose exec siem-grafana grafana-cli admin reset-admin-password newpassword
```

2. **Check environment variables**:

```bash
docker-compose logs siem-grafana | grep GF_SECURITY
```

### Network Issues

#### Services Cannot Reach Observability Stack

**Problem**: Services report connection errors to Jaeger/Prometheus

**Solutions**:

1. **Verify services are on same network**:

```bash
docker network inspect siem-network
```

All services should be listed.

2. **Check service connectivity from container**:

```bash
docker-compose exec siem-gateway ping siem-jaeger
docker-compose exec siem-gateway curl http://siem-jaeger:16686
```

3. **Verify DNS resolution**:

```bash
docker-compose exec siem-gateway nslookup siem-jaeger
```

---

## Best Practices

### Monitoring Best Practices

1. **Set Meaningful Alerts**
   - Alert on outcomes, not metrics
   - Alert on trends, not single spikes
   - Include runbook links in annotations

2. **Regular Dashboard Reviews**
   - Weekly review of dashboard performance
   - Identify and fix noisy alerts
   - Update dashboards as services evolve

3. **Trace Sampling**
   - Sample 100% of errors
   - Sample 10% of normal requests
   - Adjust based on volume

4. **Metric Retention**
   - Keep high-resolution data (15s intervals) for 2-3 days
   - Keep low-resolution data (1m intervals) for 2 weeks
   - Archive long-term data for compliance

### Performance Optimization

1. **Reduce Cardinality**
   - Avoid high-cardinality labels (user_id, request_id)
   - Use sampling for detailed information
   - Pre-aggregate when possible

2. **Efficient Queries**
   - Use rate() for counters
   - Use histogram_quantile() for latency
   - Avoid querying across long time ranges

3. **Storage Management**
   - Monitor disk usage weekly
   - Archive old data to S3/GCS
   - Clean up test data regularly

### Security

1. **Access Control**
   - Limit Grafana user access
   - Use RBAC for metrics access
   - Rotate default credentials

2. **Data Privacy**
   - Avoid logging sensitive data
   - Use span redaction for PII
   - Encrypt data in transit

3. **Infrastructure**
   - Keep Prometheus/Grafana behind firewall
   - Use VPN or auth proxy for remote access
   - Regularly update container images

---

## Advanced Topics

### Custom Exporters

Add metrics from external systems:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'splunk-metrics'
    scrape_interval: 1m
    metrics_path: '/api/metrics'
    static_configs:
      - targets: ['splunk-instance:8089']
    auth:
      basic:
        username: 'admin'
        password: 'password'
```

### Metric Relabeling

Transform metric labels:

```yaml
metric_relabel_configs:
  # Drop verbose metrics
  - source_labels: [__name__]
    regex: '.*_bucket|.*_count'
    action: drop

  # Rename labels
  - source_labels: [pod]
    target_label: kubernetes_pod
```

### Recording Rules

Pre-compute expensive queries:

```yaml
groups:
  - name: siem-recording
    interval: 15s
    rules:
      # Pre-compute error rate
      - record: 'service:error_rate:5m'
        expr: |
          rate(http_requests_total{status=~"5.."}[5m])
```

---

## References

- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)
- [OpenTelemetry](https://opentelemetry.io/)
- [PromQL Query Language](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

**Last Updated**: 2024
**Version**: 1.0.0
