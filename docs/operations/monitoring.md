# SIEM/SOAR Platform Monitoring Guide

## Overview

This guide covers monitoring, alerting, and observability for the SIEM/SOAR platform. The monitoring stack uses Prometheus, Grafana, and Loki for comprehensive observability.

## Monitoring Stack

### Components
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **Loki**: Log aggregation
- **Alertmanager**: Alert routing and notification
- **Jaeger/Tempo**: Distributed tracing

## Key Metrics

### System Health Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `up` | Service availability | == 0 for 1m |
| `http_requests_total` | Total HTTP requests | N/A |
| `http_request_duration_seconds` | Request latency | p95 > 500ms |
| `http_requests_failed_total` | Failed requests | Error rate > 1% |

### Event Processing Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `events_ingested_total` | Total events ingested | N/A |
| `events_per_second` | Event ingestion rate | < 1000 EPS (warning) |
| `event_processing_latency_ms` | Processing latency | p99 > 100ms |
| `event_processing_errors_total` | Processing errors | Error rate > 0.1% |

### Detection Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `rules_executed_total` | Rules executed | N/A |
| `rule_execution_duration_ms` | Rule execution time | p95 > 1000ms |
| `alerts_generated_total` | Alerts generated | N/A |
| `false_positive_rate` | FP rate | > 10% |

### SOAR Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `playbook_executions_total` | Total executions | N/A |
| `playbook_execution_duration_s` | Execution time | > 5m |
| `playbook_success_rate` | Success rate | < 95% |
| `action_failures_total` | Failed actions | > 5 per hour |

## Grafana Dashboards

### Platform Overview Dashboard
```
Dashboard ID: siem-overview
Panels:
- Service Health Status
- Events Per Second
- Alert Generation Rate
- Active Cases
- Resource Utilization
```

### Event Processing Dashboard
```
Dashboard ID: siem-events
Panels:
- Ingestion Rate (time series)
- Processing Latency (histogram)
- Events by Type (pie chart)
- Error Rate (time series)
- Queue Depth (gauge)
```

### Detection Dashboard
```
Dashboard ID: siem-detection
Panels:
- Rules by Severity
- Alert Generation Rate
- Top Triggering Rules
- Detection Latency
- False Positive Tracking
```

### SOAR Dashboard
```
Dashboard ID: siem-soar
Panels:
- Active Executions
- Execution Success Rate
- Average Resolution Time
- Action Performance
- Connector Status
```

## Alerting Rules

### Critical Alerts

```yaml
# prometheus-alerts.yaml
groups:
  - name: siem-critical
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.job }} is down"

      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_failed_total[5m])) /
          sum(rate(http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Error rate exceeds 5%"

      - alert: EventIngestionStopped
        expr: rate(events_ingested_total[5m]) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "No events ingested in 5 minutes"
```

### Warning Alerts

```yaml
groups:
  - name: siem-warnings
    rules:
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "P95 latency exceeds 500ms"

      - alert: LowEventRate
        expr: rate(events_ingested_total[5m]) < 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Event ingestion rate below 1000 EPS"

      - alert: PlaybookFailures
        expr: |
          sum(rate(playbook_failures_total[1h])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Multiple playbook failures"
```

## Log Aggregation

### Loki Configuration

```yaml
# loki-config.yaml
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  chunk_idle_period: 5m
  chunk_retain_period: 30s

schema_config:
  configs:
    - from: 2024-01-01
      store: boltdb-shipper
      object_store: s3
      schema: v11
      index:
        prefix: loki_index_
        period: 24h
```

### Log Queries

```logql
# Error logs from gateway
{namespace="siem-production", app="gateway"} |= "error"

# Slow queries (>1s)
{namespace="siem-production", app="query-service"}
  | json
  | duration_ms > 1000

# Failed playbook executions
{namespace="siem-production", app="soar"}
  | json
  | status="failed"

# Authentication failures
{namespace="siem-production"}
  |~ "authentication|auth"
  |= "failed"
```

## Distributed Tracing

### Trace Configuration

```yaml
# Jaeger sampling configuration
sampler:
  type: probabilistic
  param: 0.1  # Sample 10% of traces

# Production: Use adaptive sampling
sampler:
  type: adaptive
  param: 2  # Target 2 traces per second
```

### Key Traces to Monitor

1. **Event Ingestion Flow**
   - Collector → Pipeline → ClickHouse
   - Expected duration: < 100ms

2. **Alert Generation Flow**
   - Event → Detection → Alert Creation → Notification
   - Expected duration: < 500ms

3. **Playbook Execution Flow**
   - Trigger → Steps → Actions → Completion
   - Variable duration based on actions

## Health Checks

### Endpoint Health

```bash
# Gateway health
curl -s http://gateway:8080/health | jq

# All services health
for svc in gateway detection soar query pipeline; do
  echo "=== $svc ==="
  curl -s "http://$svc/health" | jq
done
```

### Database Health

```sql
-- ClickHouse health
SELECT 1;

-- Table sizes
SELECT
    database,
    table,
    formatReadableSize(sum(bytes_on_disk)) as size
FROM system.parts
WHERE active
GROUP BY database, table
ORDER BY sum(bytes_on_disk) DESC;

-- Query performance
SELECT
    query,
    query_duration_ms,
    read_rows,
    result_rows
FROM system.query_log
WHERE event_date = today()
ORDER BY query_duration_ms DESC
LIMIT 10;
```

## Performance Tuning

### Prometheus Tuning

```yaml
# Increase retention for production
storage:
  tsdb:
    retention.time: 30d
    retention.size: 100GB

# Remote write for long-term storage
remote_write:
  - url: https://cortex.example.com/api/v1/push
```

### Query Optimization

- Use recording rules for frequently computed metrics
- Pre-aggregate high-cardinality metrics
- Set appropriate scrape intervals (15s for critical, 60s for standard)

## Runbooks

### High Error Rate
1. Check service logs for error patterns
2. Verify external dependencies (DB, Kafka)
3. Check recent deployments
4. Scale if resource constrained

### Event Ingestion Issues
1. Check Kafka consumer lag
2. Verify pipeline health
3. Check ClickHouse disk space
4. Review collector logs

### Playbook Failures
1. Check connector status
2. Review failed action logs
3. Verify credentials
4. Check rate limits on external APIs
