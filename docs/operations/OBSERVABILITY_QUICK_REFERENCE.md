# Observability Quick Reference

Fast lookup guide for common observability tasks.

## Quick Links

| Resource | URL |
|----------|-----|
| Jaeger UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3001 (admin/admin) |
| Verification Script | `./scripts/observability/verify-observability.sh` |
| Complete Guide | `docs/operations/OBSERVABILITY_GUIDE.md` |
| Deployment Guide | `infra/monitoring/docker/README.md` |

## Common Commands

### Container Management

```bash
# Start observability stack
docker-compose up -d jaeger prometheus grafana otel-collector

# Stop services
docker-compose down

# View logs
docker-compose logs -f prometheus
docker-compose logs -f grafana
docker-compose logs -f jaeger

# Check status
docker-compose ps

# Restart specific service
docker-compose restart prometheus
```

### Verification

```bash
# Full verification
./scripts/observability/verify-observability.sh

# Quick health check
curl http://localhost:9090/-/healthy
curl http://localhost:16686/api/health
curl http://localhost:3001/api/health
```

### Prometheus Queries

```promql
# Current up status of all targets
up

# Request rate (requests/sec)
rate(http_requests_total[5m])

# Error rate (%)
(rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])) * 100

# P99 latency (seconds)
histogram_quantile(0.99, rate(http_duration_seconds_bucket[5m]))

# Service availability (%)
(rate(http_requests_total{status=~"2.."}[5m]) / rate(http_requests_total[5m])) * 100

# Active alerts
count(ALERTS{alertstate="firing"})

# Event processing rate
rate(events_ingested_total[1m])

# Kafka queue depth
kafka_consumer_lag_sum
```

## Common Issues & Solutions

### Service Won't Start

```bash
# Check error
docker-compose logs prometheus

# Common fixes
# 1. Port already in use
lsof -i :9090

# 2. Invalid config
docker run --rm -v $(pwd)/infra/monitoring/docker:/config \
  prom/prometheus:v2.48.0 \
  --config.file=/config/prometheus.yml --dry-run
```

### No Data in Prometheus

```bash
# Check targets
curl http://localhost:9090/api/v1/targets

# Test metrics endpoint
curl http://localhost:9090/metrics

# Check service is exposing metrics
docker-compose exec siem-gateway curl http://localhost:9090/metrics
```

### Grafana Can't Connect to Prometheus

```bash
# Check URL in Grafana
# Configuration > Data Sources > Prometheus
# URL should be: http://siem-prometheus:9090 (NOT localhost)

# Test from Grafana container
docker-compose exec siem-grafana curl http://siem-prometheus:9090
```

### No Traces in Jaeger

```bash
# Check OTEL endpoint reachable
curl http://localhost:4318/v1/health

# Verify service environment variables
docker-compose exec siem-gateway env | grep OTEL

# Check service logs for OTEL errors
docker-compose logs siem-gateway | grep -i otel
```

### High Memory Usage

```bash
# Reduce Prometheus retention
docker-compose exec siem-prometheus \
  prometheus --storage.tsdb.retention.time=7d

# Reduce scrape frequency (edit prometheus.yml)
# global:
#   scrape_interval: 30s  # Changed from 15s

docker-compose restart prometheus
```

## Alert Management

### View Active Alerts

**Prometheus**:
```
http://localhost:9090/alerts
```

**Grafana**:
```
Alerting > Alerts
```

### Common Alert Conditions

| Alert | PromQL Expression |
|-------|-------------------|
| Service Down | `up{job="siem-service"} == 0` |
| High Error Rate | `rate(http_requests_total{status=~"5.."}[5m]) > 0.05` |
| High Latency | `histogram_quantile(0.99, http_duration_seconds_bucket) > 1` |
| Disk Usage | `node_filesystem_avail_bytes / node_filesystem_size_bytes < 0.1` |
| Memory Usage | `node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.1` |

## Dashboard Navigation

### Grafana Dashboards

**SIEM-SOAR Overview**:
- System health and throughput
- Event processing rate
- Alert generation rate
- Error rates across services

**Service Health**:
- Per-service metrics
- Request rate and latency
- Error distribution
- Dependencies

**Data Pipeline**:
- Event ingestion rate
- Processing latency
- Queue depth
- Enrichment performance

**Detection Engine**:
- Rule execution count
- Detection latency
- Alert accuracy
- False positive rate

### Jaeger Service Graph

1. Open http://localhost:16686
2. Click "Service Graph" (in UI)
3. Explore service dependencies
4. Identify bottlenecks

### Prometheus Visualization

1. Open http://localhost:9090
2. Go to "Graph" tab
3. Enter PromQL query
4. Set time range and execute

## Performance Tuning

### Quick Optimizations

```bash
# Increase Prometheus memory limit
# Edit docker-compose.yml
prometheus:
  mem_limit: 4g

# Increase OTEL Collector concurrency
# Set GOGC environment variable
otel-collector:
  environment:
    - GOGC=80

# Reduce scrape frequency
# Edit prometheus.yml
global:
  scrape_interval: 30s
```

### Scaling Considerations

| Deployment Size | Prometheus Retention | Scrape Interval | Memory |
|-----------------|----------------------|-----------------|--------|
| Small (< 100 EPS) | 7 days | 30s | 1GB |
| Medium (100-1K EPS) | 15 days | 15s | 2GB |
| Large (> 1K EPS) | 30 days | 10s | 4GB |

## Backup & Restore

### Quick Backup

```bash
# Backup Prometheus data
docker run --rm \
  -v siem-soar-project_prometheus_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar czf /backup/prometheus-backup.tar.gz -C /data .

# Backup Grafana
docker run --rm \
  -v siem-soar-project_grafana_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar czf /backup/grafana-backup.tar.gz -C /data .
```

### Quick Restore

```bash
# Restore Prometheus
docker run --rm \
  -v siem-soar-project_prometheus_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar xzf /backup/prometheus-backup.tar.gz -C /data

docker-compose restart prometheus
```

## Configuration Cheat Sheet

### Enable Service Scraping

**prometheus.yml**:
```yaml
scrape_configs:
  - job_name: 'my-service'
    static_configs:
      - targets: ['my-service:9090']
    labels:
      group: 'my-group'
```

### Add Alert Rule

**prometheus.yml**:
```yaml
groups:
  - name: my-alerts
    rules:
      - alert: MyAlert
        expr: my_metric > 100
        for: 5m
        annotations:
          summary: "My alert triggered"
```

### Change Grafana Admin Password

```bash
docker-compose exec siem-grafana \
  grafana-cli admin reset-admin-password newpassword
```

### Provision Custom Dashboard

1. Create/export dashboard JSON
2. Place in `grafana/provisioning/dashboards/`
3. Restart Grafana: `docker-compose restart grafana`

## Monitoring Checklist

**Daily**:
- [ ] Check active alerts in Prometheus
- [ ] Review error rates in Grafana
- [ ] Verify service health

**Weekly**:
- [ ] Review trace patterns in Jaeger
- [ ] Check disk usage
- [ ] Review and acknowledge resolved alerts

**Monthly**:
- [ ] Review SLO compliance
- [ ] Update alert rules
- [ ] Backup data
- [ ] Performance optimization review

## Emergency Response

### Service Down

1. Check if container is running: `docker-compose ps`
2. Check logs: `docker-compose logs <service>`
3. Restart: `docker-compose restart <service>`
4. Verify: `./scripts/observability/verify-observability.sh`

### Disk Space Full

1. Check usage: `df -h`
2. Backup data: `docker run --rm -v siem_prometheus_data:/data -v $(pwd):/backup busybox tar czf /backup/backup.tar.gz -C /data .`
3. Clean up: `docker volume prune`
4. Restart services: `docker-compose restart`

### High Memory Usage

1. Identify service: `docker stats`
2. Reduce retention: Edit config
3. Restart service: `docker-compose restart <service>`
4. Monitor: `docker stats`

### Network Issues

1. Test connectivity: `docker-compose exec prometheus ping siem-jaeger`
2. Check network: `docker network inspect siem-network`
3. Verify DNS: `docker-compose exec prometheus nslookup siem-jaeger`
4. Restart network: `docker-compose down` and `docker-compose up -d`

## Useful Links

- [Prometheus Query Functions](https://prometheus.io/docs/prometheus/latest/querying/functions/)
- [PromQL Examples](https://prometheus.io/docs/prometheus/latest/querying/examples/)
- [Grafana Dashboard Variables](https://grafana.com/docs/grafana/latest/variables/)
- [Jaeger Best Practices](https://www.jaegertracing.io/docs/latest/best-practices/)
- [SIEM-SOAR Docs](../../docs/)

## Key Metrics to Monitor

### Availability
```
(rate(http_requests_total{status=~"2.."}[5m]) / rate(http_requests_total[5m])) * 100 > 99.5
```

### Performance
```
histogram_quantile(0.99, rate(http_duration_seconds_bucket[5m])) < 1
```

### Errors
```
(rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])) * 100 < 0.5
```

### Throughput
```
rate(events_ingested_total[1m]) > 100000
```

---

**Quick Reference v1.0**
**Last Updated**: February 2024
