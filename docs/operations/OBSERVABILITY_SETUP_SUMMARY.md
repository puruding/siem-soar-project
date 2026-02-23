# Observability Phase E - Setup Summary

Complete Phase E documentation: Verification scripts and operational guides for the SIEM-SOAR observability stack.

## Deliverables

### 1. Verification Script

**File**: `scripts/observability/verify-observability.sh`

**Purpose**: End-to-end verification of the observability stack

**Features**:
- Docker container health checks
- Port connectivity verification
- HTTP endpoint availability
- Service metrics endpoint verification
- Prometheus target status
- OTLP connectivity testing
- Sample trace generation and validation
- Configuration file verification
- Environment variable checks

**Usage**:

```bash
chmod +x scripts/observability/verify-observability.sh
./scripts/observability/verify-observability.sh
```

**Expected Output**:

```
=== SIEM-SOAR Observability Stack Verification ===

=== Step 1: Verifying Docker Containers ===
✓ Container siem-jaeger is running
✓ Container siem-prometheus is running
✓ Container siem-grafana is running
✓ Container siem-otel-collector is running

=== Step 2: Checking Port Connectivity ===
✓ Jaeger UI is listening on localhost:16686
✓ Jaeger OTLP gRPC is listening on localhost:4317
...

=== Verification Summary ===
Passed: 45
Warnings: 2
Failed: 0

✓ Observability stack verification completed successfully!
```

**Configuration**:

The script supports environment variable overrides:

```bash
JAEGER_URL=http://jaeger.example.com:16686 \
PROMETHEUS_URL=http://prometheus.example.com:9090 \
GRAFANA_URL=http://grafana.example.com:3001 \
./scripts/observability/verify-observability.sh
```

### 2. Observability Guide

**File**: `docs/operations/OBSERVABILITY_GUIDE.md`

**Purpose**: Comprehensive operational guide for the observability stack

**Sections**:

1. **Overview** - Key metrics and service level objectives
2. **Architecture** - Data flow and component relationships
3. **Components** - Detailed description of each service
   - Jaeger (distributed tracing)
   - Prometheus (metrics)
   - Grafana (visualization)
   - OpenTelemetry Collector
4. **Getting Started** - Quick setup and verification
5. **Accessing Dashboards** - How to use each UI
6. **Metrics Reference** - Comprehensive PromQL examples
   - HTTP service metrics
   - SIEM-specific metrics
   - System metrics
7. **Tracing Guide** - How to use Jaeger effectively
8. **Alerts Configuration** - Alert setup and management
9. **Troubleshooting** - Common issues and solutions
10. **Best Practices** - Optimization and security

**Key Content**:

- **SLOs**: Availability, latency, error rate targets
- **PromQL Examples**: 50+ query examples for common monitoring tasks
- **Trace Analysis**: Understanding spans and critical paths
- **Alert Rules**: Pre-configured alert definitions
- **Runbooks**: Step-by-step troubleshooting procedures

### 3. Monitoring Stack README

**File**: `infra/monitoring/docker/README.md`

**Purpose**: Technical guide for deploying and customizing the monitoring stack

**Sections**:

1. **Quick Start** - Fast setup (5 minutes)
2. **File Structure** - Directory organization
3. **Configuration**
   - Prometheus configuration
   - OTEL Collector setup
   - Grafana configuration
   - Environment variables
4. **Customization**
   - Adding dashboards
   - Creating alert rules
   - Enabling authentication
   - Scaling Prometheus
5. **Backup and Recovery** - Data protection procedures
6. **Performance Tuning** - Optimization techniques
7. **Logging** - Log management
8. **Troubleshooting** - Common issues
9. **Self-Monitoring** - Monitoring the monitoring stack

**Key Features**:

- Production-ready configurations
- Scaling guidance for high-volume deployments
- Security hardening options
- Backup/restore procedures

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│          SIEM-SOAR Services (13)            │
│  Gateway | Detection | SOAR | Query | etc.  │
│     All with OTEL SDK integrated            │
└──────────────┬──────────────────────────────┘
               │ Traces (OTLP gRPC/HTTP)
               │ Metrics (Prometheus format)
        ┌──────┴──────┐
        │             │
   ┌────▼────┐   ┌────▼────┐
   │  Jaeger  │   │OpenTel   │
   │  1.53    │   │Collector │
   │ Tracing  │   │ 0.91.0   │
   └────┬─────┘   └────┬─────┘
        │              │
        │         ┌────▼──────────┐
        │         │                │
   ┌────▼──────┐  │  ┌─────────┐   │
   │Admin UI   │  │  │Prometheus│  │
   │:16686     │  │  │2.48.0    │  │
   │Traces     │  │  │:9090     │  │
   │Service    │  │  │TSDB      │  │
   │Graph      │  │  └────┬─────┘  │
   │           │  │       │        │
   └───────────┘  │  ┌────▼──────┐│
                  │  │ Grafana    ││
                  │  │ 10.2.0     ││
                  │  │ :3001      ││
                  │  │ Dashboards ││
                  │  │ Alerts     ││
                  │  └────────────┘│
                  │                │
                  └────────────────┘
```

## Usage Flow

### Step 1: Start Services

```bash
docker-compose up -d
```

Wait 2-3 minutes for all services to be healthy.

### Step 2: Verify Deployment

```bash
./scripts/observability/verify-observability.sh
```

Expected: All checks pass with 0 failures.

### Step 3: Access Dashboards

| Dashboard | URL | Purpose |
|-----------|-----|---------|
| Jaeger | http://localhost:16686 | Trace analysis, service graph |
| Prometheus | http://localhost:9090 | Metric queries, alerts |
| Grafana | http://localhost:3001 | Visualization, dashboards |

### Step 4: Monitor Services

- Go to Grafana at http://localhost:3001
- Click on "Dashboards" → "Browse"
- Select "SIEM-SOAR Overview" dashboard
- Monitor key metrics in real-time

### Step 5: Configure Alerts (Optional)

- Edit `prometheus.yml` to add alert rules
- Restart Prometheus: `docker-compose restart prometheus`
- Configure notification channels in Grafana

### Step 6: Troubleshoot Issues

- Verify with: `./scripts/observability/verify-observability.sh`
- Check logs: `docker-compose logs <service-name>`
- See TROUBLESHOOTING section in OBSERVABILITY_GUIDE.md

## Metrics & SLOs

### Key Metrics Tracked

| Metric | Query | Alert Threshold |
|--------|-------|-----------------|
| Service Availability | `rate(http_requests_total{status=~"2.."}[5m])` | < 99.5% |
| P99 Latency | `histogram_quantile(0.99, http_duration_seconds_bucket)` | > 1 sec |
| Error Rate | `rate(http_requests_total{status=~"5.."}[5m])` | > 0.5% |
| Alert Processing | `rate(alerts_processed_total[1m])` | < 100 alerts/sec |
| Event Throughput | `rate(events_ingested_total[1m])` | < 100K EPS |

### Alert Rules (Pre-configured)

- ServiceDown: Service unavailable for 5 minutes
- HighErrorRate: Error rate > 5% for 5 minutes
- HighLatency: P99 latency > 2 seconds
- QueueBacklog: Kafka queue > 50K messages
- LowDiskSpace: Available disk < 10%
- HighMemoryUsage: Memory > 90%

## Configuration Files

### Key Configuration Locations

```
infra/monitoring/docker/
├── prometheus.yml              # Metrics scraping config
├── otel-collector-config.yaml  # Trace collection config
└── grafana/
    ├── provisioning/
    │   ├── datasources/        # Data source definitions
    │   ├── dashboards/         # Dashboard provisioning
    │   └── alert-rules/        # Alert rule definitions
    └── dashboards/             # Dashboard JSON files
```

### Quick Configuration Changes

**Change Prometheus scrape interval**:
```yaml
# prometheus.yml
global:
  scrape_interval: 30s  # Changed from 15s
```

**Add new service to monitor**:
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'my-new-service'
    static_configs:
      - targets: ['my-service:9090']
```

**Change Grafana admin password**:
```bash
docker-compose exec siem-grafana \
  grafana-cli admin reset-admin-password newpassword
```

## Troubleshooting Checklist

```
□ Verify containers are running: docker-compose ps
□ Run verification script: ./scripts/observability/verify-observability.sh
□ Check service logs: docker-compose logs <service>
□ Verify network: docker network inspect siem-network
□ Test port connectivity: curl http://localhost:9090
□ Check metrics endpoint: curl http://localhost:9090/metrics
□ See OBSERVABILITY_GUIDE.md for detailed troubleshooting
```

## Next Steps

1. **Configure Alerts** - Add notification channels (Slack, email, PagerDuty)
2. **Create Custom Dashboards** - Build dashboards for your SOC team
3. **Set Up Logging** - Integrate log aggregation (ELK, Splunk)
4. **Enable Authentication** - Add OAuth/LDAP to Grafana
5. **Set Up Backup** - Automated backup of Prometheus and Grafana data
6. **Scaling** - Configure remote storage for long-term data retention

## References

- [OBSERVABILITY_GUIDE.md](./OBSERVABILITY_GUIDE.md) - Complete operational guide
- [infra/monitoring/docker/README.md](../../infra/monitoring/docker/README.md) - Deployment guide
- [docker-compose.yml](../../docker-compose.yml) - Service configurations
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry](https://opentelemetry.io/)

## Version Information

| Component | Version | Image |
|-----------|---------|-------|
| Jaeger | 1.53 | jaegertracing/all-in-one:1.53 |
| Prometheus | 2.48.0 | prom/prometheus:v2.48.0 |
| Grafana | 10.2.0 | grafana/grafana:10.2.0 |
| OTEL Collector | 0.91.0 | otel/opentelemetry-collector-contrib:0.91.0 |

## Support

For issues:

1. Check logs: `docker-compose logs <service>`
2. Run verification: `./scripts/observability/verify-observability.sh`
3. Consult OBSERVABILITY_GUIDE.md troubleshooting section
4. Review service health endpoints

---

**Phase E Status**: Complete
**Date**: February 2024
**Verified**: Yes
**Production Ready**: Yes
