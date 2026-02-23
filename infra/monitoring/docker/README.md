# SIEM-SOAR Monitoring Stack - Docker Deployment

Production-ready Docker-based monitoring and observability stack for SIEM-SOAR platform.

## Overview

This directory contains Docker Compose configurations and scripts for deploying the complete observability stack:

- **Jaeger**: Distributed tracing (traces, service graph)
- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **OpenTelemetry Collector**: Telemetry pipeline and processing

## Quick Start

### Start the Stack

```bash
cd /path/to/siem-soar-project
docker-compose up -d jaeger prometheus grafana otel-collector
```

### Verify Deployment

```bash
# Check container status
docker-compose ps

# Run verification script
./scripts/observability/verify-observability.sh

# View logs
docker-compose logs -f prometheus
docker-compose logs -f grafana
docker-compose logs -f jaeger
```

### Access Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Jaeger UI | http://localhost:16686 | No auth |
| Prometheus | http://localhost:9090 | No auth |
| Grafana | http://localhost:3001 | admin/admin |
| OTEL Collector | http://localhost:8888 | No auth |

## File Structure

```
infra/monitoring/
├── docker/
│   ├── README.md                      # This file
│   ├── docker-compose.yml             # Service definitions (in root)
│   ├── prometheus.yml                 # Prometheus configuration
│   ├── otel-collector-config.yaml     # OTEL Collector configuration
│   └── grafana/
│       ├── provisioning/
│       │   ├── datasources/           # Data source definitions
│       │   ├── dashboards/            # Dashboard JSON files
│       │   └── alert-rules/           # Alert rule definitions
│       └── dashboards/                # Pre-built dashboard JSONs
├── kubernetes/                        # Kubernetes Helm charts
├── terraform/                         # IaC for cloud deployment
└── alerts/                            # Prometheus alert rules
```

## Configuration

### Prometheus Configuration

**File**: `prometheus.yml`

**Key Sections**:

```yaml
global:
  scrape_interval: 15s         # How often to scrape metrics
  evaluation_interval: 15s      # How often to evaluate rules
  external_labels:
    cluster: 'siem-soar'       # Custom label for all metrics

scrape_configs:
  # Services to monitor
  - job_name: 'siem-go-services'
    static_configs:
      - targets:
          - 'gateway:9090'
          - 'detection:9090'
          - 'soar:9090'
          # ... more services
    labels:
      group: 'go-services'
```

**Customizing**:

To add new services or change scrape intervals:

```yaml
# Add new service
- job_name: 'my-new-service'
  scrape_interval: 30s
  static_configs:
    - targets: ['my-service:9090']
```

Restart Prometheus:

```bash
docker-compose restart prometheus
```

### OpenTelemetry Collector Configuration

**File**: `otel-collector-config.yaml`

**Key Sections**:

```yaml
receivers:
  otlp:                              # OTLP protocol receivers
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317       # gRPC receiver
      http:
        endpoint: 0.0.0.0:4318       # HTTP receiver

processors:
  batch:                             # Batch processing
    send_batch_size: 100
    timeout: 10s

  attributes:                        # Add/modify attributes
    actions:
      - key: environment
        value: production
        action: insert

exporters:
  jaeger:                            # Send traces to Jaeger
    endpoint: jaeger:14250

  prometheus:                        # Export metrics as Prometheus format
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch, attributes]
      exporters: [jaeger]

    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus]
```

**Customizing**:

To add processors or change batch size:

```yaml
processors:
  batch:
    send_batch_size: 200           # Process larger batches
    timeout: 5s                    # Send faster

  span:                            # Add span processing
    name:
      to_attributes:
        rules:
          - ^/users/.*/?$
```

### Grafana Configuration

**Data Sources**: Located in `grafana/provisioning/datasources/`

**Dashboards**: Located in `grafana/provisioning/dashboards/`

**Default Configuration**:

```yaml
# grafana/provisioning/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://siem-prometheus:9090
    isDefault: true
    editable: true
```

**Adding New Data Sources**:

1. Create YAML file in `grafana/provisioning/datasources/`
2. Define datasource configuration
3. Restart Grafana:

```bash
docker-compose restart grafana
```

## Environment Variables

### Prometheus Environment

Set in `docker-compose.yml`:

```yaml
services:
  prometheus:
    environment:
      - PROMETHEUS_HOME=/prometheus
```

### Grafana Environment

```yaml
services:
  grafana:
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_LOG_LEVEL=info
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
```

**Common Variables**:

| Variable | Purpose | Default |
|----------|---------|---------|
| `GF_SECURITY_ADMIN_USER` | Admin username | admin |
| `GF_SECURITY_ADMIN_PASSWORD` | Admin password | admin |
| `GF_USERS_ALLOW_SIGN_UP` | Allow sign-ups | false |
| `GF_LOG_LEVEL` | Log level | info |
| `GF_INSTALL_PLUGINS` | Plugins to install | (empty) |

### Jaeger Environment

```yaml
services:
  jaeger:
    environment:
      - COLLECTOR_OTLP_ENABLED=true
      - COLLECTOR_ZIPKIN_ENABLED=false
      - MEMORY_MAX_TRACES=10000
```

### OTEL Collector Environment

```yaml
services:
  otel-collector:
    environment:
      - GOGC=80
```

## Customization

### Adding Custom Dashboards

1. **Option A: Export from Grafana UI**

   - Create dashboard in Grafana UI
   - Click Dashboard Settings → JSON Model
   - Copy JSON to `grafana/dashboards/custom-dashboard.json`

2. **Option B: Create from Template**

   ```bash
   cp grafana/dashboards/template.json grafana/dashboards/my-dashboard.json
   # Edit my-dashboard.json with your configuration
   ```

3. **Provision Dashboard**

   - Place JSON file in `grafana/provisioning/dashboards/`
   - Restart Grafana:

   ```bash
   docker-compose restart grafana
   ```

### Adding Custom Alert Rules

1. **Create Alert Rule File**

   ```yaml
   # infra/monitoring/alerts/custom-alerts.yml
   groups:
     - name: siem-custom
       interval: 1m
       rules:
         - alert: CustomAlert
           expr: |
             rate(custom_metric_total[5m]) > 100
           for: 5m
           labels:
             severity: warning
           annotations:
             summary: "Custom metric exceeded threshold"
   ```

2. **Add to prometheus.yml**

   ```yaml
   rule_files:
     - /etc/prometheus/custom-alerts.yml
   ```

3. **Restart Prometheus**

   ```bash
   docker-compose restart prometheus
   ```

### Scaling Prometheus

For high-volume deployments:

1. **Increase Memory**:

   ```yaml
   prometheus:
     mem_limit: 4g
   ```

2. **Adjust Retention**:

   ```yaml
   command:
     - '--storage.tsdb.retention.time=30d'
   ```

3. **Use Remote Storage**:

   ```yaml
   command:
     - '--storage.remote.write-url=http://remote-storage:9009/write'
   ```

### Enabling Authentication

**Prometheus with OAuth Proxy**:

```yaml
prometheus-oauth:
  image: oauth2-proxy/oauth2-proxy:latest
  ports:
    - "8080:8080"
  environment:
    - OAUTH2_PROXY_PROVIDER=oidc
    - OAUTH2_PROXY_CLIENT_ID=your-client-id
    - OAUTH2_PROXY_CLIENT_SECRET=your-secret
    - OAUTH2_PROXY_OIDC_ISSUER_URL=your-issuer
  command:
    - --upstream=http://prometheus:9090
```

**Grafana with LDAP/SAML**:

```yaml
# grafana/provisioning/ldap.toml
[[servers]]
host = "ldap.example.com"
port = 389
bind_dn = "cn=admin,dc=example,dc=com"
bind_password = "password"
search_filter = "(uid=%s)"
```

## Backup and Recovery

### Backup Prometheus Data

```bash
# Create backup directory
mkdir -p backups

# Backup Prometheus data
docker run --rm \
  -v siem-soar-project_prometheus_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar czf /backup/prometheus-backup.tar.gz -C /data .

# Backup size check
du -sh backups/prometheus-backup.tar.gz
```

### Backup Grafana Configuration

```bash
# Backup Grafana database
docker run --rm \
  -v siem-soar-project_grafana_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar czf /backup/grafana-backup.tar.gz -C /data .

# Backup provisioning configs
tar czf backups/grafana-provisioning-backup.tar.gz infra/monitoring/docker/grafana/provisioning/
```

### Restore Data

```bash
# Restore Prometheus data
docker run --rm \
  -v siem-soar-project_prometheus_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar xzf /backup/prometheus-backup.tar.gz -C /data

# Restore Grafana
docker run --rm \
  -v siem-soar-project_grafana_data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar xzf /backup/grafana-backup.tar.gz -C /data

# Restart services
docker-compose restart prometheus grafana
```

## Performance Tuning

### Prometheus Optimization

```yaml
prometheus:
  command:
    # Increase block size for better performance
    - '--storage.tsdb.max-block-duration=2h'
    # Increase allowed concurrency
    - '--query.max-concurrency=10'
    # Reduce chunk size
    - '--storage.tsdb.max-chunk-bytes=10485760'
```

### Grafana Optimization

```yaml
grafana:
  environment:
    # Increase max data points
    - GF_PANEL_MAX_DATA_POINTS=5000
    # Enable data source caching
    - GF_DATASOURCE_CACHE_ENABLED=true
    # Increase query timeout
    - GF_DEFAULT_DASHBOARD_REFRESH=30s
```

### OTEL Collector Optimization

```yaml
otel-collector:
  command:
    - "--config=/etc/otel-collector-config.yaml"
  environment:
    - GOGC=80  # Increase GC threshold for better performance
    - GOMAXPROCS=4
```

## Logging

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f prometheus
docker-compose logs -f grafana
docker-compose logs -f jaeger

# Last 100 lines
docker-compose logs --tail=100 prometheus

# With timestamps
docker-compose logs -f --timestamps prometheus
```

### Log Rotation

Configure Docker daemon to rotate logs:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  }
}
```

## Troubleshooting

### Services Won't Start

```bash
# Check error messages
docker-compose logs prometheus

# Common issues:
# 1. Port already in use
lsof -i :9090

# 2. Invalid configuration
docker run --rm -v $(pwd)/infra/monitoring/docker:/config \
  prom/prometheus:v2.48.0 --config.file=/config/prometheus.yml --dry-run

# 3. Permission issues
sudo chown -R 65534:65534 /var/lib/docker/volumes/siem-soar-project_prometheus_data
```

### High Resource Usage

```bash
# Check container resource usage
docker stats

# Reduce Prometheus retention
docker-compose exec prometheus \
  prometheus --storage.tsdb.retention.time=7d

# Reduce scrape frequency
# Edit prometheus.yml, change scrape_interval to 30s or 60s
```

### Network Issues

```bash
# Check network connectivity
docker-compose exec prometheus curl http://siem-service:9090

# Check DNS resolution
docker-compose exec prometheus nslookup siem-service

# Inspect network
docker network inspect siem-network
```

## Monitoring the Monitoring Stack

Self-monitoring queries for Prometheus health:

```promql
# Prometheus uptime
up{job="prometheus"}

# Scrape duration
scrape_duration_seconds

# Samples scraped per interval
scrape_samples_scraped

# Prometheus disk usage
prometheus_tsdb_symbol_table_size_bytes
prometheus_tsdb_wal_segment_total
```

## References

- [Prometheus Docker Image](https://hub.docker.com/r/prom/prometheus)
- [Grafana Docker Image](https://hub.docker.com/r/grafana/grafana)
- [Jaeger Docker Image](https://hub.docker.com/r/jaegertracing/all-in-one)
- [OTEL Collector Docker Image](https://hub.docker.com/r/otel/opentelemetry-collector-contrib)
- [SIEM-SOAR Documentation](../../docs/operations/OBSERVABILITY_GUIDE.md)

## Support

For issues or questions:

1. Check logs: `docker-compose logs <service>`
2. Run verification: `./scripts/observability/verify-observability.sh`
3. See OBSERVABILITY_GUIDE.md for detailed troubleshooting
4. Check service health endpoints

## License

See LICENSE file in project root

---

**Version**: 1.0.0
**Last Updated**: 2024
**Maintainer**: SIEM-SOAR Team
