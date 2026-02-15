# SIEM-SOAR Docker Build and Local Deployment Guide

## Overview

This guide explains how to build Docker images and deploy the SIEM-SOAR platform locally using Docker Compose.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 16GB+ RAM recommended
- 50GB+ disk space

## Quick Start

### 1. Build and Start All Services

```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Check service status
docker-compose ps
```

### 2. Stop All Services

```bash
docker-compose down

# Remove volumes as well
docker-compose down -v
```

## Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | React SOC Dashboard |
| API Gateway | http://localhost:8080 | Main API Endpoint |
| ML Gateway | http://localhost:8000 | AI/ML Services |
| ClickHouse HTTP | http://localhost:8123 | ClickHouse HTTP Interface |
| ClickHouse Native | localhost:9000 | ClickHouse Native Protocol |
| PostgreSQL | localhost:5432 | PostgreSQL Database |
| Redis | localhost:6379 | Redis Cache |
| Kafka | localhost:9092 | Kafka Broker |
| Temporal | localhost:7233 | Temporal Server |
| Syslog UDP | localhost:9514 | Syslog Collector (UDP) |
| Syslog TCP | localhost:9515 | Syslog Collector (TCP) |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| PostgreSQL | siem | siem_password |
| ClickHouse | siem | siem_password |
| Redis | - | siem_password |

## Individual Service Build

### Build Specific Service

```bash
# Build only gateway service
docker-compose build gateway

# Build without cache
docker-compose build --no-cache gateway
```

### Run Specific Service

```bash
# Start only infrastructure (databases, kafka, etc.)
docker-compose up -d clickhouse kafka redis postgres temporal

# Start specific Go service
docker-compose up -d gateway

# Start frontend
docker-compose up -d dashboard
```

## Architecture

### Service Dependencies

```
Frontend (Dashboard)
  ↓
API Gateway
  ↓
├─ Detection Engine → Kafka, ClickHouse
├─ SOAR Engine → PostgreSQL, Temporal, Kafka
├─ TI Service → PostgreSQL, Redis
├─ Query Service → ClickHouse
├─ Case Management → PostgreSQL
├─ Collector → Kafka
├─ Pipeline → Kafka, ClickHouse
└─ Parser → Kafka

ML Gateway → Kafka, Redis
```

## Build Details

### Frontend (Dashboard)

**Dockerfile**: `web/dashboard/Dockerfile`

- **Stage 1**: Build React app with Node.js 20
- **Stage 2**: Serve with Nginx Alpine
- **Port**: 80 (mapped to 3000)
- **Nginx Config**: Proxies `/api` to gateway service

### Go Services

**Pattern**: All Go services use multi-stage builds

- **Stage 1**: Build with `golang:1.23-alpine`
- **Stage 2**: Run with `gcr.io/distroless/static-debian12`
- **Build flags**: `-ldflags="-w -s"` (strip debug info)
- **Binary**: Statically linked (CGO_ENABLED=0)

**Build Context Issue**: The Dockerfiles reference `../../pkg` which needs to be copied from the monorepo root. The build context should be the project root for services that depend on shared packages.

### Python AI Service (ML Gateway)

**Dockerfile**: `ai/services/ml-gateway/Dockerfile`

- **Stage 1**: Install dependencies with Poetry
- **Stage 2**: Run with Python 3.11-slim
- **Port**: 8080 (mapped to 8000)
- **Includes**: ML models, uvicorn ASGI server

## Troubleshooting

### Build Issues

#### Go Service Build Fails

If you see errors like `COPY failed: file not found: /pkg`:

The existing Dockerfiles use an incorrect path for copying shared packages. You need to either:

**Option 1**: Build from project root context

```bash
# Example for gateway service
docker build -f services/gateway/Dockerfile -t siem-gateway .
```

**Option 2**: Update Dockerfile COPY paths (recommended for docker-compose)

Update each Go service Dockerfile to copy from the correct relative path when building from service directory.

#### Frontend Build Fails

Check Node.js version:
```bash
node --version  # Should be 18+
```

Clear npm cache:
```bash
cd web/dashboard
rm -rf node_modules dist
npm ci
```

### Runtime Issues

#### Service Can't Connect to Kafka

Wait for Kafka to be fully ready:
```bash
docker-compose logs kafka
# Wait for "Kafka Server started"
```

#### ClickHouse Connection Failed

Check ClickHouse is healthy:
```bash
docker-compose exec clickhouse clickhouse-client --query "SELECT 1"
```

#### High Memory Usage

Reduce Kafka and ClickHouse resources by editing `docker-compose.yml`:

```yaml
services:
  kafka:
    environment:
      KAFKA_HEAP_OPTS: "-Xmx512m -Xms512m"
```

## Health Checks

### Check All Service Health

```bash
# View all container status
docker-compose ps

# Check specific service logs
docker-compose logs -f gateway

# Execute health check manually
docker-compose exec dashboard wget -qO- http://localhost/health
```

### Service Health Endpoints

Most services expose `/health` or `/healthz` endpoints:

```bash
# Gateway
curl http://localhost:8080/health

# ML Gateway
curl http://localhost:8000/health

# Dashboard
curl http://localhost:3000/health
```

## Production Considerations

### Environment Variables

Create `.env` file for production:

```bash
# Database
POSTGRES_PASSWORD=<strong_password>
CLICKHOUSE_PASSWORD=<strong_password>
REDIS_PASSWORD=<strong_password>

# Kafka
KAFKA_CLUSTER_ID=<unique_cluster_id>

# Temporal
TEMPORAL_NAMESPACE=production
```

### Resource Limits

Add resource constraints to `docker-compose.yml`:

```yaml
services:
  gateway:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Persistent Volumes

Backup volumes regularly:

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U siem siem_soar > backup.sql

# Backup volumes
docker run --rm -v siem-soar-project_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data
```

## Development vs Production

### Development Mode

Use `docker-compose.dev.yml` for development with additional services:

```bash
docker-compose -f docker-compose.dev.yml up -d
```

This includes:
- Temporal UI (port 8088)
- Keycloak (port 8180)
- Prometheus (port 9090)
- Grafana (port 3030)
- MinIO (ports 9001-9002)

### Production Mode

Use `docker-compose.yml` for minimal production deployment:

```bash
docker-compose up -d
```

## Scaling Services

### Horizontal Scaling

Scale specific services:

```bash
# Scale detection engine to 3 instances
docker-compose up -d --scale detection=3

# Scale parser to 4 instances
docker-compose up -d --scale parser=4
```

### Load Balancing

For production, add a reverse proxy (nginx/traefik) in front of scaled services.

## Monitoring

### View Resource Usage

```bash
# Real-time stats
docker stats

# Specific service stats
docker stats siem-gateway siem-detection
```

### Log Aggregation

Collect logs from all services:

```bash
# Follow all logs
docker-compose logs -f

# Save logs to file
docker-compose logs > siem-logs.txt

# Filter by service
docker-compose logs -f gateway detection
```

## Cleanup

### Remove All Containers and Volumes

```bash
# Stop and remove containers
docker-compose down

# Remove all volumes (WARNING: deletes all data)
docker-compose down -v

# Remove unused images
docker image prune -a
```

### Selective Cleanup

```bash
# Remove only stopped containers
docker-compose rm

# Remove specific volume
docker volume rm siem-soar-project_kafka_data
```

## Next Steps

1. Access the dashboard: http://localhost:3000
2. Configure SIEM connectors via API Gateway
3. Start collecting logs via syslog (port 9514)
4. Create detection rules and playbooks
5. Monitor alerts and incidents

For detailed usage, see [User Guide](./docs/user/user_guide.md).
