# Docker Deployment Guide

Complete guide for deploying the SIEM-SOAR platform using Docker and Docker Compose.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Service Details](#service-details)
5. [Configuration](#configuration)
6. [Building Images](#building-images)
7. [Deployment](#deployment)
8. [Monitoring](#monitoring)
9. [Troubleshooting](#troubleshooting)
10. [Production Considerations](#production-considerations)

## Prerequisites

### Software Requirements

- **Docker**: 20.10 or higher
- **Docker Compose**: 2.0 or higher
- **Git**: For cloning the repository

### Hardware Requirements

#### Minimum (Development)
- **CPU**: 4 cores
- **RAM**: 8GB
- **Disk**: 30GB

#### Recommended (Production)
- **CPU**: 16+ cores
- **RAM**: 64GB+
- **Disk**: 500GB+ (SSD recommended)

### OS Support

- Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- macOS 11+ with Docker Desktop
- Windows 10+ with WSL2 and Docker Desktop

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/your-org/siem-soar-project.git
cd siem-soar-project
```

### 2. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration (optional for development)
nano .env
```

### 3. Start Services

```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f
```

### 4. Verify Deployment

```bash
# Check service status
docker-compose ps

# Access dashboard
# Open http://localhost:3000 in your browser
```

## Architecture

### Container Network

```
┌─────────────────────────────────────────────────────────────┐
│                      siem-network (Bridge)                  │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  Dashboard   │───▶│   Gateway    │───▶│  Detection   │ │
│  │  (nginx:80)  │    │   (Go:8080)  │    │  (Go:8081)   │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│                              │                              │
│                              ▼                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  ClickHouse  │◀───│   Pipeline   │◀───│  Collector   │ │
│  │ (9000,8123)  │    │   (Go)       │    │  (9514,9515) │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │  PostgreSQL  │◀───│    SOAR      │◀───│   Temporal   │ │
│  │   (5432)     │    │  (Go:8082)   │    │   (7233)     │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│  │    Kafka     │◀───│   Parser     │    │  ML Gateway  │ │
│  │   (9092)     │    │   (Go)       │    │  (Py:8000)   │ │
│  └──────────────┘    └──────────────┘    └──────────────┘ │
│                                                             │
│  ┌──────────────┐                                          │
│  │    Redis     │                                          │
│  │   (6379)     │                                          │
│  └──────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Log Sources → Collector → Kafka (raw-logs) → Parser → Kafka (parsed-events)
                                               ↓
                                          Normalizer → Kafka (normalized-events)
                                                          ↓
                                                     Enricher → Kafka (enriched-events)
                                                                   ↓
                                      Detection Engine → Kafka (alerts) → SOAR
                                                ↓                            ↓
                                          ClickHouse                   PostgreSQL
```

## Service Details

### Infrastructure Services

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| **ClickHouse** | clickhouse/clickhouse-server:24.1 | 8123, 9000 | Event storage (OLAP) |
| **PostgreSQL** | postgres:16-alpine | 5432 | Metadata storage (OLTP) |
| **Redis** | redis:7-alpine | 6379 | Caching and session store |
| **Kafka** | confluentinc/cp-kafka:7.5.0 | 9092 | Event streaming |
| **Temporal** | temporalio/auto-setup:latest | 7233 | Workflow engine |

### Application Services (Go)

| Service | Port | Description |
|---------|------|-------------|
| **gateway** | 8080 | API Gateway, authentication, rate limiting |
| **detection** | 8081 | Detection engine with Sigma rules |
| **soar** | 8082 | SOAR engine with Temporal workflows |
| **ti** | 8085 | Threat Intelligence (MISP, STIX/TAXII) |
| **query** | 8083 | Query service for ClickHouse |
| **case** | 8084 | Case management |
| **collector** | 9514/UDP, 9515/TCP | Log collection (Syslog, HTTP) |
| **pipeline** | - | Data pipeline orchestration |
| **parser** | - | Log parsing (Grok, CEF, LEEF) |

### AI Services (Python)

| Service | Port | Description |
|---------|------|-------------|
| **ml-gateway** | 8000 | ML models for triage, classification |

### Frontend

| Service | Port | Description |
|---------|------|-------------|
| **dashboard** | 3000 (→80) | React SOC Dashboard with Nginx |

## Configuration

### Environment Variables

Edit `.env` file to customize:

```bash
# Database credentials
POSTGRES_PASSWORD=your_secure_password
CLICKHOUSE_PASSWORD=your_secure_password
REDIS_PASSWORD=your_secure_password

# Kafka settings
KAFKA_BROKERS=kafka:9092

# API Gateway
GATEWAY_JWT_SECRET=your_jwt_secret
GATEWAY_CORS_ORIGINS=http://localhost:3000

# Feature flags
ENABLE_ML_TRIAGE=true
ENABLE_AUTO_RESPONSE=false
```

### Volume Mounts

Persistent data is stored in named volumes:

```yaml
volumes:
  clickhouse_data:     # ClickHouse database
  postgres_data:       # PostgreSQL database
  redis_data:          # Redis persistence
  kafka_data:          # Kafka logs
  clickhouse_logs:     # ClickHouse logs
```

### Custom Configuration Files

Override default configs by mounting files:

```yaml
# Example: Custom ClickHouse config
services:
  clickhouse:
    volumes:
      - ./config/clickhouse/config.xml:/etc/clickhouse-server/config.d/custom.xml:ro
```

## Building Images

### Using Docker Compose

```bash
# Build all services
docker-compose build

# Build specific service
docker-compose build gateway

# Build without cache
docker-compose build --no-cache
```

### Using Build Scripts

**Linux/macOS:**
```bash
# Build all images
./build.sh all

# Build specific service
./build.sh gateway

# List built images
./build.sh list

# Clean all images
./build.sh clean
```

**Windows PowerShell:**
```powershell
# Build all images
.\build.ps1 all

# Build specific service
.\build.ps1 gateway

# List built images
.\build.ps1 list

# Clean all images
.\build.ps1 clean
```

### Manual Build

```bash
# Go service (from service directory)
cd services/gateway
docker build -t siem-gateway:latest .

# Python service (from ai directory)
cd ai
docker build -t siem-ml-gateway:latest -f services/ml-gateway/Dockerfile .

# Frontend (from dashboard directory)
cd web/dashboard
docker build -t siem-dashboard:latest .
```

## Deployment

### Development Deployment

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose stop

# Remove containers (keep data)
docker-compose down

# Remove containers and volumes (delete all data)
docker-compose down -v
```

### Production Deployment

1. **Update environment variables:**
   ```bash
   cp .env.example .env.production
   nano .env.production
   # Set strong passwords and secrets
   ```

2. **Use production compose file:**
   ```bash
   docker-compose -f docker-compose.yml --env-file .env.production up -d
   ```

3. **Enable resource limits:**
   Edit `docker-compose.yml`:
   ```yaml
   services:
     gateway:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 2G
           reservations:
             cpus: '1'
             memory: 1G
   ```

### Scaling Services

Scale horizontally for high load:

```bash
# Scale detection engine
docker-compose up -d --scale detection=3

# Scale parser
docker-compose up -d --scale parser=4

# Check scaled instances
docker-compose ps
```

## Monitoring

### Health Checks

All services include health checks. Check status:

```bash
# Overall status
docker-compose ps

# Detailed health check
docker inspect --format='{{.State.Health.Status}}' siem-gateway
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f gateway

# Last 100 lines
docker-compose logs --tail=100 detection

# Since timestamp
docker-compose logs --since 2025-02-15T09:00:00 gateway
```

### Resource Usage

```bash
# Real-time stats
docker stats

# Specific services
docker stats siem-gateway siem-detection siem-clickhouse

# Export to CSV
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" > stats.csv
```

### Metrics

Services expose Prometheus metrics:

```bash
# Gateway metrics
curl http://localhost:8080/metrics

# ML Gateway metrics
curl http://localhost:8000/metrics
```

## Troubleshooting

### Common Issues

#### Port Already in Use

```bash
# Find process using port
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# Change port in docker-compose.yml
ports:
  - "8081:8080"  # Map host 8081 to container 8080
```

#### Service Won't Start

```bash
# View detailed logs
docker-compose logs [service]

# Inspect container
docker inspect [container_name]

# Check health
docker-compose ps
```

#### Database Connection Failed

```bash
# Check database is running
docker-compose ps postgres clickhouse

# Test connection
docker-compose exec postgres pg_isready -U siem
docker-compose exec clickhouse clickhouse-client --query "SELECT 1"

# View database logs
docker-compose logs postgres
docker-compose logs clickhouse
```

#### Kafka Not Ready

```bash
# Wait for Kafka startup
docker-compose logs -f kafka
# Wait for "Kafka Server started"

# Verify Kafka is healthy
docker-compose exec kafka kafka-broker-api-versions --bootstrap-server localhost:9092
```

#### Out of Memory

```bash
# Check resource usage
docker stats

# Reduce memory limits in docker-compose.yml
# Stop unused services
docker-compose stop temporal keycloak
```

### Debug Mode

Enable debug logging:

```bash
# Edit .env
DEBUG=true
LOG_LEVEL=debug

# Restart services
docker-compose restart
```

## Production Considerations

### Security

1. **Change Default Passwords:**
   ```bash
   # Generate strong passwords
   openssl rand -base64 32  # For database passwords
   openssl rand -hex 64     # For JWT secrets
   ```

2. **Use Secrets Management:**
   ```yaml
   # docker-compose.yml
   services:
     gateway:
       secrets:
         - jwt_secret
   secrets:
     jwt_secret:
       file: ./secrets/jwt_secret.txt
   ```

3. **Enable TLS:**
   ```yaml
   services:
     gateway:
       volumes:
         - ./certs/server.crt:/etc/ssl/certs/server.crt:ro
         - ./certs/server.key:/etc/ssl/private/server.key:ro
   ```

### Backup

#### Database Backup

```bash
# PostgreSQL
docker-compose exec postgres pg_dump -U siem siem_soar > backup_$(date +%Y%m%d).sql

# ClickHouse
docker-compose exec clickhouse clickhouse-client --query "BACKUP TABLE siem.events TO Disk('backups')"
```

#### Volume Backup

```bash
# Backup all volumes
docker run --rm \
  -v siem-soar-project_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_$(date +%Y%m%d).tar.gz /data
```

### High Availability

For production HA:

1. **Use External Databases:**
   - Managed PostgreSQL (RDS, Cloud SQL)
   - ClickHouse cluster (3+ nodes)
   - Redis Sentinel (3+ nodes)

2. **Kafka Cluster:**
   - 3+ brokers
   - Replication factor 3
   - Min ISR 2

3. **Load Balancer:**
   - Nginx/HAProxy in front of gateway
   - Round-robin across scaled instances

### Monitoring Stack

Add Prometheus and Grafana:

```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3030:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
```

Start monitoring:
```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## Performance Tuning

### Database Optimization

**PostgreSQL:**
```bash
# Edit postgresql.conf
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
```

**ClickHouse:**
```xml
<!-- config.xml -->
<max_memory_usage>10000000000</max_memory_usage>
<max_threads>16</max_threads>
```

### Kafka Tuning

```yaml
services:
  kafka:
    environment:
      KAFKA_HEAP_OPTS: "-Xmx4g -Xms4g"
      KAFKA_NUM_NETWORK_THREADS: 8
      KAFKA_NUM_IO_THREADS: 16
```

### Go Service Tuning

```yaml
services:
  gateway:
    environment:
      GOMAXPROCS: 8
      GOGC: 100
```

## Cleanup

### Remove Containers

```bash
# Stop and remove
docker-compose down

# Remove with volumes
docker-compose down -v
```

### Remove Images

```bash
# Using build scripts
./build.sh clean

# Manual
docker images | grep siem- | awk '{print $3}' | xargs docker rmi
```

### Prune System

```bash
# Remove unused containers, networks, images
docker system prune -a

# Remove volumes too
docker system prune -a --volumes
```

---

## Additional Resources

- [Quick Start Guide](./QUICKSTART.md)
- [Build Guide](./BUILD_AND_DEPLOY.md)
- [API Documentation](./docs/api/openapi.yaml)
- [User Guide](./docs/user/user_guide.md)

## Support

For issues:
1. Check logs: `docker-compose logs -f`
2. Review documentation
3. Open GitHub issue

---

**Built with ❤️ for Security Teams**
