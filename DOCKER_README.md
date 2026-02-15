# Docker Deployment for SIEM-SOAR Platform

> Complete Docker-based deployment solution for local development and production

## 🚀 Quick Start

```bash
# 1. Verify setup
./verify-setup.sh

# 2. Configure environment
cp .env.example .env

# 3. Start platform
docker-compose up -d --build

# 4. Access dashboard
# Open http://localhost:3000
```

## 📋 Table of Contents

- [Overview](#overview)
- [Files Created](#files-created)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Usage](#usage)
- [Monitoring](#monitoring)
- [Troubleshooting](#troubleshooting)
- [Production](#production)

## Overview

This Docker deployment provides:

✅ **Complete Platform** - All 15+ services containerized
✅ **One-Command Deploy** - Simple `docker-compose up`
✅ **Development Ready** - Hot reload, debug logging
✅ **Production Capable** - HA, scaling, monitoring
✅ **Well Documented** - Comprehensive guides included

## Files Created

### Core Configuration

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Main orchestration (15 services) |
| `.env.example` | Environment template (100+ variables) |
| `web/dashboard/Dockerfile` | Frontend build (Node → Nginx) |
| `web/dashboard/nginx.conf` | Reverse proxy config |

### Build Scripts

| File | Purpose |
|------|---------|
| `build.sh` | Linux/macOS build automation |
| `build.ps1` | Windows PowerShell build automation |
| `verify-setup.sh` | Pre-deployment verification |

### Documentation

| File | Purpose |
|------|---------|
| `QUICKSTART.md` | 5-minute getting started guide |
| `BUILD_AND_DEPLOY.md` | Detailed build instructions |
| `DOCKER_DEPLOYMENT.md` | Complete deployment guide |
| `DOCKER_BUILD_SUMMARY.md` | Implementation summary |

## Prerequisites

### Required Software

- **Docker** 20.10+
- **Docker Compose** 2.0+

### System Requirements

#### Development
- CPU: 4 cores
- RAM: 8GB
- Disk: 30GB

#### Production
- CPU: 16+ cores
- RAM: 64GB+
- Disk: 500GB+ SSD

### Supported Platforms

- ✅ Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- ✅ macOS 11+ (with Docker Desktop)
- ✅ Windows 10+ (with WSL2 + Docker Desktop)

## Getting Started

### 1. Verify Setup

```bash
./verify-setup.sh
```

This checks:
- Docker/Compose installed
- Required files present
- Ports available
- Disk space sufficient
- Memory adequate

### 2. Configure Environment

```bash
# Copy template
cp .env.example .env

# Edit configuration (optional for dev)
nano .env
```

Key variables:
```bash
POSTGRES_PASSWORD=siem_password
CLICKHOUSE_PASSWORD=siem_password
REDIS_PASSWORD=siem_password
GATEWAY_JWT_SECRET=your_secret_here
```

### 3. Build Images

**Option A: Using build script (recommended)**

```bash
# Linux/macOS
./build.sh all

# Windows PowerShell
.\build.ps1 all
```

**Option B: Using docker-compose**

```bash
docker-compose build
```

### 4. Start Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### 5. Verify Deployment

```bash
# Check all services healthy
docker-compose ps

# Test endpoints
curl http://localhost:8080/health  # Gateway
curl http://localhost:8000/health  # ML Gateway
curl http://localhost:3000/health  # Dashboard

# Access dashboard
open http://localhost:3000  # macOS
xdg-open http://localhost:3000  # Linux
start http://localhost:3000  # Windows
```

## Architecture

### Service Layout

```
┌─────────────────────────────────────────┐
│         Frontend (Port 3000)            │
│    React Dashboard + Nginx              │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│       API Gateway (Port 8080)           │
│  Auth, Rate Limiting, Routing           │
└──────┬──────────────────────────────────┘
       │
       ├───► Detection Engine (Go)
       ├───► SOAR Engine (Go + Temporal)
       ├───► Query Service (Go + ClickHouse)
       ├───► ML Gateway (Python)
       └───► Case Management (Go + PostgreSQL)

Infrastructure:
├─ ClickHouse (Event Storage)
├─ PostgreSQL (Metadata)
├─ Kafka (Event Streaming)
├─ Redis (Cache)
└─ Temporal (Workflows)
```

### Data Flow

```
Logs → Collector → Kafka → Parser → Normalizer → Enricher
                      ↓                              ↓
                  Detection                    ClickHouse
                      ↓
                   Alerts → SOAR → Actions
```

## Usage

### Common Commands

```bash
# Start/Stop
docker-compose up -d        # Start all
docker-compose stop         # Stop all
docker-compose restart      # Restart all

# Individual services
docker-compose up -d gateway        # Start gateway
docker-compose restart detection    # Restart detection
docker-compose stop ml-gateway      # Stop ML service

# Logs
docker-compose logs -f              # All logs
docker-compose logs -f gateway      # Service logs
docker-compose logs --tail=100      # Last 100 lines

# Status
docker-compose ps               # Service status
docker stats                    # Resource usage

# Clean up
docker-compose down             # Stop and remove
docker-compose down -v          # Remove volumes too
```

### Build Scripts

**Linux/macOS:**
```bash
./build.sh all              # Build all
./build.sh gateway          # Build one
./build.sh list             # List images
./build.sh clean            # Remove all
```

**Windows PowerShell:**
```powershell
.\build.ps1 all             # Build all
.\build.ps1 gateway         # Build one
.\build.ps1 list            # List images
.\build.ps1 clean           # Remove all
```

### Testing

#### Send Test Event

```bash
# HTTP API
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "source": "test",
    "event_type": "authentication",
    "severity": "medium",
    "message": "Test login attempt"
  }'

# Syslog UDP
echo '<14>Test syslog message' | nc -u localhost 9514

# Syslog TCP
echo '<14>Test syslog message' | nc localhost 9515
```

#### Query Events

```bash
# Via API
curl http://localhost:8080/api/v1/events?limit=10

# Direct ClickHouse
docker-compose exec clickhouse clickhouse-client \
  --query "SELECT * FROM siem.events LIMIT 10"
```

#### Kafka Topics

```bash
# List topics
docker-compose exec kafka kafka-topics \
  --list --bootstrap-server localhost:9092

# Consume alerts
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic alerts \
  --from-beginning
```

## Monitoring

### Health Checks

All services expose health endpoints:

```bash
# Gateway
curl http://localhost:8080/health

# ML Gateway
curl http://localhost:8000/health

# Dashboard
curl http://localhost:3000/health
```

### Resource Monitoring

```bash
# Real-time stats
docker stats

# Specific services
docker stats siem-gateway siem-detection siem-clickhouse

# Export metrics
curl http://localhost:8080/metrics  # Prometheus format
```

### Logs

```bash
# Stream all logs
docker-compose logs -f

# Service-specific
docker-compose logs -f gateway detection

# Save to file
docker-compose logs > siem-logs.txt

# Since timestamp
docker-compose logs --since 2025-02-15T09:00:00
```

## Troubleshooting

### Common Issues

#### Port Conflicts

```bash
# Find what's using a port
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# Solution: Change port mapping
# Edit docker-compose.yml
ports:
  - "8081:8080"  # Host 8081 → Container 8080
```

#### Service Won't Start

```bash
# Check logs
docker-compose logs [service]

# Check dependencies
docker-compose ps

# Restart specific service
docker-compose restart [service]
```

#### Database Connection Failed

```bash
# Verify database is running
docker-compose exec postgres pg_isready -U siem
docker-compose exec clickhouse clickhouse-client --query "SELECT 1"
docker-compose exec redis redis-cli -a siem_password ping

# Check connection from service
docker-compose exec gateway ping postgres
```

#### Out of Memory

```bash
# Check usage
docker stats

# Solution 1: Stop unused services
docker-compose stop temporal keycloak

# Solution 2: Reduce heap sizes
# Edit docker-compose.yml
environment:
  KAFKA_HEAP_OPTS: "-Xmx512m -Xms512m"

# Solution 3: Add resource limits
deploy:
  resources:
    limits:
      memory: 1G
```

#### Build Fails

```bash
# Clean build cache
docker-compose build --no-cache

# Manually build with verbose output
docker build --progress=plain -f services/gateway/Dockerfile .

# Check Dockerfile exists
ls -la services/*/Dockerfile
```

### Debug Mode

```bash
# Enable debug logging
echo "DEBUG=true" >> .env
echo "LOG_LEVEL=debug" >> .env

# Restart services
docker-compose restart

# View debug logs
docker-compose logs -f | grep -i debug
```

## Production

### Security Checklist

- [ ] Change all default passwords
- [ ] Generate strong JWT secrets
- [ ] Enable TLS/SSL
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up RBAC
- [ ] Use secrets management
- [ ] Regular security updates

### High Availability

```bash
# Scale services
docker-compose up -d --scale detection=3
docker-compose up -d --scale parser=4

# Use external databases
# Edit .env
POSTGRES_HOST=your-managed-postgres.com
CLICKHOUSE_HOST=your-clickhouse-cluster.com
REDIS_HOST=your-redis-sentinel.com
```

### Backup

```bash
# PostgreSQL backup
docker-compose exec postgres pg_dump -U siem siem_soar \
  > backup_$(date +%Y%m%d).sql

# ClickHouse backup
docker-compose exec clickhouse clickhouse-client \
  --query "BACKUP TABLE siem.events TO Disk('backups')"

# Volume backup
docker run --rm \
  -v siem-soar-project_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_$(date +%Y%m%d).tar.gz /data
```

### Monitoring Stack

Add Prometheus and Grafana:

```bash
# Start with monitoring
docker-compose -f docker-compose.yml \
               -f docker-compose.monitoring.yml \
               up -d

# Access Grafana
open http://localhost:3030
```

## Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | SOC Dashboard |
| API Gateway | http://localhost:8080 | Main API |
| ML Gateway | http://localhost:8000 | AI/ML Services |
| ClickHouse | http://localhost:8123 | Database HTTP |
| PostgreSQL | localhost:5432 | Metadata DB |
| Kafka | localhost:9092 | Event Stream |
| Temporal | localhost:7233 | Workflows |

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| PostgreSQL | siem | siem_password |
| ClickHouse | siem | siem_password |
| Redis | - | siem_password |

**⚠️ CHANGE IN PRODUCTION!**

## Additional Resources

- **Quick Start**: [QUICKSTART.md](./QUICKSTART.md) - Get running in 5 minutes
- **Build Guide**: [BUILD_AND_DEPLOY.md](./BUILD_AND_DEPLOY.md) - Detailed build instructions
- **Deployment Guide**: [DOCKER_DEPLOYMENT.md](./DOCKER_DEPLOYMENT.md) - Complete deployment reference
- **Summary**: [DOCKER_BUILD_SUMMARY.md](./DOCKER_BUILD_SUMMARY.md) - Implementation overview
- **API Docs**: [docs/api/openapi.yaml](./docs/api/openapi.yaml) - REST API reference
- **User Guide**: [docs/user/user_guide.md](./docs/user/user_guide.md) - Platform usage

## Support

Need help?

1. **Check Documentation**: Review the guides above
2. **View Logs**: `docker-compose logs -f`
3. **Run Verification**: `./verify-setup.sh`
4. **Open Issue**: GitHub Issues

## License

See [LICENSE](./LICENSE) for details.

---

**Built with ❤️ for Security Operations Teams**
