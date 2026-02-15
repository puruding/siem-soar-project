# SIEM-SOAR Platform - Quick Start Guide

Get the SIEM-SOAR platform running locally in minutes!

## Prerequisites

- **Docker** 20.10 or higher
- **Docker Compose** 2.0 or higher
- **RAM**: 16GB+ recommended
- **Disk**: 50GB+ free space
- **OS**: Linux, macOS, or Windows with WSL2

## 1. Clone and Setup

```bash
# Navigate to project directory
cd siem-soar-project

# (Optional) Copy and customize environment variables
cp .env.example .env
```

## 2. Start the Platform

### Option A: Using Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up -d --build

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### Option B: Using Build Scripts

**On Linux/macOS:**
```bash
# Build all images
./build.sh all

# Start services
docker-compose up -d
```

**On Windows (PowerShell):**
```powershell
# Build all images
.\build.ps1 all

# Start services
docker-compose up -d
```

## 3. Verify Services

Check that all services are running:

```bash
docker-compose ps
```

Expected output should show all services in "Up" state:
- clickhouse
- kafka
- redis
- postgres
- temporal
- gateway
- detection
- soar
- ti
- query
- case
- collector
- pipeline
- parser
- ml-gateway
- dashboard

## 4. Access the Platform

### Web Dashboard
- **URL**: http://localhost:3000
- **Description**: Main SOC Dashboard

### API Gateway
- **URL**: http://localhost:8080
- **Health Check**: http://localhost:8080/health

### ML Gateway
- **URL**: http://localhost:8000
- **Health Check**: http://localhost:8000/health

## 5. Test Data Collection

### Send Test Syslog Messages

**UDP (Port 9514):**
```bash
echo '<14>Jan 15 14:32:01 myhost systemd[1]: Starting test service...' | nc -u -w1 localhost 9514
```

**TCP (Port 9515):**
```bash
echo '<14>Jan 15 14:32:01 myhost systemd[1]: Starting test service...' | nc localhost 9515
```

### Send Test HTTP Event

```bash
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "source": "test",
    "event_type": "authentication",
    "severity": "medium",
    "message": "Test login attempt",
    "timestamp": "2025-02-15T09:00:00Z"
  }'
```

## 6. Explore the Platform

### Query Events (via API)

```bash
# List recent events
curl http://localhost:8080/api/v1/events?limit=10

# Search events
curl http://localhost:8080/api/v1/events/search?query=authentication
```

### Query ClickHouse Directly

```bash
# Execute ClickHouse query
docker-compose exec clickhouse clickhouse-client --query "SELECT * FROM siem.events LIMIT 10"
```

### View Kafka Topics

```bash
# List topics
docker-compose exec kafka kafka-topics --list --bootstrap-server localhost:9092

# Consume messages from alerts topic
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic alerts \
  --from-beginning
```

## 7. Create Detection Rules

### Example Sigma Rule

Create a file `rules/failed_login.yml`:

```yaml
title: Multiple Failed Login Attempts
description: Detects multiple failed login attempts from single IP
status: experimental
logsource:
  product: linux
  service: sshd
detection:
  selection:
    event_type: authentication
    outcome: failure
  condition: selection | count(source_ip) by source_ip > 5
  timeframe: 5m
level: medium
```

### Upload Rule via API

```bash
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Content-Type: application/json" \
  -d @rules/failed_login.yml
```

## 8. Create SOAR Playbook

### Example Playbook (Block IP)

```bash
curl -X POST http://localhost:8080/api/v1/playbooks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Malicious IP",
    "description": "Automatically block IP addresses flagged as malicious",
    "trigger": {
      "type": "alert",
      "conditions": {
        "severity": ["high", "critical"],
        "category": "network"
      }
    },
    "actions": [
      {
        "type": "enrichment",
        "action": "threat_intel_lookup"
      },
      {
        "type": "containment",
        "action": "firewall_block_ip",
        "approval_required": true
      },
      {
        "type": "notification",
        "action": "send_email",
        "recipients": ["soc@example.com"]
      }
    ]
  }'
```

## 9. Monitor the Platform

### View Service Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f gateway

# Last 100 lines
docker-compose logs --tail=100 detection
```

### Check Resource Usage

```bash
# Real-time stats
docker stats

# Specific services
docker stats siem-gateway siem-detection siem-ml-gateway
```

### Service Health Checks

```bash
# Gateway
curl http://localhost:8080/health

# ML Gateway
curl http://localhost:8000/health

# Dashboard
curl http://localhost:3000/health

# ClickHouse
docker-compose exec clickhouse clickhouse-client --query "SELECT 1"

# PostgreSQL
docker-compose exec postgres pg_isready -U siem

# Redis
docker-compose exec redis redis-cli -a siem_password ping

# Kafka
docker-compose exec kafka kafka-broker-api-versions --bootstrap-server localhost:9092
```

## 10. Stop and Clean Up

### Stop Services

```bash
# Stop all services
docker-compose stop

# Stop specific service
docker-compose stop gateway
```

### Remove Containers

```bash
# Remove all containers (keeps data)
docker-compose down

# Remove containers and volumes (deletes all data)
docker-compose down -v
```

### Clean Up Images

**Linux/macOS:**
```bash
./build.sh clean
```

**Windows PowerShell:**
```powershell
.\build.ps1 clean
```

## Troubleshooting

### Services Won't Start

1. **Check Docker is running:**
   ```bash
   docker info
   ```

2. **Check port conflicts:**
   ```bash
   # On Linux/macOS
   netstat -tuln | grep -E '(3000|8080|8123|9000|9092|5432|6379)'

   # On Windows
   netstat -an | findstr "3000 8080 8123 9000 9092 5432 6379"
   ```

3. **View error logs:**
   ```bash
   docker-compose logs [service_name]
   ```

### High Memory Usage

Reduce resource usage by editing `docker-compose.yml`:

```yaml
services:
  kafka:
    environment:
      KAFKA_HEAP_OPTS: "-Xmx512m -Xms512m"
```

### Kafka Won't Start

Wait for initialization to complete:

```bash
docker-compose logs -f kafka
# Wait for "Kafka Server started"
```

### Database Connection Errors

Ensure databases are healthy:

```bash
# PostgreSQL
docker-compose exec postgres pg_isready -U siem

# ClickHouse
docker-compose exec clickhouse clickhouse-client --query "SELECT 1"

# Redis
docker-compose exec redis redis-cli -a siem_password ping
```

## Next Steps

1. **Configure Detection Rules**: Add custom Sigma rules
2. **Setup Integrations**: Connect to Splunk, Elastic, or Sentinel
3. **Create Playbooks**: Automate incident response
4. **Configure Alerts**: Set up email/Slack notifications
5. **Import Threat Intelligence**: Connect to MISP or other TI feeds

## Resources

- [Full Build Guide](./BUILD_AND_DEPLOY.md)
- [API Documentation](./docs/api/openapi.yaml)
- [User Guide](./docs/user/user_guide.md)
- [Architecture Docs](./docs/adr/)
- [Release Notes](./RELEASE_NOTES.md)

## Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| PostgreSQL | siem | siem_password |
| ClickHouse | siem | siem_password |
| Redis | - | siem_password |

**⚠️ Change these credentials in production!**

## Support

For issues and questions:
- Check logs: `docker-compose logs -f`
- Review docs: `./docs/`
- Open an issue on GitHub

---

**Happy SIEM-ing! 🔒**
