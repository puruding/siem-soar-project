# Incident Response Runbook

This runbook provides procedures for responding to operational incidents in the SIEM-SOAR platform.

---

## Table of Contents

1. [Incident Classification](#incident-classification)
2. [Initial Response](#initial-response)
3. [Common Incidents](#common-incidents)
4. [Escalation Procedures](#escalation-procedures)
5. [Post-Incident Activities](#post-incident-activities)

---

## Incident Classification

### Severity Levels

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|----------|
| **P1 - Critical** | Complete service outage | 5 minutes | Platform down, data loss |
| **P2 - High** | Major feature impacted | 15 minutes | Detection engine down, no alerts |
| **P3 - Medium** | Minor feature impacted | 1 hour | Slow queries, delayed alerts |
| **P4 - Low** | Minimal impact | 4 hours | UI issues, minor bugs |

---

## Initial Response

### Step 1: Acknowledge Incident

```bash
# Check current alerts
kubectl get pods -n siem-prod --field-selector=status.phase!=Running

# View recent events
kubectl get events -n siem-prod --sort-by=.metadata.creationTimestamp | tail -20

# Check service health
for svc in gateway detection soar query collector; do
  curl -s "http://siem-$svc:8080/health" | jq .
done
```

### Step 2: Assess Impact

1. Check Grafana dashboards: `https://grafana.siem.local/d/soc-overview`
2. Review affected metrics:
   - Event ingestion rate
   - Alert generation rate
   - Error rates
   - Response times

### Step 3: Communicate

1. Update incident channel: `#siem-incidents`
2. Notify stakeholders based on severity
3. Create incident ticket in Jira

---

## Common Incidents

### 1. Service Not Responding

**Symptoms:**
- Health check failures
- 5xx errors increasing
- Pods not ready

**Diagnosis:**
```bash
# Check pod status
kubectl get pods -n siem-prod -l app=siem-platform

# View pod logs
kubectl logs -n siem-prod deployment/siem-gateway --tail=100

# Check resource usage
kubectl top pods -n siem-prod

# Describe pod for events
kubectl describe pod <pod-name> -n siem-prod
```

**Resolution:**
```bash
# Option 1: Restart pod
kubectl rollout restart deployment/siem-gateway -n siem-prod

# Option 2: Scale up
kubectl scale deployment/siem-gateway -n siem-prod --replicas=5

# Option 3: Rollback
kubectl rollout undo deployment/siem-gateway -n siem-prod
```

---

### 2. Event Ingestion Stopped

**Symptoms:**
- EPS drops to 0
- Kafka consumer lag increasing
- No new events in ClickHouse

**Diagnosis:**
```bash
# Check Kafka consumer groups
kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
  --describe --group siem-collector

# Check pipeline pods
kubectl logs -n siem-prod -l app=siem-collector --tail=50

# Verify Kafka connectivity
kubectl exec -it deploy/siem-collector -n siem-prod -- \
  kafka-topics.sh --bootstrap-server kafka:9092 --list
```

**Resolution:**
```bash
# Restart collector
kubectl rollout restart deployment/siem-collector -n siem-prod

# Reset consumer offset (if needed - WARNING: may cause duplicates)
kafka-consumer-groups.sh --bootstrap-server kafka:9092 \
  --group siem-collector \
  --topic events.raw \
  --reset-offsets --to-latest --execute
```

---

### 3. Detection Engine Not Generating Alerts

**Symptoms:**
- Events being processed but no alerts
- Rule evaluation errors
- High detection latency

**Diagnosis:**
```bash
# Check detection engine logs
kubectl logs -n siem-prod deployment/siem-detection --tail=100

# Verify rules are loaded
curl -s http://siem-detection:8081/api/v1/rules | jq '.rules | length'

# Check rule evaluation metrics
curl -s http://siem-detection:9090/metrics | grep siem_rule_evaluation
```

**Resolution:**
```bash
# Reload rules
curl -X POST http://siem-detection:8081/api/v1/rules/reload

# Restart detection engine
kubectl rollout restart deployment/siem-detection -n siem-prod
```

---

### 4. ClickHouse Performance Issues

**Symptoms:**
- Slow queries
- Disk space alerts
- Memory pressure

**Diagnosis:**
```bash
# Check ClickHouse status
clickhouse-client --query "SELECT * FROM system.metrics"

# View running queries
clickhouse-client --query "SELECT * FROM system.processes"

# Check disk usage
clickhouse-client --query "SELECT * FROM system.disks"

# Check replication status
clickhouse-client --query "SELECT * FROM system.replicas"
```

**Resolution:**
```bash
# Kill slow queries
clickhouse-client --query "KILL QUERY WHERE user = 'siem'"

# Optimize tables
clickhouse-client --query "OPTIMIZE TABLE events.events_distributed FINAL"

# Clear old data (if retention policy allows)
clickhouse-client --query "ALTER TABLE events.events DELETE WHERE timestamp < now() - INTERVAL 90 DAY"
```

---

### 5. AI Service Errors

**Symptoms:**
- Triage latency high
- Classification errors
- GPU memory issues

**Diagnosis:**
```bash
# Check AI service logs
kubectl logs -n siem-prod deployment/siem-ai-triage --tail=100

# Check GPU status
nvidia-smi

# Verify model loaded
curl -s http://siem-ai-triage:8000/health | jq .
```

**Resolution:**
```bash
# Restart AI service (will reload model)
kubectl rollout restart deployment/siem-ai-triage -n siem-prod

# Clear GPU memory (emergency)
nvidia-smi --gpu-reset
```

---

### 6. High Error Rate

**Symptoms:**
- Error rate > 5%
- Increased latency
- User complaints

**Diagnosis:**
```bash
# Check error logs
kubectl logs -n siem-prod deployment/siem-gateway --tail=200 | grep -i error

# View error breakdown
curl -s http://siem-gateway:9090/metrics | grep http_requests_total | grep status=\"5

# Check external dependencies
kubectl exec -it deploy/siem-gateway -n siem-prod -- \
  nc -zv kafka 9092 && echo "Kafka OK"
```

**Resolution:**
```bash
# Increase replicas for load handling
kubectl scale deployment/siem-gateway -n siem-prod --replicas=10

# Enable circuit breaker (if not already)
kubectl set env deployment/siem-gateway -n siem-prod CIRCUIT_BREAKER_ENABLED=true

# Rollback if recently deployed
kubectl rollout undo deployment/siem-gateway -n siem-prod
```

---

## Escalation Procedures

### When to Escalate

| Situation | Escalate To |
|-----------|-------------|
| P1 incident not resolved in 30 min | Engineering Manager |
| Data loss suspected | VP Engineering + Security |
| Security incident | CISO + Security Team |
| Customer impact | Customer Success + PM |

### Escalation Contacts

| Role | Name | Contact |
|------|------|---------|
| On-Call Engineer | Rotation | PagerDuty |
| Engineering Manager | [Name] | [Phone] |
| VP Engineering | [Name] | [Phone] |
| CISO | [Name] | [Phone] |

---

## Post-Incident Activities

### 1. Document the Incident

Create incident report with:
- Timeline of events
- Root cause
- Impact assessment
- Actions taken
- Lessons learned

### 2. Post-Mortem Meeting

- Schedule within 48 hours
- Include all responders
- Focus on systemic improvements
- No blame

### 3. Action Items

- Create tickets for preventive measures
- Update runbooks
- Improve monitoring/alerting
- Train team if needed

### 4. Communication

- Update stakeholders on resolution
- Share post-mortem summary
- Update status page

---

## Quick Reference Commands

```bash
# === Health Checks ===
kubectl get pods -n siem-prod
curl http://siem-gateway:8080/health

# === Logs ===
kubectl logs -n siem-prod -l app=siem-platform --tail=100
stern siem- -n siem-prod

# === Metrics ===
curl http://siem-gateway:9090/metrics

# === Restart ===
kubectl rollout restart deployment/<name> -n siem-prod

# === Scale ===
kubectl scale deployment/<name> -n siem-prod --replicas=N

# === Rollback ===
kubectl rollout undo deployment/<name> -n siem-prod

# === Blue/Green Switch ===
./scripts/deploy/blue_green.sh switch green
```

---

## Related Resources

- [Scaling Guide](./scaling.md)
- [Backup & Restore](./backup_restore.md)
- [Troubleshooting](./troubleshooting.md)
- [On-Call Guide](./on_call.md)
