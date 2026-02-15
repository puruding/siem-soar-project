# SIEM/SOAR Platform Operations Runbook

## Overview

This runbook provides step-by-step procedures for common operational tasks and incident response.

## Table of Contents
1. [Daily Operations](#daily-operations)
2. [Incident Response](#incident-response)
3. [Maintenance Procedures](#maintenance-procedures)
4. [Scaling Operations](#scaling-operations)
5. [Backup and Recovery](#backup-and-recovery)

---

## Daily Operations

### Morning Health Check

**Time:** 09:00 daily
**Duration:** 15 minutes

```bash
# 1. Check overall service health
kubectl get pods -n siem-production | grep -v Running

# 2. Review overnight alerts
curl -s "http://gateway:8080/api/v1/alerts?status=new&created_after=$(date -d '12 hours ago' -Iseconds)" | jq '.total'

# 3. Check event ingestion rate
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT count()/(12*3600) as events_per_second FROM events WHERE timestamp > now() - INTERVAL 12 HOUR"

# 4. Review error rates
curl -s http://prometheus:9090/api/v1/query?query='sum(rate(http_requests_failed_total{namespace="siem-production"}[1h]))' | jq

# 5. Check disk usage
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE active"
```

**Expected Results:**
- All pods in Running state
- EPS > 10,000
- Error rate < 0.1%
- Disk usage < 70%

### Weekly Maintenance

**Time:** Sunday 02:00
**Duration:** 2 hours

1. **Review capacity metrics**
   - Check resource utilization trends
   - Plan scaling if needed

2. **Optimize ClickHouse**
   ```sql
   -- Optimize tables
   OPTIMIZE TABLE events FINAL;
   OPTIMIZE TABLE alerts FINAL;

   -- Clean old partitions
   ALTER TABLE events DROP PARTITION '2024-01-01';
   ```

3. **Update detection rules**
   - Review rule performance
   - Disable noisy rules
   - Add new threat detections

4. **Rotate credentials**
   ```bash
   # Rotate API keys
   kubectl patch secret api-keys -n siem-production \
     --type='json' -p='[{"op": "replace", "path": "/data/jwt-secret", "value": "'$(openssl rand -base64 64 | base64 -w0)'"}]'
   ```

---

## Incident Response

### INC-001: Service Outage

**Severity:** P1
**SLA:** 15 minutes to acknowledge, 1 hour to mitigate

**Steps:**

1. **Acknowledge and communicate**
   ```
   - Post to #siem-incidents: "Investigating service outage"
   - Page on-call if not already engaged
   ```

2. **Initial assessment**
   ```bash
   # Check what's down
   kubectl get pods -n siem-production | grep -v Running

   # Check recent events
   kubectl get events -n siem-production --sort-by='.lastTimestamp' | tail -20

   # Check node health
   kubectl get nodes
   ```

3. **Attempt recovery**
   ```bash
   # Restart affected services
   kubectl rollout restart deployment/<service> -n siem-production

   # If node issue, drain and restart
   kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
   kubectl uncordon <node>
   ```

4. **Verify recovery**
   ```bash
   # Check services are up
   kubectl get pods -n siem-production

   # Test endpoints
   curl http://gateway:8080/health
   ```

5. **Post-incident**
   - Document timeline
   - Schedule postmortem
   - Create follow-up tickets

### INC-002: High Latency

**Severity:** P2
**SLA:** 30 minutes to acknowledge, 2 hours to mitigate

**Steps:**

1. **Identify bottleneck**
   ```bash
   # Check query performance
   kubectl exec -it clickhouse-0 -n siem-production -- \
     clickhouse-client -q "SELECT query, query_duration_ms FROM system.query_log WHERE event_date = today() ORDER BY query_duration_ms DESC LIMIT 5"

   # Check service metrics
   curl http://prometheus:9090/api/v1/query?query='histogram_quantile(0.95,rate(http_request_duration_seconds_bucket[5m]))'
   ```

2. **Scale if needed**
   ```bash
   # Scale stateless services
   kubectl scale deployment gateway --replicas=5 -n siem-production
   kubectl scale deployment query-service --replicas=5 -n siem-production
   ```

3. **Optimize queries**
   ```sql
   -- Add missing indexes
   ALTER TABLE events ADD INDEX idx_src_ip src_ip TYPE bloom_filter GRANULARITY 1;

   -- Kill slow queries
   KILL QUERY WHERE query_id = '<query_id>';
   ```

### INC-003: Data Loss Event

**Severity:** P1
**SLA:** Immediate response

**Steps:**

1. **Stop the bleeding**
   ```bash
   # Pause ingestion if necessary
   kubectl scale deployment collector --replicas=0 -n siem-production
   kubectl scale deployment pipeline --replicas=0 -n siem-production
   ```

2. **Assess damage**
   ```sql
   -- Check data gaps
   SELECT toStartOfHour(timestamp) as hour, count()
   FROM events
   WHERE timestamp > now() - INTERVAL 24 HOUR
   GROUP BY hour
   ORDER BY hour;
   ```

3. **Restore from backup**
   ```bash
   # List available backups
   aws s3 ls s3://siem-backups/clickhouse/

   # Restore
   ./scripts/restore-clickhouse.sh --backup-name backup_20240115
   ```

4. **Resume operations**
   ```bash
   kubectl scale deployment collector --replicas=3 -n siem-production
   kubectl scale deployment pipeline --replicas=3 -n siem-production
   ```

---

## Maintenance Procedures

### MAINT-001: Rolling Update

**Duration:** 30 minutes
**Impact:** Minimal (rolling)

```bash
# 1. Update image tag in values.yaml

# 2. Apply update
helm upgrade siem-platform infra/helm/siem-platform \
  --namespace siem-production \
  --values values-prod.yaml \
  --wait --timeout 10m

# 3. Verify
kubectl rollout status deployment/gateway -n siem-production
kubectl rollout status deployment/detection-engine -n siem-production

# 4. Smoke test
./scripts/smoke-test.sh
```

### MAINT-002: Database Schema Update

**Duration:** 1-4 hours
**Impact:** Possible brief latency increase

```bash
# 1. Backup current schema
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SHOW CREATE TABLE events" > backup/events_schema.sql

# 2. Apply migration
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client < migrations/002_add_columns.sql

# 3. Verify
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "DESCRIBE TABLE events"

# 4. Update application (if needed)
helm upgrade siem-platform ...
```

### MAINT-003: Certificate Renewal

**Duration:** 15 minutes
**Impact:** Brief TLS handshake failures

```bash
# 1. Generate new certificates
./scripts/generate-certs.sh

# 2. Update secrets
kubectl create secret tls siem-tls \
  --cert=certs/tls.crt \
  --key=certs/tls.key \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Restart ingress
kubectl rollout restart deployment ingress-nginx-controller -n ingress-nginx

# 4. Verify
curl -v https://siem.example.com/health
```

---

## Scaling Operations

### SCALE-001: Horizontal Scaling

**Trigger:** CPU > 70% or Memory > 80% for 10 minutes

```bash
# Scale specific service
kubectl scale deployment gateway --replicas=5 -n siem-production

# Or use HPA
kubectl patch hpa gateway -n siem-production \
  --type='json' -p='[{"op": "replace", "path": "/spec/maxReplicas", "value": 10}]'
```

### SCALE-002: Vertical Scaling

**Trigger:** Consistent resource pressure

```yaml
# Update resource limits in values.yaml
services:
  gateway:
    resources:
      requests:
        cpu: 2000m
        memory: 2Gi
      limits:
        cpu: 4000m
        memory: 4Gi
```

### SCALE-003: ClickHouse Scaling

**Trigger:** Storage > 70% or Query latency increasing

```bash
# Add shards
kubectl apply -f infra/clickhouse/shard-3.yaml

# Rebalance data
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "ALTER TABLE events ON CLUSTER default MOVE PARTITION '2024-01' TO SHARD '/clickhouse/tables/shard_3/events'"
```

---

## Backup and Recovery

### BACKUP-001: Scheduled Backup

**Schedule:** Daily at 02:00 UTC

```bash
# Manual backup
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "BACKUP DATABASE siem TO Disk('backups', 'backup_$(date +%Y%m%d)')"

# Verify backup
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT * FROM system.backups"
```

### BACKUP-002: Point-in-Time Recovery

```bash
# 1. Stop writes
kubectl scale deployment pipeline --replicas=0 -n siem-production

# 2. Restore to point in time
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "RESTORE DATABASE siem FROM Disk('backups', 'backup_20240115')"

# 3. Resume
kubectl scale deployment pipeline --replicas=3 -n siem-production
```

### BACKUP-003: Disaster Recovery

```bash
# 1. Switch DNS to DR site
gcloud dns record-sets transaction start --zone=siem-zone
gcloud dns record-sets transaction remove --zone=siem-zone \
  --name="api.siem.example.com." --type=A --ttl=300 "10.0.0.1"
gcloud dns record-sets transaction add --zone=siem-zone \
  --name="api.siem.example.com." --type=A --ttl=300 "10.1.0.1"
gcloud dns record-sets transaction execute --zone=siem-zone

# 2. Scale up DR cluster
kubectl --kubeconfig=dr-kubeconfig scale deployment --all --replicas=3 -n siem-production

# 3. Verify DR services
./scripts/verify-dr.sh
```

---

## Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| On-Call | PagerDuty | Auto-escalates after 15min |
| Platform Lead | platform-lead@example.com | Business hours |
| Database Admin | dba-team@example.com | For ClickHouse issues |
| Security Team | security@example.com | For security incidents |

---

*Last Updated: 2024-01-15*
*Version: 1.0*
