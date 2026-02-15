# SIEM/SOAR Platform Troubleshooting Guide

## Overview

This guide provides troubleshooting procedures for common issues in the SIEM/SOAR platform.

## Quick Diagnostics

### System Health Check
```bash
# Check all services
kubectl get pods -n siem-production -o wide

# Check service status
kubectl get svc -n siem-production

# Check recent events
kubectl get events -n siem-production --sort-by='.lastTimestamp' | tail -20

# Check resource usage
kubectl top pods -n siem-production
```

### Log Collection
```bash
# Collect logs from all services
for pod in $(kubectl get pods -n siem-production -o name); do
  kubectl logs $pod -n siem-production --tail=100 > "logs/$(basename $pod).log"
done
```

## Common Issues

### 1. Service Not Starting

**Symptoms:**
- Pod stuck in `Pending` or `CrashLoopBackOff`
- Service unavailable

**Diagnosis:**
```bash
# Check pod status
kubectl describe pod <pod-name> -n siem-production

# Check logs
kubectl logs <pod-name> -n siem-production --previous

# Check events
kubectl get events -n siem-production --field-selector involvedObject.name=<pod-name>
```

**Common Causes & Solutions:**

| Cause | Solution |
|-------|----------|
| Insufficient resources | Increase resource requests/limits or add nodes |
| PVC not bound | Check storage class and PV availability |
| Image pull error | Verify image exists and credentials are correct |
| Config error | Check ConfigMaps and Secrets |
| Dependency unavailable | Ensure dependent services are running |

### 2. High Latency

**Symptoms:**
- API responses slow (>500ms)
- Dashboard loading slowly
- Query timeouts

**Diagnosis:**
```bash
# Check service latency
curl -w "@curl-format.txt" -o /dev/null -s http://gateway:8080/health

# Check database performance
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT query, query_duration_ms FROM system.query_log WHERE query_duration_ms > 1000 ORDER BY query_duration_ms DESC LIMIT 10"

# Check network latency
kubectl exec -it gateway-pod -n siem-production -- ping -c 5 clickhouse
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Database slow queries | Add indexes, optimize queries |
| Resource exhaustion | Scale services horizontally |
| Network issues | Check network policies, DNS |
| Overloaded Kafka | Increase partitions, add brokers |

### 3. Event Ingestion Issues

**Symptoms:**
- Events not appearing in system
- Low EPS rate
- Processing backlog

**Diagnosis:**
```bash
# Check collector health
kubectl logs -l app=collector -n siem-production --tail=50

# Check Kafka consumer lag
kubectl exec -it kafka-0 -n siem-production -- \
  bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --describe --group siem-pipeline

# Check pipeline processing
kubectl logs -l app=pipeline -n siem-production --tail=50 | grep -i error

# Verify ClickHouse writes
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT count() FROM events WHERE timestamp > now() - INTERVAL 5 MINUTE"
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Kafka lag | Scale consumers, increase partitions |
| ClickHouse slow writes | Optimize batch size, check disk I/O |
| Parser errors | Check log format, update parsers |
| Network issues | Verify connectivity between services |

### 4. Alert Generation Problems

**Symptoms:**
- No alerts being generated
- Delayed alerts
- Excessive false positives

**Diagnosis:**
```bash
# Check detection engine
kubectl logs -l app=detection-engine -n siem-production --tail=100

# Verify rules are loaded
curl -s http://detection:8081/api/v1/rules | jq '.rules | length'

# Check rule execution
kubectl exec -it detection-pod -- curl -s localhost:8081/metrics | grep rule_execution

# Test specific rule
curl -X POST http://detection:8081/api/v1/rules/test \
  -H "Content-Type: application/json" \
  -d '{"rule_id": "rule-001", "events": [...]}'
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Rules disabled | Enable rules via API |
| Query errors | Validate rule syntax |
| No matching events | Verify event data matches rule criteria |
| Performance issues | Optimize complex rules |

### 5. Playbook Execution Failures

**Symptoms:**
- Playbooks not executing
- Steps failing
- Actions timing out

**Diagnosis:**
```bash
# Check SOAR service
kubectl logs -l app=soar -n siem-production --tail=100

# List failed executions
curl -s http://soar:8082/api/v1/executions?status=failed | jq

# Check specific execution
curl -s http://soar:8082/api/v1/executions/<execution-id> | jq

# Test connector
curl -X POST http://soar:8082/api/v1/connectors/<connector-id>/test
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Connector failure | Check credentials, test connectivity |
| Action timeout | Increase timeout, check external API |
| Invalid parameters | Verify playbook configuration |
| Rate limiting | Implement retry logic, reduce frequency |

### 6. Database Issues

**Symptoms:**
- Query failures
- Slow performance
- Disk space warnings

**Diagnosis:**
```bash
# ClickHouse health
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT * FROM system.metrics"

# Check disk usage
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT database, table, formatReadableSize(sum(bytes)) as size FROM system.parts WHERE active GROUP BY database, table ORDER BY sum(bytes) DESC"

# Check replication
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT * FROM system.replicas"

# Check merges
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "SELECT * FROM system.merges"
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Disk full | Add storage, implement TTL |
| Slow queries | Add indexes, optimize schema |
| Replication lag | Check network, increase bandwidth |
| Too many parts | Wait for merges, optimize insert batches |

### 7. Authentication/Authorization Issues

**Symptoms:**
- 401 Unauthorized errors
- 403 Forbidden errors
- Token expiration

**Diagnosis:**
```bash
# Check auth logs
kubectl logs -l app=gateway -n siem-production | grep -i auth

# Verify JWT secret
kubectl get secret api-keys -n siem-production -o jsonpath='{.data.jwt-secret}' | base64 -d

# Test authentication
curl -v -H "Authorization: Bearer <token>" http://gateway:8080/api/v1/alerts
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Invalid token | Regenerate token |
| Expired token | Refresh token |
| Missing permissions | Update RBAC policies |
| Clock skew | Sync NTP across nodes |

## Emergency Procedures

### Service Recovery
```bash
# Restart specific service
kubectl rollout restart deployment/<service> -n siem-production

# Restart all services
kubectl rollout restart deployment -n siem-production

# Force delete stuck pod
kubectl delete pod <pod-name> -n siem-production --force --grace-period=0
```

### Database Recovery
```bash
# Stop writes
kubectl scale deployment pipeline --replicas=0 -n siem-production

# Check data integrity
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client -q "CHECK TABLE events"

# Restore from backup
./scripts/restore-clickhouse.sh --backup-name <backup>

# Resume operations
kubectl scale deployment pipeline --replicas=3 -n siem-production
```

### Kafka Recovery
```bash
# Check broker status
kubectl exec -it kafka-0 -n siem-production -- \
  bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092

# Reset consumer offset (if needed)
kubectl exec -it kafka-0 -n siem-production -- \
  bin/kafka-consumer-groups.sh --bootstrap-server localhost:9092 \
  --group siem-pipeline --reset-offsets --to-earliest --execute --topic events
```

## Getting Help

### Log Collection for Support
```bash
# Collect diagnostic bundle
./scripts/collect-diagnostics.sh --output /tmp/diagnostics.tar.gz

# Contents include:
# - Pod logs
# - Service descriptions
# - Events
# - Resource usage
# - Configuration (sanitized)
```

### Contact Information
- Platform Team: platform-team@example.com
- On-call: +1-XXX-XXX-XXXX
- Slack: #siem-platform-support
