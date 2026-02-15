# Scaling Guide

This guide covers horizontal and vertical scaling procedures for the SIEM-SOAR platform.

---

## Table of Contents

1. [Scaling Overview](#scaling-overview)
2. [Auto-Scaling Configuration](#auto-scaling-configuration)
3. [Manual Scaling](#manual-scaling)
4. [Component-Specific Scaling](#component-specific-scaling)
5. [Performance Baselines](#performance-baselines)

---

## Scaling Overview

### Current Architecture

```
                    ┌─────────────────────────────────────┐
                    │           Load Balancer             │
                    └─────────────────────────────────────┘
                                      │
                    ┌─────────────────┴─────────────────┐
                    │                                   │
              ┌─────▼─────┐                       ┌─────▼─────┐
              │  Gateway  │                       │  Gateway  │
              │ (3-20 pods)                       │ (replica) │
              └─────┬─────┘                       └─────┬─────┘
                    │                                   │
       ┌────────────┼────────────┬──────────────────────┤
       │            │            │                      │
 ┌─────▼─────┐ ┌────▼────┐ ┌────▼────┐           ┌─────▼─────┐
 │ Detection │ │  SOAR   │ │  Query  │           │ Collector │
 │(3-15 pods)│ │(3-10)   │ │(3-10)   │           │(5-30 pods)│
 └───────────┘ └─────────┘ └─────────┘           └───────────┘
```

### Scaling Dimensions

| Component | Min Replicas | Max Replicas | Scale Factor |
|-----------|--------------|--------------|--------------|
| Gateway | 3 | 20 | CPU, RPS |
| Collector | 5 | 30 | Kafka Lag, EPS |
| Detection | 3 | 15 | Queue Size |
| SOAR | 3 | 10 | Pending Executions |
| Query | 3 | 10 | Query Latency |
| AI Triage | 2 | 8 | GPU Utilization |

---

## Auto-Scaling Configuration

### Horizontal Pod Autoscaler (HPA)

```yaml
# Example HPA for Gateway
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: siem-gateway-hpa
  namespace: siem-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: siem-gateway
  minReplicas: 3
  maxReplicas: 20
  metrics:
    # CPU-based scaling
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    # Memory-based scaling
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    # Custom metric: RPS
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "1000"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
        - type: Percent
          value: 100
          periodSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
```

### Apply HPA

```bash
# Apply HPA configuration
kubectl apply -f infra/k8s/hpa/

# Verify HPA status
kubectl get hpa -n siem-prod

# Watch HPA activity
kubectl get hpa -n siem-prod -w
```

### KEDA (Event-Driven Scaling)

For Kafka-based scaling:

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: siem-collector-scaler
  namespace: siem-prod
spec:
  scaleTargetRef:
    name: siem-collector
  minReplicaCount: 5
  maxReplicaCount: 30
  triggers:
    - type: kafka
      metadata:
        bootstrapServers: kafka:9092
        consumerGroup: siem-collector
        topic: events.raw
        lagThreshold: "10000"
```

---

## Manual Scaling

### Scale Deployment

```bash
# Scale to specific replica count
kubectl scale deployment/siem-gateway -n siem-prod --replicas=10

# Scale multiple deployments
kubectl scale deployment/siem-gateway deployment/siem-collector \
  -n siem-prod --replicas=8
```

### Scale StatefulSet

```bash
# Scale ClickHouse (careful with data)
kubectl scale statefulset/clickhouse -n siem-data --replicas=6
```

### Vertical Scaling (Resource Limits)

```bash
# Update resource limits
kubectl set resources deployment/siem-gateway -n siem-prod \
  --limits=cpu=4,memory=4Gi \
  --requests=cpu=2,memory=2Gi
```

---

## Component-Specific Scaling

### 1. Gateway Service

**When to Scale:**
- HTTP latency > 500ms (p95)
- CPU utilization > 70%
- Request rate > 1000 RPS per pod

**Scale Commands:**
```bash
kubectl scale deployment/siem-gateway -n siem-prod --replicas=10
```

**Vertical Scaling:**
```bash
kubectl set resources deployment/siem-gateway -n siem-prod \
  --limits=cpu=4,memory=4Gi
```

### 2. Collector Service

**When to Scale:**
- Kafka consumer lag > 100K
- EPS per pod > 10K
- Memory pressure

**Scale Commands:**
```bash
kubectl scale deployment/siem-collector -n siem-prod --replicas=15

# Increase partitions for more parallelism
kafka-topics.sh --bootstrap-server kafka:9092 \
  --alter --topic events.raw --partitions 30
```

### 3. Detection Engine

**When to Scale:**
- Detection queue > 10K
- Rule evaluation latency > 1s
- CPU > 80%

**Scale Commands:**
```bash
kubectl scale deployment/siem-detection -n siem-prod --replicas=10
```

### 4. Query Service

**When to Scale:**
- Query latency > 2s (p95)
- Concurrent queries > 100
- Memory pressure from large queries

**Scale Commands:**
```bash
kubectl scale deployment/siem-query -n siem-prod --replicas=8

# Increase query parallelism
kubectl set env deployment/siem-query -n siem-prod \
  MAX_CONCURRENT_QUERIES=50
```

### 5. AI Triage Service

**When to Scale:**
- Inference latency > 500ms
- GPU utilization > 80%
- Pending triage queue > 1000

**Scale Commands:**
```bash
# Scale GPU pods (requires GPU nodes)
kubectl scale deployment/siem-ai-triage -n siem-prod --replicas=4

# Increase batch size for throughput
kubectl set env deployment/siem-ai-triage -n siem-prod \
  BATCH_SIZE=64
```

### 6. ClickHouse

**When to Scale:**
- Query latency > 5s
- Disk usage > 80%
- Insert latency > 1s

**Scale Commands:**
```bash
# Add shard (requires cluster reconfiguration)
# See docs/operations/clickhouse-scaling.md

# Add replica to existing shard
kubectl scale statefulset/clickhouse-shard1 -n siem-data --replicas=3
```

### 7. Kafka

**When to Scale:**
- Consumer lag increasing
- Broker CPU > 70%
- Disk usage > 75%

**Scale Commands:**
```bash
# Add broker
kubectl scale statefulset/kafka -n siem-data --replicas=6

# Rebalance partitions
kafka-reassign-partitions.sh --bootstrap-server kafka:9092 \
  --reassignment-json-file new-assignment.json --execute
```

---

## Performance Baselines

### Target SLOs

| Metric | Target | Alert Threshold |
|--------|--------|-----------------|
| Event Ingestion | 30K EPS | < 10K EPS |
| Detection Latency | < 1s (p95) | > 5s |
| Query Latency | < 2s (p95) | > 10s |
| Alert Generation | < 30s | > 60s |
| Playbook Execution | < 60s | > 120s |
| AI Triage | < 500ms | > 1s |

### Resource Recommendations

| Component | CPU Request | CPU Limit | Memory Request | Memory Limit |
|-----------|-------------|-----------|----------------|--------------|
| Gateway | 500m | 2 | 512Mi | 2Gi |
| Collector | 1 | 4 | 1Gi | 4Gi |
| Detection | 1 | 4 | 2Gi | 8Gi |
| Query | 500m | 2 | 1Gi | 4Gi |
| SOAR | 500m | 2 | 512Mi | 2Gi |
| AI Triage | 2 | 8 | 4Gi | 16Gi |

### Capacity Planning

| EPS Target | Gateway | Collector | Detection | ClickHouse |
|------------|---------|-----------|-----------|------------|
| 10K | 3 | 5 | 3 | 3 nodes |
| 30K | 5 | 10 | 6 | 6 nodes |
| 100K | 15 | 30 | 15 | 12 nodes |
| 300K | 40 | 80 | 40 | 24 nodes |

---

## Scaling Automation

### Scale Script

```bash
#!/bin/bash
# Scale SIEM platform based on load

EPS=$(curl -s http://prometheus:9090/api/v1/query?query=sum(rate(siem_events_ingested_total[5m])) | jq -r '.data.result[0].value[1]')

if (( $(echo "$EPS > 25000" | bc -l) )); then
  echo "High load detected: ${EPS} EPS"
  kubectl scale deployment/siem-collector -n siem-prod --replicas=20
  kubectl scale deployment/siem-detection -n siem-prod --replicas=10
elif (( $(echo "$EPS < 5000" | bc -l) )); then
  echo "Low load detected: ${EPS} EPS"
  kubectl scale deployment/siem-collector -n siem-prod --replicas=5
  kubectl scale deployment/siem-detection -n siem-prod --replicas=3
fi
```

---

## Related Resources

- [Incident Response](./incident_response.md)
- [Troubleshooting](./troubleshooting.md)
- [Performance Tuning](./performance_tuning.md)
