# SIEM/SOAR Platform Deployment Guide

## Overview

This guide covers the deployment of the SIEM/SOAR platform across different environments. The platform is designed for Kubernetes-native deployment with support for both GKE and EKS.

## Prerequisites

### Required Tools
- Kubernetes 1.28+
- Helm 3.12+
- kubectl configured for target cluster
- Terraform 1.5+ (for infrastructure provisioning)
- Docker 24+ (for local development)

### Infrastructure Requirements

| Component | Development | Staging | Production |
|-----------|------------|---------|------------|
| Kubernetes Nodes | 3 | 5 | 10+ |
| Node Size | n2-standard-4 | n2-standard-8 | n2-standard-16 |
| ClickHouse | 1 node, 100GB | 3 nodes, 500GB | 6+ nodes, 2TB+ |
| Kafka | 1 broker | 3 brokers | 5+ brokers |
| Redis | 1 node | 3 nodes (sentinel) | 6 nodes (cluster) |

## Deployment Steps

### 1. Infrastructure Provisioning

#### GCP/GKE
```bash
cd infra/terraform/environments/prod

# Initialize Terraform
terraform init

# Review plan
terraform plan -var-file="terraform.tfvars"

# Apply infrastructure
terraform apply -var-file="terraform.tfvars"

# Get kubeconfig
gcloud container clusters get-credentials siem-cluster --region us-central1
```

#### AWS/EKS
```bash
cd infra/terraform/environments/prod

# Initialize with AWS backend
terraform init -backend-config="backend-aws.hcl"

# Apply
terraform apply -var="cloud_provider=aws"

# Update kubeconfig
aws eks update-kubeconfig --name siem-cluster --region us-east-1
```

### 2. Namespace Setup

```bash
# Create namespaces
kubectl apply -f infra/k8s/namespaces/namespaces.yaml

# Verify
kubectl get namespaces | grep siem
```

### 3. Secrets Management

```bash
# Create secrets from files (recommended: use external secrets operator in production)
kubectl create secret generic clickhouse-credentials \
  --namespace siem-production \
  --from-literal=username=siem_user \
  --from-literal=password=$(openssl rand -base64 32)

kubectl create secret generic kafka-credentials \
  --namespace siem-production \
  --from-literal=username=siem_kafka \
  --from-literal=password=$(openssl rand -base64 32)

kubectl create secret generic api-keys \
  --namespace siem-production \
  --from-literal=jwt-secret=$(openssl rand -base64 64) \
  --from-literal=encryption-key=$(openssl rand -base64 32)
```

### 4. Deploy Data Layer

#### ClickHouse
```bash
# Deploy ClickHouse operator
helm repo add altinity https://altinity.github.io/clickhouse-operator
helm install clickhouse-operator altinity/clickhouse-operator \
  --namespace siem-production

# Deploy ClickHouse cluster
kubectl apply -f infra/clickhouse/cluster/

# Initialize schema
kubectl exec -it clickhouse-0 -n siem-production -- \
  clickhouse-client < infra/clickhouse/schemas/001_events.sql
```

#### Kafka
```bash
# Deploy Strimzi Kafka operator
helm repo add strimzi https://strimzi.io/charts/
helm install strimzi-kafka-operator strimzi/strimzi-kafka-operator \
  --namespace siem-production

# Deploy Kafka cluster
kubectl apply -f infra/kafka/cluster.yaml
```

### 5. Deploy Application Services

```bash
# Install platform Helm chart
helm install siem-platform infra/helm/siem-platform \
  --namespace siem-production \
  --values infra/helm/siem-platform/values-prod.yaml \
  --wait --timeout 10m

# Verify deployment
kubectl get pods -n siem-production
kubectl get services -n siem-production
```

### 6. Deploy AI Services

```bash
# Deploy AI services
helm install siem-ai infra/helm/ai-services \
  --namespace siem-production \
  --values infra/helm/ai-services/values-prod.yaml

# Verify
kubectl get pods -n siem-production -l app.kubernetes.io/component=ai
```

### 7. Configure Ingress

```bash
# Deploy ingress controller (if not present)
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace

# Apply ingress configuration
kubectl apply -f infra/k8s/ingress/siem-ingress.yaml
```

### 8. Post-Deployment Verification

```bash
# Run deployment verification
./scripts/verify-deployment.sh

# Expected output:
# - All pods Running
# - All services have endpoints
# - ClickHouse responsive
# - Kafka topics created
# - API health check passing
```

## Environment-Specific Configuration

### Development
```yaml
# values-dev.yaml
global:
  environment: development
  replicas: 1

services:
  gateway:
    resources:
      requests:
        cpu: 100m
        memory: 256Mi
```

### Staging
```yaml
# values-staging.yaml
global:
  environment: staging
  replicas: 2

services:
  gateway:
    resources:
      requests:
        cpu: 500m
        memory: 512Mi
```

### Production
```yaml
# values-prod.yaml
global:
  environment: production
  replicas: 3

services:
  gateway:
    resources:
      requests:
        cpu: 1000m
        memory: 1Gi
    autoscaling:
      enabled: true
      minReplicas: 3
      maxReplicas: 10
```

## Rollback Procedure

```bash
# List helm releases
helm list -n siem-production

# Rollback to previous version
helm rollback siem-platform 1 -n siem-production

# Or rollback to specific revision
helm rollback siem-platform <revision> -n siem-production

# Verify rollback
kubectl rollout status deployment/gateway -n siem-production
```

## Troubleshooting

### Common Issues

1. **Pods stuck in Pending**
   ```bash
   kubectl describe pod <pod-name> -n siem-production
   # Check for resource constraints or PVC issues
   ```

2. **ClickHouse connection failures**
   ```bash
   kubectl logs clickhouse-0 -n siem-production
   kubectl exec -it clickhouse-0 -n siem-production -- clickhouse-client -q "SELECT 1"
   ```

3. **Kafka connectivity issues**
   ```bash
   kubectl exec -it kafka-0 -n siem-production -- \
     bin/kafka-topics.sh --bootstrap-server localhost:9092 --list
   ```

## Security Considerations

- Enable Pod Security Standards
- Use Network Policies to restrict traffic
- Enable audit logging
- Rotate secrets regularly
- Enable encryption at rest for ClickHouse
- Use TLS for all service communication
