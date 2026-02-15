#!/bin/bash
# Canary Deployment Strategy
# Gradually shifts traffic to new version with monitoring

set -euo pipefail

NAMESPACE="${NAMESPACE:-siem-soar}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TIMEOUT="${TIMEOUT:-600}"
CANARY_STEPS="${CANARY_STEPS:-10,25,50,75,100}"  # Percentage steps
STEP_DURATION="${STEP_DURATION:-300}"  # Seconds between steps

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -t|--tag) IMAGE_TAG="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --steps) CANARY_STEPS="$2"; shift 2 ;;
        --step-duration) STEP_DURATION="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Deploy canary version
deploy_canary() {
    local weight=$1

    log_info "Deploying canary with $weight% traffic..."

    # Calculate replicas based on weight
    local total_replicas=10
    local canary_replicas=$(( (total_replicas * weight) / 100 ))
    local stable_replicas=$(( total_replicas - canary_replicas ))

    [[ $canary_replicas -lt 1 ]] && canary_replicas=1

    log_info "Stable replicas: $stable_replicas"
    log_info "Canary replicas: $canary_replicas"

    # Scale canary deployment
    if ! kubectl get deployment api-canary -n "$NAMESPACE" &>/dev/null; then
        # Create canary deployment
        kubectl create deployment api-canary -n "$NAMESPACE" \
            --image="siem-soar/api:${IMAGE_TAG}" \
            --replicas="$canary_replicas"

        kubectl patch deployment api-canary -n "$NAMESPACE" -p \
            '{"spec":{"template":{"metadata":{"labels":{"version":"canary"}}}}}'
    else
        # Update existing canary
        kubectl set image deployment/api-canary -n "$NAMESPACE" \
            api="siem-soar/api:${IMAGE_TAG}"
        kubectl scale deployment api-canary -n "$NAMESPACE" --replicas="$canary_replicas"
    fi

    # Scale stable deployment
    kubectl scale deployment api -n "$NAMESPACE" --replicas="$stable_replicas"

    # Wait for rollout
    kubectl rollout status deployment/api-canary -n "$NAMESPACE" --timeout="${TIMEOUT}s"

    log_info "✓ Canary deployment at $weight% traffic"
}

# Monitor metrics
monitor_metrics() {
    local duration=$1

    log_info "Monitoring canary metrics for ${duration}s..."

    local start_time=$(date +%s)
    local end_time=$((start_time + duration))

    while [[ $(date +%s) -lt $end_time ]]; do
        # Get error rates
        local canary_errors=$(kubectl exec -n "$NAMESPACE" deployment/prometheus -- \
            promtool query instant 'rate(http_requests_total{version="canary",status=~"5.."}[5m])' 2>/dev/null | \
            grep -oP '\d+\.\d+' | head -1 || echo "0")

        local stable_errors=$(kubectl exec -n "$NAMESPACE" deployment/prometheus -- \
            promtool query instant 'rate(http_requests_total{version="stable",status=~"5.."}[5m])' 2>/dev/null | \
            grep -oP '\d+\.\d+' | head -1 || echo "0")

        log_info "Error rates - Canary: $canary_errors, Stable: $stable_errors"

        # Check if canary error rate is significantly higher
        if (( $(echo "$canary_errors > $stable_errors * 2" | bc -l 2>/dev/null || echo 0) )); then
            log_error "Canary error rate is too high"
            return 1
        fi

        # Get latency
        local canary_latency=$(kubectl exec -n "$NAMESPACE" deployment/prometheus -- \
            promtool query instant 'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{version="canary"}[5m]))' 2>/dev/null | \
            grep -oP '\d+\.\d+' | head -1 || echo "0")

        log_info "Canary p99 latency: ${canary_latency}s"

        # Check latency threshold
        if (( $(echo "$canary_latency > 1.0" | bc -l 2>/dev/null || echo 0) )); then
            log_warn "Canary latency is high"
        fi

        local remaining=$((end_time - $(date +%s)))
        log_info "Monitoring for ${remaining}s more..."
        sleep 30
    done

    log_info "✓ Monitoring period complete"
    return 0
}

# Rollback canary
rollback_canary() {
    log_error "Rolling back canary deployment..."

    # Scale canary to 0
    kubectl scale deployment api-canary -n "$NAMESPACE" --replicas=0

    # Restore stable to full capacity
    kubectl scale deployment api -n "$NAMESPACE" --replicas=10

    log_warn "Canary rollback complete"
}

# Promote canary to stable
promote_canary() {
    log_info "Promoting canary to stable..."

    # Update stable deployment to canary image
    kubectl set image deployment/api -n "$NAMESPACE" \
        api="siem-soar/api:${IMAGE_TAG}"

    # Wait for rollout
    kubectl rollout status deployment/api -n "$NAMESPACE" --timeout="${TIMEOUT}s"

    # Delete canary deployment
    kubectl delete deployment api-canary -n "$NAMESPACE"

    # Restore full replica count
    kubectl scale deployment api -n "$NAMESPACE" --replicas=10

    log_info "✓ Canary promoted to stable"
}

# Main execution
main() {
    log_info "=== Canary Deployment ==="
    log_info "Namespace: $NAMESPACE"
    log_info "Image tag: $IMAGE_TAG"
    log_info "Traffic steps: $CANARY_STEPS"
    log_info "Step duration: ${STEP_DURATION}s"
    echo

    # Convert steps to array
    IFS=',' read -ra STEPS <<< "$CANARY_STEPS"

    # Execute canary rollout
    for step in "${STEPS[@]}"; do
        log_info "=== Step: ${step}% traffic to canary ==="

        if ! deploy_canary "$step"; then
            rollback_canary
            exit 1
        fi

        if ! monitor_metrics "$STEP_DURATION"; then
            log_error "Metrics indicate problems with canary"
            rollback_canary
            exit 1
        fi

        log_info "✓ Step ${step}% successful"
        echo

        # Prompt for manual approval at key milestones
        if [[ "$step" == "50" ]] || [[ "$step" == "100" ]]; then
            read -p "Continue to next step? (yes/no): " -r
            if [[ ! $REPLY =~ ^yes$ ]]; then
                log_warn "Canary deployment paused by user"
                rollback_canary
                exit 1
            fi
        fi
    done

    # All steps passed, promote canary
    promote_canary

    log_info "=== Canary Deployment Complete ==="
    log_info "Version: $IMAGE_TAG"
    log_info "Status: Fully promoted to production"
}

main
