#!/bin/bash
# Blue-Green Deployment Strategy
# Deploys new version alongside old, then switches traffic atomically

set -euo pipefail

NAMESPACE="${NAMESPACE:-siem-soar}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TIMEOUT="${TIMEOUT:-600}"
WARM_UP_DURATION="${WARM_UP_DURATION:-60}"

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
        --warm-up) WARM_UP_DURATION="$2"; shift 2 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Determine current and new colors
get_current_color() {
    local current=$(kubectl get service -n "$NAMESPACE" api -o jsonpath='{.spec.selector.color}' 2>/dev/null || echo "blue")
    echo "$current"
}

get_new_color() {
    local current=$(get_current_color)
    [[ "$current" == "blue" ]] && echo "green" || echo "blue"
}

CURRENT_COLOR=$(get_current_color)
NEW_COLOR=$(get_new_color)

log_info "Current color: $CURRENT_COLOR"
log_info "New color: $NEW_COLOR"

# Deploy new version
deploy_new_version() {
    log_info "Deploying new version to $NEW_COLOR environment..."

    # Create deployment for new color
    kubectl set image deployment/api-${NEW_COLOR} -n "$NAMESPACE" \
        api="siem-soar/api:${IMAGE_TAG}" || \
    kubectl create deployment api-${NEW_COLOR} -n "$NAMESPACE" \
        --image="siem-soar/api:${IMAGE_TAG}" \
        --replicas=3

    # Add color label
    kubectl patch deployment api-${NEW_COLOR} -n "$NAMESPACE" -p \
        '{"spec":{"template":{"metadata":{"labels":{"color":"'"${NEW_COLOR}"'"}}}}}'

    log_info "Waiting for new deployment to be ready..."
    kubectl rollout status deployment/api-${NEW_COLOR} -n "$NAMESPACE" --timeout="${TIMEOUT}s"

    log_info "✓ New version deployed to $NEW_COLOR"
}

# Warm up new version
warm_up() {
    log_info "Warming up new version ($WARM_UP_DURATION seconds)..."

    # Send test traffic to new version
    local pod=$(kubectl get pod -n "$NAMESPACE" -l "app=api,color=${NEW_COLOR}" -o jsonpath='{.items[0].metadata.name}')

    for i in $(seq 1 10); do
        kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/health >/dev/null || true
        sleep 1
    done

    # Wait for warm-up duration
    sleep "$WARM_UP_DURATION"

    log_info "✓ Warm-up complete"
}

# Health check new version
health_check_new_version() {
    log_info "Running health checks on new version..."

    local pods=$(kubectl get pods -n "$NAMESPACE" -l "app=api,color=${NEW_COLOR}" -o jsonpath='{.items[*].metadata.name}')

    for pod in $pods; do
        log_info "Checking pod: $pod"

        # Health check
        if ! kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/health >/dev/null; then
            log_error "Health check failed for $pod"
            return 1
        fi

        # Readiness check
        if ! kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/ready >/dev/null; then
            log_error "Readiness check failed for $pod"
            return 1
        fi
    done

    log_info "✓ All health checks passed"
}

# Switch traffic
switch_traffic() {
    log_info "Switching traffic from $CURRENT_COLOR to $NEW_COLOR..."

    # Update service selector to point to new color
    kubectl patch service api -n "$NAMESPACE" -p \
        '{"spec":{"selector":{"color":"'"${NEW_COLOR}"'"}}}'

    log_info "✓ Traffic switched to $NEW_COLOR"

    # Wait for traffic to stabilize
    log_info "Monitoring for 30 seconds..."
    sleep 30
}

# Verify traffic switch
verify_traffic() {
    log_info "Verifying traffic is flowing to new version..."

    # Check service endpoints
    local endpoints=$(kubectl get endpoints api -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}')
    log_info "Active endpoints: $endpoints"

    # Test external access
    local api_url="http://$(kubectl get svc -n "$NAMESPACE" api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"

    for i in $(seq 1 5); do
        if curl -sf "${api_url}/health" >/dev/null; then
            log_info "✓ External access verified (attempt $i/5)"
        else
            log_error "External access failed (attempt $i/5)"
            return 1
        fi
        sleep 2
    done

    log_info "✓ Traffic verification complete"
}

# Cleanup old version
cleanup_old_version() {
    log_info "Cleaning up old version ($CURRENT_COLOR)..."

    read -p "Delete old $CURRENT_COLOR deployment? (yes/no): " -r
    if [[ $REPLY =~ ^yes$ ]]; then
        kubectl delete deployment api-${CURRENT_COLOR} -n "$NAMESPACE" || true
        log_info "✓ Old deployment deleted"
    else
        log_warn "Keeping old deployment for manual cleanup"
        log_warn "Run: kubectl delete deployment api-${CURRENT_COLOR} -n $NAMESPACE"
    fi
}

# Rollback
rollback() {
    log_error "Rolling back to $CURRENT_COLOR..."

    # Switch service back to old color
    kubectl patch service api -n "$NAMESPACE" -p \
        '{"spec":{"selector":{"color":"'"${CURRENT_COLOR}"'"}}}'

    # Delete failed deployment
    kubectl delete deployment api-${NEW_COLOR} -n "$NAMESPACE" || true

    log_warn "Rollback complete - traffic restored to $CURRENT_COLOR"
}

# Main execution
main() {
    log_info "=== Blue-Green Deployment ==="
    log_info "Namespace: $NAMESPACE"
    log_info "Image tag: $IMAGE_TAG"
    log_info "Current color: $CURRENT_COLOR"
    log_info "New color: $NEW_COLOR"
    echo

    if ! deploy_new_version; then
        log_error "Deployment failed"
        exit 1
    fi

    warm_up

    if ! health_check_new_version; then
        rollback
        exit 1
    fi

    switch_traffic

    if ! verify_traffic; then
        rollback
        exit 1
    fi

    cleanup_old_version

    log_info "=== Blue-Green Deployment Complete ==="
    log_info "Active color: $NEW_COLOR"
    log_info "Version: $IMAGE_TAG"
}

main
