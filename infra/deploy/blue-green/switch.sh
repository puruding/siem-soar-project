#!/bin/bash
#
# Blue-Green Deployment Switch Script
# Switches traffic between Blue and Green environments
#
# Usage: ./switch.sh [blue|green]
#

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-siem-prod}"
SERVICE_NAME="siem-platform"
INGRESS_NAME="siem-platform-ingress"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get current active version
get_current_version() {
    kubectl get ingress ${INGRESS_NAME} -n ${NAMESPACE} \
        -o jsonpath='{.metadata.annotations.siem\.io/active-version}' 2>/dev/null || echo "unknown"
}

# Check if deployment is ready
check_deployment_ready() {
    local version=$1
    local deployment="${SERVICE_NAME}-${version}"

    log_info "Checking deployment ${deployment}..."

    # Check if deployment exists
    if ! kubectl get deployment ${deployment} -n ${NAMESPACE} &>/dev/null; then
        log_error "Deployment ${deployment} not found"
        return 1
    fi

    # Check replica count
    local ready=$(kubectl get deployment ${deployment} -n ${NAMESPACE} \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local desired=$(kubectl get deployment ${deployment} -n ${NAMESPACE} \
        -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$ready" != "$desired" ]] || [[ "$ready" == "0" ]]; then
        log_error "Deployment ${deployment} not ready: ${ready}/${desired} replicas"
        return 1
    fi

    log_info "Deployment ${deployment} is ready: ${ready}/${desired} replicas"
    return 0
}

# Health check target service
health_check() {
    local version=$1
    local service="${SERVICE_NAME}-${version}"

    log_info "Running health check on ${service}..."

    # Get service ClusterIP
    local service_ip=$(kubectl get service ${service} -n ${NAMESPACE} \
        -o jsonpath='{.spec.clusterIP}' 2>/dev/null)

    if [[ -z "$service_ip" ]]; then
        log_error "Could not get service IP for ${service}"
        return 1
    fi

    # Run health check from within cluster
    local health_result=$(kubectl run health-check-${version}-$$ --rm -i --restart=Never \
        --image=curlimages/curl:latest \
        -- curl -s -o /dev/null -w "%{http_code}" \
        "http://${service_ip}:80/health" 2>/dev/null || echo "000")

    if [[ "$health_result" == "200" ]]; then
        log_info "Health check passed for ${service}"
        return 0
    else
        log_error "Health check failed for ${service}: HTTP ${health_result}"
        return 1
    fi
}

# Switch traffic to target version
switch_traffic() {
    local target_version=$1
    local current_version=$(get_current_version)

    log_info "Current active version: ${current_version}"
    log_info "Target version: ${target_version}"

    if [[ "$current_version" == "$target_version" ]]; then
        log_warn "Already on ${target_version} version. No switch needed."
        return 0
    fi

    # Verify target deployment is ready
    if ! check_deployment_ready ${target_version}; then
        log_error "Target deployment not ready. Aborting switch."
        return 1
    fi

    # Run health checks
    if ! health_check ${target_version}; then
        log_error "Health check failed. Aborting switch."
        return 1
    fi

    log_info "Switching traffic to ${target_version}..."

    # Update Ingress to point to new service
    kubectl patch ingress ${INGRESS_NAME} -n ${NAMESPACE} --type=json \
        -p="[
            {\"op\": \"replace\", \"path\": \"/spec/rules/0/http/paths/0/backend/service/name\", \"value\": \"${SERVICE_NAME}-${target_version}\"},
            {\"op\": \"replace\", \"path\": \"/metadata/annotations/siem.io~1active-version\", \"value\": \"${target_version}\"}
        ]"

    # Update main service selector
    kubectl patch service ${SERVICE_NAME} -n ${NAMESPACE} --type=json \
        -p="[{\"op\": \"replace\", \"path\": \"/spec/selector/version\", \"value\": \"${target_version}\"}]"

    log_info "Traffic switched to ${target_version}"

    # Verify switch
    sleep 5
    local new_version=$(get_current_version)
    if [[ "$new_version" == "$target_version" ]]; then
        log_info "Switch verified. Active version: ${new_version}"
    else
        log_error "Switch verification failed. Expected ${target_version}, got ${new_version}"
        return 1
    fi

    # Post-switch health check
    log_info "Running post-switch health check..."
    sleep 10
    if health_check ${target_version}; then
        log_info "Post-switch health check passed"
    else
        log_warn "Post-switch health check failed. Consider rollback."
    fi

    return 0
}

# Rollback to previous version
rollback() {
    local current_version=$(get_current_version)
    local target_version

    if [[ "$current_version" == "blue" ]]; then
        target_version="green"
    else
        target_version="blue"
    fi

    log_warn "Rolling back from ${current_version} to ${target_version}..."
    switch_traffic ${target_version}
}

# Show status
show_status() {
    log_info "Current deployment status:"
    echo ""

    local current=$(get_current_version)
    echo "Active version: ${current}"
    echo ""

    echo "Blue deployment:"
    kubectl get deployment ${SERVICE_NAME}-blue -n ${NAMESPACE} 2>/dev/null || echo "  Not found"
    echo ""

    echo "Green deployment:"
    kubectl get deployment ${SERVICE_NAME}-green -n ${NAMESPACE} 2>/dev/null || echo "  Not found"
    echo ""

    echo "Services:"
    kubectl get services -n ${NAMESPACE} -l app=${SERVICE_NAME} 2>/dev/null
    echo ""

    echo "Ingress:"
    kubectl get ingress ${INGRESS_NAME} -n ${NAMESPACE} 2>/dev/null
}

# Main
main() {
    local command="${1:-status}"

    case "$command" in
        blue)
            switch_traffic "blue"
            ;;
        green)
            switch_traffic "green"
            ;;
        rollback)
            rollback
            ;;
        status)
            show_status
            ;;
        *)
            echo "Usage: $0 [blue|green|rollback|status]"
            echo ""
            echo "Commands:"
            echo "  blue     - Switch traffic to blue deployment"
            echo "  green    - Switch traffic to green deployment"
            echo "  rollback - Rollback to previous version"
            echo "  status   - Show current deployment status"
            exit 1
            ;;
    esac
}

main "$@"
