#!/bin/bash
#
# Rollback Script for SIEM-SOAR Platform
# Supports instant rollback to previous deployment
#
# Usage: ./rollback.sh [options]
#

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-siem-prod}"
SERVICE_NAME="siem-platform"
ROLLBACK_TIMEOUT="${ROLLBACK_TIMEOUT:-300}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"; }

# Get previous revision
get_previous_revision() {
    local deployment=$1
    local current_revision=$(kubectl rollout history deployment/${deployment} -n ${NAMESPACE} | \
        grep -v "REVISION\|^$" | tail -2 | head -1 | awk '{print $1}')
    echo "$current_revision"
}

# Get current revision
get_current_revision() {
    local deployment=$1
    kubectl rollout history deployment/${deployment} -n ${NAMESPACE} | \
        grep -v "REVISION\|^$" | tail -1 | awk '{print $1}'
}

# List available revisions
list_revisions() {
    local deployment=$1
    log_info "Available revisions for ${deployment}:"
    kubectl rollout history deployment/${deployment} -n ${NAMESPACE}
}

# Rollback to previous revision
rollback_to_previous() {
    local deployment=$1

    log_step "Rolling back ${deployment} to previous revision..."

    local current=$(get_current_revision ${deployment})
    local previous=$(get_previous_revision ${deployment})

    log_info "Current revision: ${current}"
    log_info "Target revision: ${previous}"

    if [[ -z "$previous" ]]; then
        log_error "No previous revision found for ${deployment}"
        return 1
    fi

    # Execute rollback
    kubectl rollout undo deployment/${deployment} -n ${NAMESPACE}

    # Wait for rollback to complete
    log_info "Waiting for rollback to complete..."
    if ! kubectl rollout status deployment/${deployment} -n ${NAMESPACE} --timeout=${ROLLBACK_TIMEOUT}s; then
        log_error "Rollback timeout. Current status:"
        kubectl get pods -n ${NAMESPACE} -l app=${deployment}
        return 1
    fi

    log_info "Rollback completed successfully"
    return 0
}

# Rollback to specific revision
rollback_to_revision() {
    local deployment=$1
    local revision=$2

    log_step "Rolling back ${deployment} to revision ${revision}..."

    # Verify revision exists
    if ! kubectl rollout history deployment/${deployment} -n ${NAMESPACE} | grep -q "^${revision}"; then
        log_error "Revision ${revision} not found for ${deployment}"
        return 1
    fi

    # Execute rollback
    kubectl rollout undo deployment/${deployment} -n ${NAMESPACE} --to-revision=${revision}

    # Wait for rollback
    log_info "Waiting for rollback to complete..."
    if ! kubectl rollout status deployment/${deployment} -n ${NAMESPACE} --timeout=${ROLLBACK_TIMEOUT}s; then
        log_error "Rollback timeout"
        return 1
    fi

    log_info "Rollback to revision ${revision} completed"
    return 0
}

# Rollback all platform components
rollback_all() {
    log_step "Rolling back all SIEM-SOAR components..."

    local deployments=(
        "gateway"
        "detection"
        "soar"
        "query"
        "collector"
        "pipeline"
        "alert"
        "case"
    )

    local failed=0

    for deploy in "${deployments[@]}"; do
        local full_name="${SERVICE_NAME}-${deploy}"
        log_info "Processing ${full_name}..."

        if kubectl get deployment ${full_name} -n ${NAMESPACE} &>/dev/null; then
            if ! rollback_to_previous ${full_name}; then
                log_error "Failed to rollback ${full_name}"
                ((failed++))
            fi
        else
            log_warn "Deployment ${full_name} not found, skipping"
        fi
    done

    if [[ $failed -gt 0 ]]; then
        log_error "${failed} rollbacks failed"
        return 1
    fi

    log_info "All rollbacks completed successfully"
    return 0
}

# Verify rollback
verify_rollback() {
    local deployment=$1

    log_step "Verifying rollback for ${deployment}..."

    # Check deployment status
    local ready=$(kubectl get deployment ${deployment} -n ${NAMESPACE} \
        -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local desired=$(kubectl get deployment ${deployment} -n ${NAMESPACE} \
        -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")

    if [[ "$ready" != "$desired" ]]; then
        log_error "Deployment not ready: ${ready}/${desired}"
        return 1
    fi

    # Check pod status
    local pod_status=$(kubectl get pods -n ${NAMESPACE} -l app=${deployment} \
        -o jsonpath='{.items[*].status.phase}' | tr ' ' '\n' | sort | uniq -c)

    log_info "Pod status:\n${pod_status}"

    # Check for any non-Running pods
    if kubectl get pods -n ${NAMESPACE} -l app=${deployment} | grep -v "Running\|Completed\|NAME"; then
        log_warn "Some pods are not in Running state"
    fi

    log_info "Verification completed"
    return 0
}

# Create rollback checkpoint
create_checkpoint() {
    local deployment=$1
    local checkpoint_file="/tmp/rollback_checkpoint_${deployment}_$(date +%Y%m%d_%H%M%S).yaml"

    log_step "Creating checkpoint for ${deployment}..."

    kubectl get deployment ${deployment} -n ${NAMESPACE} -o yaml > ${checkpoint_file}

    log_info "Checkpoint saved to ${checkpoint_file}"
    echo "${checkpoint_file}"
}

# Emergency stop - scale to 0
emergency_stop() {
    local deployment=$1

    log_warn "EMERGENCY STOP: Scaling ${deployment} to 0 replicas"

    kubectl scale deployment ${deployment} -n ${NAMESPACE} --replicas=0

    log_info "Deployment scaled to 0"
}

# Show usage
usage() {
    cat << EOF
SIEM-SOAR Platform Rollback Script

Usage: $0 [command] [options]

Commands:
  previous <deployment>           Rollback to previous revision
  revision <deployment> <rev>     Rollback to specific revision
  all                             Rollback all platform components
  list <deployment>               List available revisions
  verify <deployment>             Verify deployment status
  checkpoint <deployment>         Create rollback checkpoint
  emergency <deployment>          Emergency stop (scale to 0)

Options:
  -n, --namespace    Kubernetes namespace (default: siem-prod)
  -t, --timeout      Rollback timeout in seconds (default: 300)

Examples:
  $0 previous siem-platform-gateway
  $0 revision siem-platform-gateway 5
  $0 all
  $0 list siem-platform-gateway
  $0 emergency siem-platform-gateway

EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -t|--timeout)
                ROLLBACK_TIMEOUT="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    ARGS=("$@")
}

# Main
main() {
    parse_args "$@"
    set -- "${ARGS[@]}"

    local command="${1:-help}"

    case "$command" in
        previous)
            [[ -z "${2:-}" ]] && { log_error "Deployment name required"; exit 1; }
            rollback_to_previous "$2"
            verify_rollback "$2"
            ;;
        revision)
            [[ -z "${2:-}" || -z "${3:-}" ]] && { log_error "Deployment and revision required"; exit 1; }
            rollback_to_revision "$2" "$3"
            verify_rollback "$2"
            ;;
        all)
            rollback_all
            ;;
        list)
            [[ -z "${2:-}" ]] && { log_error "Deployment name required"; exit 1; }
            list_revisions "$2"
            ;;
        verify)
            [[ -z "${2:-}" ]] && { log_error "Deployment name required"; exit 1; }
            verify_rollback "$2"
            ;;
        checkpoint)
            [[ -z "${2:-}" ]] && { log_error "Deployment name required"; exit 1; }
            create_checkpoint "$2"
            ;;
        emergency)
            [[ -z "${2:-}" ]] && { log_error "Deployment name required"; exit 1; }
            emergency_stop "$2"
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
