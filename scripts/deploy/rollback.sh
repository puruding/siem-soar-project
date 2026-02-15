#!/bin/bash
# Deployment Rollback Script
# Reverts to previous stable version

set -euo pipefail

NAMESPACE="${NAMESPACE:-siem-soar}"
REVISION="${REVISION:-}"  # Empty means previous
TIMEOUT="${TIMEOUT:-600}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -n, --namespace NS      Kubernetes namespace (default: siem-soar)
    -r, --revision REV      Specific revision to rollback to (default: previous)
    --timeout SECONDS       Rollback timeout (default: 600)
    -h, --help              Show this help message

Examples:
    # Rollback to previous revision
    $0

    # Rollback to specific revision
    $0 --revision 5

    # Rollback with custom namespace
    $0 --namespace siem-soar-prod
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -r|--revision) REVISION="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Show rollout history
show_history() {
    log_info "Deployment history for api:"
    kubectl rollout history deployment/api -n "$NAMESPACE"
    echo

    log_info "Deployment history for worker:"
    kubectl rollout history deployment/worker -n "$NAMESPACE"
    echo

    log_info "Deployment history for collector:"
    kubectl rollout history deployment/collector -n "$NAMESPACE"
    echo
}

# Get current revision
get_current_revision() {
    kubectl get deployment api -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}'
}

# Confirm rollback
confirm_rollback() {
    local current_rev=$(get_current_revision)

    log_warn "!!! PRODUCTION ROLLBACK !!!"
    log_warn "Current revision: $current_rev"

    if [[ -n "$REVISION" ]]; then
        log_warn "Rollback target: Revision $REVISION"
    else
        log_warn "Rollback target: Previous revision"
    fi

    echo
    read -p "Type 'ROLLBACK' to confirm: " -r

    if [[ ! $REPLY == "ROLLBACK" ]]; then
        log_warn "Rollback cancelled"
        exit 0
    fi
}

# Execute rollback
execute_rollback() {
    log_info "Executing rollback..."

    local rollback_args=("rollout" "undo")

    if [[ -n "$REVISION" ]]; then
        rollback_args+=("--to-revision=$REVISION")
    fi

    # Rollback API
    log_info "Rolling back API deployment..."
    kubectl "${rollback_args[@]}" deployment/api -n "$NAMESPACE"

    # Rollback Worker
    log_info "Rolling back Worker deployment..."
    kubectl "${rollback_args[@]}" deployment/worker -n "$NAMESPACE"

    # Rollback Collector
    log_info "Rolling back Collector deployment..."
    kubectl "${rollback_args[@]}" deployment/collector -n "$NAMESPACE"

    log_info "Waiting for rollback to complete..."
    kubectl rollout status deployment/api -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    kubectl rollout status deployment/worker -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    kubectl rollout status deployment/collector -n "$NAMESPACE" --timeout="${TIMEOUT}s"

    log_info "✓ Rollback complete"
}

# Verify rollback
verify_rollback() {
    log_info "Verifying rollback..."

    # Check pod status
    local not_ready=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running | wc -l)
    if [[ $not_ready -gt 1 ]]; then  # 1 for header line
        log_error "Some pods are not running"
        kubectl get pods -n "$NAMESPACE"
        return 1
    fi

    # Health checks
    log_info "Running health checks..."
    local pods=$(kubectl get pods -n "$NAMESPACE" -l app=api -o jsonpath='{.items[*].metadata.name}')

    for pod in $pods; do
        if ! kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/health >/dev/null; then
            log_error "Health check failed for $pod"
            return 1
        fi
    done

    log_info "✓ All health checks passed"
}

# Create incident record
create_incident_record() {
    log_info "Creating incident record..."

    local incident_file="/var/log/siem-soar/rollback-$(date +%Y%m%d_%H%M%S).json"

    cat > "$incident_file" <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "namespace": "$NAMESPACE",
  "from_revision": "$(get_current_revision)",
  "to_revision": "${REVISION:-previous}",
  "reason": "Manual rollback",
  "operator": "$(whoami)",
  "context": "$(kubectl config current-context)"
}
EOF

    log_info "Incident record: $incident_file"
}

# Main execution
main() {
    log_info "=== SIEM-SOAR Deployment Rollback ==="
    log_info "Namespace: $NAMESPACE"
    echo

    show_history

    confirm_rollback

    execute_rollback

    if ! verify_rollback; then
        log_error "Rollback verification failed"
        log_error "Manual investigation required"
        exit 1
    fi

    create_incident_record

    log_info "=== Rollback Complete ==="
    log_info "System restored to previous state"
    log_warn "Please monitor system closely for next 30 minutes"
}

main "$@"
