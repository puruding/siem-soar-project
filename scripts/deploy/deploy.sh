#!/bin/bash
# Production Deployment Script
# Handles safe deployment with health checks and rollback capability

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Configuration
ENVIRONMENT="${ENVIRONMENT:-prod}"
NAMESPACE="${NAMESPACE:-siem-soar}"
DEPLOYMENT_STRATEGY="${DEPLOYMENT_STRATEGY:-rolling}"  # rolling, blue-green, canary
DRY_RUN="${DRY_RUN:-false}"
HELM_CHART="${HELM_CHART:-${PROJECT_ROOT}/infra/helm/siem-soar}"
VALUES_FILE="${VALUES_FILE:-${PROJECT_ROOT}/infra/helm/values/prod.yaml}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
TIMEOUT="${TIMEOUT:-600}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $*"; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
    -e, --environment ENV       Target environment (default: prod)
    -n, --namespace NS          Kubernetes namespace (default: siem-soar)
    -s, --strategy STRATEGY     Deployment strategy: rolling, blue-green, canary (default: rolling)
    -t, --tag TAG              Docker image tag (default: latest)
    -d, --dry-run              Perform dry run without applying changes
    --timeout SECONDS          Deployment timeout in seconds (default: 600)
    -h, --help                 Show this help message

Examples:
    # Standard rolling deployment
    $0 --tag v1.0.0

    # Blue-green deployment
    $0 --strategy blue-green --tag v1.0.0

    # Canary deployment
    $0 --strategy canary --tag v1.0.0

    # Dry run to preview changes
    $0 --dry-run --tag v1.0.0
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment) ENVIRONMENT="$2"; shift 2 ;;
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -s|--strategy) DEPLOYMENT_STRATEGY="$2"; shift 2 ;;
        -t|--tag) IMAGE_TAG="$2"; shift 2 ;;
        -d|--dry-run) DRY_RUN=true; shift ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Pre-flight checks
preflight_checks() {
    log_step "Running pre-flight checks..."

    # Check required tools
    for tool in kubectl helm; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done

    # Verify kubectl context
    CURRENT_CONTEXT=$(kubectl config current-context)
    log_info "Current kubectl context: $CURRENT_CONTEXT"

    if [[ "$ENVIRONMENT" == "prod" ]] && [[ ! "$CURRENT_CONTEXT" =~ prod ]]; then
        log_warn "Context '$CURRENT_CONTEXT' doesn't match production environment"
        read -p "Continue anyway? (yes/no): " -r
        [[ ! $REPLY =~ ^yes$ ]] && exit 0
    fi

    # Verify namespace
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_error "Namespace not found: $NAMESPACE"
        exit 1
    fi

    # Verify Helm chart
    if [[ ! -d "$HELM_CHART" ]]; then
        log_error "Helm chart not found: $HELM_CHART"
        exit 1
    fi

    # Verify values file
    if [[ ! -f "$VALUES_FILE" ]]; then
        log_error "Values file not found: $VALUES_FILE"
        exit 1
    fi

    log_info "✓ Pre-flight checks passed"
}

# Backup current state
backup_current_state() {
    log_step "Backing up current state..."

    local backup_dir="/tmp/siem-soar-deploy-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"

    # Backup current deployment manifests
    kubectl get all -n "$NAMESPACE" -o yaml > "$backup_dir/manifests.yaml"
    kubectl get configmap -n "$NAMESPACE" -o yaml > "$backup_dir/configmaps.yaml"
    kubectl get secret -n "$NAMESPACE" -o yaml > "$backup_dir/secrets.yaml"

    # Backup Helm release
    helm get values -n "$NAMESPACE" siem-soar > "$backup_dir/helm-values.yaml" || true

    log_info "Backup created: $backup_dir"
    echo "$backup_dir" > /tmp/siem-soar-last-backup.txt
}

# Rolling deployment
deploy_rolling() {
    log_step "Executing rolling deployment..."

    local helm_args=(
        "upgrade"
        "--install"
        "siem-soar"
        "$HELM_CHART"
        "--namespace" "$NAMESPACE"
        "--values" "$VALUES_FILE"
        "--set" "image.tag=$IMAGE_TAG"
        "--timeout" "${TIMEOUT}s"
        "--wait"
    )

    if [[ "$DRY_RUN" == "true" ]]; then
        helm_args+=("--dry-run" "--debug")
    fi

    log_info "Running: helm ${helm_args[*]}"
    helm "${helm_args[@]}"

    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Waiting for rollout to complete..."
        kubectl rollout status deployment/api -n "$NAMESPACE" --timeout="${TIMEOUT}s"
        kubectl rollout status deployment/worker -n "$NAMESPACE" --timeout="${TIMEOUT}s"
        kubectl rollout status deployment/collector -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    fi
}

# Blue-green deployment
deploy_blue_green() {
    log_step "Executing blue-green deployment..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would perform blue-green deployment"
        return
    fi

    # Use dedicated script for blue-green
    bash "${SCRIPT_DIR}/blue_green.sh" \
        --namespace "$NAMESPACE" \
        --tag "$IMAGE_TAG" \
        --timeout "$TIMEOUT"
}

# Canary deployment
deploy_canary() {
    log_step "Executing canary deployment..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would perform canary deployment"
        return
    fi

    # Use dedicated script for canary
    bash "${SCRIPT_DIR}/canary.sh" \
        --namespace "$NAMESPACE" \
        --tag "$IMAGE_TAG" \
        --timeout "$TIMEOUT"
}

# Health checks
run_health_checks() {
    log_step "Running health checks..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Skipping health checks"
        return
    fi

    # Use dedicated health check script
    if ! bash "${SCRIPT_DIR}/health_check.sh" --namespace "$NAMESPACE"; then
        log_error "Health checks failed"
        return 1
    fi

    log_info "✓ All health checks passed"
}

# Smoke tests
run_smoke_tests() {
    log_step "Running smoke tests..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Skipping smoke tests"
        return
    fi

    # Test API endpoint
    local api_url="http://$(kubectl get svc -n "$NAMESPACE" api -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"

    log_info "Testing API health endpoint..."
    if curl -sf "${api_url}/health" >/dev/null; then
        log_info "✓ API health check passed"
    else
        log_error "✗ API health check failed"
        return 1
    fi

    log_info "Testing API readiness..."
    if curl -sf "${api_url}/ready" >/dev/null; then
        log_info "✓ API readiness check passed"
    else
        log_error "✗ API readiness check failed"
        return 1
    fi

    log_info "✓ All smoke tests passed"
}

# Rollback on failure
rollback_deployment() {
    log_error "Deployment failed, initiating rollback..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would rollback deployment"
        return
    fi

    helm rollback siem-soar -n "$NAMESPACE" --wait --timeout="${TIMEOUT}s"

    log_info "Waiting for rollback to complete..."
    kubectl rollout status deployment/api -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    kubectl rollout status deployment/worker -n "$NAMESPACE" --timeout="${TIMEOUT}s"
    kubectl rollout status deployment/collector -n "$NAMESPACE" --timeout="${TIMEOUT}s"

    log_warn "Rollback completed"
}

# Post-deployment tasks
post_deployment() {
    log_step "Running post-deployment tasks..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Skipping post-deployment tasks"
        return
    fi

    # Update deployment record
    kubectl annotate deployment -n "$NAMESPACE" api \
        "deployment.kubernetes.io/revision=$(date +%Y%m%d_%H%M%S)" \
        "deployment.kubernetes.io/tag=$IMAGE_TAG" \
        --overwrite

    # Notify monitoring systems
    log_info "Sending deployment notification..."
    # Add Slack/email notification here if configured

    log_info "✓ Post-deployment tasks completed"
}

# Main execution
main() {
    log_info "=== SIEM-SOAR Production Deployment ==="
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Strategy: $DEPLOYMENT_STRATEGY"
    log_info "Image tag: $IMAGE_TAG"
    log_info "Dry run: $DRY_RUN"
    echo

    preflight_checks

    if [[ "$DRY_RUN" == "false" ]]; then
        backup_current_state
    fi

    # Deploy based on strategy
    case "$DEPLOYMENT_STRATEGY" in
        rolling)
            deploy_rolling
            ;;
        blue-green)
            deploy_blue_green
            ;;
        canary)
            deploy_canary
            ;;
        *)
            log_error "Unknown deployment strategy: $DEPLOYMENT_STRATEGY"
            exit 1
            ;;
    esac

    # Run checks
    if ! run_health_checks; then
        rollback_deployment
        exit 1
    fi

    if ! run_smoke_tests; then
        rollback_deployment
        exit 1
    fi

    post_deployment

    log_info "=== Deployment Complete ==="
    log_info "Version: $IMAGE_TAG"
    log_info "Strategy: $DEPLOYMENT_STRATEGY"

    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Backup location: $(cat /tmp/siem-soar-last-backup.txt 2>/dev/null || echo 'N/A')"
    fi
}

main "$@"
