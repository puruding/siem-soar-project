#!/bin/bash
# Health Check Script
# Comprehensive system health validation

set -euo pipefail

NAMESPACE="${NAMESPACE:-siem-soar}"
VERBOSE="${VERBOSE:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

ERRORS=0
WARNINGS=0

check_failed() {
    ERRORS=$((ERRORS + 1))
    log_error "$*"
}

check_warn() {
    WARNINGS=$((WARNINGS + 1))
    log_warn "$*"
}

# Check pod health
check_pods() {
    log_info "Checking pod health..."

    local components=("api" "worker" "collector" "postgres" "clickhouse" "kafka" "redis")

    for component in "${components[@]}"; do
        local ready=$(kubectl get deployment -n "$NAMESPACE" "$component" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        local desired=$(kubectl get deployment -n "$NAMESPACE" "$component" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")

        if [[ "$ready" == "$desired" ]] && [[ "$ready" != "0" ]]; then
            log_info "✓ $component: $ready/$desired ready"
        else
            check_failed "✗ $component: $ready/$desired ready"
        fi
    done
}

# Check endpoints
check_endpoints() {
    log_info "Checking service endpoints..."

    # API health endpoint
    local api_pods=$(kubectl get pods -n "$NAMESPACE" -l app=api -o jsonpath='{.items[*].metadata.name}')

    for pod in $api_pods; do
        if kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/health >/dev/null 2>&1; then
            log_info "✓ API health check passed: $pod"
        else
            check_failed "✗ API health check failed: $pod"
        fi

        if kubectl exec -n "$NAMESPACE" "$pod" -- curl -sf http://localhost:8000/ready >/dev/null 2>&1; then
            log_info "✓ API readiness check passed: $pod"
        else
            check_warn "⚠ API readiness check failed: $pod"
        fi
    done
}

# Check database connectivity
check_databases() {
    log_info "Checking database connectivity..."

    # PostgreSQL
    if kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -c "SELECT 1" >/dev/null 2>&1; then
        log_info "✓ PostgreSQL connection successful"
    else
        check_failed "✗ PostgreSQL connection failed"
    fi

    # ClickHouse
    if kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "SELECT 1" >/dev/null 2>&1; then
        log_info "✓ ClickHouse connection successful"
    else
        check_failed "✗ ClickHouse connection failed"
    fi

    # Redis
    if kubectl exec -n "$NAMESPACE" deployment/redis -- \
        redis-cli ping | grep -q "PONG"; then
        log_info "✓ Redis connection successful"
    else
        check_failed "✗ Redis connection failed"
    fi
}

# Check Kafka
check_kafka() {
    log_info "Checking Kafka..."

    if kubectl exec -n "$NAMESPACE" deployment/kafka -- \
        kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; then
        log_info "✓ Kafka connection successful"

        # Check topic count
        local topic_count=$(kubectl exec -n "$NAMESPACE" deployment/kafka -- \
            kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | wc -l)
        log_info "  Kafka topics: $topic_count"
    else
        check_failed "✗ Kafka connection failed"
    fi
}

# Check resource usage
check_resources() {
    log_info "Checking resource usage..."

    # CPU and memory usage
    kubectl top pods -n "$NAMESPACE" 2>/dev/null | tail -n +2 | while read -r pod cpu mem; do
        cpu_val=$(echo "$cpu" | tr -d 'm')
        mem_val=$(echo "$mem" | tr -d 'Mi')

        if [[ ${cpu_val%.*} -gt 900 ]]; then
            check_warn "High CPU usage: $pod ($cpu)"
        fi

        if [[ ${mem_val%.*} -gt 1500 ]]; then
            check_warn "High memory usage: $pod ($mem)"
        fi
    done || log_warn "Metrics server not available"

    log_info "✓ Resource check complete"
}

# Check recent errors
check_logs() {
    log_info "Checking recent errors in logs..."

    local api_pod=$(kubectl get pod -n "$NAMESPACE" -l app=api -o jsonpath='{.items[0].metadata.name}')

    if [[ -n "$api_pod" ]]; then
        local error_count=$(kubectl logs -n "$NAMESPACE" "$api_pod" --tail=100 2>/dev/null | \
            grep -i "error\|exception\|fatal" | wc -l || echo "0")

        if [[ $error_count -gt 10 ]]; then
            check_warn "High error count in API logs: $error_count errors in last 100 lines"
        else
            log_info "✓ API error count acceptable: $error_count"
        fi
    fi
}

# Check ingress
check_ingress() {
    log_info "Checking ingress..."

    if kubectl get ingress -n "$NAMESPACE" siem-soar &>/dev/null; then
        local ingress_ip=$(kubectl get ingress -n "$NAMESPACE" siem-soar -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

        if [[ -n "$ingress_ip" ]]; then
            log_info "✓ Ingress IP: $ingress_ip"

            # Test external access
            if curl -sf "http://${ingress_ip}/health" >/dev/null 2>&1; then
                log_info "✓ External access verified"
            else
                check_warn "⚠ External access check failed"
            fi
        else
            check_warn "⚠ Ingress IP not assigned"
        fi
    else
        log_info "  No ingress configured"
    fi
}

# Check certificates
check_certificates() {
    log_info "Checking TLS certificates..."

    if kubectl get secret -n "$NAMESPACE" siem-soar-tls &>/dev/null; then
        # Check certificate expiry
        local cert_data=$(kubectl get secret -n "$NAMESPACE" siem-soar-tls -o jsonpath='{.data.tls\.crt}')

        if [[ -n "$cert_data" ]]; then
            local expiry=$(echo "$cert_data" | base64 -d | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
            log_info "✓ TLS certificate expires: $expiry"

            # Check if expiring soon (30 days)
            local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
            local now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            if [[ $days_left -lt 30 ]]; then
                check_warn "⚠ TLS certificate expires in $days_left days"
            fi
        fi
    else
        log_info "  TLS certificate not configured"
    fi
}

# Check persistent volumes
check_pvs() {
    log_info "Checking persistent volumes..."

    kubectl get pvc -n "$NAMESPACE" -o json | jq -r '.items[] | "\(.metadata.name) \(.status.phase)"' | while read -r pvc phase; do
        if [[ "$phase" == "Bound" ]]; then
            log_info "✓ PVC bound: $pvc"
        else
            check_failed "✗ PVC not bound: $pvc ($phase)"
        fi
    done
}

# Performance test
performance_test() {
    log_info "Running basic performance test..."

    local api_pod=$(kubectl get pod -n "$NAMESPACE" -l app=api -o jsonpath='{.items[0].metadata.name}')

    if [[ -n "$api_pod" ]]; then
        local start=$(date +%s%N)
        kubectl exec -n "$NAMESPACE" "$api_pod" -- curl -sf http://localhost:8000/health >/dev/null
        local end=$(date +%s%N)
        local duration=$(( (end - start) / 1000000 ))  # Convert to ms

        log_info "  API response time: ${duration}ms"

        if [[ $duration -gt 1000 ]]; then
            check_warn "⚠ Slow API response: ${duration}ms"
        fi
    fi
}

# Main execution
main() {
    log_info "=== SIEM-SOAR Health Check ==="
    log_info "Namespace: $NAMESPACE"
    echo

    check_pods
    echo

    check_endpoints
    echo

    check_databases
    echo

    check_kafka
    echo

    check_resources
    echo

    check_logs
    echo

    check_ingress
    echo

    check_certificates
    echo

    check_pvs
    echo

    performance_test
    echo

    # Summary
    log_info "=== Health Check Summary ==="
    log_info "Errors: $ERRORS"
    log_info "Warnings: $WARNINGS"
    echo

    if [[ $ERRORS -gt 0 ]]; then
        log_error "${RED}✗ Health check FAILED${NC}"
        exit 1
    elif [[ $WARNINGS -gt 0 ]]; then
        log_warn "${YELLOW}⚠ Health check passed with WARNINGS${NC}"
        exit 0
    else
        log_info "${GREEN}✓ All health checks PASSED${NC}"
        exit 0
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -n, --namespace NS   Kubernetes namespace (default: siem-soar)"
            echo "  -v, --verbose        Enable verbose output"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

main
