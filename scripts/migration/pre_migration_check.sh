#!/bin/bash
# Pre-Migration Health Check
# Validates system readiness before running migrations

set -euo pipefail

NAMESPACE="${NAMESPACE:-siem-soar}"
MIN_DISK_GB=100
MIN_MEMORY_GB=16

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

# Check kubectl connectivity
check_kubectl() {
    log_info "Checking kubectl connectivity..."

    if ! kubectl cluster-info &>/dev/null; then
        check_failed "Cannot connect to Kubernetes cluster"
        return 1
    fi

    local context=$(kubectl config current-context)
    log_info "✓ Connected to cluster: $context"

    # Verify namespace exists
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        check_failed "Namespace not found: $NAMESPACE"
        return 1
    fi

    log_info "✓ Namespace exists: $NAMESPACE"
}

# Check pod health
check_pods() {
    log_info "Checking pod health..."

    local not_ready=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running -o name 2>/dev/null | wc -l)

    if [[ $not_ready -gt 0 ]]; then
        check_warn "$not_ready pod(s) not in Running state"
        kubectl get pods -n "$NAMESPACE" --field-selector=status.phase!=Running
    else
        log_info "✓ All pods are running"
    fi

    # Check database pods specifically
    for db in postgres clickhouse; do
        if ! kubectl get deployment -n "$NAMESPACE" "$db" &>/dev/null; then
            check_failed "Database deployment not found: $db"
            continue
        fi

        local ready=$(kubectl get deployment -n "$NAMESPACE" "$db" -o jsonpath='{.status.readyReplicas}')
        local desired=$(kubectl get deployment -n "$NAMESPACE" "$db" -o jsonpath='{.spec.replicas}')

        if [[ "$ready" == "$desired" ]]; then
            log_info "✓ $db deployment ready: $ready/$desired"
        else
            check_failed "$db deployment not ready: $ready/$desired"
        fi
    done
}

# Check resource availability
check_resources() {
    log_info "Checking resource availability..."

    # Check node resources
    kubectl top nodes 2>/dev/null | tail -n +2 | while read -r node cpu mem; do
        cpu_pct=$(echo "$cpu" | tr -d '%')
        mem_pct=$(echo "$mem" | tr -d '%')

        if [[ ${cpu_pct%.*} -gt 80 ]]; then
            check_warn "High CPU usage on node $node: $cpu"
        fi

        if [[ ${mem_pct%.*} -gt 80 ]]; then
            check_warn "High memory usage on node $node: $mem"
        fi
    done

    log_info "✓ Resource check complete"
}

# Check disk space
check_disk_space() {
    log_info "Checking disk space..."

    # Check PV usage for databases
    for pv in postgres-data clickhouse-data; do
        local usage=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- df -BG /var/lib/postgresql/data | tail -1 | awk '{print $3}' | tr -d 'G' 2>/dev/null || echo "0")

        if [[ ${usage%.*} -lt $MIN_DISK_GB ]]; then
            check_failed "Insufficient disk space for $pv: ${usage}GB (minimum: ${MIN_DISK_GB}GB)"
        else
            log_info "✓ Sufficient disk space for $pv: ${usage}GB"
        fi
    done
}

# Check database connectivity
check_database_connectivity() {
    log_info "Checking database connectivity..."

    # PostgreSQL
    if kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -c "SELECT 1" &>/dev/null; then
        log_info "✓ PostgreSQL connection successful"
    else
        check_failed "Cannot connect to PostgreSQL"
    fi

    # ClickHouse
    if kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "SELECT 1" &>/dev/null; then
        log_info "✓ ClickHouse connection successful"
    else
        check_failed "Cannot connect to ClickHouse"
    fi
}

# Check backup availability
check_backup_system() {
    log_info "Checking backup system..."

    # Verify backup tools are available
    if ! kubectl exec -n "$NAMESPACE" deployment/postgres -- which pg_dump &>/dev/null; then
        check_failed "pg_dump not found in PostgreSQL pod"
    else
        log_info "✓ pg_dump available"
    fi

    # Check backup storage
    BACKUP_DIR="${BACKUP_DIR:-/var/backups/siem-soar}"
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_warn "Backup directory does not exist: $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR" || check_failed "Cannot create backup directory"
    else
        log_info "✓ Backup directory exists: $BACKUP_DIR"
    fi

    # Check disk space for backup
    local available=$(df -BG "$BACKUP_DIR" | tail -1 | awk '{print $4}' | tr -d 'G')
    if [[ ${available%.*} -lt 50 ]]; then
        check_warn "Low disk space for backups: ${available}GB available"
    else
        log_info "✓ Sufficient backup storage: ${available}GB available"
    fi
}

# Check migration prerequisites
check_migration_tools() {
    log_info "Checking migration tools..."

    # Check alembic/migration tools in API pod
    if kubectl exec -n "$NAMESPACE" deployment/api -- \
        python -c "import alembic" &>/dev/null; then
        log_info "✓ Alembic available in API pod"
    else
        check_failed "Alembic not found in API pod"
    fi

    # Check migration files exist
    if kubectl exec -n "$NAMESPACE" deployment/api -- \
        ls /app/migrations/*.py &>/dev/null; then
        local migration_count=$(kubectl exec -n "$NAMESPACE" deployment/api -- \
            ls /app/migrations/*.py 2>/dev/null | wc -l)
        log_info "✓ Found $migration_count migration files"
    else
        check_warn "No migration files found"
    fi
}

# Check current schema version
check_schema_version() {
    log_info "Checking current schema version..."

    local current_version=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc \
        "SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1" 2>/dev/null || echo "none")

    log_info "Current schema version: $current_version"

    # Check for pending migrations
    local pending=$(kubectl exec -n "$NAMESPACE" deployment/api -- \
        python -m alembic history 2>/dev/null | grep -c "current" || echo "0")

    if [[ $pending -gt 0 ]]; then
        log_info "✓ Migration system initialized"
    else
        check_warn "Migration system may not be initialized"
    fi
}

# Check for active transactions
check_active_transactions() {
    log_info "Checking for active transactions..."

    local active_tx=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc \
        "SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%'")

    if [[ $active_tx -gt 10 ]]; then
        check_warn "High number of active transactions: $active_tx"
        check_warn "Consider running migration during low-traffic period"
    else
        log_info "✓ Active transactions: $active_tx"
    fi
}

# Check application traffic
check_traffic() {
    log_info "Checking application traffic..."

    # Check recent API requests
    local recent_requests=$(kubectl exec -n "$NAMESPACE" deployment/api -- \
        cat /var/log/api/access.log 2>/dev/null | tail -100 | wc -l || echo "0")

    if [[ $recent_requests -gt 50 ]]; then
        check_warn "High API traffic detected: $recent_requests requests in recent logs"
        check_warn "Consider scheduling migration during maintenance window"
    else
        log_info "✓ API traffic level acceptable"
    fi
}

# Main execution
main() {
    log_info "=== Pre-Migration Health Check ==="
    log_info "Namespace: $NAMESPACE"
    log_info "Minimum disk space: ${MIN_DISK_GB}GB"
    echo

    check_kubectl || exit 1
    echo

    check_pods
    echo

    check_resources
    echo

    check_disk_space
    echo

    check_database_connectivity
    echo

    check_backup_system
    echo

    check_migration_tools
    echo

    check_schema_version
    echo

    check_active_transactions
    echo

    check_traffic
    echo

    # Summary
    log_info "=== Health Check Summary ==="
    log_info "Errors: $ERRORS"
    log_info "Warnings: $WARNINGS"
    echo

    if [[ $ERRORS -gt 0 ]]; then
        log_error "${RED}✗ Pre-migration checks FAILED${NC}"
        log_error "Please resolve errors before proceeding with migration"
        exit 1
    elif [[ $WARNINGS -gt 0 ]]; then
        log_warn "${YELLOW}⚠ Pre-migration checks passed with WARNINGS${NC}"
        log_warn "Review warnings before proceeding"
        exit 0
    else
        log_info "${GREEN}✓ All pre-migration checks PASSED${NC}"
        log_info "System is ready for migration"
        exit 0
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -n, --namespace NS   Kubernetes namespace (default: siem-soar)"
            echo "  -h, --help           Show this help message"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

main
