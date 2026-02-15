#!/bin/bash
# Production Database Migration Script
# Handles schema migrations with safety checks and rollback capability

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Configuration
ENVIRONMENT="${ENVIRONMENT:-prod}"
NAMESPACE="${NAMESPACE:-siem-soar}"
DRY_RUN="${DRY_RUN:-false}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/siem-soar}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

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
    -e, --environment ENV    Target environment (default: prod)
    -n, --namespace NS       Kubernetes namespace (default: siem-soar)
    -d, --dry-run           Perform dry run without applying changes
    -b, --backup-dir DIR    Backup directory (default: /var/backups/siem-soar)
    -h, --help              Show this help message

Examples:
    # Production migration with defaults
    $0

    # Dry run to preview changes
    $0 --dry-run

    # Custom namespace
    $0 --namespace siem-soar-prod
EOF
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment) ENVIRONMENT="$2"; shift 2 ;;
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -d|--dry-run) DRY_RUN=true; shift ;;
        -b|--backup-dir) BACKUP_DIR="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Pre-flight checks
check_prerequisites() {
    log_info "Running pre-flight checks..."

    # Check required tools
    for tool in kubectl psql pg_dump; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done

    # Verify kubectl context
    CURRENT_CONTEXT=$(kubectl config current-context)
    log_info "Current kubectl context: $CURRENT_CONTEXT"

    if [[ "$DRY_RUN" == "false" ]]; then
        read -p "Continue with migration in $ENVIRONMENT? (yes/no): " -r
        if [[ ! $REPLY =~ ^yes$ ]]; then
            log_warn "Migration cancelled by user"
            exit 0
        fi
    fi
}

# Create backup
create_backup() {
    log_info "Creating database backup..."

    mkdir -p "$BACKUP_DIR"

    # PostgreSQL backup
    log_info "Backing up PostgreSQL..."
    kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        pg_dumpall -U postgres | gzip > "$BACKUP_DIR/postgres_${TIMESTAMP}.sql.gz"

    # ClickHouse backup
    log_info "Backing up ClickHouse..."
    kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "BACKUP DATABASE siem TO Disk('backups', '${TIMESTAMP}')"

    # Export current schema versions
    log_info "Exporting schema versions..."
    kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -c "SELECT * FROM schema_migrations" \
        > "$BACKUP_DIR/schema_versions_${TIMESTAMP}.txt"

    log_info "Backup completed: $BACKUP_DIR"
    log_info "Backup size: $(du -sh "$BACKUP_DIR" | cut -f1)"
}

# Run migrations
run_migrations() {
    log_info "Running database migrations..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "DRY RUN MODE - No changes will be applied"
    fi

    # PostgreSQL migrations (using alembic or similar)
    log_info "Applying PostgreSQL migrations..."
    kubectl exec -n "$NAMESPACE" deployment/api -- \
        python -m alembic upgrade head ${DRY_RUN:+--sql}

    # ClickHouse migrations
    log_info "Applying ClickHouse migrations..."
    for migration in "${PROJECT_ROOT}"/migrations/clickhouse/*.sql; do
        if [[ -f "$migration" ]]; then
            log_info "Applying: $(basename "$migration")"
            if [[ "$DRY_RUN" == "false" ]]; then
                kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
                    clickhouse-client --multiquery < "$migration"
            else
                log_info "Would apply: $migration"
            fi
        fi
    done

    # Update schema version tracking
    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "Updating schema version tracking..."
        kubectl exec -n "$NAMESPACE" deployment/postgres -- \
            psql -U postgres -d siem -c \
            "INSERT INTO migration_history (version, applied_at, description)
             VALUES ('v1.0', NOW(), 'GA Release Migration')"
    fi
}

# Verify migrations
verify_migrations() {
    log_info "Verifying migrations..."

    # Check PostgreSQL schema
    log_info "Checking PostgreSQL schema..."
    kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -c "\dt" | tee "$BACKUP_DIR/schema_verify_${TIMESTAMP}.txt"

    # Check ClickHouse schema
    log_info "Checking ClickHouse schema..."
    kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "SHOW TABLES" | tee -a "$BACKUP_DIR/schema_verify_${TIMESTAMP}.txt"

    # Run verification script
    if [[ -f "${SCRIPT_DIR}/verify.sh" ]]; then
        log_info "Running verification script..."
        bash "${SCRIPT_DIR}/verify.sh" --namespace "$NAMESPACE"
    fi

    log_info "Migration verification completed"
}

# Health check
health_check() {
    log_info "Running health checks..."

    # Check pod status
    kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=siem-soar

    # Check database connectivity
    log_info "Testing database connectivity..."
    kubectl exec -n "$NAMESPACE" deployment/api -- \
        python -c "from app.db import test_connection; test_connection()"

    # Check API health
    log_info "Testing API health endpoint..."
    kubectl exec -n "$NAMESPACE" deployment/api -- \
        curl -f http://localhost:8000/health || {
            log_error "API health check failed"
            return 1
        }

    log_info "All health checks passed"
}

# Main execution
main() {
    log_info "=== SIEM-SOAR Database Migration ==="
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Dry Run: $DRY_RUN"
    log_info "Timestamp: $TIMESTAMP"
    echo

    check_prerequisites

    if [[ "$DRY_RUN" == "false" ]]; then
        create_backup
    fi

    run_migrations

    if [[ "$DRY_RUN" == "false" ]]; then
        verify_migrations
        health_check
    fi

    log_info "=== Migration Complete ==="
    log_info "Backup location: $BACKUP_DIR"

    if [[ "$DRY_RUN" == "false" ]]; then
        log_info "To rollback, run: ${SCRIPT_DIR}/rollback.sh --timestamp $TIMESTAMP"
    fi
}

main "$@"
