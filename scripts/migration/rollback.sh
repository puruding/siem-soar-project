#!/bin/bash
# Database Rollback Script
# Restores database to previous backup snapshot

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
NAMESPACE="${NAMESPACE:-siem-soar}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/siem-soar}"
TIMESTAMP="${TIMESTAMP:-}"

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
    -t, --timestamp TS      Backup timestamp to restore (YYYYMMDD_HHMMSS)
    -n, --namespace NS      Kubernetes namespace (default: siem-soar)
    -b, --backup-dir DIR    Backup directory (default: /var/backups/siem-soar)
    -l, --list              List available backups
    -h, --help              Show this help message

Examples:
    # List available backups
    $0 --list

    # Rollback to specific timestamp
    $0 --timestamp 20260204_120000

    # Rollback with custom namespace
    $0 --timestamp 20260204_120000 --namespace siem-soar-prod
EOF
    exit 1
}

list_backups() {
    log_info "Available backups in $BACKUP_DIR:"
    echo

    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_error "Backup directory not found: $BACKUP_DIR"
        exit 1
    fi

    find "$BACKUP_DIR" -name "postgres_*.sql.gz" -type f | while read -r backup; do
        timestamp=$(basename "$backup" | sed 's/postgres_\(.*\)\.sql\.gz/\1/')
        size=$(du -h "$backup" | cut -f1)
        date=$(stat -c %y "$backup" 2>/dev/null || stat -f %Sm "$backup")
        echo "Timestamp: $timestamp"
        echo "  Size: $size"
        echo "  Date: $date"
        echo
    done
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--timestamp) TIMESTAMP="$2"; shift 2 ;;
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        -b|--backup-dir) BACKUP_DIR="$2"; shift 2 ;;
        -l|--list) list_backups; exit 0 ;;
        -h|--help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$TIMESTAMP" ]]; then
    log_error "Timestamp is required for rollback"
    usage
fi

# Verify backup exists
POSTGRES_BACKUP="$BACKUP_DIR/postgres_${TIMESTAMP}.sql.gz"
if [[ ! -f "$POSTGRES_BACKUP" ]]; then
    log_error "Backup not found: $POSTGRES_BACKUP"
    list_backups
    exit 1
fi

# Confirmation prompt
log_warn "!!! CRITICAL OPERATION !!!"
log_warn "This will restore the database to timestamp: $TIMESTAMP"
log_warn "Current data will be LOST unless backed up separately"
echo
read -p "Type 'ROLLBACK' to confirm: " -r
if [[ ! $REPLY == "ROLLBACK" ]]; then
    log_warn "Rollback cancelled"
    exit 0
fi

# Create pre-rollback backup
log_info "Creating pre-rollback backup..."
PRE_ROLLBACK_TS=$(date +%Y%m%d_%H%M%S)
kubectl exec -n "$NAMESPACE" deployment/postgres -- \
    pg_dumpall -U postgres | gzip > "$BACKUP_DIR/postgres_pre_rollback_${PRE_ROLLBACK_TS}.sql.gz"

log_info "Pre-rollback backup created: postgres_pre_rollback_${PRE_ROLLBACK_TS}.sql.gz"

# Stop dependent services
log_info "Stopping dependent services..."
kubectl scale deployment -n "$NAMESPACE" \
    --replicas=0 api worker collector || true

# Wait for pods to terminate
log_info "Waiting for pods to terminate..."
sleep 10

# Restore PostgreSQL
log_info "Restoring PostgreSQL from backup..."
zcat "$POSTGRES_BACKUP" | kubectl exec -i -n "$NAMESPACE" deployment/postgres -- \
    psql -U postgres

# Restore ClickHouse
log_info "Restoring ClickHouse from backup..."
kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
    clickhouse-client --query "RESTORE DATABASE siem FROM Disk('backups', '${TIMESTAMP}')"

# Restart services
log_info "Restarting services..."
kubectl scale deployment -n "$NAMESPACE" \
    --replicas=1 postgres clickhouse

# Wait for databases to be ready
log_info "Waiting for databases to be ready..."
kubectl wait --for=condition=ready pod -n "$NAMESPACE" -l app=postgres --timeout=300s
kubectl wait --for=condition=ready pod -n "$NAMESPACE" -l app=clickhouse --timeout=300s

# Restart application services
log_info "Restarting application services..."
kubectl scale deployment -n "$NAMESPACE" \
    --replicas=3 api \
    --replicas=2 worker \
    --replicas=2 collector

# Verify rollback
log_info "Verifying rollback..."
if [[ -f "${SCRIPT_DIR}/verify.sh" ]]; then
    bash "${SCRIPT_DIR}/verify.sh" --namespace "$NAMESPACE"
fi

log_info "=== Rollback Complete ==="
log_info "Restored from: $TIMESTAMP"
log_info "Pre-rollback backup: postgres_pre_rollback_${PRE_ROLLBACK_TS}.sql.gz"
log_warn "Please verify application functionality manually"
