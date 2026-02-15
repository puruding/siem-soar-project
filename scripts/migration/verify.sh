#!/bin/bash
# Migration Verification Script
# Validates database schema and data integrity after migration

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

check_failed() {
    ERRORS=$((ERRORS + 1))
    log_error "$*"
}

# Verify PostgreSQL schema
verify_postgres_schema() {
    log_info "Verifying PostgreSQL schema..."

    # Check required tables exist
    local required_tables=(
        "alerts"
        "events"
        "rules"
        "playbooks"
        "users"
        "organizations"
        "integrations"
        "audit_logs"
        "schema_migrations"
    )

    for table in "${required_tables[@]}"; do
        if kubectl exec -n "$NAMESPACE" deployment/postgres -- \
            psql -U postgres -d siem -tAc "SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = '$table')" | grep -q "t"; then
            log_info "✓ Table exists: $table"
        else
            check_failed "✗ Missing table: $table"
        fi
    done

    # Verify indexes
    log_info "Checking critical indexes..."
    local index_count=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public'")

    if [[ $index_count -gt 20 ]]; then
        log_info "✓ Index count: $index_count"
    else
        check_failed "✗ Insufficient indexes: $index_count (expected > 20)"
    fi

    # Check foreign key constraints
    log_info "Checking foreign key constraints..."
    local fk_count=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc "SELECT COUNT(*) FROM pg_constraint WHERE contype = 'f'")

    if [[ $fk_count -gt 10 ]]; then
        log_info "✓ Foreign key constraints: $fk_count"
    else
        log_warn "⚠ Low foreign key count: $fk_count"
    fi
}

# Verify ClickHouse schema
verify_clickhouse_schema() {
    log_info "Verifying ClickHouse schema..."

    # Check required tables
    local required_tables=(
        "events"
        "metrics"
        "logs"
        "network_flows"
        "threat_intel"
    )

    for table in "${required_tables[@]}"; do
        if kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
            clickhouse-client --query "EXISTS TABLE siem.$table" | grep -q "1"; then
            log_info "✓ Table exists: $table"
        else
            check_failed "✗ Missing table: $table"
        fi
    done

    # Check partitioning
    log_info "Checking table partitions..."
    kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "SELECT table, partition_key FROM system.tables WHERE database = 'siem' AND partition_key != ''" \
        > /tmp/clickhouse_partitions.txt

    if [[ -s /tmp/clickhouse_partitions.txt ]]; then
        log_info "✓ Tables are partitioned"
        if [[ "$VERBOSE" == "true" ]]; then
            cat /tmp/clickhouse_partitions.txt
        fi
    else
        log_warn "⚠ No partitioned tables found"
    fi
}

# Verify data integrity
verify_data_integrity() {
    log_info "Verifying data integrity..."

    # Check record counts
    local pg_event_count=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc "SELECT COUNT(*) FROM events")

    local ch_event_count=$(kubectl exec -n "$NAMESPACE" deployment/clickhouse -- \
        clickhouse-client --query "SELECT COUNT(*) FROM siem.events")

    log_info "PostgreSQL events: $pg_event_count"
    log_info "ClickHouse events: $ch_event_count"

    # Check for orphaned records
    log_info "Checking for orphaned alert records..."
    local orphaned_alerts=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc \
        "SELECT COUNT(*) FROM alerts WHERE event_id NOT IN (SELECT id FROM events)")

    if [[ $orphaned_alerts -eq 0 ]]; then
        log_info "✓ No orphaned alerts"
    else
        log_warn "⚠ Found $orphaned_alerts orphaned alert records"
    fi

    # Verify recent data
    log_info "Checking for recent data..."
    local recent_events=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc \
        "SELECT COUNT(*) FROM events WHERE created_at > NOW() - INTERVAL '1 hour'")

    log_info "Events in last hour: $recent_events"
}

# Verify migrations applied
verify_migration_history() {
    log_info "Verifying migration history..."

    # Check latest migration version
    local latest_version=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc \
        "SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 1")

    log_info "Latest migration version: $latest_version"

    # Check migration count
    local migration_count=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc "SELECT COUNT(*) FROM schema_migrations")

    log_info "Total migrations applied: $migration_count"
}

# Verify application connectivity
verify_application() {
    log_info "Verifying application connectivity..."

    # Check API can connect to database
    if kubectl exec -n "$NAMESPACE" deployment/api -- \
        python -c "from app.db import engine; engine.connect()" 2>/dev/null; then
        log_info "✓ API database connection successful"
    else
        check_failed "✗ API cannot connect to database"
    fi

    # Check API health endpoint
    if kubectl exec -n "$NAMESPACE" deployment/api -- \
        curl -sf http://localhost:8000/health >/dev/null; then
        log_info "✓ API health check passed"
    else
        check_failed "✗ API health check failed"
    fi
}

# Performance checks
verify_performance() {
    log_info "Running performance checks..."

    # Query performance test
    log_info "Testing query performance..."
    local query_time=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -c "EXPLAIN ANALYZE SELECT * FROM events ORDER BY created_at DESC LIMIT 100" | \
        grep "Execution Time" | awk '{print $3}')

    log_info "Query execution time: ${query_time}ms"

    # Check connection pool
    local active_connections=$(kubectl exec -n "$NAMESPACE" deployment/postgres -- \
        psql -U postgres -d siem -tAc "SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active'")

    log_info "Active connections: $active_connections"
}

# Main execution
main() {
    log_info "=== Migration Verification ==="
    log_info "Namespace: $NAMESPACE"
    echo

    verify_postgres_schema
    echo

    verify_clickhouse_schema
    echo

    verify_data_integrity
    echo

    verify_migration_history
    echo

    verify_application
    echo

    verify_performance
    echo

    # Summary
    log_info "=== Verification Summary ==="
    if [[ $ERRORS -eq 0 ]]; then
        log_info "${GREEN}✓ All checks passed${NC}"
        exit 0
    else
        log_error "${RED}✗ $ERRORS check(s) failed${NC}"
        exit 1
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
