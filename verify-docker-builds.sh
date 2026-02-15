#!/bin/bash
#
# Docker Build Verification Script
# Tests all service builds individually to identify any remaining issues
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counter for results
PASSED=0
FAILED=0
declare -a FAILED_SERVICES

echo "========================================"
echo "Docker Build Verification"
echo "========================================"
echo ""

# Function to build and test a service
build_service() {
    local service=$1
    echo -n "Building ${service}... "

    if docker-compose build --no-cache "$service" > "/tmp/docker-build-${service}.log" 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAILED${NC}"
        echo "  See log: /tmp/docker-build-${service}.log"
        ((FAILED++))
        FAILED_SERVICES+=("$service")
        return 1
    fi
}

# Test frontend
echo "Testing Frontend Services..."
echo "----------------------------"
build_service "dashboard"
echo ""

# Test Go backend services
echo "Testing Go Backend Services..."
echo "------------------------------"
for service in gateway detection soar ti query case collector pipeline parser; do
    build_service "$service"
done
echo ""

# Test AI services
echo "Testing AI Services..."
echo "----------------------"
build_service "ml-gateway"
echo ""

# Summary
echo "========================================"
echo "Build Verification Summary"
echo "========================================"
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo ""

if [ ${FAILED} -eq 0 ]; then
    echo -e "${GREEN}All builds passed successfully!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run 'docker-compose up -d' to start all services"
    echo "  2. Check service health with 'docker-compose ps'"
    echo "  3. View logs with 'docker-compose logs -f'"
    exit 0
else
    echo -e "${RED}The following services failed to build:${NC}"
    for svc in "${FAILED_SERVICES[@]}"; do
        echo "  - $svc (log: /tmp/docker-build-${svc}.log)"
    done
    echo ""
    echo "Fix the failed services and run this script again."
    exit 1
fi
