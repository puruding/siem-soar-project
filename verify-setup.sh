#!/bin/bash

# SIEM-SOAR Setup Verification Script
# This script verifies that the Docker deployment is properly configured

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

print_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARNINGS++))
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check prerequisites
print_header "Checking Prerequisites"

# Check Docker
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    print_pass "Docker is installed (version $DOCKER_VERSION)"

    # Check Docker daemon
    if docker info &> /dev/null; then
        print_pass "Docker daemon is running"
    else
        print_fail "Docker daemon is not running"
    fi
else
    print_fail "Docker is not installed"
fi

# Check Docker Compose
if command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $3}' | sed 's/,//')
    print_pass "Docker Compose is installed (version $COMPOSE_VERSION)"
else
    print_fail "Docker Compose is not installed"
fi

# Check required files
print_header "Checking Configuration Files"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Check docker-compose.yml
if [ -f "docker-compose.yml" ]; then
    print_pass "docker-compose.yml exists"
else
    print_fail "docker-compose.yml not found"
fi

# Check .env
if [ -f ".env" ]; then
    print_pass ".env file exists"
else
    print_warn ".env file not found (will use defaults)"
    if [ -f ".env.example" ]; then
        print_info "You can create .env from .env.example: cp .env.example .env"
    fi
fi

# Check Dockerfiles
print_header "Checking Dockerfiles"

DOCKERFILES=(
    "services/gateway/Dockerfile"
    "services/detection/Dockerfile"
    "services/soar/Dockerfile"
    "services/ti/Dockerfile"
    "services/query/Dockerfile"
    "services/case/Dockerfile"
    "services/collector/Dockerfile"
    "services/pipeline/Dockerfile"
    "services/parser/Dockerfile"
    "ai/services/ml-gateway/Dockerfile"
    "web/dashboard/Dockerfile"
)

for dockerfile in "${DOCKERFILES[@]}"; do
    if [ -f "$dockerfile" ]; then
        print_pass "$dockerfile exists"
    else
        print_fail "$dockerfile not found"
    fi
done

# Check nginx config
if [ -f "web/dashboard/nginx.conf" ]; then
    print_pass "web/dashboard/nginx.conf exists"
else
    print_fail "web/dashboard/nginx.conf not found"
fi

# Check port availability
print_header "Checking Port Availability"

PORTS=(3000 8080 8000 8123 9000 9092 5432 6379 7233 9514)
for port in "${PORTS[@]}"; do
    if command -v lsof &> /dev/null; then
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            print_warn "Port $port is already in use"
        else
            print_pass "Port $port is available"
        fi
    elif command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$port "; then
            print_warn "Port $port is already in use"
        else
            print_pass "Port $port is available"
        fi
    else
        print_info "Cannot check port $port (lsof/netstat not available)"
    fi
done

# Check disk space
print_header "Checking Disk Space"

AVAILABLE_GB=$(df -BG . | tail -1 | awk '{print $4}' | sed 's/G//')
if [ "$AVAILABLE_GB" -ge 50 ]; then
    print_pass "Sufficient disk space available (${AVAILABLE_GB}GB)"
elif [ "$AVAILABLE_GB" -ge 30 ]; then
    print_warn "Limited disk space (${AVAILABLE_GB}GB, recommended 50GB+)"
else
    print_fail "Insufficient disk space (${AVAILABLE_GB}GB, minimum 30GB required)"
fi

# Check memory
print_header "Checking Memory"

if command -v free &> /dev/null; then
    TOTAL_MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM_GB" -ge 16 ]; then
        print_pass "Sufficient RAM available (${TOTAL_MEM_GB}GB)"
    elif [ "$TOTAL_MEM_GB" -ge 8 ]; then
        print_warn "Limited RAM (${TOTAL_MEM_GB}GB, recommended 16GB+)"
    else
        print_fail "Insufficient RAM (${TOTAL_MEM_GB}GB, minimum 8GB required)"
    fi
else
    print_info "Cannot check memory (free command not available)"
fi

# Check Docker resources
print_header "Checking Docker Resources"

if docker info &> /dev/null; then
    # Check images
    IMAGE_COUNT=$(docker images | wc -l)
    print_info "Existing Docker images: $((IMAGE_COUNT - 1))"

    # Check containers
    CONTAINER_COUNT=$(docker ps -a | wc -l)
    print_info "Existing Docker containers: $((CONTAINER_COUNT - 1))"

    # Check volumes
    VOLUME_COUNT=$(docker volume ls | wc -l)
    print_info "Existing Docker volumes: $((VOLUME_COUNT - 1))"
fi

# Check existing SIEM services
print_header "Checking Existing SIEM Services"

if docker-compose ps 2>/dev/null | grep -q "siem-"; then
    print_warn "SIEM services are already running"
    print_info "Run 'docker-compose down' to stop them"
else
    print_pass "No conflicting SIEM services running"
fi

# Summary
print_header "Verification Summary"

echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ Setup verification completed successfully!${NC}"
    echo -e "\nNext steps:"
    echo -e "  1. Create .env file: ${BLUE}cp .env.example .env${NC}"
    echo -e "  2. Build images: ${BLUE}./build.sh all${NC}"
    echo -e "  3. Start services: ${BLUE}docker-compose up -d${NC}"
    echo -e "  4. Check status: ${BLUE}docker-compose ps${NC}"
    echo -e "  5. View logs: ${BLUE}docker-compose logs -f${NC}"
    echo -e "\nFor more information, see QUICKSTART.md"
    exit 0
else
    echo -e "\n${RED}✗ Setup verification found issues that need to be resolved${NC}"
    echo -e "\nPlease address the failed checks above before deploying."
    exit 1
fi
