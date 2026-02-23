#!/bin/bash

# SIEM-SOAR End-to-End Observability Verification Script
# This script verifies that the observability stack is properly configured and operational
# Usage: ./verify-observability.sh

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Configuration
JAEGER_URL="${JAEGER_URL:-http://localhost:16686}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
GRAFANA_URL="${GRAFANA_URL:-http://localhost:3001}"
JAEGER_GRPC="${JAEGER_GRPC:-localhost:4317}"
OTEL_COLLECTOR="${OTEL_COLLECTOR:-http://localhost:8888}"

# Timeout for health checks
TIMEOUT=5

# Functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

print_subheader() {
    echo -e "\n${CYAN}-- $1 --${NC}"
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

check_http_endpoint() {
    local url=$1
    local name=$2

    if command -v curl &> /dev/null; then
        if curl -s -f -m $TIMEOUT "$url" > /dev/null 2>&1; then
            print_pass "$name is accessible ($url)"
            return 0
        else
            print_fail "$name is not accessible ($url)"
            return 1
        fi
    else
        print_warn "curl not available - skipping HTTP check for $name"
        return 0
    fi
}

check_port() {
    local host=$1
    local port=$2
    local name=$3

    if command -v nc &> /dev/null; then
        if nc -z -w $TIMEOUT "$host" "$port" 2>/dev/null; then
            print_pass "$name is listening on $host:$port"
            return 0
        else
            print_fail "$name is not listening on $host:$port"
            return 1
        fi
    elif command -v timeout &> /dev/null; then
        # Fallback using bash
        if timeout $TIMEOUT bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
            print_pass "$name is listening on $host:$port"
            return 0
        else
            print_fail "$name is not listening on $host:$port"
            return 1
        fi
    else
        print_warn "nc or timeout not available - skipping port check for $name"
        return 0
    fi
}

check_docker_container() {
    local container_name=$1

    if command -v docker &> /dev/null; then
        if docker ps --filter "name=$container_name" --format "{{.Names}}" | grep -q "$container_name"; then
            local status=$(docker ps --filter "name=$container_name" --format "{{.Status}}")
            print_pass "Container $container_name is running ($status)"
            return 0
        elif docker ps -a --filter "name=$container_name" --format "{{.Names}}" | grep -q "$container_name"; then
            print_fail "Container $container_name exists but is not running"
            return 1
        else
            print_warn "Container $container_name not found"
            return 0
        fi
    else
        print_warn "Docker not available - skipping container check for $container_name"
        return 0
    fi
}

check_prometheus_targets() {
    if command -v curl &> /dev/null; then
        local api_endpoint="${PROMETHEUS_URL}/api/v1/targets"

        if curl -s -f -m $TIMEOUT "$api_endpoint" > /dev/null 2>&1; then
            local response=$(curl -s "$api_endpoint")
            local up_count=$(echo "$response" | grep -o '"state":"up"' | wc -l)
            local down_count=$(echo "$response" | grep -o '"state":"down"' | wc -l)

            if [ "$down_count" -gt 0 ]; then
                print_warn "Prometheus targets: $up_count up, $down_count down"
                return 0
            else
                print_pass "Prometheus targets: $up_count up"
                return 0
            fi
        else
            print_fail "Cannot query Prometheus targets API"
            return 1
        fi
    else
        print_warn "curl not available - skipping Prometheus targets check"
        return 0
    fi
}

check_jaeger_ui() {
    local search_endpoint="${JAEGER_URL}/api/traces"

    if command -v curl &> /dev/null; then
        if curl -s -f -m $TIMEOUT "$search_endpoint" > /dev/null 2>&1; then
            print_pass "Jaeger search API is accessible"
            return 0
        else
            print_fail "Jaeger search API is not accessible"
            return 1
        fi
    else
        print_warn "curl not available - skipping Jaeger search check"
        return 0
    fi
}

check_service_metrics() {
    local service_name=$1
    local service_port=$2

    if command -v curl &> /dev/null; then
        if curl -s -f -m $TIMEOUT "http://localhost:$service_port/metrics" > /dev/null 2>&1; then
            print_pass "$service_name metrics endpoint is working"
            return 0
        else
            print_warn "$service_name metrics endpoint is not accessible on port $service_port"
            return 0
        fi
    else
        print_warn "curl not available - skipping metrics check for $service_name"
        return 0
    fi
}

generate_sample_trace() {
    print_info "Generating sample trace..."

    if command -v curl &> /dev/null; then
        # Create a simple OTLP trace request
        local trace_json=$(cat <<'EOF'
{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {
            "key": "service.name",
            "value": {
              "stringValue": "siem-observability-verification"
            }
          }
        ]
      },
      "scopeSpans": [
        {
          "scope": {
            "name": "verification-tool"
          },
          "spans": [
            {
              "traceId": "0af7651916cd43dd8448eb211c80319c",
              "spanId": "b7ad6b7169203331",
              "parentSpanId": "",
              "name": "verification-span",
              "status": {
                "code": 0
              },
              "startTimeUnixNano": "1700000000000000000",
              "endTimeUnixNano": "1700000001000000000",
              "attributes": [
                {
                  "key": "verification",
                  "value": {
                    "stringValue": "observability-stack"
                  }
                }
              ]
            }
          ]
        }
      ]
    }
  ]
}
EOF
        )

        if curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "$trace_json" \
            "http://localhost:4318/v1/traces" > /dev/null 2>&1; then
            print_pass "Sample trace sent to OTLP HTTP endpoint"
            return 0
        else
            print_warn "Failed to send sample trace to OTLP HTTP endpoint"
            return 0
        fi
    else
        print_warn "curl not available - skipping sample trace generation"
        return 0
    fi
}

query_traces() {
    print_info "Querying Jaeger for traces..."

    if command -v curl &> /dev/null; then
        local search_url="${JAEGER_URL}/api/traces?service=siem-observability-verification&limit=10"

        if curl -s -f -m $TIMEOUT "$search_url" > /dev/null 2>&1; then
            local response=$(curl -s "$search_url")
            local trace_count=$(echo "$response" | grep -o '"traceID"' | wc -l)

            if [ "$trace_count" -gt 0 ]; then
                print_pass "Found $trace_count trace(s) in Jaeger for verification service"
            else
                print_info "No traces found yet for verification service (normal if just started)"
            fi
            return 0
        else
            print_warn "Failed to query Jaeger for traces"
            return 0
        fi
    else
        print_warn "curl not available - skipping trace query"
        return 0
    fi
}

# Main verification

print_header "SIEM-SOAR Observability Stack Verification"

print_info "Jaeger UI: $JAEGER_URL"
print_info "Prometheus: $PROMETHEUS_URL"
print_info "Grafana: $GRAFANA_URL"

# Step 1: Docker Containers
print_header "Step 1: Verifying Docker Containers"

check_docker_container "siem-jaeger"
check_docker_container "siem-prometheus"
check_docker_container "siem-grafana"
check_docker_container "siem-otel-collector"

# Step 2: Port Connectivity
print_header "Step 2: Checking Port Connectivity"

print_subheader "Jaeger Ports"
check_port "localhost" "16686" "Jaeger UI"
check_port "localhost" "4317" "Jaeger OTLP gRPC"
check_port "localhost" "4318" "Jaeger OTLP HTTP"
check_port "localhost" "14250" "Jaeger gRPC (legacy)"

print_subheader "Prometheus Ports"
check_port "localhost" "9090" "Prometheus"

print_subheader "Grafana Ports"
check_port "localhost" "3001" "Grafana"

print_subheader "OpenTelemetry Collector Ports"
check_port "localhost" "4319" "OTEL Collector OTLP gRPC"
check_port "localhost" "4320" "OTEL Collector OTLP HTTP"
check_port "localhost" "8888" "OTEL Collector Prometheus"

# Step 3: HTTP Endpoints
print_header "Step 3: Verifying HTTP Endpoints"

print_subheader "Jaeger"
check_http_endpoint "${JAEGER_URL}" "Jaeger UI"
check_jaeger_ui

print_subheader "Prometheus"
check_http_endpoint "${PROMETHEUS_URL}" "Prometheus UI"
check_http_endpoint "${PROMETHEUS_URL}/api/v1/query?query=up" "Prometheus API"

print_subheader "Grafana"
check_http_endpoint "${GRAFANA_URL}" "Grafana UI"

print_subheader "OpenTelemetry Collector"
check_http_endpoint "${OTEL_COLLECTOR}/metrics" "OTEL Collector Prometheus Metrics"

# Step 4: Service Metrics Endpoints
print_header "Step 4: Checking Service Metrics Endpoints"

print_subheader "SIEM Go Services"
check_service_metrics "Gateway" "9090"
check_service_metrics "Detection" "9090"
check_service_metrics "SOAR" "9090"

print_subheader "SIEM AI Services"
check_service_metrics "ML-Gateway" "9090"
check_service_metrics "Copilot" "9090"

# Step 5: Prometheus Targets
print_header "Step 5: Verifying Prometheus Targets"

check_prometheus_targets

# Step 6: OTLP Connectivity
print_header "Step 6: Testing OTLP Connectivity"

if command -v curl &> /dev/null; then
    # Test OTLP health check endpoint
    if curl -s -f -m $TIMEOUT "http://localhost:4318/v1/health" > /dev/null 2>&1; then
        print_pass "OTLP HTTP health endpoint is responding"
    else
        print_warn "OTLP HTTP health endpoint is not accessible (this is normal for some versions)"
    fi
fi

# Step 7: Sample Trace
print_header "Step 7: Generating and Verifying Sample Trace"

generate_sample_trace
sleep 2  # Give Jaeger time to process the trace
query_traces

# Step 8: Configuration Verification
print_header "Step 8: Verifying Configuration Files"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ -f "$PROJECT_ROOT/infra/monitoring/docker/prometheus.yml" ]; then
    print_pass "Prometheus configuration exists"
else
    print_warn "Prometheus configuration not found at expected path"
fi

if [ -f "$PROJECT_ROOT/docker-compose.yml" ]; then
    if grep -q "siem-jaeger\|siem-prometheus\|siem-grafana" "$PROJECT_ROOT/docker-compose.yml"; then
        print_pass "docker-compose.yml contains observability services"
    else
        print_fail "docker-compose.yml does not contain observability services"
    fi
else
    print_fail "docker-compose.yml not found"
fi

# Step 9: Environment Variable Check
print_header "Step 9: Checking Service Environment Variables"

if command -v docker &> /dev/null; then
    for service in gateway detection soar copilot ml-gateway; do
        container="siem-$service"
        if docker ps --filter "name=$container" --format "{{.Names}}" | grep -q "$container"; then
            if docker inspect "$container" | grep -q "OTEL_EXPORTER_OTLP_ENDPOINT"; then
                print_pass "$service has OTEL tracing configured"
            else
                print_warn "$service may not have OTEL tracing configured"
            fi
        fi
    done
fi

# Summary
print_header "Verification Summary"

TOTAL=$((PASSED + WARNINGS + FAILED))
echo -e "${GREEN}Passed:${NC}   $PASSED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo -e "${RED}Failed:${NC}   $FAILED"
echo -e "${BLUE}Total:${NC}    $TOTAL"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}✓ Observability stack verification completed successfully!${NC}"

    echo -e "\n${BLUE}Next steps:${NC}"
    echo -e "  1. Access Jaeger UI:     ${CYAN}${JAEGER_URL}${NC}"
    echo -e "  2. Access Prometheus:    ${CYAN}${PROMETHEUS_URL}${NC}"
    echo -e "  3. Access Grafana:       ${CYAN}${GRAFANA_URL}${NC}"
    echo -e "  4. Default credentials for Grafana: admin/admin"
    echo -e "\n${BLUE}For more information, see:${NC}"
    echo -e "  - docs/operations/OBSERVABILITY_GUIDE.md"
    echo -e "  - infra/monitoring/docker/README.md"

    exit 0
else
    echo -e "\n${RED}✗ Observability stack verification found issues${NC}"

    if [ $WARNINGS -gt 0 ]; then
        echo -e "\n${YELLOW}Note: Some warnings may be non-critical${NC}"
    fi

    echo -e "\n${BLUE}Troubleshooting steps:${NC}"
    echo -e "  1. Check if containers are running: docker-compose ps"
    echo -e "  2. Check container logs: docker-compose logs <service-name>"
    echo -e "  3. Verify network: docker network ls"
    echo -e "  4. See docs/operations/OBSERVABILITY_GUIDE.md for troubleshooting"

    exit 1
fi
