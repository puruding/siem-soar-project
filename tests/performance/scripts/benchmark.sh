#!/bin/bash
#
# SIEM/SOAR Platform Benchmark Script
#
# This script runs various performance benchmarks and generates reports.
#

set -e

# Configuration
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8080}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8086}"
RESULTS_DIR="${RESULTS_DIR:-./results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="${RESULTS_DIR}/${TIMESTAMP}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "${REPORT_DIR}"

echo -e "${GREEN}SIEM/SOAR Platform Benchmark${NC}"
echo "=============================="
echo "Gateway URL: ${GATEWAY_URL}"
echo "Collector URL: ${COLLECTOR_URL}"
echo "Results Directory: ${REPORT_DIR}"
echo ""

# Function to check if service is available
check_service() {
    local url=$1
    local name=$2

    echo -n "Checking ${name}... "
    if curl -s -o /dev/null -w "%{http_code}" "${url}/health" | grep -q "200"; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

# Function to measure response time
measure_response_time() {
    local url=$1
    local name=$2
    local iterations=${3:-100}

    echo "Measuring ${name} response time (${iterations} iterations)..."

    local total_time=0
    local min_time=999999
    local max_time=0
    local successful=0

    for i in $(seq 1 $iterations); do
        local start_time=$(date +%s%N)
        local status=$(curl -s -o /dev/null -w "%{http_code}" "${url}")
        local end_time=$(date +%s%N)

        if [ "$status" = "200" ] || [ "$status" = "404" ]; then
            local duration=$(( (end_time - start_time) / 1000000 ))
            total_time=$((total_time + duration))
            successful=$((successful + 1))

            if [ $duration -lt $min_time ]; then
                min_time=$duration
            fi
            if [ $duration -gt $max_time ]; then
                max_time=$duration
            fi
        fi
    done

    if [ $successful -gt 0 ]; then
        local avg_time=$((total_time / successful))
        echo "  Average: ${avg_time}ms"
        echo "  Min: ${min_time}ms"
        echo "  Max: ${max_time}ms"
        echo "  Success Rate: $((successful * 100 / iterations))%"

        echo "${name},${avg_time},${min_time},${max_time},${successful},${iterations}" >> "${REPORT_DIR}/response_times.csv"
    else
        echo -e "  ${RED}All requests failed${NC}"
    fi
}

# Function to benchmark event ingestion
benchmark_event_ingestion() {
    local batch_sizes=(10 50 100 500 1000)

    echo ""
    echo "Benchmarking Event Ingestion"
    echo "----------------------------"

    for size in "${batch_sizes[@]}"; do
        echo "Testing batch size: ${size}"

        # Generate sample events JSON
        local events_json='{"events":['
        for i in $(seq 1 $size); do
            if [ $i -gt 1 ]; then
                events_json+=','
            fi
            events_json+='{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","event_id":"'$(uuidgen)'","event_type":"auth_failure"}'
        done
        events_json+=']}'

        local start_time=$(date +%s%N)
        local status=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "${events_json}" \
            "${COLLECTOR_URL}/api/v1/events/batch")
        local end_time=$(date +%s%N)

        local duration=$(( (end_time - start_time) / 1000000 ))
        local eps=0
        if [ $duration -gt 0 ]; then
            eps=$((size * 1000 / duration))
        fi

        echo "  Status: ${status}"
        echo "  Duration: ${duration}ms"
        echo "  Events/second: ${eps}"

        echo "${size},${duration},${eps},${status}" >> "${REPORT_DIR}/ingestion_benchmark.csv"
    done
}

# Function to benchmark query performance
benchmark_queries() {
    local queries=(
        "SELECT count(*) FROM events"
        "SELECT event_type, count(*) FROM events GROUP BY event_type"
        "SELECT src_ip, count(*) FROM events GROUP BY src_ip ORDER BY count(*) DESC LIMIT 10"
    )

    echo ""
    echo "Benchmarking Query Performance"
    echo "------------------------------"

    for query in "${queries[@]}"; do
        echo "Testing query: ${query:0:50}..."

        local query_json='{"query":"'"${query}"'","start_time":"'$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)'","end_time":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}'

        local start_time=$(date +%s%N)
        local response=$(curl -s -w "\n%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -d "${query_json}" \
            "${GATEWAY_URL}/api/v1/query")
        local end_time=$(date +%s%N)

        local status=$(echo "$response" | tail -n1)
        local duration=$(( (end_time - start_time) / 1000000 ))

        echo "  Status: ${status}"
        echo "  Duration: ${duration}ms"

        echo "\"${query}\",${duration},${status}" >> "${REPORT_DIR}/query_benchmark.csv"
    done
}

# Function to run concurrent load test
benchmark_concurrency() {
    local concurrent_users=(1 5 10 25 50 100)

    echo ""
    echo "Benchmarking Concurrency"
    echo "------------------------"

    for users in "${concurrent_users[@]}"; do
        echo "Testing with ${users} concurrent users..."

        local total_time=0
        local successful=0

        # Run concurrent requests
        for i in $(seq 1 $users); do
            (
                local start_time=$(date +%s%N)
                curl -s -o /dev/null -w "%{http_code}" "${GATEWAY_URL}/api/v1/alerts?limit=10"
                local end_time=$(date +%s%N)
                echo $(( (end_time - start_time) / 1000000 ))
            ) &
        done

        # Wait for all background jobs and collect results
        wait

        echo "  Completed ${users} concurrent requests"
        echo "${users}" >> "${REPORT_DIR}/concurrency_benchmark.csv"
    done
}

# Function to generate HTML report
generate_html_report() {
    echo ""
    echo "Generating HTML Report..."

    cat > "${REPORT_DIR}/report.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SIEM/SOAR Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #666; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { font-size: 24px; font-weight: bold; color: #4CAF50; }
        .warning { color: #ff9800; }
        .error { color: #f44336; }
        .summary-box {
            display: inline-block;
            padding: 20px;
            margin: 10px;
            background: #f5f5f5;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <h1>SIEM/SOAR Platform Benchmark Report</h1>
    <p>Generated: <span id="timestamp"></span></p>

    <h2>Summary</h2>
    <div class="summary-box">
        <div class="metric" id="avg-response">-</div>
        <div>Avg Response Time (ms)</div>
    </div>
    <div class="summary-box">
        <div class="metric" id="max-eps">-</div>
        <div>Max Events/Second</div>
    </div>
    <div class="summary-box">
        <div class="metric" id="success-rate">-</div>
        <div>Success Rate</div>
    </div>

    <h2>Response Times</h2>
    <div id="response-times-table"></div>

    <h2>Event Ingestion</h2>
    <div id="ingestion-table"></div>

    <h2>Query Performance</h2>
    <div id="query-table"></div>

    <script>
        document.getElementById('timestamp').textContent = new Date().toISOString();
        // Additional JavaScript to load and display CSV data would go here
    </script>
</body>
</html>
EOF

    echo "Report generated: ${REPORT_DIR}/report.html"
}

# Main benchmark execution
main() {
    echo "Starting benchmark at $(date)"
    echo ""

    # Initialize CSV files with headers
    echo "endpoint,avg_ms,min_ms,max_ms,successful,total" > "${REPORT_DIR}/response_times.csv"
    echo "batch_size,duration_ms,events_per_second,status" > "${REPORT_DIR}/ingestion_benchmark.csv"
    echo "query,duration_ms,status" > "${REPORT_DIR}/query_benchmark.csv"
    echo "concurrent_users" > "${REPORT_DIR}/concurrency_benchmark.csv"

    # Check services
    echo "Checking Services"
    echo "-----------------"
    check_service "${GATEWAY_URL}" "Gateway" || echo -e "${YELLOW}Warning: Gateway not available, some tests may fail${NC}"
    check_service "${COLLECTOR_URL}" "Collector" || echo -e "${YELLOW}Warning: Collector not available, some tests may fail${NC}"

    # Run benchmarks
    echo ""
    echo "Running Benchmarks"
    echo "=================="

    # Endpoint response times
    echo ""
    echo "Endpoint Response Times"
    echo "-----------------------"
    measure_response_time "${GATEWAY_URL}/health" "Health Check" 50
    measure_response_time "${GATEWAY_URL}/api/v1/alerts" "List Alerts" 50
    measure_response_time "${GATEWAY_URL}/api/v1/rules" "List Rules" 50
    measure_response_time "${GATEWAY_URL}/api/v1/playbooks" "List Playbooks" 50

    # Event ingestion benchmark
    benchmark_event_ingestion

    # Query benchmark
    benchmark_queries

    # Concurrency benchmark
    benchmark_concurrency

    # Generate report
    generate_html_report

    echo ""
    echo -e "${GREEN}Benchmark completed!${NC}"
    echo "Results saved to: ${REPORT_DIR}"
    echo ""

    # Summary
    echo "Summary"
    echo "======="
    if [ -f "${REPORT_DIR}/response_times.csv" ]; then
        echo "Response times recorded"
    fi
    if [ -f "${REPORT_DIR}/ingestion_benchmark.csv" ]; then
        echo "Ingestion benchmark completed"
    fi
    if [ -f "${REPORT_DIR}/query_benchmark.csv" ]; then
        echo "Query benchmark completed"
    fi
}

# Run main function
main "$@"
