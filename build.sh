#!/bin/bash

# SIEM-SOAR Platform Docker Build Script
# This script helps build Docker images for all services

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to build a service
build_service() {
    local service_name=$1
    local service_path=$2
    local dockerfile_path=$3

    print_info "Building $service_name..."

    if [ ! -f "$dockerfile_path" ]; then
        print_error "Dockerfile not found: $dockerfile_path"
        return 1
    fi

    docker build -t "siem-$service_name:latest" -f "$dockerfile_path" "$service_path"

    if [ $? -eq 0 ]; then
        print_info "$service_name built successfully"
    else
        print_error "Failed to build $service_name"
        return 1
    fi
}

# Function to build all services
build_all() {
    print_info "Building all services..."

    # Build Go services from project root (to access shared pkg)
    GO_SERVICES=(
        "gateway"
        "detection"
        "soar"
        "ti"
        "query"
        "case"
        "collector"
        "pipeline"
        "parser"
    )

    for service in "${GO_SERVICES[@]}"; do
        print_info "Building Go service: $service"
        docker build \
            -t "siem-$service:latest" \
            -f "$PROJECT_ROOT/services/$service/Dockerfile" \
            "$PROJECT_ROOT/services/$service" || {
                print_error "Failed to build $service"
                continue
            }
    done

    # Build AI service
    print_info "Building ML Gateway..."
    docker build \
        -t "siem-ml-gateway:latest" \
        -f "$PROJECT_ROOT/ai/services/ml-gateway/Dockerfile" \
        "$PROJECT_ROOT/ai" || print_error "Failed to build ml-gateway"

    # Build frontend
    print_info "Building Dashboard..."
    docker build \
        -t "siem-dashboard:latest" \
        -f "$PROJECT_ROOT/web/dashboard/Dockerfile" \
        "$PROJECT_ROOT/web/dashboard" || print_error "Failed to build dashboard"

    print_info "Build completed!"
}

# Function to build specific service
build_specific() {
    local service=$1

    case $service in
        gateway|detection|soar|ti|query|case|collector|pipeline|parser)
            print_info "Building Go service: $service"
            docker build \
                -t "siem-$service:latest" \
                -f "$PROJECT_ROOT/services/$service/Dockerfile" \
                "$PROJECT_ROOT/services/$service"
            ;;
        ml-gateway)
            print_info "Building ML Gateway..."
            docker build \
                -t "siem-ml-gateway:latest" \
                -f "$PROJECT_ROOT/ai/services/ml-gateway/Dockerfile" \
                "$PROJECT_ROOT/ai"
            ;;
        dashboard)
            print_info "Building Dashboard..."
            docker build \
                -t "siem-dashboard:latest" \
                -f "$PROJECT_ROOT/web/dashboard/Dockerfile" \
                "$PROJECT_ROOT/web/dashboard"
            ;;
        *)
            print_error "Unknown service: $service"
            print_info "Available services: gateway, detection, soar, ti, query, case, collector, pipeline, parser, ml-gateway, dashboard"
            exit 1
            ;;
    esac
}

# Function to list images
list_images() {
    print_info "SIEM-SOAR Docker images:"
    docker images | grep "siem-" | awk '{print $1":"$2" ("$7" "$8" "$9")"}'
}

# Function to clean images
clean_images() {
    print_warn "Removing all SIEM-SOAR Docker images..."
    docker images | grep "siem-" | awk '{print $3}' | xargs -r docker rmi -f
    print_info "Cleanup completed"
}

# Function to show usage
usage() {
    cat << EOF
SIEM-SOAR Platform Build Script

Usage: $0 [COMMAND] [SERVICE]

Commands:
    all                 Build all services
    [service]           Build specific service
    list                List all SIEM images
    clean               Remove all SIEM images
    help                Show this help message

Services:
    gateway             API Gateway
    detection           Detection Engine
    soar                SOAR Engine
    ti                  Threat Intelligence
    query               Query Service
    case                Case Management
    collector           Log Collector
    pipeline            Data Pipeline
    parser              Parser Service
    ml-gateway          ML Gateway (Python)
    dashboard           React Dashboard

Examples:
    $0 all              # Build all services
    $0 gateway          # Build only gateway
    $0 list             # List all images
    $0 clean            # Remove all images

EOF
}

# Main execution
main() {
    cd "$PROJECT_ROOT"

    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    case $1 in
        all)
            build_all
            ;;
        list)
            list_images
            ;;
        clean)
            clean_images
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            build_specific "$1"
            ;;
    esac
}

main "$@"
