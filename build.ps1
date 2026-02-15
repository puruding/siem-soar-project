# SIEM-SOAR Platform Docker Build Script (PowerShell)
# This script helps build Docker images for all services

# Set error action preference
$ErrorActionPreference = "Stop"

# Project root directory
$ProjectRoot = $PSScriptRoot

# Function to print colored messages
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to build a Go service
function Build-GoService {
    param([string]$ServiceName)

    Write-Info "Building Go service: $ServiceName"

    $DockerfilePath = Join-Path $ProjectRoot "services\$ServiceName\Dockerfile"
    $ContextPath = Join-Path $ProjectRoot "services\$ServiceName"

    if (-not (Test-Path $DockerfilePath)) {
        Write-Error "Dockerfile not found: $DockerfilePath"
        return $false
    }

    try {
        docker build -t "siem-${ServiceName}:latest" -f $DockerfilePath $ContextPath
        Write-Info "$ServiceName built successfully"
        return $true
    }
    catch {
        Write-Error "Failed to build $ServiceName : $_"
        return $false
    }
}

# Function to build ML Gateway
function Build-MLGateway {
    Write-Info "Building ML Gateway..."

    $DockerfilePath = Join-Path $ProjectRoot "ai\services\ml-gateway\Dockerfile"
    $ContextPath = Join-Path $ProjectRoot "ai"

    if (-not (Test-Path $DockerfilePath)) {
        Write-Error "Dockerfile not found: $DockerfilePath"
        return $false
    }

    try {
        docker build -t "siem-ml-gateway:latest" -f $DockerfilePath $ContextPath
        Write-Info "ML Gateway built successfully"
        return $true
    }
    catch {
        Write-Error "Failed to build ML Gateway: $_"
        return $false
    }
}

# Function to build Dashboard
function Build-Dashboard {
    Write-Info "Building Dashboard..."

    $DockerfilePath = Join-Path $ProjectRoot "web\dashboard\Dockerfile"
    $ContextPath = Join-Path $ProjectRoot "web\dashboard"

    if (-not (Test-Path $DockerfilePath)) {
        Write-Error "Dockerfile not found: $DockerfilePath"
        return $false
    }

    try {
        docker build -t "siem-dashboard:latest" -f $DockerfilePath $ContextPath
        Write-Info "Dashboard built successfully"
        return $true
    }
    catch {
        Write-Error "Failed to build Dashboard: $_"
        return $false
    }
}

# Function to build all services
function Build-All {
    Write-Info "Building all services..."

    # Go services
    $GoServices = @(
        "gateway",
        "detection",
        "soar",
        "ti",
        "query",
        "case",
        "collector",
        "pipeline",
        "parser"
    )

    foreach ($service in $GoServices) {
        Build-GoService -ServiceName $service
    }

    # AI service
    Build-MLGateway

    # Frontend
    Build-Dashboard

    Write-Info "Build completed!"
}

# Function to build specific service
function Build-Specific {
    param([string]$ServiceName)

    switch ($ServiceName.ToLower()) {
        {$_ -in @("gateway", "detection", "soar", "ti", "query", "case", "collector", "pipeline", "parser")} {
            Build-GoService -ServiceName $ServiceName
        }
        "ml-gateway" {
            Build-MLGateway
        }
        "dashboard" {
            Build-Dashboard
        }
        default {
            Write-Error "Unknown service: $ServiceName"
            Write-Info "Available services: gateway, detection, soar, ti, query, case, collector, pipeline, parser, ml-gateway, dashboard"
            exit 1
        }
    }
}

# Function to list images
function List-Images {
    Write-Info "SIEM-SOAR Docker images:"
    docker images | Select-String "siem-"
}

# Function to clean images
function Clean-Images {
    Write-Warn "Removing all SIEM-SOAR Docker images..."

    $images = docker images --format "{{.Repository}}:{{.Tag}}" | Select-String "siem-"

    if ($images) {
        foreach ($image in $images) {
            docker rmi -f $image
        }
        Write-Info "Cleanup completed"
    }
    else {
        Write-Info "No SIEM images found"
    }
}

# Function to show usage
function Show-Usage {
    $usage = @"
SIEM-SOAR Platform Build Script (PowerShell)

Usage: .\build.ps1 [COMMAND] [SERVICE]

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
    .\build.ps1 all              # Build all services
    .\build.ps1 gateway          # Build only gateway
    .\build.ps1 list             # List all images
    .\build.ps1 clean            # Remove all images

"@
    Write-Host $usage
}

# Main execution
function Main {
    param([string[]]$Arguments)

    Set-Location $ProjectRoot

    if ($Arguments.Count -eq 0) {
        Show-Usage
        exit 0
    }

    $command = $Arguments[0].ToLower()

    switch ($command) {
        "all" {
            Build-All
        }
        "list" {
            List-Images
        }
        "clean" {
            Clean-Images
        }
        {$_ -in @("help", "--help", "-h")} {
            Show-Usage
        }
        default {
            Build-Specific -ServiceName $command
        }
    }
}

# Run main function
Main -Arguments $args
