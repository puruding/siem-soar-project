@echo off
REM ============================================================================
REM Gateway Service - Development Mode
REM ============================================================================
REM This script runs the Gateway service with authentication disabled
REM for easier local development and testing.
REM ============================================================================

echo Starting Gateway Service (Development Mode)...
echo.
echo Configuration:
echo   - Port: 8080
echo   - Auth: DISABLED
echo   - Rate Limiting: 100 RPS
echo.

cd /d "%~dp0..\services\gateway"

REM Set environment variables for development
set AUTH_ENABLED=false
set PORT=8080
set RATE_LIMIT_RPS=100
set RATE_LIMIT_BURST=200

REM Run the pre-built gateway executable
gateway.exe

REM Alternative: Build and run from source
REM go run main.go
