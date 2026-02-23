#!/bin/bash
# Gateway Development Start Script
# Sets environment variables for local development

export AUTH_ENABLED=false
export CLICKHOUSE_USERNAME=siem
export CLICKHOUSE_PASSWORD=siem_password
export CLICKHOUSE_HOST=localhost:9000
export CLICKHOUSE_DATABASE=siem

cd "$(dirname "$0")"
go run main.go
