# Gateway Development Start Script
# Sets environment variables for local development

$env:AUTH_ENABLED = "false"
$env:CLICKHOUSE_USERNAME = "siem"
$env:CLICKHOUSE_PASSWORD = "siem_dev_password"
$env:CLICKHOUSE_HOST = "localhost:9000"
$env:CLICKHOUSE_DATABASE = "siem"

Set-Location $PSScriptRoot
go run main.go
