# Router Service Development Start Script

$env:KAFKA_BROKERS = "localhost:9092"
$env:KAFKA_INPUT_TOPIC = "logs.normalized"
$env:KAFKA_OUTPUT_TOPIC = "logs.routed"
$env:KAFKA_CONSUMER_GROUP = "router-service"
$env:LOG_LEVEL = "info"

# ClickHouse
$env:CLICKHOUSE_HOSTS = "localhost:9000"
$env:CLICKHOUSE_DATABASE = "siem"
$env:CLICKHOUSE_TABLE = "events"
$env:CLICKHOUSE_USERNAME = "siem"
$env:CLICKHOUSE_PASSWORD = "siem_dev_password"
$env:CLICKHOUSE_BATCH_SIZE = "100"
$env:CLICKHOUSE_FLUSH_INTERVAL = "1s"

Set-Location $PSScriptRoot
go run main.go
