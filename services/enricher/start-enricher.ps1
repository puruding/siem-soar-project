# Enricher Service Development Start Script

$env:KAFKA_BROKERS = "localhost:9092"
$env:KAFKA_INPUT_TOPIC = "logs.normalized"
$env:KAFKA_OUTPUT_TOPIC = "logs.enriched"
$env:KAFKA_DLQ_TOPIC = "logs.dlq.enricher"
$env:KAFKA_CONSUMER_GROUP = "enricher-service"
$env:LOG_LEVEL = "info"

# GeoIP (optional - will skip if not available)
$env:GEOIP_DATABASE_PATH = ""

# Redis for caching
$env:REDIS_ADDR = "localhost:6379"

Set-Location $PSScriptRoot
go run main.go
