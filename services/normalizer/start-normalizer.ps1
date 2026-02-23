# Normalizer Service Development Start Script

$env:KAFKA_BROKERS = "localhost:9092"
$env:KAFKA_INPUT_TOPIC = "logs.parsed"
$env:KAFKA_OUTPUT_TOPIC = "logs.normalized"
$env:KAFKA_DLQ_TOPIC = "logs.dlq.normalizer"
$env:KAFKA_CONSUMER_GROUP = "normalizer-service"
$env:LOG_LEVEL = "info"

Set-Location $PSScriptRoot
go run main.go
