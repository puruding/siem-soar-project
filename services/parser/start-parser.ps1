# Parser Service Development Start Script

$env:KAFKA_BROKERS = "localhost:9092"
$env:KAFKA_INPUT_TOPIC = "raw-logs"
$env:KAFKA_OUTPUT_TOPIC = "logs.parsed"
$env:KAFKA_DLQ_TOPIC = "logs.dlq.parser"
$env:KAFKA_CONSUMER_GROUP = "parser-service"
$env:LOG_LEVEL = "info"

Set-Location $PSScriptRoot
go run main.go
