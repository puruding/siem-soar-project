# Start Full Pipeline Services
# Run this script in PowerShell: .\scripts\start-pipeline.ps1

Write-Host "Starting SIEM Pipeline Services..." -ForegroundColor Green

# Parser
Write-Host "`n[1/4] Starting Parser (raw-logs -> logs.parsed)..." -ForegroundColor Cyan
$parserEnv = @{
    KAFKA_BROKERS = "localhost:9092"
    KAFKA_INPUT_TOPIC = "raw-logs"
    KAFKA_OUTPUT_TOPIC = "logs.parsed"
    KAFKA_DLQ_TOPIC = "logs.dlq.parser"
}
$parser = Start-Process -FilePath "go" -ArgumentList "run", "main.go" `
    -WorkingDirectory "$PSScriptRoot\..\services\parser" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$PSScriptRoot\..\logs\parser.log" `
    -RedirectStandardError "$PSScriptRoot\..\logs\parser.err"
foreach ($key in $parserEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $parserEnv[$key], "Process") }

Start-Sleep -Seconds 2

# Normalizer
Write-Host "[2/4] Starting Normalizer (logs.parsed -> logs.normalized)..." -ForegroundColor Cyan
$normalizer = Start-Process -FilePath "go" -ArgumentList "run", "main.go" `
    -WorkingDirectory "$PSScriptRoot\..\services\normalizer" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2

# Enricher
Write-Host "[3/4] Starting Enricher (logs.normalized -> logs.enriched)..." -ForegroundColor Cyan
$enricher = Start-Process -FilePath "go" -ArgumentList "run", "main.go" `
    -WorkingDirectory "$PSScriptRoot\..\services\enricher" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2

# Router
Write-Host "[4/4] Starting Router (logs.enriched -> ClickHouse)..." -ForegroundColor Cyan
$router = Start-Process -FilePath "go" -ArgumentList "run", "main.go" `
    -WorkingDirectory "$PSScriptRoot\..\services\router" `
    -PassThru -WindowStyle Hidden

Write-Host "`nPipeline Services Started:" -ForegroundColor Green
Write-Host "  Parser PID:     $($parser.Id)"
Write-Host "  Normalizer PID: $($normalizer.Id)"
Write-Host "  Enricher PID:   $($enricher.Id)"
Write-Host "  Router PID:     $($router.Id)"

Write-Host "`nPipeline Flow:" -ForegroundColor Yellow
Write-Host "  Collector -> raw-logs -> Parser -> logs.parsed -> Normalizer"
Write-Host "  -> logs.normalized -> Enricher -> logs.enriched -> Router -> ClickHouse"
