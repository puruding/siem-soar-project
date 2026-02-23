module github.com/siem-soar-platform/services/query

go 1.23.0

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/connector => ../../pkg/connector
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/observability => ../../pkg/observability
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
)

require (
	github.com/ClickHouse/clickhouse-go/v2 v2.23.0
	github.com/google/uuid v1.6.0
	github.com/siem-soar-platform/pkg/connector v0.0.0-00010101000000-000000000000
	github.com/siem-soar-platform/pkg/observability v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.58.0
)

require (
	github.com/ClickHouse/ch-go v0.61.5 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.7.1 // indirect
	github.com/klauspost/compress v1.17.7 // indirect
	github.com/paulmach/orb v0.11.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
