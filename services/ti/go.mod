module github.com/siem-soar-platform/services/ti

go 1.23.0

require (
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.10.9
	github.com/redis/go-redis/v9 v9.5.1
	github.com/siem-soar-platform/pkg/observability v0.0.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.58.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/observability => ../../pkg/observability
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
)
