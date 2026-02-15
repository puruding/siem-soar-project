module github.com/siem-soar-platform/services/case

go 1.23.0

require (
	github.com/google/uuid v1.5.0
	github.com/gorilla/mux v1.8.1
	github.com/jmoiron/sqlx v1.3.5
	github.com/lib/pq v1.10.9
)

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
)
