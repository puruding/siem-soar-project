module github.com/siem-soar-platform/pkg/middleware

go 1.23.0

require (
	github.com/siem-soar-platform/pkg/logger v0.0.0
	github.com/siem-soar-platform/pkg/errors v0.0.0
)

replace (
	github.com/siem-soar-platform/pkg/logger => ../logger
	github.com/siem-soar-platform/pkg/errors => ../errors
)
