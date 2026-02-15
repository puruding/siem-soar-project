module github.com/siem-soar-platform/services/gateway

go 1.23.0

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/middleware => ../../pkg/middleware
)
