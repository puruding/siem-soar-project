module github.com/siem-soar-platform/services/query

go 1.23.0

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/connector => ../../pkg/connector
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
)

require github.com/siem-soar-platform/pkg/connector v0.0.0-00010101000000-000000000000
