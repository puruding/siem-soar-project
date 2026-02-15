module github.com/siem-soar-platform/services/detection

go 1.23.0

require (
	github.com/google/uuid v1.6.0
	github.com/siem-soar-platform/pkg/connector v0.0.0
	gopkg.in/yaml.v3 v3.0.1
)

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/connector => ../../pkg/connector
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
)
