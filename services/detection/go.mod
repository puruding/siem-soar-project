module github.com/siem-soar-platform/services/detection

go 1.23.0

require (
	github.com/google/uuid v1.6.0
	github.com/siem-soar-platform/pkg/connector v0.0.0
	github.com/siem-soar-platform/pkg/udm v0.0.0
	github.com/twmb/franz-go v1.16.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.19 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.7.0 // indirect
)

replace (
	github.com/siem-soar-platform/pkg/config => ../../pkg/config
	github.com/siem-soar-platform/pkg/connector => ../../pkg/connector
	github.com/siem-soar-platform/pkg/errors => ../../pkg/errors
	github.com/siem-soar-platform/pkg/logger => ../../pkg/logger
	github.com/siem-soar-platform/pkg/repository => ../../pkg/repository
	github.com/siem-soar-platform/pkg/udm => ../../pkg/udm
)
