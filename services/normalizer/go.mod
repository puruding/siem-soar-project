module github.com/siem-soar-platform/services/normalizer

go 1.23.0

require (
	github.com/google/uuid v1.6.0
	github.com/siem-soar-platform/pkg/udm v0.0.0
	github.com/twmb/franz-go v1.16.1
)

require (
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.7.0 // indirect
)

replace (
	github.com/siem-soar-platform/pkg/udm => ../../pkg/udm
)
