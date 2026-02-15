package connector

import (
	"context"
)

// Connector is the base interface for all connectors.
type Connector interface {
	Connect() error
	Close() error
	Disconnect() error
	Health(ctx context.Context) (*ConnectorHealth, error)
	Type() ConnectorType
	IsConnected() bool
}

// Config is a basic configuration struct (deprecated, use ConnectorConfig instead).
type Config struct {
	Type     string
	Host     string
	Port     int
	Username string
	Password string
	Database string
}
