// Package schema provides shared data structures for the SIEM pipeline.
package schema

import (
	"encoding/json"
	"time"
)

// RawLogMessage represents a raw log message in the SIEM pipeline.
// This is the canonical format used between Collector → Parser → Normalizer → Enricher.
type RawLogMessage struct {
	EventID    string            `json:"event_id"`
	TenantID   string            `json:"tenant_id"`
	SourceType string            `json:"source_type"`
	Timestamp  time.Time         `json:"timestamp"`
	Data       json.RawMessage   `json:"data"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// NewRawLogMessage creates a new RawLogMessage with the given parameters.
func NewRawLogMessage(eventID, tenantID, sourceType string, timestamp time.Time, data json.RawMessage) *RawLogMessage {
	return &RawLogMessage{
		EventID:    eventID,
		TenantID:   tenantID,
		SourceType: sourceType,
		Timestamp:  timestamp,
		Data:       data,
		Metadata:   make(map[string]string),
	}
}

// AddMetadata adds a key-value pair to the metadata.
func (m *RawLogMessage) AddMetadata(key, value string) {
	if m.Metadata == nil {
		m.Metadata = make(map[string]string)
	}
	m.Metadata[key] = value
}
