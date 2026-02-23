package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewRawLogMessage(t *testing.T) {
	now := time.Now()
	data := json.RawMessage(`{"key":"value"}`)

	msg := NewRawLogMessage("event-123", "tenant-1", "http", now, data)

	if msg.EventID != "event-123" {
		t.Errorf("Expected EventID to be 'event-123', got %s", msg.EventID)
	}
	if msg.TenantID != "tenant-1" {
		t.Errorf("Expected TenantID to be 'tenant-1', got %s", msg.TenantID)
	}
	if msg.SourceType != "http" {
		t.Errorf("Expected SourceType to be 'http', got %s", msg.SourceType)
	}
	if !msg.Timestamp.Equal(now) {
		t.Errorf("Expected Timestamp to be %v, got %v", now, msg.Timestamp)
	}
	if string(msg.Data) != `{"key":"value"}` {
		t.Errorf("Expected Data to be '{\"key\":\"value\"}', got %s", string(msg.Data))
	}
	if msg.Metadata == nil {
		t.Error("Expected Metadata to be initialized")
	}
}

func TestAddMetadata(t *testing.T) {
	msg := NewRawLogMessage("event-123", "tenant-1", "http", time.Now(), json.RawMessage(`{}`))

	msg.AddMetadata("key1", "value1")
	msg.AddMetadata("key2", "value2")

	if len(msg.Metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got %d", len(msg.Metadata))
	}
	if msg.Metadata["key1"] != "value1" {
		t.Errorf("Expected metadata key1 to be 'value1', got %s", msg.Metadata["key1"])
	}
	if msg.Metadata["key2"] != "value2" {
		t.Errorf("Expected metadata key2 to be 'value2', got %s", msg.Metadata["key2"])
	}
}

func TestAddMetadataInitializesMap(t *testing.T) {
	msg := &RawLogMessage{
		EventID:    "event-123",
		TenantID:   "tenant-1",
		SourceType: "http",
		Timestamp:  time.Now(),
		Data:       json.RawMessage(`{}`),
		// Metadata is nil
	}

	msg.AddMetadata("key", "value")

	if msg.Metadata == nil {
		t.Error("Expected Metadata to be initialized")
	}
	if msg.Metadata["key"] != "value" {
		t.Errorf("Expected metadata key to be 'value', got %s", msg.Metadata["key"])
	}
}

func TestRawLogMessageJSON(t *testing.T) {
	now := time.Date(2024, 2, 21, 12, 0, 0, 0, time.UTC)
	data := json.RawMessage(`{"message":"test log"}`)

	msg := NewRawLogMessage("event-123", "tenant-1", "http", now, data)
	msg.AddMetadata("content_type", "application/json")
	msg.AddMetadata("remote_addr", "192.168.1.1")

	jsonBytes, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Failed to marshal RawLogMessage: %v", err)
	}

	var unmarshaled RawLogMessage
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal RawLogMessage: %v", err)
	}

	if unmarshaled.EventID != msg.EventID {
		t.Errorf("Expected EventID to be %s, got %s", msg.EventID, unmarshaled.EventID)
	}
	if unmarshaled.TenantID != msg.TenantID {
		t.Errorf("Expected TenantID to be %s, got %s", msg.TenantID, unmarshaled.TenantID)
	}
	if unmarshaled.SourceType != msg.SourceType {
		t.Errorf("Expected SourceType to be %s, got %s", msg.SourceType, unmarshaled.SourceType)
	}
	if !unmarshaled.Timestamp.Equal(msg.Timestamp) {
		t.Errorf("Expected Timestamp to be %v, got %v", msg.Timestamp, unmarshaled.Timestamp)
	}
	if string(unmarshaled.Data) != string(msg.Data) {
		t.Errorf("Expected Data to be %s, got %s", string(msg.Data), string(unmarshaled.Data))
	}
	if len(unmarshaled.Metadata) != len(msg.Metadata) {
		t.Errorf("Expected %d metadata entries, got %d", len(msg.Metadata), len(unmarshaled.Metadata))
	}
}
