package udm

import (
	"testing"
	"time"
)

func TestGetField(t *testing.T) {
	// Create a sample UDM event
	event := &UDMEvent{
		Metadata: &Metadata{
			EventTimestamp: time.Now(),
			EventType:      EventTypeUserLogin,
			VendorName:     "TestVendor",
			ProductName:    "TestProduct",
			ID:             "test-event-123",
		},
		Principal: &Entity{
			Hostname: "workstation-01",
			IP:       []string{"192.168.1.100", "10.0.0.50"},
			Port:     45678,
			User: &User{
				UserName:       "john.doe",
				UserID:         "user-123",
				EmailAddresses: []string{"john@example.com", "j.doe@example.com"},
			},
		},
		Target: &Entity{
			Hostname: "server-01",
			IP:       []string{"192.168.1.1"},
			Port:     443,
		},
		Network: &Network{
			IPProtocol:          "TCP",
			ApplicationProtocol: "HTTPS",
			Direction:           "OUTBOUND",
			DNS: &DNS{
				Questions: []*DNSQuestion{
					{Name: "example.com", Type: 1},
					{Name: "test.com", Type: 1},
				},
			},
		},
		SecurityResult: &SecurityResult{
			Action:   "ALLOW",
			Severity: "LOW",
		},
	}

	tests := []struct {
		name     string
		path     string
		expected interface{}
		wantErr  bool
	}{
		// Basic field access
		{
			name:     "metadata.vendor_name",
			path:     "metadata.vendor_name",
			expected: "TestVendor",
		},
		{
			name:     "metadata.event_type",
			path:     "metadata.event_type",
			expected: EventTypeUserLogin,
		},
		{
			name:     "metadata.id",
			path:     "metadata.id",
			expected: "test-event-123",
		},
		// Nested entity access
		{
			name:     "principal.hostname",
			path:     "principal.hostname",
			expected: "workstation-01",
		},
		{
			name:     "principal.user.user_name",
			path:     "principal.user.user_name",
			expected: "john.doe",
		},
		{
			name:     "principal.port",
			path:     "principal.port",
			expected: 45678,
		},
		// Array access with index
		{
			name:     "principal.ip[0]",
			path:     "principal.ip[0]",
			expected: "192.168.1.100",
		},
		{
			name:     "principal.ip[1]",
			path:     "principal.ip[1]",
			expected: "10.0.0.50",
		},
		{
			name:     "principal.user.email_addresses[0]",
			path:     "principal.user.email_addresses[0]",
			expected: "john@example.com",
		},
		// Network fields
		{
			name:     "network.ip_protocol",
			path:     "network.ip_protocol",
			expected: "TCP",
		},
		{
			name:     "network.direction",
			path:     "network.direction",
			expected: "OUTBOUND",
		},
		// Nested DNS access
		{
			name:     "network.dns.questions[0].name",
			path:     "network.dns.questions[0].name",
			expected: "example.com",
		},
		{
			name:     "network.dns.questions[1].name",
			path:     "network.dns.questions[1].name",
			expected: "test.com",
		},
		// Security result
		{
			name:     "security_result.action",
			path:     "security_result.action",
			expected: "ALLOW",
		},
		// Target entity
		{
			name:     "target.ip[0]",
			path:     "target.ip[0]",
			expected: "192.168.1.1",
		},
		{
			name:     "target.port",
			path:     "target.port",
			expected: 443,
		},
		// Non-existent fields
		{
			name:    "nonexistent.field",
			path:    "nonexistent.field",
			wantErr: true,
		},
		{
			name:     "principal.ip[99]", // Out of bounds
			path:     "principal.ip[99]",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := GetField(event, tt.path)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil && tt.expected != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if value != tt.expected {
				t.Errorf("GetField(%q) = %v (%T), want %v (%T)",
					tt.path, value, value, tt.expected, tt.expected)
			}
		})
	}
}

func TestGetFieldAsString(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			Hostname: "test-host",
			Port:     8080,
			User: &User{
				UserName: "alice",
			},
		},
	}

	// String field
	s, err := GetFieldAsString(event, "principal.hostname")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if s != "test-host" {
		t.Errorf("expected 'test-host', got %q", s)
	}

	// Int field as string
	s, err = GetFieldAsString(event, "principal.port")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if s != "8080" {
		t.Errorf("expected '8080', got %q", s)
	}
}

func TestGetFieldAsStringSlice(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			IP: []string{"1.1.1.1", "2.2.2.2"},
		},
	}

	slice, err := GetFieldAsStringSlice(event, "principal.ip")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(slice) != 2 {
		t.Errorf("expected 2 elements, got %d", len(slice))
	}
	if slice[0] != "1.1.1.1" || slice[1] != "2.2.2.2" {
		t.Errorf("unexpected slice contents: %v", slice)
	}
}

func TestHasField(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			Hostname: "test-host",
			User: &User{
				UserName: "alice",
			},
		},
		Target: &Entity{}, // Empty entity
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"principal.hostname", true},
		{"principal.user.user_name", true},
		{"principal.ip", false},           // Empty slice
		{"target.hostname", false},        // Empty string
		{"nonexistent.field", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			has := HasField(event, tt.path)
			if has != tt.expected {
				t.Errorf("HasField(%q) = %v, want %v", tt.path, has, tt.expected)
			}
		})
	}
}

func TestGetFields(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			Hostname: "host1",
			Port:     80,
		},
		Target: &Entity{
			Hostname: "host2",
		},
	}

	fields := GetFields(event,
		"principal.hostname",
		"principal.port",
		"target.hostname",
		"nonexistent.field",
	)

	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}

	if fields["principal.hostname"] != "host1" {
		t.Errorf("unexpected principal.hostname: %v", fields["principal.hostname"])
	}
	if fields["principal.port"] != 80 {
		t.Errorf("unexpected principal.port: %v", fields["principal.port"])
	}
	if fields["target.hostname"] != "host2" {
		t.Errorf("unexpected target.hostname: %v", fields["target.hostname"])
	}
}

func TestToMap(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			Hostname: "test-host",
			IP:       []string{"1.1.1.1"},
		},
	}

	m, err := ToMap(event)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check that the map contains expected keys
	if m == nil {
		t.Error("ToMap returned nil")
		return
	}

	// The structure should be navigable
	if principal, ok := m["principal"].(map[string]interface{}); ok {
		if principal["hostname"] != "test-host" {
			t.Errorf("unexpected principal.hostname: %v", principal["hostname"])
		}
	}
}

func TestNilEvent(t *testing.T) {
	_, err := GetField(nil, "principal.hostname")
	if err == nil {
		t.Error("expected error for nil event")
	}
}

func TestEmptyPath(t *testing.T) {
	event := &UDMEvent{}
	_, err := GetField(event, "")
	if err == nil {
		t.Error("expected error for empty path")
	}
}

func TestGetFieldOrDefault(t *testing.T) {
	event := &UDMEvent{
		Principal: &Entity{
			Hostname: "real-host",
		},
	}

	// Existing field
	v := GetFieldOrDefault(event, "principal.hostname", "default")
	if v != "real-host" {
		t.Errorf("expected 'real-host', got %v", v)
	}

	// Non-existent field
	v = GetFieldOrDefault(event, "principal.ip[0]", "default-ip")
	if v != "default-ip" {
		t.Errorf("expected 'default-ip', got %v", v)
	}
}
