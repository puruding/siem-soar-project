// Package engine provides the core parsing engine for log events.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// JSONParser parses JSON log messages.
type JSONParser struct {
	maxDepth    int
	maxFields   int
	timestampFields []string
}

// NewJSONParser creates a new JSON parser.
func NewJSONParser() *JSONParser {
	return &JSONParser{
		maxDepth:  10,
		maxFields: 500,
		timestampFields: []string{
			"timestamp", "@timestamp", "time", "datetime", "date",
			"eventTime", "event_time", "created_at", "ts",
			"logTime", "log_time", "receivedTime", "received_time",
		},
	}
}

// Name returns the parser name.
func (p *JSONParser) Name() string {
	return "json"
}

// Parse parses a JSON log message.
func (p *JSONParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	var data interface{}

	if err := json.Unmarshal(raw.Data, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	fields := make(map[string]interface{})

	switch v := data.(type) {
	case map[string]interface{}:
		fields = p.flattenMap("", v, 0)
	case []interface{}:
		// For arrays, store as-is
		fields["_items"] = v
		fields["_count"] = len(v)
	default:
		fields["_value"] = v
	}

	// Extract timestamp
	timestamp := p.extractTimestamp(fields)
	if timestamp.IsZero() {
		timestamp = raw.Timestamp
	}

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "json",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// CanParse returns true if the data looks like JSON.
func (p *JSONParser) CanParse(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Skip whitespace
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '{' || b == '['
	}
	return false
}

// flattenMap flattens a nested map with dot notation.
func (p *JSONParser) flattenMap(prefix string, m map[string]interface{}, depth int) map[string]interface{} {
	result := make(map[string]interface{})

	if depth > p.maxDepth {
		// Serialize as JSON string if too deep
		if data, err := json.Marshal(m); err == nil {
			result[prefix] = string(data)
		}
		return result
	}

	for k, v := range m {
		if len(result) >= p.maxFields {
			break
		}

		key := k
		if prefix != "" {
			key = prefix + "." + k
		}

		switch val := v.(type) {
		case map[string]interface{}:
			nested := p.flattenMap(key, val, depth+1)
			for nk, nv := range nested {
				if len(result) >= p.maxFields {
					break
				}
				result[nk] = nv
			}
		case []interface{}:
			// Store array metadata
			result[key+"._count"] = len(val)
			// Flatten array elements
			for i, item := range val {
				if len(result) >= p.maxFields {
					break
				}
				itemKey := fmt.Sprintf("%s.%d", key, i)
				if nested, ok := item.(map[string]interface{}); ok {
					for nk, nv := range p.flattenMap(itemKey, nested, depth+1) {
						if len(result) >= p.maxFields {
							break
						}
						result[nk] = nv
					}
				} else {
					result[itemKey] = item
				}
			}
		default:
			result[key] = val
		}
	}

	return result
}

// extractTimestamp tries to extract a timestamp from parsed fields.
func (p *JSONParser) extractTimestamp(fields map[string]interface{}) time.Time {
	for _, tsField := range p.timestampFields {
		// Check direct field
		if val, ok := fields[tsField]; ok {
			if ts := p.parseTimestamp(val); !ts.IsZero() {
				return ts
			}
		}

		// Check with common prefixes
		for prefix := range fields {
			if strings.HasSuffix(prefix, "."+tsField) {
				if ts := p.parseTimestamp(fields[prefix]); !ts.IsZero() {
					return ts
				}
			}
		}
	}
	return time.Time{}
}

// parseTimestamp attempts to parse various timestamp formats.
func (p *JSONParser) parseTimestamp(v interface{}) time.Time {
	switch val := v.(type) {
	case string:
		// Try common formats
		formats := []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05.000Z",
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05.000",
			"2006-01-02 15:04:05",
			"2006/01/02 15:04:05",
			"02/Jan/2006:15:04:05 -0700",
			"Jan 02 15:04:05",
			"Jan  2 15:04:05",
		}
		for _, format := range formats {
			if ts, err := time.Parse(format, val); err == nil {
				return ts
			}
		}

	case float64:
		// Unix timestamp (seconds or milliseconds)
		if val > 1e12 {
			// Milliseconds
			return time.UnixMilli(int64(val))
		}
		return time.Unix(int64(val), 0)

	case int64:
		if val > 1e12 {
			return time.UnixMilli(val)
		}
		return time.Unix(val, 0)

	case int:
		if val > 1e12 {
			return time.UnixMilli(int64(val))
		}
		return time.Unix(int64(val), 0)
	}

	return time.Time{}
}

// NestedJSONParser handles deeply nested JSON with specific extraction rules.
type NestedJSONParser struct {
	*JSONParser
	extractPaths  []string // JSON paths to extract
	flattenArrays bool
}

// NewNestedJSONParser creates a parser with custom extraction paths.
func NewNestedJSONParser(paths []string) *NestedJSONParser {
	return &NestedJSONParser{
		JSONParser:    NewJSONParser(),
		extractPaths:  paths,
		flattenArrays: true,
	}
}

// Parse parses nested JSON with path extraction.
func (p *NestedJSONParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	var data map[string]interface{}

	if err := json.Unmarshal(raw.Data, &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	fields := make(map[string]interface{})

	// Extract specific paths if configured
	if len(p.extractPaths) > 0 {
		for _, path := range p.extractPaths {
			if val := p.getPath(data, path); val != nil {
				fields[path] = val
			}
		}
	} else {
		// Default flatten
		fields = p.flattenMap("", data, 0)
	}

	timestamp := p.extractTimestamp(fields)
	if timestamp.IsZero() {
		timestamp = raw.Timestamp
	}

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "json",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// getPath retrieves a value from nested map using dot notation.
func (p *NestedJSONParser) getPath(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	return current
}
