// Package consumer provides Kafka consumer functionality for the detection service.
package consumer

import (
	"time"

	"github.com/siem-soar-platform/pkg/udm"
)

// ParsedEvent represents an event from the parser service (logs.parsed topic).
type ParsedEvent struct {
	EventID        string                 `json:"event_id"`
	TenantID       string                 `json:"tenant_id"`
	Timestamp      time.Time              `json:"timestamp"`
	ReceivedAt     time.Time              `json:"received_at"`
	SourceType     string                 `json:"source_type"`
	Format         string                 `json:"format"`
	Fields         map[string]interface{} `json:"fields"`
	UDM            *udm.UDMEvent          `json:"udm,omitempty"` // UDM normalized data
	RawLog         string                 `json:"raw_log"`
	ParseSuccess   bool                   `json:"parse_success"`
	PatternMatched string                 `json:"pattern_matched"`
}

// HasUDM checks if the event has UDM data.
func (e *ParsedEvent) HasUDM() bool {
	return e.UDM != nil
}

// GetFieldValue retrieves a field value from the event.
// It first tries UDM fields, then falls back to Fields.
func (e *ParsedEvent) GetFieldValue(path string) (interface{}, bool) {
	// Try UDM first if available
	if e.UDM != nil {
		value, err := udm.GetField(e.UDM, path)
		if err == nil && value != nil {
			return value, true
		}
	}

	// Fall back to Fields
	return getFieldFromMap(e.Fields, path)
}

// getFieldFromMap retrieves a value from a nested map using dot notation.
func getFieldFromMap(data map[string]interface{}, path string) (interface{}, bool) {
	if data == nil {
		return nil, false
	}

	parts := splitPath(path)
	var current interface{} = data

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

// splitPath splits a dot-notation path into parts.
func splitPath(path string) []string {
	var parts []string
	var current string

	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}

	if current != "" {
		parts = append(parts, current)
	}

	return parts
}

// Alert represents an alert produced by the detection service.
type Alert struct {
	AlertID         string                 `json:"alert_id"`
	EventID         string                 `json:"event_id"`
	TenantID        string                 `json:"tenant_id"`
	RuleID          string                 `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	Severity        string                 `json:"severity"`
	Timestamp       time.Time              `json:"timestamp"`
	SourceType      string                 `json:"source_type"`
	Fields          map[string]interface{} `json:"fields"`
	MatchedFields   map[string]interface{} `json:"matched_fields,omitempty"`
	RawLog          string                 `json:"raw_log"`
	MITRETactics    []string               `json:"mitre_tactics,omitempty"`
	MITRETechniques []string               `json:"mitre_techniques,omitempty"`
}

// ConsumerMetrics holds consumer statistics.
type ConsumerMetrics struct {
	EventsConsumed   uint64 `json:"events_consumed"`
	EventsProcessed  uint64 `json:"events_processed"`
	AlertsGenerated  uint64 `json:"alerts_generated"`
	Errors           uint64 `json:"errors"`
	ParseErrors      uint64 `json:"parse_errors"`
	ProcessingTimeNs uint64 `json:"processing_time_ns"`
}

// SimpleRule represents a simple detection rule for testing.
type SimpleRule struct {
	ID              string
	Name            string
	Description     string
	Severity        string
	Field           string
	Operator        string
	Value           interface{}
	MITRETactics    []string
	MITRETechniques []string
	Enabled         bool
}

// Operator constants
const (
	OpEquals     = "eq"
	OpContains   = "contains"
	OpStartsWith = "startswith"
	OpEndsWith   = "endswith"
	OpIn         = "in"
	OpGT         = "gt"
	OpLT         = "lt"
	OpGTE        = "gte"
	OpLTE        = "lte"
	OpExists     = "exists"
)

// Severity constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// SigmaRule represents a Sigma detection rule in YAML format.
type SigmaRule struct {
	Title       string              `yaml:"title"`
	ID          string              `yaml:"id"`
	Status      string              `yaml:"status"`
	Description string              `yaml:"description"`
	Author      string              `yaml:"author"`
	Level       string              `yaml:"level"`
	Tags        []string            `yaml:"tags"`
	LogSource   SigmaLogSource      `yaml:"logsource"`
	Detection   SigmaDetection      `yaml:"detection"`
}

// SigmaLogSource represents the log source section of a Sigma rule.
type SigmaLogSource struct {
	Category string `yaml:"category"`
	Product  string `yaml:"product"`
}

// SigmaDetection represents the detection section of a Sigma rule.
type SigmaDetection struct {
	Selection map[string]interface{} `yaml:"selection"`
	Condition string                 `yaml:"condition"`
}
