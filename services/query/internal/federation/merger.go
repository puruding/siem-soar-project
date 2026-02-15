// Package federation provides result merging capabilities.
package federation

import (
	"sort"
	"strings"
	"time"

	"github.com/siem-soar-platform/pkg/connector"
)

// Merger merges results from multiple SIEMs.
type Merger struct {
	normalizeFields bool
	fieldMappings   map[string][]string // standard -> SIEM-specific names
}

// NewMerger creates a new merger.
func NewMerger(normalizeFields bool) *Merger {
	m := &Merger{
		normalizeFields: normalizeFields,
		fieldMappings:   make(map[string][]string),
	}

	// Initialize field mappings for normalization
	m.initFieldMappings()

	return m
}

// initFieldMappings initializes field mappings.
func (m *Merger) initFieldMappings() {
	m.fieldMappings = map[string][]string{
		"timestamp": {"_time", "@timestamp", "TimeGenerated", "time", "Time", "timestamp"},
		"source_ip": {"src_ip", "source.ip", "SourceIP", "srcip", "src", "SrcAddr"},
		"destination_ip": {"dest_ip", "destination.ip", "DestinationIP", "destip", "dst", "DstAddr"},
		"source_port": {"src_port", "source.port", "SourcePort", "srcport"},
		"destination_port": {"dest_port", "destination.port", "DestinationPort", "destport"},
		"user": {"user", "user.name", "Account", "username", "UserName"},
		"hostname": {"host", "host.name", "Computer", "hostname", "HostName"},
		"process_name": {"process", "process.name", "ProcessName", "Image"},
		"command_line": {"CommandLine", "process.command_line", "cmdline"},
		"event_id": {"EventID", "event.id", "eventid", "event_code"},
		"severity": {"severity", "event.severity", "SeverityLevel", "priority"},
		"action": {"action", "event.action", "Activity", "EventType"},
		"message": {"_raw", "message", "Message", "RawData"},
		"siem_source": {"_siem_source"}, // Added field indicating source SIEM
	}
}

// Merge merges results from multiple SIEMs.
func (m *Merger) Merge(siemResults map[connector.SIEMType]*SIEMResult) []map[string]interface{} {
	var allResults []map[string]interface{}

	for siemType, siemResult := range siemResults {
		if siemResult.Status != connector.QueryStatusCompleted {
			continue
		}

		for _, result := range siemResult.Results {
			// Add source SIEM indicator
			result["_siem_source"] = string(siemType)

			// Normalize fields if enabled
			if m.normalizeFields {
				result = m.normalizeResult(result, siemType)
			}

			allResults = append(allResults, result)
		}
	}

	// Sort by timestamp
	sort.Slice(allResults, func(i, j int) bool {
		ti := m.extractTimestamp(allResults[i])
		tj := m.extractTimestamp(allResults[j])
		return ti.After(tj) // Most recent first
	})

	return allResults
}

// normalizeResult normalizes field names in a result.
func (m *Merger) normalizeResult(result map[string]interface{}, siem connector.SIEMType) map[string]interface{} {
	normalized := make(map[string]interface{})

	// Copy all original fields
	for k, v := range result {
		normalized[k] = v
	}

	// Add normalized versions
	for standardName, siemNames := range m.fieldMappings {
		for _, siemName := range siemNames {
			if val, ok := result[siemName]; ok {
				normalized[standardName] = val
				break
			}
		}
	}

	return normalized
}

// extractTimestamp extracts a timestamp from a result.
func (m *Merger) extractTimestamp(result map[string]interface{}) time.Time {
	// Try different timestamp field names
	timestampFields := m.fieldMappings["timestamp"]

	for _, field := range timestampFields {
		if val, ok := result[field]; ok {
			switch v := val.(type) {
			case time.Time:
				return v
			case string:
				// Try parsing various formats
				formats := []string{
					time.RFC3339,
					time.RFC3339Nano,
					"2006-01-02T15:04:05.000Z",
					"2006-01-02T15:04:05",
					"2006-01-02 15:04:05",
				}
				for _, format := range formats {
					if t, err := time.Parse(format, v); err == nil {
						return t
					}
				}
			case float64:
				// Unix timestamp
				return time.Unix(int64(v), 0)
			case int64:
				return time.Unix(v, 0)
			}
		}
	}

	return time.Time{}
}

// MergeOptions holds options for merging.
type MergeOptions struct {
	SortField        string
	SortAscending    bool
	DeduplicateBy    []string
	MaxResults       int
	FilterEmpty      bool
	NormalizeFields  bool
}

// MergeWithOptions merges results with additional options.
func (m *Merger) MergeWithOptions(siemResults map[connector.SIEMType]*SIEMResult, opts MergeOptions) []map[string]interface{} {
	var allResults []map[string]interface{}

	for siemType, siemResult := range siemResults {
		if siemResult.Status != connector.QueryStatusCompleted {
			continue
		}

		for _, result := range siemResult.Results {
			// Add source SIEM indicator
			result["_siem_source"] = string(siemType)

			// Normalize fields if requested
			if opts.NormalizeFields {
				result = m.normalizeResult(result, siemType)
			}

			// Filter empty results
			if opts.FilterEmpty && m.isEmpty(result) {
				continue
			}

			allResults = append(allResults, result)
		}
	}

	// Deduplicate
	if len(opts.DeduplicateBy) > 0 {
		allResults = m.deduplicate(allResults, opts.DeduplicateBy)
	}

	// Sort
	if opts.SortField != "" {
		sort.Slice(allResults, func(i, j int) bool {
			vi := m.extractFieldValue(allResults[i], opts.SortField)
			vj := m.extractFieldValue(allResults[j], opts.SortField)
			cmp := m.compareValues(vi, vj)
			if opts.SortAscending {
				return cmp < 0
			}
			return cmp > 0
		})
	}

	// Apply limit
	if opts.MaxResults > 0 && len(allResults) > opts.MaxResults {
		allResults = allResults[:opts.MaxResults]
	}

	return allResults
}

// deduplicate removes duplicate results based on specified fields.
func (m *Merger) deduplicate(results []map[string]interface{}, fields []string) []map[string]interface{} {
	seen := make(map[string]bool)
	var deduped []map[string]interface{}

	for _, result := range results {
		key := m.buildDedupeKey(result, fields)
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, result)
		}
	}

	return deduped
}

// buildDedupeKey builds a deduplication key from specified fields.
func (m *Merger) buildDedupeKey(result map[string]interface{}, fields []string) string {
	var parts []string
	for _, field := range fields {
		val := m.extractFieldValue(result, field)
		parts = append(parts, valueToString(val))
	}
	return strings.Join(parts, "|")
}

// isEmpty checks if a result is effectively empty.
func (m *Merger) isEmpty(result map[string]interface{}) bool {
	// Check for meaningful content
	meaningfulFields := []string{"message", "_raw", "RawData", "event.id", "EventID"}
	for _, field := range meaningfulFields {
		if val, ok := result[field]; ok && val != nil && val != "" {
			return false
		}
	}
	return len(result) < 3 // Very few fields
}

// extractFieldValue extracts a field value, handling nested fields.
func (m *Merger) extractFieldValue(result map[string]interface{}, field string) interface{} {
	// Handle nested fields (e.g., "source.ip")
	parts := strings.Split(field, ".")

	var current interface{} = result
	for _, part := range parts {
		if m, ok := current.(map[string]interface{}); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	return current
}

// compareValues compares two values of any type.
func (m *Merger) compareValues(a, b interface{}) int {
	// Handle nil
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}

	// Compare by type
	switch va := a.(type) {
	case string:
		if vb, ok := b.(string); ok {
			return strings.Compare(va, vb)
		}
	case float64:
		if vb, ok := b.(float64); ok {
			if va < vb {
				return -1
			}
			if va > vb {
				return 1
			}
			return 0
		}
	case int64:
		if vb, ok := b.(int64); ok {
			if va < vb {
				return -1
			}
			if va > vb {
				return 1
			}
			return 0
		}
	case time.Time:
		if vb, ok := b.(time.Time); ok {
			if va.Before(vb) {
				return -1
			}
			if va.After(vb) {
				return 1
			}
			return 0
		}
	}

	// Fallback to string comparison
	return strings.Compare(valueToString(a), valueToString(b))
}

// valueToString converts any value to a string.
func valueToString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case float64:
		return strings.TrimRight(strings.TrimRight(strings.Replace(string(rune(int(val))), ".", "", 1), "0"), ".")
	case int64:
		return string(rune(val))
	case bool:
		if val {
			return "true"
		}
		return "false"
	case time.Time:
		return val.Format(time.RFC3339)
	default:
		return ""
	}
}

// Statistics holds merge statistics.
type Statistics struct {
	TotalResults       int
	ResultsPerSIEM     map[connector.SIEMType]int
	DuplicatesRemoved  int
	NormalizationCount int
}

// GetStatistics returns statistics about the merged results.
func (m *Merger) GetStatistics(siemResults map[connector.SIEMType]*SIEMResult) *Statistics {
	stats := &Statistics{
		ResultsPerSIEM: make(map[connector.SIEMType]int),
	}

	for siemType, siemResult := range siemResults {
		if siemResult.Status == connector.QueryStatusCompleted {
			count := len(siemResult.Results)
			stats.ResultsPerSIEM[siemType] = count
			stats.TotalResults += count
		}
	}

	return stats
}
