// Package deploy provides Splunk-specific Sigma rule conversion and deployment.
package deploy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/siem-soar-platform/pkg/connector"
)

// SplunkConverter converts Sigma rules to Splunk SPL.
type SplunkConverter struct {
	config        *Config
	fieldMappings map[string]string
	logSourceMap  map[string]string
}

// NewSplunkConverter creates a new Splunk converter.
func NewSplunkConverter(config *Config) *SplunkConverter {
	c := &SplunkConverter{
		config:        config,
		fieldMappings: make(map[string]string),
		logSourceMap:  make(map[string]string),
	}

	c.initFieldMappings()
	c.initLogSourceMap()

	return c
}

// initFieldMappings initializes field name mappings.
func (c *SplunkConverter) initFieldMappings() {
	c.fieldMappings = map[string]string{
		"CommandLine":          "CommandLine",
		"Image":                "Image",
		"ParentImage":          "ParentImage",
		"ParentCommandLine":    "ParentCommandLine",
		"User":                 "user",
		"TargetFilename":       "TargetFilename",
		"SourceIP":             "src_ip",
		"DestinationIP":        "dest_ip",
		"SourcePort":           "src_port",
		"DestinationPort":      "dest_port",
		"DestinationHostname":  "dest",
		"EventID":              "EventCode",
		"Channel":              "source",
		"Provider_Name":        "SourceName",
		"Hashes":               "Hashes",
		"md5":                  "MD5",
		"sha1":                 "SHA1",
		"sha256":               "SHA256",
		"ProcessId":            "ProcessId",
		"TargetObject":         "TargetObject",
		"Details":              "Details",
		"QueryName":            "query",
		"QueryResults":         "answer",
	}
}

// initLogSourceMap initializes log source to index mappings.
func (c *SplunkConverter) initLogSourceMap() {
	c.logSourceMap = map[string]string{
		"windows/sysmon":           "index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
		"windows/security":         "index=windows sourcetype=XmlWinEventLog:Security",
		"windows/system":           "index=windows sourcetype=XmlWinEventLog:System",
		"windows/powershell":       "index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
		"windows/dns_server":       "index=windows sourcetype=DnsServer",
		"linux/syslog":             "index=linux sourcetype=syslog",
		"linux/auditd":             "index=linux sourcetype=linux:audit",
		"proxy":                    "index=proxy",
		"firewall":                 "index=firewall",
		"webserver":                "index=web",
		"dns":                      "index=dns",
		"network_connection":       "index=network",
		"process_creation":         "index=windows EventCode=1",
		"file_create":              "index=windows EventCode=11",
		"registry_event":           "index=windows (EventCode=12 OR EventCode=13 OR EventCode=14)",
		"network_connection/sysmon": "index=windows EventCode=3",
		"dns_query":                "index=windows EventCode=22",
		"image_load":               "index=windows EventCode=7",
		"create_remote_thread":     "index=windows EventCode=8",
		"raw_access_thread":        "index=windows EventCode=9",
		"process_access":           "index=windows EventCode=10",
	}
}

// SIEM returns the SIEM type.
func (c *SplunkConverter) SIEM() connector.SIEMType {
	return connector.SIEMSplunk
}

// Convert converts a Sigma rule to Splunk SPL.
func (c *SplunkConverter) Convert(ctx context.Context, rule *SigmaRule) (*ConvertedRule, error) {
	// Build base query from log source
	baseQuery := c.buildBaseQuery(rule.LogSource)

	// Build detection query
	detectionQuery, err := c.buildDetectionQuery(rule.Detection)
	if err != nil {
		return nil, fmt.Errorf("failed to build detection query: %w", err)
	}

	// Combine queries
	fullQuery := baseQuery
	if detectionQuery != "" {
		fullQuery += " " + detectionQuery
	}

	// Add fields selection
	if len(rule.Fields) > 0 {
		mappedFields := make([]string, len(rule.Fields))
		for i, f := range rule.Fields {
			mappedFields[i] = c.mapFieldName(f)
		}
		fullQuery += " | table " + strings.Join(mappedFields, ", ")
	}

	// Extract MITRE ATT&CK tags
	mitreTags := extractMITRETags(rule.Tags)

	return &ConvertedRule{
		OriginalID:    rule.ID,
		SIEM:          connector.SIEMSplunk,
		Query:         fullQuery,
		QueryLanguage: "SPL",
		Index:         extractIndex(baseQuery),
		Title:         rule.Title,
		Description:   rule.Description,
		Severity:      mapSeverity(rule.Level),
		Tags:          rule.Tags,
		MITRE:         mitreTags,
	}, nil
}

// buildBaseQuery builds the base query from log source.
func (c *SplunkConverter) buildBaseQuery(ls LogSource) string {
	// Try to find exact match
	key := ""
	if ls.Category != "" && ls.Product != "" {
		key = ls.Product + "/" + ls.Category
	} else if ls.Product != "" {
		key = ls.Product
	} else if ls.Category != "" {
		key = ls.Category
	}

	if query, ok := c.logSourceMap[key]; ok {
		return query
	}

	// Build generic query
	var parts []string
	if ls.Product == "windows" {
		parts = append(parts, "index=windows")
	} else if ls.Product == "linux" {
		parts = append(parts, "index=linux")
	}

	if ls.Service != "" {
		parts = append(parts, fmt.Sprintf("sourcetype=*%s*", ls.Service))
	}

	if len(parts) == 0 {
		return "index=*" // Fallback to all indexes
	}

	return strings.Join(parts, " ")
}

// buildDetectionQuery builds the detection query from Sigma detection logic.
func (c *SplunkConverter) buildDetectionQuery(detection map[string]interface{}) (string, error) {
	condition, ok := detection["condition"].(string)
	if !ok {
		return "", fmt.Errorf("missing condition in detection")
	}

	// Build queries for each selection
	selectionQueries := make(map[string]string)
	for key, value := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}

		query, err := c.buildSelectionQuery(key, value)
		if err != nil {
			return "", fmt.Errorf("failed to build selection %s: %w", key, err)
		}
		selectionQueries[key] = query
	}

	// Parse and apply condition
	return c.applyCondition(condition, selectionQueries)
}

// buildSelectionQuery builds a query for a single selection.
func (c *SplunkConverter) buildSelectionQuery(name string, value interface{}) (string, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		return c.buildMapSelection(v)
	case []interface{}:
		return c.buildArraySelection(v)
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("unsupported selection type: %T", value)
	}
}

// buildMapSelection builds a query from a map selection.
func (c *SplunkConverter) buildMapSelection(m map[string]interface{}) (string, error) {
	var parts []string

	for field, value := range m {
		mappedField := c.mapFieldName(field)
		query := c.buildFieldQuery(mappedField, value)
		parts = append(parts, query)
	}

	if len(parts) == 0 {
		return "", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}

	return "(" + strings.Join(parts, " ") + ")", nil
}

// buildArraySelection builds a query from an array selection.
func (c *SplunkConverter) buildArraySelection(arr []interface{}) (string, error) {
	var parts []string

	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			query, err := c.buildMapSelection(m)
			if err != nil {
				return "", err
			}
			parts = append(parts, query)
		}
	}

	if len(parts) == 0 {
		return "", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}

	return "(" + strings.Join(parts, " OR ") + ")", nil
}

// buildFieldQuery builds a query for a single field.
func (c *SplunkConverter) buildFieldQuery(field string, value interface{}) string {
	switch v := value.(type) {
	case string:
		return c.buildStringQuery(field, v)
	case []interface{}:
		return c.buildMultiValueQuery(field, v)
	case int, int64, float64:
		return fmt.Sprintf("%s=%v", field, v)
	case bool:
		if v {
			return fmt.Sprintf("%s=true", field)
		}
		return fmt.Sprintf("%s=false", field)
	default:
		return fmt.Sprintf("%s=\"%v\"", field, v)
	}
}

// buildStringQuery builds a query for a string value.
func (c *SplunkConverter) buildStringQuery(field, value string) string {
	// Check for modifiers
	if strings.HasSuffix(field, "|contains") {
		actualField := strings.TrimSuffix(field, "|contains")
		return fmt.Sprintf("%s=*%s*", actualField, escapeValue(value))
	}
	if strings.HasSuffix(field, "|startswith") {
		actualField := strings.TrimSuffix(field, "|startswith")
		return fmt.Sprintf("%s=%s*", actualField, escapeValue(value))
	}
	if strings.HasSuffix(field, "|endswith") {
		actualField := strings.TrimSuffix(field, "|endswith")
		return fmt.Sprintf("%s=*%s", actualField, escapeValue(value))
	}
	if strings.HasSuffix(field, "|re") {
		actualField := strings.TrimSuffix(field, "|re")
		return fmt.Sprintf("%s IN regexp(\"%s\")", actualField, value)
	}
	if strings.HasSuffix(field, "|all") {
		// All modifier handled in array
		actualField := strings.TrimSuffix(field, "|all")
		return fmt.Sprintf("%s=\"%s\"", actualField, escapeValue(value))
	}

	// Handle wildcards
	if strings.Contains(value, "*") || strings.Contains(value, "?") {
		return fmt.Sprintf("%s=%s", field, value)
	}

	return fmt.Sprintf("%s=\"%s\"", field, escapeValue(value))
}

// buildMultiValueQuery builds a query for multiple values.
func (c *SplunkConverter) buildMultiValueQuery(field string, values []interface{}) string {
	// Check for "all" modifier
	isAll := strings.HasSuffix(field, "|all")
	if isAll {
		field = strings.TrimSuffix(field, "|all")
	}

	var parts []string
	for _, v := range values {
		if str, ok := v.(string); ok {
			parts = append(parts, c.buildStringQuery(field, str))
		} else {
			parts = append(parts, fmt.Sprintf("%s=\"%v\"", field, v))
		}
	}

	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	if isAll {
		return "(" + strings.Join(parts, " ") + ")"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// mapFieldName maps a Sigma field name to Splunk field name.
func (c *SplunkConverter) mapFieldName(field string) string {
	// Strip modifiers for mapping lookup
	baseField := field
	for _, mod := range []string{"|contains", "|startswith", "|endswith", "|re", "|all", "|base64", "|base64offset"} {
		baseField = strings.TrimSuffix(baseField, mod)
	}

	if mapped, ok := c.fieldMappings[baseField]; ok {
		// Re-add modifier if present
		if baseField != field {
			modifier := strings.TrimPrefix(field, baseField)
			return mapped + modifier
		}
		return mapped
	}

	return field
}

// applyCondition applies the Sigma condition logic.
func (c *SplunkConverter) applyCondition(condition string, selections map[string]string) (string, error) {
	// Replace selection names with their queries
	result := condition

	// Handle "not" keyword
	result = regexp.MustCompile(`\bnot\s+(\w+)`).ReplaceAllStringFunc(result, func(match string) string {
		parts := strings.Fields(match)
		if len(parts) == 2 {
			selName := parts[1]
			if query, ok := selections[selName]; ok {
				return "NOT " + query
			}
		}
		return match
	})

	// Replace selection names
	for name, query := range selections {
		result = strings.ReplaceAll(result, name, query)
	}

	// Replace operators
	result = strings.ReplaceAll(result, " and ", " ")
	result = strings.ReplaceAll(result, " AND ", " ")
	result = strings.ReplaceAll(result, " or ", " OR ")

	// Handle parentheses groups
	result = regexp.MustCompile(`\s+`).ReplaceAllString(result, " ")

	return strings.TrimSpace(result), nil
}

// escapeValue escapes special characters in a value.
func escapeValue(value string) string {
	// Escape special Splunk characters
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

// extractIndex extracts the index from a query.
func extractIndex(query string) string {
	re := regexp.MustCompile(`index=(\S+)`)
	if m := re.FindStringSubmatch(query); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractMITRETags extracts MITRE ATT&CK tags from Sigma tags.
func extractMITRETags(tags []string) []string {
	var mitre []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.") {
			mitre = append(mitre, strings.TrimPrefix(tag, "attack."))
		}
	}
	return mitre
}

// mapSeverity maps Sigma level to SIEM severity.
func mapSeverity(level string) string {
	switch strings.ToLower(level) {
	case "informational", "low":
		return "low"
	case "medium":
		return "medium"
	case "high":
		return "high"
	case "critical":
		return "critical"
	default:
		return "medium"
	}
}
