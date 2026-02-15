// Package deploy provides Microsoft Sentinel-specific Sigma rule conversion and deployment.
package deploy

import (
	"context"
	"fmt"
	"strings"

	"github.com/siem-soar-platform/pkg/connector"
)

// SentinelConverter converts Sigma rules to Sentinel KQL.
type SentinelConverter struct {
	config        *Config
	fieldMappings map[string]string
	tableMappings map[string]string
}

// NewSentinelConverter creates a new Sentinel converter.
func NewSentinelConverter(config *Config) *SentinelConverter {
	c := &SentinelConverter{
		config:        config,
		fieldMappings: make(map[string]string),
		tableMappings: make(map[string]string),
	}

	c.initFieldMappings()
	c.initTableMappings()

	return c
}

// initFieldMappings initializes field name mappings for Sentinel.
func (c *SentinelConverter) initFieldMappings() {
	c.fieldMappings = map[string]string{
		"CommandLine":          "CommandLine",
		"Image":                "Image",
		"ParentImage":          "ParentImage",
		"ParentCommandLine":    "ParentCommandLine",
		"User":                 "TargetUserName",
		"TargetFilename":       "TargetFilename",
		"SourceIP":             "SourceIP",
		"DestinationIP":        "DestinationIP",
		"SourcePort":           "SourcePort",
		"DestinationPort":      "DestinationPort",
		"DestinationHostname":  "DestinationHostname",
		"EventID":              "EventID",
		"Channel":              "Channel",
		"Provider_Name":        "SourceName",
		"Hashes":               "Hashes",
		"md5":                  "MD5",
		"sha1":                 "SHA1",
		"sha256":               "SHA256",
		"ProcessId":            "ProcessId",
		"TargetObject":         "TargetObject",
		"Details":              "Details",
		"QueryName":            "QueryName",
		"QueryResults":         "QueryResults",
		"CurrentDirectory":     "CurrentDirectory",
		"IntegrityLevel":       "IntegrityLevel",
		"LogonType":            "LogonType",
		"OriginalFileName":     "OriginalFileName",
		"Product":              "Product",
		"Company":              "Company",
		"FileVersion":          "FileVersion",
		"Computer":             "Computer",
		"ProcessGuid":          "ProcessGuid",
		"ParentProcessGuid":    "ParentProcessGuid",
		"ParentProcessId":      "ParentProcessId",
		"UtcTime":              "UtcTime",
		"LogonId":              "LogonId",
		"TerminalSessionId":    "TerminalSessionId",
	}
}

// initTableMappings initializes log source to table mappings.
func (c *SentinelConverter) initTableMappings() {
	c.tableMappings = map[string]string{
		"windows/sysmon":              "SysmonEvent",
		"windows/sysmon/process_creation": "SysmonEvent | where EventID == 1",
		"windows/sysmon/file_create":   "SysmonEvent | where EventID == 11",
		"windows/sysmon/network_connection": "SysmonEvent | where EventID == 3",
		"windows/sysmon/registry_event": "SysmonEvent | where EventID in (12, 13, 14)",
		"windows/sysmon/dns_query":     "SysmonEvent | where EventID == 22",
		"windows/sysmon/image_load":    "SysmonEvent | where EventID == 7",
		"windows/security":             "SecurityEvent",
		"windows/system":               "Event",
		"windows/powershell":           "Event | where Source == 'Microsoft-Windows-PowerShell'",
		"windows/dns_server":           "DnsEvents",
		"linux/syslog":                 "Syslog",
		"linux/auditd":                 "LinuxAuditLog",
		"proxy":                        "CommonSecurityLog",
		"firewall":                     "CommonSecurityLog",
		"webserver":                    "W3CIISLog",
		"dns":                          "DnsEvents",
		"network_connection":           "VMConnection",
		"process_creation":             "SecurityEvent | where EventID == 4688",
		"azure/activitylogs":           "AzureActivity",
		"azure/signinlogs":             "SigninLogs",
		"azure/auditlogs":              "AuditLogs",
		"m365/defender":                "DeviceEvents",
		"aws/cloudtrail":               "AWSCloudTrail",
		"gcp/audit":                    "GCPAuditLogs",
	}
}

// SIEM returns the SIEM type.
func (c *SentinelConverter) SIEM() connector.SIEMType {
	return connector.SIEMSentinel
}

// Convert converts a Sigma rule to Sentinel KQL.
func (c *SentinelConverter) Convert(ctx context.Context, rule *SigmaRule) (*ConvertedRule, error) {
	// Get table/source
	table := c.getTable(rule.LogSource)

	// Build detection query
	detectionQuery, err := c.buildDetectionQuery(rule.Detection)
	if err != nil {
		return nil, fmt.Errorf("failed to build detection query: %w", err)
	}

	// Build full KQL query
	var queryBuilder strings.Builder
	queryBuilder.WriteString(table)
	queryBuilder.WriteString("\n")

	if detectionQuery != "" {
		queryBuilder.WriteString("| where ")
		queryBuilder.WriteString(detectionQuery)
		queryBuilder.WriteString("\n")
	}

	// Add field projection
	if len(rule.Fields) > 0 {
		mappedFields := make([]string, len(rule.Fields))
		for i, f := range rule.Fields {
			mappedFields[i] = c.mapFieldName(f)
		}
		queryBuilder.WriteString("| project ")
		queryBuilder.WriteString(strings.Join(mappedFields, ", "))
		queryBuilder.WriteString("\n")
	}

	// Extract MITRE ATT&CK tags
	mitreTags := extractMITRETags(rule.Tags)

	return &ConvertedRule{
		OriginalID:    rule.ID,
		SIEM:          connector.SIEMSentinel,
		Query:         queryBuilder.String(),
		QueryLanguage: "KQL",
		Index:         extractTableName(table),
		Title:         rule.Title,
		Description:   rule.Description,
		Severity:      mapSeverity(rule.Level),
		Tags:          rule.Tags,
		MITRE:         mitreTags,
		Extra: map[string]interface{}{
			"tactics":    extractTactics(rule.Tags),
			"techniques": extractTechniques(rule.Tags),
		},
	}, nil
}

// getTable determines the Sentinel table for the log source.
func (c *SentinelConverter) getTable(ls LogSource) string {
	// Try specific mappings first
	keys := []string{
		ls.Product + "/" + ls.Service + "/" + ls.Category,
		ls.Product + "/" + ls.Category,
		ls.Product + "/" + ls.Service,
		ls.Product,
		ls.Category,
		ls.Service,
	}

	for _, key := range keys {
		if key == "" || key == "/" || key == "//" {
			continue
		}
		if table, ok := c.tableMappings[key]; ok {
			return table
		}
	}

	// Default tables based on product
	switch ls.Product {
	case "windows":
		if ls.Category == "process_creation" {
			return "SecurityEvent | where EventID == 4688"
		}
		return "SecurityEvent"
	case "linux":
		return "Syslog"
	case "azure":
		return "AzureActivity"
	default:
		return "CommonSecurityLog"
	}
}

// buildDetectionQuery builds the KQL detection query.
func (c *SentinelConverter) buildDetectionQuery(detection map[string]interface{}) (string, error) {
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

		query, err := c.buildSelectionQuery(value)
		if err != nil {
			return "", fmt.Errorf("failed to build selection %s: %w", key, err)
		}
		selectionQueries[key] = query
	}

	// Apply condition
	return c.applyCondition(condition, selectionQueries)
}

// buildSelectionQuery builds a KQL query for a selection.
func (c *SentinelConverter) buildSelectionQuery(value interface{}) (string, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		return c.buildMapSelection(v)
	case []interface{}:
		return c.buildArraySelection(v)
	default:
		return "", fmt.Errorf("unsupported selection type: %T", value)
	}
}

// buildMapSelection builds a KQL query from a map selection.
func (c *SentinelConverter) buildMapSelection(m map[string]interface{}) (string, error) {
	var parts []string

	for field, value := range m {
		query := c.buildFieldQuery(field, value)
		parts = append(parts, query)
	}

	if len(parts) == 0 {
		return "", nil
	}
	if len(parts) == 1 {
		return parts[0], nil
	}

	return "(" + strings.Join(parts, " and ") + ")", nil
}

// buildArraySelection builds a KQL query from an array selection.
func (c *SentinelConverter) buildArraySelection(arr []interface{}) (string, error) {
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

	return "(" + strings.Join(parts, " or ") + ")", nil
}

// buildFieldQuery builds a KQL query for a single field.
func (c *SentinelConverter) buildFieldQuery(field string, value interface{}) string {
	// Extract modifiers
	actualField, modifiers := c.parseFieldModifiers(field)
	mappedField := c.mapFieldName(actualField)

	switch v := value.(type) {
	case string:
		return c.buildStringQuery(mappedField, v, modifiers)
	case []interface{}:
		return c.buildMultiValueQuery(mappedField, v, modifiers)
	case int, int64, float64:
		return fmt.Sprintf("%s == %v", mappedField, v)
	case bool:
		if v {
			return fmt.Sprintf("%s == true", mappedField)
		}
		return fmt.Sprintf("%s == false", mappedField)
	default:
		return fmt.Sprintf("%s == \"%v\"", mappedField, v)
	}
}

// parseFieldModifiers extracts modifiers from a field name.
func (c *SentinelConverter) parseFieldModifiers(field string) (string, []string) {
	parts := strings.Split(field, "|")
	if len(parts) == 1 {
		return field, nil
	}
	return parts[0], parts[1:]
}

// buildStringQuery builds a KQL query for a string value.
func (c *SentinelConverter) buildStringQuery(field, value string, modifiers []string) string {
	hasContains := containsModifier(modifiers, "contains")
	hasStartsWith := containsModifier(modifiers, "startswith")
	hasEndsWith := containsModifier(modifiers, "endswith")
	hasRe := containsModifier(modifiers, "re")

	if hasRe {
		return fmt.Sprintf("%s matches regex @\"%s\"", field, escapeKQLRegex(value))
	}

	if hasContains || strings.Contains(value, "*") {
		// Convert wildcards to KQL format
		kqlValue := strings.ReplaceAll(value, "*", "")
		if strings.HasPrefix(value, "*") && strings.HasSuffix(value, "*") {
			return fmt.Sprintf("%s contains \"%s\"", field, kqlValue)
		}
		if strings.HasPrefix(value, "*") {
			return fmt.Sprintf("%s endswith \"%s\"", field, kqlValue)
		}
		if strings.HasSuffix(value, "*") {
			return fmt.Sprintf("%s startswith \"%s\"", field, kqlValue)
		}
		return fmt.Sprintf("%s contains \"%s\"", field, kqlValue)
	}

	if hasStartsWith {
		return fmt.Sprintf("%s startswith \"%s\"", field, escapeKQLString(value))
	}

	if hasEndsWith {
		return fmt.Sprintf("%s endswith \"%s\"", field, escapeKQLString(value))
	}

	// Exact match (case-insensitive by default in KQL)
	return fmt.Sprintf("%s =~ \"%s\"", field, escapeKQLString(value))
}

// buildMultiValueQuery builds a KQL query for multiple values.
func (c *SentinelConverter) buildMultiValueQuery(field string, values []interface{}, modifiers []string) string {
	hasAll := containsModifier(modifiers, "all")

	var parts []string
	for _, v := range values {
		if str, ok := v.(string); ok {
			parts = append(parts, c.buildStringQuery(field, str, modifiers))
		} else {
			parts = append(parts, fmt.Sprintf("%s == \"%v\"", field, v))
		}
	}

	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	if hasAll {
		return "(" + strings.Join(parts, " and ") + ")"
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// mapFieldName maps a Sigma field name to Sentinel field name.
func (c *SentinelConverter) mapFieldName(field string) string {
	if mapped, ok := c.fieldMappings[field]; ok {
		return mapped
	}
	return field
}

// applyCondition applies the Sigma condition logic.
func (c *SentinelConverter) applyCondition(condition string, selections map[string]string) (string, error) {
	result := condition

	// Handle "not" keyword
	for name, query := range selections {
		notPattern := "not " + name
		if strings.Contains(result, notPattern) {
			result = strings.ReplaceAll(result, notPattern, "not("+query+")")
		}
		result = strings.ReplaceAll(result, name, "("+query+")")
	}

	// Replace operators
	result = strings.ReplaceAll(result, " and ", " and ")
	result = strings.ReplaceAll(result, " AND ", " and ")
	result = strings.ReplaceAll(result, " or ", " or ")
	result = strings.ReplaceAll(result, " OR ", " or ")

	return strings.TrimSpace(result), nil
}

// escapeKQLString escapes special characters in a KQL string.
func escapeKQLString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

// escapeKQLRegex escapes special characters for KQL regex.
func escapeKQLRegex(value string) string {
	// KQL uses @ prefix for raw strings, minimal escaping needed
	return strings.ReplaceAll(value, "\"", "\\\"")
}

// extractTableName extracts the base table name from a KQL query.
func extractTableName(query string) string {
	parts := strings.Fields(query)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// extractTactics extracts MITRE ATT&CK tactics from tags.
func extractTactics(tags []string) []string {
	var tactics []string
	tacticMap := map[string]string{
		"initial_access":       "InitialAccess",
		"execution":            "Execution",
		"persistence":          "Persistence",
		"privilege_escalation": "PrivilegeEscalation",
		"defense_evasion":      "DefenseEvasion",
		"credential_access":    "CredentialAccess",
		"discovery":            "Discovery",
		"lateral_movement":     "LateralMovement",
		"collection":           "Collection",
		"command_and_control":  "CommandAndControl",
		"exfiltration":         "Exfiltration",
		"impact":               "Impact",
	}

	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.") {
			tactic := strings.TrimPrefix(tag, "attack.")
			if mapped, ok := tacticMap[tactic]; ok {
				tactics = append(tactics, mapped)
			}
		}
	}
	return tactics
}

// extractTechniques extracts MITRE ATT&CK techniques from tags.
func extractTechniques(tags []string) []string {
	var techniques []string
	for _, tag := range tags {
		if strings.HasPrefix(tag, "attack.t") {
			technique := strings.TrimPrefix(tag, "attack.")
			techniques = append(techniques, strings.ToUpper(technique))
		}
	}
	return techniques
}
