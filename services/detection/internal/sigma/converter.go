// Package sigma provides Sigma rule parsing and conversion.
package sigma

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SigmaRule represents a Sigma detection rule.
type SigmaRule struct {
	Title          string                 `yaml:"title"`
	ID             string                 `yaml:"id"`
	Status         string                 `yaml:"status"`
	Description    string                 `yaml:"description"`
	Author         string                 `yaml:"author"`
	Date           string                 `yaml:"date"`
	Modified       string                 `yaml:"modified"`
	References     []string               `yaml:"references"`
	Tags           []string               `yaml:"tags"`
	LogSource      LogSource              `yaml:"logsource"`
	Detection      Detection              `yaml:"detection"`
	FalsePositives []string               `yaml:"falsepositives"`
	Level          string                 `yaml:"level"`
	Fields         []string               `yaml:"fields"`
}

// LogSource defines the log source for a Sigma rule.
type LogSource struct {
	Category   string `yaml:"category"`
	Product    string `yaml:"product"`
	Service    string `yaml:"service"`
	Definition string `yaml:"definition"`
}

// Detection defines the detection logic.
type Detection struct {
	Selection  map[string]interface{} `yaml:"-"`
	Filter     map[string]interface{} `yaml:"-"`
	Condition  string                 `yaml:"condition"`
	Timeframe  string                 `yaml:"timeframe"`
	RawData    map[string]interface{} `yaml:"-"`
}

// UnmarshalYAML custom unmarshaler for Detection.
func (d *Detection) UnmarshalYAML(node *yaml.Node) error {
	d.RawData = make(map[string]interface{})
	d.Selection = make(map[string]interface{})
	d.Filter = make(map[string]interface{})

	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]

		var v interface{}
		if err := value.Decode(&v); err != nil {
			return err
		}

		d.RawData[key] = v

		if key == "condition" {
			d.Condition = v.(string)
		} else if key == "timeframe" {
			d.Timeframe = v.(string)
		} else if strings.HasPrefix(key, "filter") {
			if m, ok := v.(map[string]interface{}); ok {
				for fk, fv := range m {
					d.Filter[fk] = fv
				}
			}
		} else if strings.HasPrefix(key, "selection") {
			if m, ok := v.(map[string]interface{}); ok {
				for sk, sv := range m {
					d.Selection[sk] = sv
				}
			}
		}
	}

	return nil
}

// InternalCondition represents an internal detection condition.
type InternalCondition struct {
	Field       string        `json:"field"`
	Modifier    string        `json:"modifier,omitempty"`
	Operator    string        `json:"operator"`
	Value       interface{}   `json:"value,omitempty"`
	Values      []interface{} `json:"values,omitempty"`
	Negate      bool          `json:"negate,omitempty"`
}

// InternalRule represents the converted internal rule format.
type InternalRule struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Severity        string              `json:"severity"`
	Conditions      []InternalCondition `json:"conditions"`
	Logic           string              `json:"logic"` // "and" or "or"
	LogSource       LogSource           `json:"log_source"`
	MITRETactics    []string            `json:"mitre_tactics,omitempty"`
	MITRETechniques []string            `json:"mitre_techniques,omitempty"`
	Tags            []string            `json:"tags,omitempty"`
	References      []string            `json:"references,omitempty"`
}

// Converter converts Sigma rules to internal format.
type Converter struct {
	fieldMapping map[string]string
}

// NewConverter creates a new Sigma converter.
func NewConverter() *Converter {
	return &Converter{
		fieldMapping: DefaultFieldMapping(),
	}
}

// NewConverterWithMapping creates a converter with custom field mapping.
func NewConverterWithMapping(mapping map[string]string) *Converter {
	return &Converter{
		fieldMapping: mapping,
	}
}

// DefaultFieldMapping returns the default field mapping.
func DefaultFieldMapping() map[string]string {
	return map[string]string{
		// Windows Event Log mappings
		"EventID":             "event_id",
		"CommandLine":         "process.command_line",
		"ParentCommandLine":   "process.parent.command_line",
		"Image":               "process.executable",
		"ParentImage":         "process.parent.executable",
		"User":                "user.name",
		"TargetFilename":      "file.path",
		"SourceIp":            "source.ip",
		"DestinationIp":       "destination.ip",
		"DestinationPort":     "destination.port",
		"SourcePort":          "source.port",
		"QueryName":           "dns.question.name",
		"OriginalFileName":    "file.name",
		"CurrentDirectory":    "process.working_directory",
		"IntegrityLevel":      "process.integrity_level",
		"Hashes":              "file.hash",
		"md5":                 "file.hash.md5",
		"sha1":                "file.hash.sha1",
		"sha256":              "file.hash.sha256",

		// Sysmon specific
		"ProcessId":           "process.pid",
		"ProcessGuid":         "process.entity_id",
		"ParentProcessId":     "process.parent.pid",
		"ParentProcessGuid":   "process.parent.entity_id",
		"TargetObject":        "registry.path",
		"Details":             "registry.value",

		// Network
		"SourceHostname":      "source.hostname",
		"DestinationHostname": "destination.hostname",
		"Initiated":           "network.direction",

		// Authentication
		"LogonType":           "winlog.event_data.LogonType",
		"TargetUserName":      "user.target.name",
		"SubjectUserName":     "user.name",
		"IpAddress":           "source.ip",
		"WorkstationName":     "source.hostname",
	}
}

// Parse parses a Sigma rule from YAML content.
func (c *Converter) Parse(content string) (*SigmaRule, error) {
	var rule SigmaRule
	if err := yaml.Unmarshal([]byte(content), &rule); err != nil {
		return nil, fmt.Errorf("failed to parse sigma rule: %w", err)
	}
	return &rule, nil
}

// Convert converts a Sigma rule to internal format.
func (c *Converter) Convert(sigma *SigmaRule) (*InternalRule, error) {
	internal := &InternalRule{
		ID:          sigma.ID,
		Name:        sigma.Title,
		Description: sigma.Description,
		Severity:    c.convertLevel(sigma.Level),
		LogSource:   sigma.LogSource,
		Tags:        sigma.Tags,
		References:  sigma.References,
		Logic:       "and",
	}

	// Extract MITRE tags
	for _, tag := range sigma.Tags {
		if strings.HasPrefix(tag, "attack.") {
			technique := strings.TrimPrefix(tag, "attack.")
			if strings.HasPrefix(technique, "t") || strings.HasPrefix(technique, "T") {
				internal.MITRETechniques = append(internal.MITRETechniques, strings.ToUpper(technique))
			} else {
				internal.MITRETactics = append(internal.MITRETactics, technique)
			}
		}
	}

	// Convert detection
	conditions, err := c.convertDetection(&sigma.Detection)
	if err != nil {
		return nil, err
	}
	internal.Conditions = conditions

	// Determine logic from condition
	if sigma.Detection.Condition != "" {
		if strings.Contains(sigma.Detection.Condition, " or ") {
			internal.Logic = "or"
		}
	}

	return internal, nil
}

// ConvertYAML parses and converts YAML content to internal format.
func (c *Converter) ConvertYAML(content string) (*InternalRule, error) {
	sigma, err := c.Parse(content)
	if err != nil {
		return nil, err
	}
	return c.Convert(sigma)
}

func (c *Converter) convertLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational":
		return "info"
	default:
		return "medium"
	}
}

func (c *Converter) convertDetection(detection *Detection) ([]InternalCondition, error) {
	var conditions []InternalCondition

	// Process selection
	for field, value := range detection.Selection {
		conds := c.convertSelectionField(field, value, false)
		conditions = append(conditions, conds...)
	}

	// Process filter (negated conditions)
	for field, value := range detection.Filter {
		conds := c.convertSelectionField(field, value, true)
		conditions = append(conditions, conds...)
	}

	return conditions, nil
}

func (c *Converter) convertSelectionField(field string, value interface{}, negate bool) []InternalCondition {
	var conditions []InternalCondition

	// Parse field and modifiers
	parts := strings.Split(field, "|")
	baseField := parts[0]
	modifiers := parts[1:]

	// Map field name
	mappedField := c.mapField(baseField)

	// Determine operator from modifiers
	operator := "eq"
	var modifier string
	for _, mod := range modifiers {
		switch mod {
		case "contains":
			operator = "contains"
		case "startswith":
			operator = "startswith"
		case "endswith":
			operator = "endswith"
		case "re":
			operator = "regex"
		case "cidr":
			operator = "cidr"
		case "all":
			modifier = "all"
		case "base64", "base64offset":
			modifier = mod
		case "wide":
			modifier = "wide"
		}
	}

	cond := InternalCondition{
		Field:    mappedField,
		Operator: operator,
		Modifier: modifier,
		Negate:   negate,
	}

	switch v := value.(type) {
	case string:
		cond.Value = v
		conditions = append(conditions, cond)

	case []interface{}:
		if modifier == "all" {
			// All values must match
			for _, item := range v {
				itemCond := cond
				itemCond.Value = item
				conditions = append(conditions, itemCond)
			}
		} else {
			// Any value matches (IN operator)
			cond.Operator = "in"
			cond.Values = v
			conditions = append(conditions, cond)
		}

	case map[string]interface{}:
		// Nested conditions
		for k, nestedV := range v {
			nestedConds := c.convertSelectionField(k, nestedV, negate)
			conditions = append(conditions, nestedConds...)
		}

	default:
		cond.Value = value
		conditions = append(conditions, cond)
	}

	return conditions
}

func (c *Converter) mapField(field string) string {
	if mapped, ok := c.fieldMapping[field]; ok {
		return mapped
	}
	// Convert to lowercase with dots for unmapped fields
	return strings.ToLower(field)
}

// SetFieldMapping sets a custom field mapping.
func (c *Converter) SetFieldMapping(mapping map[string]string) {
	c.fieldMapping = mapping
}

// AddFieldMapping adds a field mapping.
func (c *Converter) AddFieldMapping(sigmaField, internalField string) {
	c.fieldMapping[sigmaField] = internalField
}

// SigmaToQuery converts a Sigma rule to a query string (simplified).
func SigmaToQuery(content string, target string) (string, error) {
	converter := NewConverter()
	internal, err := converter.ConvertYAML(content)
	if err != nil {
		return "", err
	}

	switch target {
	case "elasticsearch", "es":
		return toElasticsearchQuery(internal)
	case "clickhouse":
		return toClickHouseQuery(internal)
	case "splunk":
		return toSplunkQuery(internal)
	default:
		return "", fmt.Errorf("unsupported target: %s", target)
	}
}

func toElasticsearchQuery(rule *InternalRule) (string, error) {
	var parts []string

	for _, cond := range rule.Conditions {
		var part string
		switch cond.Operator {
		case "eq":
			part = fmt.Sprintf("%s:%v", cond.Field, escapeES(cond.Value))
		case "contains":
			part = fmt.Sprintf("%s:*%v*", cond.Field, escapeES(cond.Value))
		case "startswith":
			part = fmt.Sprintf("%s:%v*", cond.Field, escapeES(cond.Value))
		case "endswith":
			part = fmt.Sprintf("%s:*%v", cond.Field, escapeES(cond.Value))
		case "regex":
			part = fmt.Sprintf("%s:/%v/", cond.Field, cond.Value)
		case "in":
			values := make([]string, len(cond.Values))
			for i, v := range cond.Values {
				values[i] = fmt.Sprintf("%v", escapeES(v))
			}
			part = fmt.Sprintf("%s:(%s)", cond.Field, strings.Join(values, " OR "))
		}

		if cond.Negate {
			part = "NOT " + part
		}
		parts = append(parts, part)
	}

	logic := " AND "
	if rule.Logic == "or" {
		logic = " OR "
	}

	return strings.Join(parts, logic), nil
}

func toClickHouseQuery(rule *InternalRule) (string, error) {
	var parts []string

	for _, cond := range rule.Conditions {
		var part string
		switch cond.Operator {
		case "eq":
			part = fmt.Sprintf("%s = '%v'", cond.Field, escapeCH(cond.Value))
		case "contains":
			part = fmt.Sprintf("%s ILIKE '%%%v%%'", cond.Field, escapeCH(cond.Value))
		case "startswith":
			part = fmt.Sprintf("%s ILIKE '%v%%'", cond.Field, escapeCH(cond.Value))
		case "endswith":
			part = fmt.Sprintf("%s ILIKE '%%%v'", cond.Field, escapeCH(cond.Value))
		case "regex":
			part = fmt.Sprintf("match(%s, '%v')", cond.Field, escapeCH(cond.Value))
		case "in":
			values := make([]string, len(cond.Values))
			for i, v := range cond.Values {
				values[i] = fmt.Sprintf("'%v'", escapeCH(v))
			}
			part = fmt.Sprintf("%s IN (%s)", cond.Field, strings.Join(values, ", "))
		}

		if cond.Negate {
			part = "NOT (" + part + ")"
		}
		parts = append(parts, part)
	}

	logic := " AND "
	if rule.Logic == "or" {
		logic = " OR "
	}

	return strings.Join(parts, logic), nil
}

func toSplunkQuery(rule *InternalRule) (string, error) {
	var parts []string

	for _, cond := range rule.Conditions {
		var part string
		switch cond.Operator {
		case "eq":
			part = fmt.Sprintf("%s=\"%v\"", cond.Field, escapeSplunk(cond.Value))
		case "contains":
			part = fmt.Sprintf("%s=\"*%v*\"", cond.Field, escapeSplunk(cond.Value))
		case "startswith":
			part = fmt.Sprintf("%s=\"%v*\"", cond.Field, escapeSplunk(cond.Value))
		case "endswith":
			part = fmt.Sprintf("%s=\"*%v\"", cond.Field, escapeSplunk(cond.Value))
		case "regex":
			part = fmt.Sprintf("%s=%v", cond.Field, cond.Value)
		case "in":
			values := make([]string, len(cond.Values))
			for i, v := range cond.Values {
				values[i] = fmt.Sprintf("\"%v\"", escapeSplunk(v))
			}
			part = fmt.Sprintf("%s IN (%s)", cond.Field, strings.Join(values, ", "))
		}

		if cond.Negate {
			part = "NOT " + part
		}
		parts = append(parts, part)
	}

	logic := " "
	if rule.Logic == "or" {
		logic = " OR "
	}

	return strings.Join(parts, logic), nil
}

func escapeES(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	// Escape special characters
	specialChars := regexp.MustCompile(`([+\-=&|!(){}\[\]^"~*?:\\/])`)
	return specialChars.ReplaceAllString(s, "\\$1")
}

func escapeCH(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	return strings.ReplaceAll(s, "'", "''")
}

func escapeSplunk(v interface{}) string {
	s := fmt.Sprintf("%v", v)
	return strings.ReplaceAll(s, "\"", "\\\"")
}
