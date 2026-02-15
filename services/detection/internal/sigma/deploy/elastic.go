// Package deploy provides Elasticsearch-specific Sigma rule conversion and deployment.
package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/siem-soar-platform/pkg/connector"
)

// ElasticConverter converts Sigma rules to Elasticsearch queries.
type ElasticConverter struct {
	config        *Config
	fieldMappings map[string]string
	indexMappings map[string]string
}

// NewElasticConverter creates a new Elasticsearch converter.
func NewElasticConverter(config *Config) *ElasticConverter {
	c := &ElasticConverter{
		config:        config,
		fieldMappings: make(map[string]string),
		indexMappings: make(map[string]string),
	}

	c.initFieldMappings()
	c.initIndexMappings()

	return c
}

// initFieldMappings initializes ECS field mappings.
func (c *ElasticConverter) initFieldMappings() {
	// Map Sigma fields to Elastic Common Schema (ECS)
	c.fieldMappings = map[string]string{
		"CommandLine":          "process.command_line",
		"Image":                "process.executable",
		"ParentImage":          "process.parent.executable",
		"ParentCommandLine":    "process.parent.command_line",
		"User":                 "user.name",
		"TargetFilename":       "file.path",
		"SourceIP":             "source.ip",
		"DestinationIP":        "destination.ip",
		"SourcePort":           "source.port",
		"DestinationPort":      "destination.port",
		"DestinationHostname":  "destination.domain",
		"EventID":              "event.code",
		"Channel":              "log.provider",
		"Provider_Name":        "winlog.provider_name",
		"Hashes":               "file.hash",
		"md5":                  "file.hash.md5",
		"sha1":                 "file.hash.sha1",
		"sha256":               "file.hash.sha256",
		"ProcessId":            "process.pid",
		"TargetObject":         "registry.path",
		"Details":              "registry.data.strings",
		"QueryName":            "dns.question.name",
		"QueryResults":         "dns.answers",
		"CurrentDirectory":     "process.working_directory",
		"IntegrityLevel":       "winlog.event_data.IntegrityLevel",
		"LogonType":            "winlog.logon.type",
		"OriginalFileName":     "process.pe.original_file_name",
		"Product":              "process.pe.product",
		"Company":              "process.pe.company",
		"FileVersion":          "process.pe.file_version",
		"SourceHostname":       "source.domain",
		"TargetHostname":       "destination.domain",
		"TargetUserName":       "user.target.name",
		"SubjectUserName":      "user.name",
		"ServiceName":          "service.name",
		"Status":               "event.outcome",
		"FailureReason":        "event.reason",
		"PipeName":             "file.path",
	}
}

// initIndexMappings initializes log source to index mappings.
func (c *ElasticConverter) initIndexMappings() {
	c.indexMappings = map[string]string{
		"windows/sysmon":       "winlogbeat-*",
		"windows/security":     "winlogbeat-*",
		"windows/system":       "winlogbeat-*",
		"windows/powershell":   "winlogbeat-*",
		"linux/syslog":         "filebeat-*",
		"linux/auditd":         "auditbeat-*",
		"proxy":                "filebeat-*",
		"firewall":             "filebeat-*",
		"webserver":            "filebeat-*",
		"dns":                  "packetbeat-*",
		"network_connection":   "packetbeat-*",
		"process_creation":     "winlogbeat-*",
	}
}

// SIEM returns the SIEM type.
func (c *ElasticConverter) SIEM() connector.SIEMType {
	return connector.SIEMElastic
}

// Convert converts a Sigma rule to Elasticsearch query.
func (c *ElasticConverter) Convert(ctx context.Context, rule *SigmaRule) (*ConvertedRule, error) {
	// Determine index
	index := c.getIndex(rule.LogSource)

	// Build detection query
	query, err := c.buildDetectionQuery(rule.Detection, rule.LogSource)
	if err != nil {
		return nil, fmt.Errorf("failed to build detection query: %w", err)
	}

	// Build full query JSON
	fullQuery := c.wrapInBoolQuery(query, rule.LogSource)

	queryJSON, err := json.MarshalIndent(fullQuery, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Extract MITRE ATT&CK tags
	mitreTags := extractMITRETags(rule.Tags)

	return &ConvertedRule{
		OriginalID:    rule.ID,
		SIEM:          connector.SIEMElastic,
		Query:         string(queryJSON),
		QueryLanguage: "ES DSL",
		Index:         index,
		Title:         rule.Title,
		Description:   rule.Description,
		Severity:      mapSeverity(rule.Level),
		Tags:          rule.Tags,
		MITRE:         mitreTags,
		Extra: map[string]interface{}{
			"rule_id": rule.ID,
			"author":  rule.Author,
		},
	}, nil
}

// getIndex determines the Elasticsearch index for the log source.
func (c *ElasticConverter) getIndex(ls LogSource) string {
	key := ""
	if ls.Product != "" && ls.Category != "" {
		key = ls.Product + "/" + ls.Category
	} else if ls.Product != "" {
		key = ls.Product
	} else if ls.Category != "" {
		key = ls.Category
	}

	if index, ok := c.indexMappings[key]; ok {
		return index
	}

	// Default index
	if ls.Product == "windows" {
		return "winlogbeat-*"
	}
	if ls.Product == "linux" {
		return "filebeat-*"
	}

	return "logs-*"
}

// buildDetectionQuery builds the detection part of the query.
func (c *ElasticConverter) buildDetectionQuery(detection map[string]interface{}, ls LogSource) (interface{}, error) {
	condition, ok := detection["condition"].(string)
	if !ok {
		return nil, fmt.Errorf("missing condition in detection")
	}

	// Build queries for each selection
	selectionQueries := make(map[string]interface{})
	for key, value := range detection {
		if key == "condition" || key == "timeframe" {
			continue
		}

		query, err := c.buildSelectionQuery(value)
		if err != nil {
			return nil, fmt.Errorf("failed to build selection %s: %w", key, err)
		}
		selectionQueries[key] = query
	}

	// Apply condition
	return c.applyCondition(condition, selectionQueries)
}

// buildSelectionQuery builds a query for a single selection.
func (c *ElasticConverter) buildSelectionQuery(value interface{}) (interface{}, error) {
	switch v := value.(type) {
	case map[string]interface{}:
		return c.buildMapSelection(v)
	case []interface{}:
		return c.buildArraySelection(v)
	default:
		return nil, fmt.Errorf("unsupported selection type: %T", value)
	}
}

// buildMapSelection builds a bool query from a map selection.
func (c *ElasticConverter) buildMapSelection(m map[string]interface{}) (map[string]interface{}, error) {
	must := make([]interface{}, 0)

	for field, value := range m {
		query := c.buildFieldQuery(field, value)
		must = append(must, query)
	}

	if len(must) == 0 {
		return map[string]interface{}{"match_all": map[string]interface{}{}}, nil
	}
	if len(must) == 1 {
		return must[0].(map[string]interface{}), nil
	}

	return map[string]interface{}{
		"bool": map[string]interface{}{
			"must": must,
		},
	}, nil
}

// buildArraySelection builds a bool query from an array selection (OR logic).
func (c *ElasticConverter) buildArraySelection(arr []interface{}) (map[string]interface{}, error) {
	should := make([]interface{}, 0)

	for _, item := range arr {
		if m, ok := item.(map[string]interface{}); ok {
			query, err := c.buildMapSelection(m)
			if err != nil {
				return nil, err
			}
			should = append(should, query)
		}
	}

	if len(should) == 0 {
		return map[string]interface{}{"match_all": map[string]interface{}{}}, nil
	}
	if len(should) == 1 {
		return should[0].(map[string]interface{}), nil
	}

	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should":               should,
			"minimum_should_match": 1,
		},
	}, nil
}

// buildFieldQuery builds a query for a single field.
func (c *ElasticConverter) buildFieldQuery(field string, value interface{}) map[string]interface{} {
	// Extract modifiers
	actualField, modifiers := c.parseFieldModifiers(field)
	mappedField := c.mapFieldName(actualField)

	switch v := value.(type) {
	case string:
		return c.buildStringQuery(mappedField, v, modifiers)
	case []interface{}:
		return c.buildMultiValueQuery(mappedField, v, modifiers)
	case int, int64, float64:
		return map[string]interface{}{
			"term": map[string]interface{}{
				mappedField: v,
			},
		}
	case bool:
		return map[string]interface{}{
			"term": map[string]interface{}{
				mappedField: v,
			},
		}
	default:
		return map[string]interface{}{
			"match": map[string]interface{}{
				mappedField: fmt.Sprintf("%v", v),
			},
		}
	}
}

// parseFieldModifiers extracts modifiers from a field name.
func (c *ElasticConverter) parseFieldModifiers(field string) (string, []string) {
	parts := strings.Split(field, "|")
	if len(parts) == 1 {
		return field, nil
	}
	return parts[0], parts[1:]
}

// buildStringQuery builds a query for a string value.
func (c *ElasticConverter) buildStringQuery(field, value string, modifiers []string) map[string]interface{} {
	hasContains := containsModifier(modifiers, "contains")
	hasStartsWith := containsModifier(modifiers, "startswith")
	hasEndsWith := containsModifier(modifiers, "endswith")
	hasRe := containsModifier(modifiers, "re")

	if hasRe {
		return map[string]interface{}{
			"regexp": map[string]interface{}{
				field: value,
			},
		}
	}

	// Check for wildcards
	if strings.Contains(value, "*") || strings.Contains(value, "?") {
		return map[string]interface{}{
			"wildcard": map[string]interface{}{
				field: map[string]interface{}{
					"value":            value,
					"case_insensitive": true,
				},
			},
		}
	}

	if hasContains {
		return map[string]interface{}{
			"wildcard": map[string]interface{}{
				field: map[string]interface{}{
					"value":            "*" + value + "*",
					"case_insensitive": true,
				},
			},
		}
	}

	if hasStartsWith {
		return map[string]interface{}{
			"wildcard": map[string]interface{}{
				field: map[string]interface{}{
					"value":            value + "*",
					"case_insensitive": true,
				},
			},
		}
	}

	if hasEndsWith {
		return map[string]interface{}{
			"wildcard": map[string]interface{}{
				field: map[string]interface{}{
					"value":            "*" + value,
					"case_insensitive": true,
				},
			},
		}
	}

	// Exact match
	return map[string]interface{}{
		"match_phrase": map[string]interface{}{
			field: value,
		},
	}
}

// buildMultiValueQuery builds a query for multiple values.
func (c *ElasticConverter) buildMultiValueQuery(field string, values []interface{}, modifiers []string) map[string]interface{} {
	hasAll := containsModifier(modifiers, "all")

	queries := make([]interface{}, 0, len(values))
	for _, v := range values {
		if str, ok := v.(string); ok {
			queries = append(queries, c.buildStringQuery(field, str, modifiers))
		} else {
			queries = append(queries, map[string]interface{}{
				"term": map[string]interface{}{
					field: v,
				},
			})
		}
	}

	if len(queries) == 1 {
		return queries[0].(map[string]interface{})
	}

	if hasAll {
		// All values must match (AND)
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"must": queries,
			},
		}
	}

	// Any value can match (OR)
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should":               queries,
			"minimum_should_match": 1,
		},
	}
}

// mapFieldName maps a Sigma field name to ECS field name.
func (c *ElasticConverter) mapFieldName(field string) string {
	if mapped, ok := c.fieldMappings[field]; ok {
		return mapped
	}
	return field
}

// applyCondition applies the Sigma condition logic.
func (c *ElasticConverter) applyCondition(condition string, selections map[string]interface{}) (interface{}, error) {
	// Parse simple conditions
	condition = strings.TrimSpace(condition)

	// Handle single selection
	if query, ok := selections[condition]; ok {
		return query, nil
	}

	// Handle "selection and filter"
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		must := make([]interface{}, 0)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			isNegated := strings.HasPrefix(part, "not ")
			if isNegated {
				part = strings.TrimPrefix(part, "not ")
			}

			if query, ok := selections[part]; ok {
				if isNegated {
					must = append(must, map[string]interface{}{
						"bool": map[string]interface{}{
							"must_not": []interface{}{query},
						},
					})
				} else {
					must = append(must, query)
				}
			}
		}

		return map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		}, nil
	}

	// Handle "selection or filter"
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		should := make([]interface{}, 0)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if query, ok := selections[part]; ok {
				should = append(should, query)
			}
		}

		return map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
			},
		}, nil
	}

	// Handle "not selection"
	if strings.HasPrefix(condition, "not ") {
		part := strings.TrimPrefix(condition, "not ")
		if query, ok := selections[part]; ok {
			return map[string]interface{}{
				"bool": map[string]interface{}{
					"must_not": []interface{}{query},
				},
			}, nil
		}
	}

	// Fallback: try to find matching selection
	for name, query := range selections {
		if strings.Contains(condition, name) {
			return query, nil
		}
	}

	return nil, fmt.Errorf("could not parse condition: %s", condition)
}

// wrapInBoolQuery wraps the detection query with log source filters.
func (c *ElasticConverter) wrapInBoolQuery(detection interface{}, ls LogSource) map[string]interface{} {
	filter := make([]interface{}, 0)

	// Add product filter
	if ls.Product == "windows" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"agent.type": "winlogbeat",
			},
		})
	}

	// Add category-specific filters
	if ls.Category == "process_creation" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"event.code": "1",
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": detection,
			},
		},
	}

	if len(filter) > 0 {
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = filter
	}

	return query
}

// containsModifier checks if a modifier is present.
func containsModifier(modifiers []string, mod string) bool {
	for _, m := range modifiers {
		if m == mod {
			return true
		}
	}
	return false
}
