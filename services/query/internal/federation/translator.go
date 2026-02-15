// Package federation provides query translation between different SIEM query languages.
package federation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/siem-soar-platform/pkg/connector"
)

// Translator translates queries between different query languages.
type Translator struct {
	sqlParser    *SQLParser
	splParser    *SPLParser
	kqlParser    *KQLParser
	fieldMappings map[string]FieldMapping
}

// FieldMapping maps field names across different SIEMs.
type FieldMapping struct {
	Standard string            // Standard/canonical name
	SIEM     map[connector.SIEMType]string // SIEM-specific names
}

// NewTranslator creates a new translator.
func NewTranslator() *Translator {
	t := &Translator{
		sqlParser: NewSQLParser(),
		splParser: NewSPLParser(),
		kqlParser: NewKQLParser(),
		fieldMappings: make(map[string]FieldMapping),
	}

	// Initialize standard field mappings
	t.initFieldMappings()

	return t
}

// initFieldMappings initializes standard field mappings.
func (t *Translator) initFieldMappings() {
	mappings := []FieldMapping{
		{
			Standard: "timestamp",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "_time",
				connector.SIEMElastic:  "@timestamp",
				connector.SIEMSentinel: "TimeGenerated",
			},
		},
		{
			Standard: "source_ip",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "src_ip",
				connector.SIEMElastic:  "source.ip",
				connector.SIEMSentinel: "SourceIP",
			},
		},
		{
			Standard: "destination_ip",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "dest_ip",
				connector.SIEMElastic:  "destination.ip",
				connector.SIEMSentinel: "DestinationIP",
			},
		},
		{
			Standard: "source_port",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "src_port",
				connector.SIEMElastic:  "source.port",
				connector.SIEMSentinel: "SourcePort",
			},
		},
		{
			Standard: "destination_port",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "dest_port",
				connector.SIEMElastic:  "destination.port",
				connector.SIEMSentinel: "DestinationPort",
			},
		},
		{
			Standard: "user",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "user",
				connector.SIEMElastic:  "user.name",
				connector.SIEMSentinel: "Account",
			},
		},
		{
			Standard: "hostname",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "host",
				connector.SIEMElastic:  "host.name",
				connector.SIEMSentinel: "Computer",
			},
		},
		{
			Standard: "process_name",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "process",
				connector.SIEMElastic:  "process.name",
				connector.SIEMSentinel: "ProcessName",
			},
		},
		{
			Standard: "command_line",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "CommandLine",
				connector.SIEMElastic:  "process.command_line",
				connector.SIEMSentinel: "CommandLine",
			},
		},
		{
			Standard: "event_id",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "EventID",
				connector.SIEMElastic:  "event.id",
				connector.SIEMSentinel: "EventID",
			},
		},
		{
			Standard: "severity",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "severity",
				connector.SIEMElastic:  "event.severity",
				connector.SIEMSentinel: "SeverityLevel",
			},
		},
		{
			Standard: "action",
			SIEM: map[connector.SIEMType]string{
				connector.SIEMSplunk:   "action",
				connector.SIEMElastic:  "event.action",
				connector.SIEMSentinel: "Activity",
			},
		},
	}

	for _, m := range mappings {
		t.fieldMappings[m.Standard] = m
	}
}

// Translate translates a query from one language to another.
func (t *Translator) Translate(query string, from, to connector.QueryLanguage) (string, error) {
	if from == to {
		return query, nil
	}

	// Parse to intermediate representation
	ir, err := t.parse(query, from)
	if err != nil {
		return "", fmt.Errorf("failed to parse query: %w", err)
	}

	// Generate target query
	result, err := t.generate(ir, to)
	if err != nil {
		return "", fmt.Errorf("failed to generate query: %w", err)
	}

	return result, nil
}

// QueryIR is the intermediate representation of a query.
type QueryIR struct {
	Table       string
	Filters     []Filter
	Fields      []string
	Aggregations []Aggregation
	OrderBy     []OrderBy
	Limit       int
	TimeRange   *TimeRange
}

// Filter represents a filter condition.
type Filter struct {
	Field    string
	Operator string // "=", "!=", "<", ">", "<=", ">=", "contains", "regex", "in", "not in"
	Value    interface{}
	Logic    string // "AND", "OR"
}

// Aggregation represents an aggregation operation.
type Aggregation struct {
	Function string // "count", "sum", "avg", "min", "max", "distinct"
	Field    string
	Alias    string
	GroupBy  []string
}

// OrderBy represents ordering.
type OrderBy struct {
	Field     string
	Ascending bool
}

// TimeRange represents a time range for the query.
type TimeRange struct {
	Start    string
	End      string
	Relative string
}

// parse parses a query into the intermediate representation.
func (t *Translator) parse(query string, lang connector.QueryLanguage) (*QueryIR, error) {
	switch lang {
	case connector.QueryLanguageSQL:
		return t.sqlParser.Parse(query)
	case connector.QueryLanguageSPL:
		return t.splParser.Parse(query)
	case connector.QueryLanguageKQL:
		return t.kqlParser.Parse(query)
	default:
		return nil, fmt.Errorf("unsupported source language: %s", lang)
	}
}

// generate generates a query from the intermediate representation.
func (t *Translator) generate(ir *QueryIR, lang connector.QueryLanguage) (string, error) {
	// Map fields to target SIEM
	targetSIEM := langToSIEM(lang)
	ir = t.mapFields(ir, targetSIEM)

	switch lang {
	case connector.QueryLanguageSQL:
		return t.generateSQL(ir)
	case connector.QueryLanguageSPL:
		return t.generateSPL(ir)
	case connector.QueryLanguageKQL:
		return t.generateKQL(ir)
	case connector.QueryLanguageDSL:
		return t.generateDSL(ir)
	default:
		return "", fmt.Errorf("unsupported target language: %s", lang)
	}
}

// mapFields maps field names to the target SIEM.
func (t *Translator) mapFields(ir *QueryIR, siem connector.SIEMType) *QueryIR {
	result := &QueryIR{
		Table:       ir.Table,
		Limit:       ir.Limit,
		TimeRange:   ir.TimeRange,
	}

	// Map filter fields
	for _, f := range ir.Filters {
		mappedField := t.mapFieldName(f.Field, siem)
		result.Filters = append(result.Filters, Filter{
			Field:    mappedField,
			Operator: f.Operator,
			Value:    f.Value,
			Logic:    f.Logic,
		})
	}

	// Map select fields
	for _, field := range ir.Fields {
		result.Fields = append(result.Fields, t.mapFieldName(field, siem))
	}

	// Map aggregation fields
	for _, agg := range ir.Aggregations {
		mappedAgg := Aggregation{
			Function: agg.Function,
			Field:    t.mapFieldName(agg.Field, siem),
			Alias:    agg.Alias,
		}
		for _, gb := range agg.GroupBy {
			mappedAgg.GroupBy = append(mappedAgg.GroupBy, t.mapFieldName(gb, siem))
		}
		result.Aggregations = append(result.Aggregations, mappedAgg)
	}

	// Map order by fields
	for _, ob := range ir.OrderBy {
		result.OrderBy = append(result.OrderBy, OrderBy{
			Field:     t.mapFieldName(ob.Field, siem),
			Ascending: ob.Ascending,
		})
	}

	return result
}

// mapFieldName maps a field name to the target SIEM.
func (t *Translator) mapFieldName(field string, siem connector.SIEMType) string {
	// Check if it's a standard field
	for _, mapping := range t.fieldMappings {
		if mapping.Standard == field {
			if siemField, ok := mapping.SIEM[siem]; ok {
				return siemField
			}
		}
		// Check if it's already a SIEM-specific field
		for _, siemField := range mapping.SIEM {
			if siemField == field {
				if targetField, ok := mapping.SIEM[siem]; ok {
					return targetField
				}
			}
		}
	}
	return field
}

// langToSIEM maps a query language to a SIEM type.
func langToSIEM(lang connector.QueryLanguage) connector.SIEMType {
	switch lang {
	case connector.QueryLanguageSPL:
		return connector.SIEMSplunk
	case connector.QueryLanguageDSL, connector.QueryLanguageEQL:
		return connector.SIEMElastic
	case connector.QueryLanguageKQL:
		return connector.SIEMSentinel
	default:
		return ""
	}
}

// generateSQL generates a SQL query.
func (t *Translator) generateSQL(ir *QueryIR) (string, error) {
	var sb strings.Builder

	// SELECT clause
	sb.WriteString("SELECT ")
	if len(ir.Fields) == 0 {
		sb.WriteString("*")
	} else {
		sb.WriteString(strings.Join(ir.Fields, ", "))
	}

	// FROM clause
	sb.WriteString(" FROM ")
	sb.WriteString(ir.Table)

	// WHERE clause
	if len(ir.Filters) > 0 {
		sb.WriteString(" WHERE ")
		for i, f := range ir.Filters {
			if i > 0 {
				sb.WriteString(" " + f.Logic + " ")
			}
			sb.WriteString(formatSQLFilter(f))
		}
	}

	// ORDER BY clause
	if len(ir.OrderBy) > 0 {
		sb.WriteString(" ORDER BY ")
		for i, ob := range ir.OrderBy {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(ob.Field)
			if !ob.Ascending {
				sb.WriteString(" DESC")
			}
		}
	}

	// LIMIT clause
	if ir.Limit > 0 {
		sb.WriteString(fmt.Sprintf(" LIMIT %d", ir.Limit))
	}

	return sb.String(), nil
}

// generateSPL generates a Splunk SPL query.
func (t *Translator) generateSPL(ir *QueryIR) (string, error) {
	var parts []string

	// Index/source
	if ir.Table != "" {
		parts = append(parts, fmt.Sprintf("index=%s", ir.Table))
	}

	// Search terms (filters)
	for _, f := range ir.Filters {
		parts = append(parts, formatSPLFilter(f))
	}

	query := strings.Join(parts, " ")

	// Table/Fields
	if len(ir.Fields) > 0 && ir.Fields[0] != "*" {
		query += " | table " + strings.Join(ir.Fields, ", ")
	}

	// Aggregations
	if len(ir.Aggregations) > 0 {
		agg := ir.Aggregations[0]
		query += fmt.Sprintf(" | stats %s(%s)", agg.Function, agg.Field)
		if len(agg.GroupBy) > 0 {
			query += " by " + strings.Join(agg.GroupBy, ", ")
		}
	}

	// Sort
	if len(ir.OrderBy) > 0 {
		query += " | sort "
		for i, ob := range ir.OrderBy {
			if i > 0 {
				query += ", "
			}
			if !ob.Ascending {
				query += "-"
			}
			query += ob.Field
		}
	}

	// Limit
	if ir.Limit > 0 {
		query += fmt.Sprintf(" | head %d", ir.Limit)
	}

	return query, nil
}

// generateKQL generates a Kusto Query Language query.
func (t *Translator) generateKQL(ir *QueryIR) (string, error) {
	var parts []string

	// Table
	parts = append(parts, ir.Table)

	// Time range
	if ir.TimeRange != nil {
		if ir.TimeRange.Relative != "" {
			parts = append(parts, fmt.Sprintf("| where TimeGenerated > ago(%s)", ir.TimeRange.Relative))
		}
	}

	// Filters
	for _, f := range ir.Filters {
		parts = append(parts, fmt.Sprintf("| where %s", formatKQLFilter(f)))
	}

	// Project fields
	if len(ir.Fields) > 0 && ir.Fields[0] != "*" {
		parts = append(parts, "| project "+strings.Join(ir.Fields, ", "))
	}

	// Aggregations
	if len(ir.Aggregations) > 0 {
		agg := ir.Aggregations[0]
		aggExpr := fmt.Sprintf("| summarize %s(%s)", agg.Function, agg.Field)
		if len(agg.GroupBy) > 0 {
			aggExpr += " by " + strings.Join(agg.GroupBy, ", ")
		}
		parts = append(parts, aggExpr)
	}

	// Order by
	if len(ir.OrderBy) > 0 {
		sortExpr := "| order by "
		for i, ob := range ir.OrderBy {
			if i > 0 {
				sortExpr += ", "
			}
			sortExpr += ob.Field
			if ob.Ascending {
				sortExpr += " asc"
			} else {
				sortExpr += " desc"
			}
		}
		parts = append(parts, sortExpr)
	}

	// Limit
	if ir.Limit > 0 {
		parts = append(parts, fmt.Sprintf("| take %d", ir.Limit))
	}

	return strings.Join(parts, "\n"), nil
}

// generateDSL generates an Elasticsearch DSL query.
func (t *Translator) generateDSL(ir *QueryIR) (string, error) {
	// Build a simple query string for now
	var terms []string

	for _, f := range ir.Filters {
		switch f.Operator {
		case "=":
			terms = append(terms, fmt.Sprintf("%s:%v", f.Field, f.Value))
		case "!=":
			terms = append(terms, fmt.Sprintf("NOT %s:%v", f.Field, f.Value))
		case "contains":
			terms = append(terms, fmt.Sprintf("%s:*%v*", f.Field, f.Value))
		default:
			terms = append(terms, fmt.Sprintf("%s:%v", f.Field, f.Value))
		}
	}

	return strings.Join(terms, " AND "), nil
}

// Helper functions for formatting filters

func formatSQLFilter(f Filter) string {
	switch f.Operator {
	case "contains":
		return fmt.Sprintf("%s LIKE '%%%v%%'", f.Field, f.Value)
	case "regex":
		return fmt.Sprintf("%s REGEXP '%v'", f.Field, f.Value)
	case "in":
		return fmt.Sprintf("%s IN (%v)", f.Field, f.Value)
	default:
		return fmt.Sprintf("%s %s '%v'", f.Field, f.Operator, f.Value)
	}
}

func formatSPLFilter(f Filter) string {
	switch f.Operator {
	case "=":
		return fmt.Sprintf("%s=\"%v\"", f.Field, f.Value)
	case "!=":
		return fmt.Sprintf("NOT %s=\"%v\"", f.Field, f.Value)
	case "contains":
		return fmt.Sprintf("%s=*%v*", f.Field, f.Value)
	case "regex":
		return fmt.Sprintf("%s IN regexp(\"%v\")", f.Field, f.Value)
	default:
		return fmt.Sprintf("%s%s%v", f.Field, f.Operator, f.Value)
	}
}

func formatKQLFilter(f Filter) string {
	switch f.Operator {
	case "=":
		return fmt.Sprintf("%s == \"%v\"", f.Field, f.Value)
	case "!=":
		return fmt.Sprintf("%s != \"%v\"", f.Field, f.Value)
	case "contains":
		return fmt.Sprintf("%s contains \"%v\"", f.Field, f.Value)
	case "regex":
		return fmt.Sprintf("%s matches regex \"%v\"", f.Field, f.Value)
	default:
		return fmt.Sprintf("%s %s \"%v\"", f.Field, f.Operator, f.Value)
	}
}

// Parsers (simplified implementations)

// SQLParser parses SQL queries.
type SQLParser struct{}

func NewSQLParser() *SQLParser {
	return &SQLParser{}
}

func (p *SQLParser) Parse(query string) (*QueryIR, error) {
	ir := &QueryIR{}

	// Simple regex-based parsing
	query = strings.TrimSpace(query)

	// Extract table
	tableRe := regexp.MustCompile(`(?i)FROM\s+(\w+)`)
	if m := tableRe.FindStringSubmatch(query); len(m) > 1 {
		ir.Table = m[1]
	}

	// Extract fields
	fieldsRe := regexp.MustCompile(`(?i)SELECT\s+(.+?)\s+FROM`)
	if m := fieldsRe.FindStringSubmatch(query); len(m) > 1 {
		fields := strings.Split(m[1], ",")
		for _, f := range fields {
			ir.Fields = append(ir.Fields, strings.TrimSpace(f))
		}
	}

	// Extract filters (WHERE clause)
	whereRe := regexp.MustCompile(`(?i)WHERE\s+(.+?)(?:\s+ORDER|\s+LIMIT|$)`)
	if m := whereRe.FindStringSubmatch(query); len(m) > 1 {
		// Parse simple conditions
		conditions := strings.Split(m[1], " AND ")
		for _, cond := range conditions {
			filter := parseCondition(cond)
			if filter != nil {
				filter.Logic = "AND"
				ir.Filters = append(ir.Filters, *filter)
			}
		}
	}

	// Extract limit
	limitRe := regexp.MustCompile(`(?i)LIMIT\s+(\d+)`)
	if m := limitRe.FindStringSubmatch(query); len(m) > 1 {
		fmt.Sscanf(m[1], "%d", &ir.Limit)
	}

	return ir, nil
}

// SPLParser parses Splunk SPL queries.
type SPLParser struct{}

func NewSPLParser() *SPLParser {
	return &SPLParser{}
}

func (p *SPLParser) Parse(query string) (*QueryIR, error) {
	ir := &QueryIR{}

	// Split by pipe
	parts := strings.Split(query, "|")

	// Parse search part
	searchPart := strings.TrimSpace(parts[0])

	// Extract index
	indexRe := regexp.MustCompile(`index=(\S+)`)
	if m := indexRe.FindStringSubmatch(searchPart); len(m) > 1 {
		ir.Table = m[1]
	}

	// Extract search terms as filters
	termRe := regexp.MustCompile(`(\w+)=["']?([^"'\s]+)["']?`)
	for _, m := range termRe.FindAllStringSubmatch(searchPart, -1) {
		if m[1] != "index" {
			ir.Filters = append(ir.Filters, Filter{
				Field:    m[1],
				Operator: "=",
				Value:    m[2],
				Logic:    "AND",
			})
		}
	}

	// Parse pipe commands
	for i := 1; i < len(parts); i++ {
		cmd := strings.TrimSpace(parts[i])

		// table command
		if strings.HasPrefix(cmd, "table ") {
			fields := strings.TrimPrefix(cmd, "table ")
			for _, f := range strings.Split(fields, ",") {
				ir.Fields = append(ir.Fields, strings.TrimSpace(f))
			}
		}

		// head command
		if strings.HasPrefix(cmd, "head ") {
			fmt.Sscanf(cmd, "head %d", &ir.Limit)
		}
	}

	return ir, nil
}

// KQLParser parses Kusto Query Language queries.
type KQLParser struct{}

func NewKQLParser() *KQLParser {
	return &KQLParser{}
}

func (p *KQLParser) Parse(query string) (*QueryIR, error) {
	ir := &QueryIR{}

	lines := strings.Split(query, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Table name (first line without pipe)
		if !strings.HasPrefix(line, "|") && ir.Table == "" {
			ir.Table = line
			continue
		}

		// Strip leading pipe
		if strings.HasPrefix(line, "|") {
			line = strings.TrimSpace(line[1:])
		}

		// where clause
		if strings.HasPrefix(line, "where ") {
			cond := strings.TrimPrefix(line, "where ")
			filter := parseKQLCondition(cond)
			if filter != nil {
				ir.Filters = append(ir.Filters, *filter)
			}
		}

		// project clause
		if strings.HasPrefix(line, "project ") {
			fields := strings.TrimPrefix(line, "project ")
			for _, f := range strings.Split(fields, ",") {
				ir.Fields = append(ir.Fields, strings.TrimSpace(f))
			}
		}

		// take clause
		if strings.HasPrefix(line, "take ") {
			fmt.Sscanf(line, "take %d", &ir.Limit)
		}
	}

	return ir, nil
}

// Helper function to parse a condition string into a Filter.
func parseCondition(cond string) *Filter {
	cond = strings.TrimSpace(cond)

	// Try different operators
	operators := []string{"!=", "<=", ">=", "=", "<", ">", " LIKE ", " IN "}
	for _, op := range operators {
		if strings.Contains(strings.ToUpper(cond), strings.ToUpper(op)) {
			parts := strings.SplitN(cond, op, 2)
			if len(parts) == 2 {
				mappedOp := strings.TrimSpace(strings.ToLower(op))
				if mappedOp == " like " {
					mappedOp = "contains"
				}
				if mappedOp == " in " {
					mappedOp = "in"
				}
				return &Filter{
					Field:    strings.TrimSpace(parts[0]),
					Operator: mappedOp,
					Value:    strings.Trim(strings.TrimSpace(parts[1]), "'\""),
				}
			}
		}
	}

	return nil
}

// parseKQLCondition parses a KQL condition.
func parseKQLCondition(cond string) *Filter {
	// Check for different KQL operators
	if strings.Contains(cond, " == ") {
		parts := strings.SplitN(cond, " == ", 2)
		return &Filter{
			Field:    strings.TrimSpace(parts[0]),
			Operator: "=",
			Value:    strings.Trim(strings.TrimSpace(parts[1]), "\""),
			Logic:    "AND",
		}
	}
	if strings.Contains(cond, " contains ") {
		parts := strings.SplitN(cond, " contains ", 2)
		return &Filter{
			Field:    strings.TrimSpace(parts[0]),
			Operator: "contains",
			Value:    strings.Trim(strings.TrimSpace(parts[1]), "\""),
			Logic:    "AND",
		}
	}

	return nil
}
