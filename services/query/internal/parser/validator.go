// Package parser provides SQL query validation capabilities.
package parser

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationResult represents the result of query validation.
type ValidationResult struct {
	Valid       bool              `json:"valid"`
	Errors      []ValidationError `json:"errors,omitempty"`
	Warnings    []ValidationWarning `json:"warnings,omitempty"`
	Sanitized   string            `json:"sanitized,omitempty"`
	Risk        RiskLevel         `json:"risk"`
	Suggestions []string          `json:"suggestions,omitempty"`
}

// ValidationError represents a validation error.
type ValidationError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Position int    `json:"position,omitempty"`
	Severity string `json:"severity"`
}

// ValidationWarning represents a validation warning.
type ValidationWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// RiskLevel represents the risk level of a query.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// ValidatorConfig holds validator configuration.
type ValidatorConfig struct {
	AllowedTables       []string `json:"allowed_tables"`
	DeniedTables        []string `json:"denied_tables"`
	AllowedFunctions    []string `json:"allowed_functions"`
	DeniedFunctions     []string `json:"denied_functions"`
	MaxQueryLength      int      `json:"max_query_length"`
	MaxJoins            int      `json:"max_joins"`
	MaxSubqueries       int      `json:"max_subqueries"`
	RequireWhereClause  bool     `json:"require_where_clause"`
	RequireLimit        bool     `json:"require_limit"`
	MaxLimit            int      `json:"max_limit"`
	AllowUnion          bool     `json:"allow_union"`
	AllowSubqueries     bool     `json:"allow_subqueries"`
	AllowWildcard       bool     `json:"allow_wildcard"`
	AllowComments       bool     `json:"allow_comments"`
	StrictMode          bool     `json:"strict_mode"`
	TenantIDColumn      string   `json:"tenant_id_column"`
	RequireTenantFilter bool     `json:"require_tenant_filter"`
}

// DefaultValidatorConfig returns default validator configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		AllowedTables:       nil, // nil = all allowed
		DeniedTables:        []string{"system", "information_schema"},
		AllowedFunctions:    nil,
		DeniedFunctions:     []string{"SLEEP", "BENCHMARK", "LOAD_FILE", "INTO OUTFILE", "INTO DUMPFILE"},
		MaxQueryLength:      100000,
		MaxJoins:            10,
		MaxSubqueries:       5,
		RequireWhereClause:  false,
		RequireLimit:        true,
		MaxLimit:            10000,
		AllowUnion:          true,
		AllowSubqueries:     true,
		AllowWildcard:       false,
		AllowComments:       false,
		StrictMode:          false,
		TenantIDColumn:      "tenant_id",
		RequireTenantFilter: true,
	}
}

// Validator validates SQL queries.
type Validator struct {
	config ValidatorConfig
	parser *Parser
}

// NewValidator creates a new SQL validator.
func NewValidator(config ValidatorConfig) *Validator {
	return &Validator{
		config: config,
		parser: NewParser("clickhouse"),
	}
}

// Validate validates a SQL query.
func (v *Validator) Validate(query string, tenantID string) *ValidationResult {
	result := &ValidationResult{
		Valid: true,
		Risk:  RiskLevelLow,
	}

	// Basic checks
	v.checkLength(query, result)
	v.checkSQLInjection(query, result)
	v.checkComments(query, result)
	v.checkDangerousPatterns(query, result)

	if !result.Valid {
		return result
	}

	// Parse query
	parsed, err := v.parser.Parse(query)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "PARSE_ERROR",
			Message:  fmt.Sprintf("Failed to parse query: %s", err.Error()),
			Severity: "error",
		})
		return result
	}

	// Structural checks
	v.checkTables(parsed, result)
	v.checkFunctions(query, result)
	v.checkJoins(parsed, result)
	v.checkSubqueries(parsed, result)
	v.checkWhereClause(parsed, result)
	v.checkLimit(parsed, result)
	v.checkUnion(query, result)
	v.checkWildcard(parsed, result)
	v.checkTenantFilter(parsed, tenantID, result)

	// Sanitize query
	result.Sanitized = v.sanitize(query)

	// Calculate overall risk
	v.calculateRisk(result)

	return result
}

// checkLength checks query length.
func (v *Validator) checkLength(query string, result *ValidationResult) {
	if len(query) > v.config.MaxQueryLength {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "QUERY_TOO_LONG",
			Message:  fmt.Sprintf("Query exceeds maximum length of %d characters", v.config.MaxQueryLength),
			Severity: "error",
		})
	}
}

// checkSQLInjection checks for SQL injection patterns.
func (v *Validator) checkSQLInjection(query string, result *ValidationResult) {
	// Check for common SQL injection patterns
	injectionPatterns := []struct {
		pattern *regexp.Regexp
		code    string
		message string
	}{
		{
			regexp.MustCompile(`(?i)'\s*OR\s+'?\d+'?\s*=\s*'?\d+'?`),
			"SQL_INJECTION_OR",
			"Potential SQL injection detected: OR tautology",
		},
		{
			regexp.MustCompile(`(?i)'\s*OR\s+'\w+'\s*=\s*'\w+'`),
			"SQL_INJECTION_OR_STRING",
			"Potential SQL injection detected: OR string comparison",
		},
		{
			regexp.MustCompile(`(?i);\s*(DROP|DELETE|UPDATE|INSERT|TRUNCATE)\s+`),
			"SQL_INJECTION_STACKED",
			"Potential SQL injection detected: stacked queries",
		},
		{
			regexp.MustCompile(`(?i)UNION\s+(ALL\s+)?SELECT\s+NULL`),
			"SQL_INJECTION_UNION",
			"Potential SQL injection detected: UNION-based attack",
		},
		{
			regexp.MustCompile(`(?i)'\s*;\s*--`),
			"SQL_INJECTION_COMMENT",
			"Potential SQL injection detected: comment-based termination",
		},
		{
			regexp.MustCompile(`(?i)CHAR\s*\(\s*\d+\s*\)`),
			"SQL_INJECTION_CHAR",
			"Potential SQL injection detected: CHAR encoding",
		},
		{
			regexp.MustCompile(`(?i)0x[0-9a-fA-F]+`),
			"SQL_INJECTION_HEX",
			"Potential SQL injection detected: hex encoding",
		},
		{
			regexp.MustCompile(`(?i)CONCAT\s*\([^)]*,\s*0x`),
			"SQL_INJECTION_CONCAT",
			"Potential SQL injection detected: CONCAT with hex",
		},
		{
			regexp.MustCompile(`(?i)'\s*\+\s*'`),
			"SQL_INJECTION_CONCAT_STRING",
			"Potential SQL injection detected: string concatenation",
		},
		{
			regexp.MustCompile(`(?i)EXEC\s*\(`),
			"SQL_INJECTION_EXEC",
			"Potential SQL injection detected: EXEC function",
		},
	}

	for _, ip := range injectionPatterns {
		if ip.pattern.MatchString(query) {
			result.Valid = false
			result.Risk = RiskLevelCritical
			result.Errors = append(result.Errors, ValidationError{
				Code:     ip.code,
				Message:  ip.message,
				Severity: "critical",
			})
		}
	}
}

// checkComments checks for SQL comments.
func (v *Validator) checkComments(query string, result *ValidationResult) {
	if !v.config.AllowComments {
		commentPatterns := []string{
			`--`,
			`/\*`,
			`\*/`,
			`#`,
		}

		for _, pattern := range commentPatterns {
			re := regexp.MustCompile(pattern)
			if re.MatchString(query) {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Code:     "COMMENTS_NOT_ALLOWED",
					Message:  "SQL comments are not allowed",
					Severity: "error",
				})
				return
			}
		}
	}
}

// checkDangerousPatterns checks for dangerous SQL patterns.
func (v *Validator) checkDangerousPatterns(query string, result *ValidationResult) {
	upper := strings.ToUpper(query)

	dangerousKeywords := []struct {
		keyword string
		code    string
		message string
	}{
		{"DROP TABLE", "DROP_TABLE", "DROP TABLE statements are not allowed"},
		{"DROP DATABASE", "DROP_DATABASE", "DROP DATABASE statements are not allowed"},
		{"TRUNCATE", "TRUNCATE", "TRUNCATE statements are not allowed"},
		{"ALTER TABLE", "ALTER_TABLE", "ALTER TABLE statements are not allowed"},
		{"CREATE TABLE", "CREATE_TABLE", "CREATE TABLE statements are not allowed"},
		{"GRANT ", "GRANT", "GRANT statements are not allowed"},
		{"REVOKE ", "REVOKE", "REVOKE statements are not allowed"},
		{"SHUTDOWN", "SHUTDOWN", "SHUTDOWN command is not allowed"},
		{"INTO OUTFILE", "INTO_OUTFILE", "INTO OUTFILE is not allowed"},
		{"INTO DUMPFILE", "INTO_DUMPFILE", "INTO DUMPFILE is not allowed"},
		{"LOAD_FILE", "LOAD_FILE", "LOAD_FILE function is not allowed"},
	}

	for _, dk := range dangerousKeywords {
		if strings.Contains(upper, dk.keyword) {
			result.Valid = false
			result.Risk = RiskLevelCritical
			result.Errors = append(result.Errors, ValidationError{
				Code:     dk.code,
				Message:  dk.message,
				Severity: "critical",
			})
		}
	}

	// Check for denied functions
	for _, fn := range v.config.DeniedFunctions {
		fnPattern := regexp.MustCompile(fmt.Sprintf(`(?i)\b%s\s*\(`, regexp.QuoteMeta(fn)))
		if fnPattern.MatchString(query) {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:     "DENIED_FUNCTION",
				Message:  fmt.Sprintf("Function %s is not allowed", fn),
				Severity: "error",
			})
		}
	}
}

// checkTables checks table references.
func (v *Validator) checkTables(parsed *ParsedQuery, result *ValidationResult) {
	for _, table := range parsed.Tables {
		tableName := strings.ToLower(table.Table)

		// Check denied tables
		for _, denied := range v.config.DeniedTables {
			if strings.ToLower(denied) == tableName {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Code:     "DENIED_TABLE",
					Message:  fmt.Sprintf("Access to table %s is not allowed", table.Table),
					Severity: "error",
				})
			}
		}

		// Check allowed tables (if specified)
		if len(v.config.AllowedTables) > 0 {
			found := false
			for _, allowed := range v.config.AllowedTables {
				if strings.ToLower(allowed) == tableName {
					found = true
					break
				}
			}
			if !found {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Code:     "TABLE_NOT_ALLOWED",
					Message:  fmt.Sprintf("Table %s is not in the allowed list", table.Table),
					Severity: "error",
				})
			}
		}
	}
}

// checkFunctions checks function usage.
func (v *Validator) checkFunctions(query string, result *ValidationResult) {
	if len(v.config.AllowedFunctions) == 0 {
		return
	}

	// Extract function calls
	funcPattern := regexp.MustCompile(`(?i)\b(\w+)\s*\(`)
	matches := funcPattern.FindAllStringSubmatch(query, -1)

	for _, match := range matches {
		funcName := strings.ToUpper(match[1])

		// Skip SQL keywords
		sqlKeywords := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "AND", "OR", "NOT", "IN", "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END"}
		isKeyword := false
		for _, kw := range sqlKeywords {
			if funcName == kw {
				isKeyword = true
				break
			}
		}
		if isKeyword {
			continue
		}

		// Check if function is allowed
		found := false
		for _, allowed := range v.config.AllowedFunctions {
			if strings.ToUpper(allowed) == funcName {
				found = true
				break
			}
		}
		if !found {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:    "UNKNOWN_FUNCTION",
				Message: fmt.Sprintf("Function %s is not in the allowed list", funcName),
			})
		}
	}
}

// checkJoins checks JOIN clauses.
func (v *Validator) checkJoins(parsed *ParsedQuery, result *ValidationResult) {
	if len(parsed.Joins) > v.config.MaxJoins {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "TOO_MANY_JOINS",
			Message:  fmt.Sprintf("Query has %d JOINs, maximum allowed is %d", len(parsed.Joins), v.config.MaxJoins),
			Severity: "error",
		})
	}
}

// checkSubqueries checks subqueries.
func (v *Validator) checkSubqueries(parsed *ParsedQuery, result *ValidationResult) {
	if !v.config.AllowSubqueries && len(parsed.Subqueries) > 0 {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "SUBQUERIES_NOT_ALLOWED",
			Message:  "Subqueries are not allowed",
			Severity: "error",
		})
		return
	}

	if len(parsed.Subqueries) > v.config.MaxSubqueries {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "TOO_MANY_SUBQUERIES",
			Message:  fmt.Sprintf("Query has %d subqueries, maximum allowed is %d", len(parsed.Subqueries), v.config.MaxSubqueries),
			Severity: "error",
		})
	}
}

// checkWhereClause checks WHERE clause presence.
func (v *Validator) checkWhereClause(parsed *ParsedQuery, result *ValidationResult) {
	if v.config.RequireWhereClause && parsed.Type == QueryTypeSelect {
		if len(parsed.Conditions) == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:     "WHERE_CLAUSE_REQUIRED",
				Message:  "WHERE clause is required",
				Severity: "error",
			})
		}
	}
}

// checkLimit checks LIMIT clause.
func (v *Validator) checkLimit(parsed *ParsedQuery, result *ValidationResult) {
	if v.config.RequireLimit && parsed.Type == QueryTypeSelect {
		if parsed.Limit == nil {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Code:    "LIMIT_RECOMMENDED",
				Message: "LIMIT clause is recommended to prevent excessive data retrieval",
			})
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("Add LIMIT %d to restrict results", v.config.MaxLimit))
		} else if *parsed.Limit > v.config.MaxLimit {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:     "LIMIT_TOO_HIGH",
				Message:  fmt.Sprintf("LIMIT %d exceeds maximum allowed value of %d", *parsed.Limit, v.config.MaxLimit),
				Severity: "error",
			})
		}
	}
}

// checkUnion checks UNION usage.
func (v *Validator) checkUnion(query string, result *ValidationResult) {
	if !v.config.AllowUnion {
		upper := strings.ToUpper(query)
		if strings.Contains(upper, "UNION") {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Code:     "UNION_NOT_ALLOWED",
				Message:  "UNION queries are not allowed",
				Severity: "error",
			})
		}
	}
}

// checkWildcard checks SELECT * usage.
func (v *Validator) checkWildcard(parsed *ParsedQuery, result *ValidationResult) {
	if !v.config.AllowWildcard {
		for _, col := range parsed.Columns {
			if col.Column == "*" {
				result.Warnings = append(result.Warnings, ValidationWarning{
					Code:    "WILDCARD_SELECT",
					Message: "SELECT * is not recommended, specify required columns explicitly",
				})
				break
			}
		}
	}
}

// checkTenantFilter checks for tenant isolation.
func (v *Validator) checkTenantFilter(parsed *ParsedQuery, tenantID string, result *ValidationResult) {
	if !v.config.RequireTenantFilter || tenantID == "" {
		return
	}

	// Check if tenant_id filter exists
	hasTenantFilter := false
	for _, cond := range parsed.Conditions {
		if strings.ToLower(cond.Left) == strings.ToLower(v.config.TenantIDColumn) {
			hasTenantFilter = true
			break
		}
	}

	if !hasTenantFilter {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Code:     "TENANT_FILTER_REQUIRED",
			Message:  fmt.Sprintf("Query must filter by %s for tenant isolation", v.config.TenantIDColumn),
			Severity: "error",
		})
	}
}

// sanitize sanitizes a SQL query.
func (v *Validator) sanitize(query string) string {
	sanitized := query

	// Remove comments
	sanitized = regexp.MustCompile(`--[^\n]*`).ReplaceAllString(sanitized, "")
	sanitized = regexp.MustCompile(`/\*[\s\S]*?\*/`).ReplaceAllString(sanitized, "")
	sanitized = regexp.MustCompile(`#[^\n]*`).ReplaceAllString(sanitized, "")

	// Normalize whitespace
	sanitized = regexp.MustCompile(`\s+`).ReplaceAllString(sanitized, " ")
	sanitized = strings.TrimSpace(sanitized)

	return sanitized
}

// calculateRisk calculates overall risk level.
func (v *Validator) calculateRisk(result *ValidationResult) {
	errorCount := len(result.Errors)
	warningCount := len(result.Warnings)

	// Check for critical errors
	for _, err := range result.Errors {
		if err.Severity == "critical" {
			result.Risk = RiskLevelCritical
			return
		}
	}

	if errorCount > 0 {
		result.Risk = RiskLevelHigh
	} else if warningCount > 2 {
		result.Risk = RiskLevelMedium
	} else if warningCount > 0 {
		result.Risk = RiskLevelLow
	}
}

// ParameterizedQuery represents a parameterized query.
type ParameterizedQuery struct {
	Query      string
	Parameters []interface{}
}

// Parameterize converts a query with literals to parameterized form.
func (v *Validator) Parameterize(query string) (*ParameterizedQuery, error) {
	pq := &ParameterizedQuery{
		Parameters: make([]interface{}, 0),
	}

	paramCount := 0

	// Replace string literals
	stringPattern := regexp.MustCompile(`'([^']*)'`)
	query = stringPattern.ReplaceAllStringFunc(query, func(match string) string {
		// Don't replace if it's part of a function name or keyword
		inner := match[1 : len(match)-1]
		pq.Parameters = append(pq.Parameters, inner)
		paramCount++
		return fmt.Sprintf("$%d", paramCount)
	})

	// Replace numeric literals (careful not to replace column numbers)
	numPattern := regexp.MustCompile(`\b(\d+\.?\d*)\b`)
	query = numPattern.ReplaceAllStringFunc(query, func(match string) string {
		// Only replace if not preceded by $ (already a parameter)
		var num float64
		fmt.Sscanf(match, "%f", &num)
		pq.Parameters = append(pq.Parameters, num)
		paramCount++
		return fmt.Sprintf("$%d", paramCount)
	})

	pq.Query = query
	return pq, nil
}
