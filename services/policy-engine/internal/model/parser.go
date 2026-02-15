// Package model provides data models for parser management.
package model

import (
	"time"
)

// ParserStatus represents the status of a parser.
type ParserStatus string

const (
	ParserStatusActive   ParserStatus = "active"
	ParserStatusInactive ParserStatus = "inactive"
	ParserStatusError    ParserStatus = "error"
	ParserStatusLoading  ParserStatus = "loading"
)

// ParserType represents the type of parser.
type ParserType string

const (
	ParserTypeGrok   ParserType = "grok"
	ParserTypeJSON   ParserType = "json"
	ParserTypeCSV    ParserType = "csv"
	ParserTypeCEF    ParserType = "cef"
	ParserTypeLEEF   ParserType = "leef"
	ParserTypeRegex  ParserType = "regex"
	ParserTypeSyslog ParserType = "syslog"
	ParserTypeXML    ParserType = "xml"
)

// Product represents a security product.
type Product struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Vendor      string    `json:"vendor" db:"vendor"`
	Version     string    `json:"version,omitempty" db:"version"`
	Description string    `json:"description,omitempty" db:"description"`
	Category    string    `json:"category,omitempty" db:"category"` // firewall, edr, ips, etc.

	// Log format information
	LogFormats  []string  `json:"log_formats,omitempty"` // syslog, json, cef, etc.
	SampleLogs  []string  `json:"sample_logs,omitempty"`

	// Metadata
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Parser count
	ParserCount int `json:"parser_count" db:"parser_count"`

	// Audit
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy   string    `json:"created_by" db:"created_by"`
	UpdatedBy   string    `json:"updated_by,omitempty" db:"updated_by"`
}

// Parser represents a log parser configuration.
type Parser struct {
	ID          string       `json:"id" db:"id"`
	TenantID    string       `json:"tenant_id" db:"tenant_id"`
	ProductID   string       `json:"product_id" db:"product_id"`
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description,omitempty" db:"description"`
	Type        ParserType   `json:"type" db:"type"`
	Status      ParserStatus `json:"status" db:"status"`
	Priority    int          `json:"priority" db:"priority"` // Higher = try first

	// Parser configuration
	Pattern      string                 `json:"pattern,omitempty" db:"pattern"` // Grok/regex pattern
	GrokPatterns map[string]string      `json:"grok_patterns,omitempty"`        // Custom grok patterns
	FieldMapping map[string]string      `json:"field_mapping,omitempty"`        // Field name mapping
	Transforms   []FieldTransform       `json:"transforms,omitempty"`           // Field transformations
	Filters      []ParserFilter         `json:"filters,omitempty"`              // Pre-parsing filters
	Config       map[string]interface{} `json:"config,omitempty"`               // Type-specific config

	// Normalization
	NormalizeToUDM bool `json:"normalize_to_udm" db:"normalize_to_udm"`
	UDMMapping     map[string]string `json:"udm_mapping,omitempty"`

	// Detection
	DetectionPattern string `json:"detection_pattern,omitempty" db:"detection_pattern"` // Pattern to detect this parser should be used

	// Version control
	Version     int    `json:"version" db:"version"`
	ParentID    string `json:"parent_id,omitempty" db:"parent_id"`

	// Statistics
	ParseCount    int64      `json:"parse_count" db:"parse_count"`
	ErrorCount    int64      `json:"error_count" db:"error_count"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	AvgParseTimeMs float64   `json:"avg_parse_time_ms" db:"avg_parse_time_ms"`

	// Hot reload tracking
	LoadedAt      *time.Time `json:"loaded_at,omitempty" db:"loaded_at"`
	ReloadCount   int        `json:"reload_count" db:"reload_count"`
	LastReloadAt  *time.Time `json:"last_reload_at,omitempty" db:"last_reload_at"`
	LastReloadBy  string     `json:"last_reload_by,omitempty" db:"last_reload_by"`

	// Audit
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy   string    `json:"created_by" db:"created_by"`
	UpdatedBy   string    `json:"updated_by,omitempty" db:"updated_by"`

	// Metadata
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// FieldTransform represents a transformation on a parsed field.
type FieldTransform struct {
	Field       string `json:"field"`
	Type        string `json:"type"` // rename, delete, lowercase, uppercase, trim, regex_replace, split, join, timestamp
	Source      string `json:"source,omitempty"`
	Target      string `json:"target,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Format      string `json:"format,omitempty"` // For timestamp parsing
}

// ParserFilter represents a filter applied before parsing.
type ParserFilter struct {
	Field    string `json:"field"`
	Operator string `json:"operator"` // contains, starts_with, ends_with, regex, eq, ne
	Value    string `json:"value"`
	Negate   bool   `json:"negate,omitempty"`
}

// CreateProductRequest represents a request to create a product.
type CreateProductRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=255"`
	Vendor      string            `json:"vendor" validate:"required"`
	Version     string            `json:"version,omitempty"`
	Description string            `json:"description,omitempty"`
	Category    string            `json:"category,omitempty"`
	LogFormats  []string          `json:"log_formats,omitempty"`
	SampleLogs  []string          `json:"sample_logs,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// UpdateProductRequest represents a request to update a product.
type UpdateProductRequest struct {
	Name        *string           `json:"name,omitempty"`
	Vendor      *string           `json:"vendor,omitempty"`
	Version     *string           `json:"version,omitempty"`
	Description *string           `json:"description,omitempty"`
	Category    *string           `json:"category,omitempty"`
	LogFormats  []string          `json:"log_formats,omitempty"`
	SampleLogs  []string          `json:"sample_logs,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// CreateParserRequest represents a request to create a parser.
type CreateParserRequest struct {
	ProductID        string                 `json:"product_id" validate:"required"`
	Name             string                 `json:"name" validate:"required,min=1,max=255"`
	Description      string                 `json:"description,omitempty"`
	Type             ParserType             `json:"type" validate:"required"`
	Priority         int                    `json:"priority,omitempty"`
	Pattern          string                 `json:"pattern,omitempty"`
	GrokPatterns     map[string]string      `json:"grok_patterns,omitempty"`
	FieldMapping     map[string]string      `json:"field_mapping,omitempty"`
	Transforms       []FieldTransform       `json:"transforms,omitempty"`
	Filters          []ParserFilter         `json:"filters,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
	NormalizeToUDM   bool                   `json:"normalize_to_udm,omitempty"`
	UDMMapping       map[string]string      `json:"udm_mapping,omitempty"`
	DetectionPattern string                 `json:"detection_pattern,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	Labels           map[string]string      `json:"labels,omitempty"`
}

// UpdateParserRequest represents a request to update a parser.
type UpdateParserRequest struct {
	Name             *string                `json:"name,omitempty"`
	Description      *string                `json:"description,omitempty"`
	Status           *ParserStatus          `json:"status,omitempty"`
	Priority         *int                   `json:"priority,omitempty"`
	Pattern          *string                `json:"pattern,omitempty"`
	GrokPatterns     map[string]string      `json:"grok_patterns,omitempty"`
	FieldMapping     map[string]string      `json:"field_mapping,omitempty"`
	Transforms       []FieldTransform       `json:"transforms,omitempty"`
	Filters          []ParserFilter         `json:"filters,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
	NormalizeToUDM   *bool                  `json:"normalize_to_udm,omitempty"`
	UDMMapping       map[string]string      `json:"udm_mapping,omitempty"`
	DetectionPattern *string                `json:"detection_pattern,omitempty"`
	Tags             []string               `json:"tags,omitempty"`
	Labels           map[string]string      `json:"labels,omitempty"`
}

// ParserTestRequest represents a request to test a parser.
type ParserTestRequest struct {
	ParserID string   `json:"parser_id,omitempty"`
	Config   *Parser  `json:"config,omitempty"` // For testing before saving
	Samples  []string `json:"samples" validate:"required,min=1"`
}

// ParserTestResult represents the result of parser testing.
type ParserTestResult struct {
	Sample       string                 `json:"sample"`
	Success      bool                   `json:"success"`
	ParsedFields map[string]interface{} `json:"parsed_fields,omitempty"`
	UDMEvent     map[string]interface{} `json:"udm_event,omitempty"`
	Error        string                 `json:"error,omitempty"`
	DurationMs   float64                `json:"duration_ms"`
}

// ParserReloadResult represents the result of a parser reload.
type ParserReloadResult struct {
	ParserID    string    `json:"parser_id"`
	ParserName  string    `json:"parser_name"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	LoadedAt    time.Time `json:"loaded_at"`
	DurationMs  float64   `json:"duration_ms"`
}

// ParserStats represents parser statistics.
type ParserStats struct {
	TotalParsers   int64   `json:"total_parsers"`
	ActiveParsers  int64   `json:"active_parsers"`
	ErrorParsers   int64   `json:"error_parsers"`
	TotalParseCount int64  `json:"total_parse_count"`
	TotalErrorCount int64  `json:"total_error_count"`
	AvgParseTimeMs float64 `json:"avg_parse_time_ms"`
	TopParsers     []ParserStat `json:"top_parsers,omitempty"`
	ErrorRatePct   float64 `json:"error_rate_pct"`
	ByType         map[string]int64 `json:"by_type"`
	ByProduct      map[string]int64 `json:"by_product"`
}

// ParserStat represents statistics for a single parser.
type ParserStat struct {
	ParserID      string  `json:"parser_id"`
	ParserName    string  `json:"parser_name"`
	ProductName   string  `json:"product_name"`
	ParseCount    int64   `json:"parse_count"`
	ErrorCount    int64   `json:"error_count"`
	ErrorRatePct  float64 `json:"error_rate_pct"`
	AvgParseTimeMs float64 `json:"avg_parse_time_ms"`
}
