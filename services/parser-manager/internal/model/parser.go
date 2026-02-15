// Package model provides parser data models.
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
	ParserStatusTesting  ParserStatus = "testing"
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
	NormalizeToUDM bool              `json:"normalize_to_udm" db:"normalize_to_udm"`
	UDMMapping     map[string]string `json:"udm_mapping,omitempty"`

	// Detection
	DetectionPattern string `json:"detection_pattern,omitempty" db:"detection_pattern"` // Pattern to detect this parser should be used

	// Version control
	Version  int    `json:"version" db:"version"`
	ParentID string `json:"parent_id,omitempty" db:"parent_id"`

	// Statistics
	ParseCount     int64      `json:"parse_count" db:"parse_count"`
	ErrorCount     int64      `json:"error_count" db:"error_count"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	AvgParseTimeMs float64    `json:"avg_parse_time_ms" db:"avg_parse_time_ms"`

	// Hot reload tracking
	LoadedAt     *time.Time `json:"loaded_at,omitempty" db:"loaded_at"`
	DeployedAt   *time.Time `json:"deployed_at,omitempty" db:"deployed_at"`
	DeployedBy   string     `json:"deployed_by,omitempty" db:"deployed_by"`
	ReloadCount  int        `json:"reload_count" db:"reload_count"`
	LastReloadAt *time.Time `json:"last_reload_at,omitempty" db:"last_reload_at"`
	LastReloadBy string     `json:"last_reload_by,omitempty" db:"last_reload_by"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy string    `json:"created_by" db:"created_by"`
	UpdatedBy string    `json:"updated_by,omitempty" db:"updated_by"`

	// Metadata
	Tags   []string          `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
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

// ParserFilter2 defines filters for listing parsers.
type ParserFilter2 struct {
	ProductID  string         `json:"product_id,omitempty"`
	Types      []ParserType   `json:"types,omitempty"`
	Statuses   []ParserStatus `json:"statuses,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Search     string         `json:"search,omitempty"`
	TenantID   string         `json:"tenant_id,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	Offset     int            `json:"offset,omitempty"`
	SortBy     string         `json:"sort_by,omitempty"`
	SortOrder  string         `json:"sort_order,omitempty"`
}

// ParserListResult contains paginated parser results.
type ParserListResult struct {
	Parsers []*Parser `json:"parsers"`
	Total   int64     `json:"total"`
	Limit   int       `json:"limit"`
	Offset  int       `json:"offset"`
	HasMore bool      `json:"has_more"`
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

// ParserDeployRequest represents a request to deploy a parser.
type ParserDeployRequest struct {
	ParserID string `json:"parser_id" validate:"required"`
	Force    bool   `json:"force,omitempty"`
}

// ParserDeployResult represents the result of a parser deployment.
type ParserDeployResult struct {
	ParserID   string    `json:"parser_id"`
	ParserName string    `json:"parser_name"`
	Success    bool      `json:"success"`
	Error      string    `json:"error,omitempty"`
	DeployedAt time.Time `json:"deployed_at"`
	DurationMs float64   `json:"duration_ms"`
	Instances  int       `json:"instances"` // Number of parser instances updated
}

// ReloadStatus represents the current reload status.
type ReloadStatus struct {
	LastReloadAt    time.Time         `json:"last_reload_at"`
	ReloadInProgress bool             `json:"reload_in_progress"`
	PendingParsers   int              `json:"pending_parsers"`
	LoadedParsers    int              `json:"loaded_parsers"`
	FailedParsers    int              `json:"failed_parsers"`
	ParserStatuses   []ParserReloadStatus `json:"parser_statuses,omitempty"`
}

// ParserReloadStatus represents reload status for a single parser.
type ParserReloadStatus struct {
	ParserID   string    `json:"parser_id"`
	ParserName string    `json:"parser_name"`
	Status     string    `json:"status"` // pending, loading, loaded, failed
	LoadedAt   time.Time `json:"loaded_at,omitempty"`
	Error      string    `json:"error,omitempty"`
}
