// Package model provides data models for policy management.
package model

import (
	"encoding/json"
	"time"
)

// PolicyStatus represents the status of a policy.
type PolicyStatus string

const (
	PolicyStatusDraft     PolicyStatus = "draft"
	PolicyStatusActive    PolicyStatus = "active"
	PolicyStatusInactive  PolicyStatus = "inactive"
	PolicyStatusArchived  PolicyStatus = "archived"
)

// PolicyType represents the type of policy.
type PolicyType string

const (
	PolicyTypeDetection   PolicyType = "detection"
	PolicyTypeResponse    PolicyType = "response"
	PolicyTypeCompliance  PolicyType = "compliance"
	PolicyTypeRouting     PolicyType = "routing"
	PolicyTypeEnrichment  PolicyType = "enrichment"
	PolicyTypeFiltering   PolicyType = "filtering"
)

// Severity represents the severity level.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Policy represents a policy in the system.
type Policy struct {
	ID          string       `json:"id" db:"id"`
	TenantID    string       `json:"tenant_id" db:"tenant_id"`
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description,omitempty" db:"description"`
	Type        PolicyType   `json:"type" db:"type"`
	Status      PolicyStatus `json:"status" db:"status"`
	Priority    int          `json:"priority" db:"priority"` // Higher = more priority

	// Rules
	Rules       []Rule       `json:"rules,omitempty"`

	// Conditions
	Conditions  []Condition  `json:"conditions,omitempty"`

	// Actions
	Actions     []Action     `json:"actions,omitempty"`

	// Exceptions
	Exceptions  []Exception  `json:"exceptions,omitempty"`

	// Targeting
	TargetAssets  []string `json:"target_assets,omitempty"`
	TargetGroups  []string `json:"target_groups,omitempty"`
	TargetTags    []string `json:"target_tags,omitempty"`

	// Schedule
	Schedule    *Schedule `json:"schedule,omitempty"`

	// Metadata
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	// Versioning
	Version     int       `json:"version" db:"version"`
	ParentID    string    `json:"parent_id,omitempty" db:"parent_id"` // Previous version

	// Statistics
	EvaluationCount int64     `json:"evaluation_count" db:"evaluation_count"`
	MatchCount      int64     `json:"match_count" db:"match_count"`
	LastEvaluatedAt *time.Time `json:"last_evaluated_at,omitempty" db:"last_evaluated_at"`

	// Audit
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   string     `json:"created_by" db:"created_by"`
	UpdatedBy   string     `json:"updated_by,omitempty" db:"updated_by"`
	ActivatedAt *time.Time `json:"activated_at,omitempty" db:"activated_at"`
	ActivatedBy string     `json:"activated_by,omitempty" db:"activated_by"`
}

// Rule represents a rule within a policy.
type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Priority    int         `json:"priority"`
	Conditions  []Condition `json:"conditions,omitempty"`
	Actions     []Action    `json:"actions,omitempty"`
	Severity    Severity    `json:"severity,omitempty"`
}

// Condition represents a condition for rule evaluation.
type Condition struct {
	ID        string      `json:"id"`
	Field     string      `json:"field"`          // Field to evaluate
	Operator  string      `json:"operator"`       // eq, ne, gt, lt, gte, lte, contains, regex, in, not_in
	Value     interface{} `json:"value"`          // Value to compare against
	ValueType string      `json:"value_type"`     // string, number, boolean, array
	Logic     string      `json:"logic,omitempty"` // and, or (for combining with previous condition)
}

// Action represents an action to take when a rule matches.
type Action struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // alert, enrich, route, block, notify, playbook
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Order      int                    `json:"order"`
	OnError    string                 `json:"on_error,omitempty"` // continue, stop, retry
}

// Exception represents an exception to a policy.
type Exception struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Conditions  []Condition `json:"conditions"`
	Reason      string      `json:"reason,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
}

// Schedule represents when a policy should be active.
type Schedule struct {
	Type       string     `json:"type"` // always, time_range, cron
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	CronExpr   string     `json:"cron_expression,omitempty"`
	Timezone   string     `json:"timezone,omitempty"`
	DaysOfWeek []int      `json:"days_of_week,omitempty"` // 0=Sunday, 6=Saturday
}

// PolicyVersion represents a historical version of a policy.
type PolicyVersion struct {
	ID          string          `json:"id" db:"id"`
	PolicyID    string          `json:"policy_id" db:"policy_id"`
	Version     int             `json:"version" db:"version"`
	Data        json.RawMessage `json:"data" db:"data"`
	ChangeLog   string          `json:"change_log,omitempty" db:"change_log"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	CreatedBy   string          `json:"created_by" db:"created_by"`
}

// CreatePolicyRequest represents a request to create a new policy.
type CreatePolicyRequest struct {
	Name         string            `json:"name" validate:"required,min=1,max=255"`
	Description  string            `json:"description,omitempty"`
	Type         PolicyType        `json:"type" validate:"required"`
	Status       PolicyStatus      `json:"status,omitempty"`
	Priority     int               `json:"priority,omitempty"`
	Rules        []Rule            `json:"rules,omitempty"`
	Conditions   []Condition       `json:"conditions,omitempty"`
	Actions      []Action          `json:"actions,omitempty"`
	Exceptions   []Exception       `json:"exceptions,omitempty"`
	TargetAssets []string          `json:"target_assets,omitempty"`
	TargetGroups []string          `json:"target_groups,omitempty"`
	TargetTags   []string          `json:"target_tags,omitempty"`
	Schedule     *Schedule         `json:"schedule,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// UpdatePolicyRequest represents a request to update a policy.
type UpdatePolicyRequest struct {
	Name         *string           `json:"name,omitempty"`
	Description  *string           `json:"description,omitempty"`
	Status       *PolicyStatus     `json:"status,omitempty"`
	Priority     *int              `json:"priority,omitempty"`
	Rules        []Rule            `json:"rules,omitempty"`
	Conditions   []Condition       `json:"conditions,omitempty"`
	Actions      []Action          `json:"actions,omitempty"`
	TargetAssets []string          `json:"target_assets,omitempty"`
	TargetGroups []string          `json:"target_groups,omitempty"`
	TargetTags   []string          `json:"target_tags,omitempty"`
	Schedule     *Schedule         `json:"schedule,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// AddRuleRequest represents a request to add a rule to a policy.
type AddRuleRequest struct {
	Name        string      `json:"name" validate:"required"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Priority    int         `json:"priority,omitempty"`
	Conditions  []Condition `json:"conditions,omitempty"`
	Actions     []Action    `json:"actions,omitempty"`
	Severity    Severity    `json:"severity,omitempty"`
}

// AddExceptionRequest represents a request to add an exception.
type AddExceptionRequest struct {
	Name        string      `json:"name" validate:"required"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Conditions  []Condition `json:"conditions" validate:"required"`
	Reason      string      `json:"reason,omitempty"`
	ExpiresAt   *time.Time  `json:"expires_at,omitempty"`
}

// EvaluateRequest represents a request to evaluate a policy.
type EvaluateRequest struct {
	Event      map[string]interface{} `json:"event" validate:"required"`
	Context    map[string]interface{} `json:"context,omitempty"`
	PolicyIDs  []string               `json:"policy_ids,omitempty"` // If empty, evaluate all active policies
	DryRun     bool                   `json:"dry_run,omitempty"`
}

// EvaluateResult represents the result of policy evaluation.
type EvaluateResult struct {
	PolicyID      string                 `json:"policy_id"`
	PolicyName    string                 `json:"policy_name"`
	Matched       bool                   `json:"matched"`
	MatchedRules  []string               `json:"matched_rules,omitempty"`
	Actions       []Action               `json:"actions,omitempty"`
	Exceptions    []string               `json:"exceptions_applied,omitempty"`
	EvaluatedAt   time.Time              `json:"evaluated_at"`
	DurationMs    float64                `json:"duration_ms"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// PolicyFilter defines filters for listing policies.
type PolicyFilter struct {
	Types      []PolicyType   `json:"types,omitempty"`
	Statuses   []PolicyStatus `json:"statuses,omitempty"`
	Name       string         `json:"name,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Search     string         `json:"search,omitempty"`
	TenantID   string         `json:"tenant_id,omitempty"`
	Limit      int            `json:"limit,omitempty"`
	Offset     int            `json:"offset,omitempty"`
	SortBy     string         `json:"sort_by,omitempty"`
	SortOrder  string         `json:"sort_order,omitempty"`
}

// PolicyListResult contains paginated policy results.
type PolicyListResult struct {
	Policies []*Policy `json:"policies"`
	Total    int64     `json:"total"`
	Limit    int       `json:"limit"`
	Offset   int       `json:"offset"`
	HasMore  bool      `json:"has_more"`
}

// RollbackRequest represents a request to rollback to a previous version.
type RollbackRequest struct {
	Version int    `json:"version" validate:"required"`
	Reason  string `json:"reason,omitempty"`
}
