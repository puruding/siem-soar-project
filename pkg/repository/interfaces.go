// Package repository provides database access abstractions for SIEM-SOAR platform.
package repository

import (
	"context"
	"time"
)

// ============================================================================
// Core Types
// ============================================================================

// Pagination holds pagination parameters.
type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
	Total    int `json:"total"`
}

// DefaultPagination returns default pagination settings.
func DefaultPagination() Pagination {
	return Pagination{
		Page:     1,
		PageSize: 20,
	}
}

// Offset calculates the database offset for pagination.
func (p Pagination) Offset() int {
	return (p.Page - 1) * p.PageSize
}

// Limit returns the page size as the limit.
func (p Pagination) Limit() int {
	return p.PageSize
}

// SortOrder represents sort direction.
type SortOrder string

const (
	SortAsc  SortOrder = "ASC"
	SortDesc SortOrder = "DESC"
)

// Sort holds sorting parameters.
type Sort struct {
	Field string    `json:"field"`
	Order SortOrder `json:"order"`
}

// Operator represents filter operators.
type Operator string

const (
	OpEq         Operator = "eq"
	OpNe         Operator = "ne"
	OpGt         Operator = "gt"
	OpGte        Operator = "gte"
	OpLt         Operator = "lt"
	OpLte        Operator = "lte"
	OpLike       Operator = "like"
	OpILike      Operator = "ilike"
	OpIn         Operator = "in"
	OpNotIn      Operator = "not_in"
	OpBetween    Operator = "between"
	OpIsNull     Operator = "is_null"
	OpIsNotNull  Operator = "is_not_null"
	OpContains   Operator = "contains"
	OpStartsWith Operator = "starts_with"
	OpEndsWith   Operator = "ends_with"
)

// Filter represents a query filter.
type Filter struct {
	Field    string      `json:"field"`
	Operator Operator    `json:"operator"`
	Value    interface{} `json:"value"`
}

// TimeRange represents a time-based filter.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// QueryOptions holds common query options.
type QueryOptions struct {
	Pagination Pagination
	Sorts      []Sort
	Filters    []Filter
	TimeRange  *TimeRange
	TenantID   string
	Select     []string // Fields to select
}

// NewQueryOptions creates QueryOptions with defaults.
func NewQueryOptions() QueryOptions {
	return QueryOptions{
		Pagination: DefaultPagination(),
		Sorts:      make([]Sort, 0),
		Filters:    make([]Filter, 0),
	}
}

// BaseEntity contains common fields for all entities.
type BaseEntity struct {
	ID        string    `json:"id" db:"id"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TenantEntity extends BaseEntity with tenant isolation.
type TenantEntity struct {
	BaseEntity
	TenantID string `json:"tenant_id" db:"tenant_id"`
}

// ============================================================================
// Transaction Interfaces
// ============================================================================

// Transaction represents a database transaction.
type Transaction interface {
	Commit() error
	Rollback() error
}

// TxFunc is a function that runs within a transaction.
type TxFunc func(ctx context.Context, tx Transaction) error

// Transactor provides transaction management.
type Transactor interface {
	WithTransaction(ctx context.Context, fn TxFunc) error
}

// ============================================================================
// Health Check Interfaces
// ============================================================================

// HealthChecker provides database health checks.
type HealthChecker interface {
	Ping(ctx context.Context) error
	IsHealthy(ctx context.Context) bool
}

// ============================================================================
// Migration Interface
// ============================================================================

// Migrator handles database migrations.
type Migrator interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Version(ctx context.Context) (int, error)
	MigrateTo(ctx context.Context, version int) error
}

// ============================================================================
// Generic Repository Interface
// ============================================================================

// Repository is a generic interface for CRUD operations.
type Repository[T any] interface {
	Create(ctx context.Context, entity *T) error
	GetByID(ctx context.Context, id string) (*T, error)
	Update(ctx context.Context, entity *T) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, opts QueryOptions) ([]*T, int, error)
	Exists(ctx context.Context, id string) (bool, error)
}

// ============================================================================
// Event Repository Interface (ClickHouse)
// ============================================================================

// EventFilter represents event-specific filters.
type EventFilter struct {
	TenantID      string
	EventTypes    []string
	TimeRange     TimeRange
	Severity      []string
	PrincipalIPs  []string
	TargetIPs     []string
	Hostnames     []string
	UserIDs       []string
	RuleIDs       []string
	VendorNames   []string
	ProductNames  []string
	TIMatched     *bool
	SearchQuery   string
	CustomFilters map[string]interface{}
}

// EventStats represents event statistics.
type EventStats struct {
	TotalEvents      int64                  `json:"total_events"`
	EventsByType     map[string]int64       `json:"events_by_type"`
	EventsBySeverity map[string]int64       `json:"events_by_severity"`
	EventsByVendor   map[string]int64       `json:"events_by_vendor"`
	UniqueHosts      int64                  `json:"unique_hosts"`
	UniqueUsers      int64                  `json:"unique_users"`
	TIMatches        int64                  `json:"ti_matches"`
	BytesTotal       int64                  `json:"bytes_total"`
	TimeRange        TimeRange              `json:"time_range"`
	TopTalkers       []TopTalker            `json:"top_talkers,omitempty"`
	Breakdown        map[string]interface{} `json:"breakdown,omitempty"`
}

// TopTalker represents top network talkers.
type TopTalker struct {
	IP         string `json:"ip"`
	EventCount int64  `json:"event_count"`
	BytesTotal int64  `json:"bytes_total"`
	Country    string `json:"country,omitempty"`
}

// Event represents a security event from ClickHouse.
type Event struct {
	EventID               string                 `json:"event_id" ch:"event_id"`
	TenantID              string                 `json:"tenant_id" ch:"tenant_id"`
	Timestamp             time.Time              `json:"timestamp" ch:"timestamp"`
	EventType             string                 `json:"event_type" ch:"event_type"`
	VendorName            string                 `json:"vendor_name" ch:"vendor_name"`
	ProductName           string                 `json:"product_name" ch:"product_name"`
	Severity              string                 `json:"severity" ch:"security_severity"`
	PrincipalHostname     string                 `json:"principal_hostname" ch:"principal_hostname"`
	PrincipalIP           []string               `json:"principal_ip" ch:"principal_ip"`
	PrincipalUserID       string                 `json:"principal_user_id" ch:"principal_user_id"`
	TargetHostname        string                 `json:"target_hostname" ch:"target_hostname"`
	TargetIP              []string               `json:"target_ip" ch:"target_ip"`
	SecurityAction        string                 `json:"security_action" ch:"security_action"`
	SecurityRuleName      string                 `json:"security_rule_name" ch:"security_rule_name"`
	Description           string                 `json:"description" ch:"description"`
	RawLog                string                 `json:"raw_log,omitempty" ch:"raw_log"`
	AdditionalFields      map[string]interface{} `json:"additional_fields,omitempty"`
}

// EventRepository defines ClickHouse event operations.
type EventRepository interface {
	// Write operations
	Insert(ctx context.Context, events []*Event) error
	InsertBatch(ctx context.Context, events []*Event, batchSize int) error

	// Read operations
	GetByID(ctx context.Context, tenantID, eventID string) (*Event, error)
	Search(ctx context.Context, filter EventFilter, opts QueryOptions) ([]*Event, int64, error)
	GetStats(ctx context.Context, filter EventFilter) (*EventStats, error)

	// Aggregation
	CountByField(ctx context.Context, filter EventFilter, field string, limit int) (map[string]int64, error)
	Timeline(ctx context.Context, filter EventFilter, interval string) ([]TimelinePoint, error)

	// Raw queries
	Query(ctx context.Context, query string, args ...interface{}) ([]map[string]interface{}, error)
}

// TimelinePoint represents a point in time series data.
type TimelinePoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// ============================================================================
// Alert Repository Interface (ClickHouse)
// ============================================================================

// Alert represents a security alert.
type Alert struct {
	AlertID       string    `json:"alert_id" ch:"alert_id"`
	TenantID      string    `json:"tenant_id" ch:"tenant_id"`
	CreatedAt     time.Time `json:"created_at" ch:"created_at"`
	AlertName     string    `json:"alert_name" ch:"alert_name"`
	AlertType     string    `json:"alert_type" ch:"alert_type"`
	Severity      string    `json:"severity" ch:"severity"`
	Status        string    `json:"status" ch:"status"`
	Resolution    string    `json:"resolution" ch:"resolution"`
	RuleID        string    `json:"rule_id" ch:"rule_id"`
	RuleName      string    `json:"rule_name" ch:"rule_name"`
	EventCount    int64     `json:"event_count" ch:"event_count"`
	AssigneeID    string    `json:"assignee_id" ch:"assignee_id"`
	CaseID        string    `json:"case_id" ch:"case_id"`
	AITriageScore float32   `json:"ai_triage_score" ch:"ai_triage_score"`
	AITriageLabel string    `json:"ai_triage_label" ch:"ai_triage_label"`
}

// AlertFilter represents alert-specific filters.
type AlertFilter struct {
	TenantID     string
	Statuses     []string
	Severities   []string
	AlertTypes   []string
	RuleIDs      []string
	AssigneeIDs  []string
	CaseIDs      []string
	AILabels     []string
	TimeRange    TimeRange
	SLABreached  *bool
	HasCase      *bool
	SearchQuery  string
}

// AlertRepository defines ClickHouse alert operations.
type AlertRepository interface {
	Insert(ctx context.Context, alerts []*Alert) error
	GetByID(ctx context.Context, tenantID, alertID string) (*Alert, error)
	Search(ctx context.Context, filter AlertFilter, opts QueryOptions) ([]*Alert, int64, error)
	UpdateStatus(ctx context.Context, tenantID, alertID, status, resolution string) error
	AssignTo(ctx context.Context, tenantID, alertID, assigneeID string) error
	LinkToCase(ctx context.Context, tenantID, alertID, caseID string) error
	GetStats(ctx context.Context, filter AlertFilter) (*AlertStats, error)
}

// AlertStats represents alert statistics.
type AlertStats struct {
	TotalAlerts      int64            `json:"total_alerts"`
	OpenAlerts       int64            `json:"open_alerts"`
	AlertsByStatus   map[string]int64 `json:"alerts_by_status"`
	AlertsBySeverity map[string]int64 `json:"alerts_by_severity"`
	AlertsByType     map[string]int64 `json:"alerts_by_type"`
	AvgTriageScore   float64          `json:"avg_triage_score"`
	SLABreached      int64            `json:"sla_breached"`
	MTTRAcknowledge  float64          `json:"mttr_acknowledge_minutes"`
	MTTRResolve      float64          `json:"mttr_resolve_minutes"`
}

// ============================================================================
// User Repository Interface (PostgreSQL)
// ============================================================================

// User represents a platform user.
type User struct {
	TenantEntity
	Email               string    `json:"email" db:"email"`
	Username            string    `json:"username" db:"username"`
	DisplayName         string    `json:"display_name" db:"display_name"`
	PasswordHash        string    `json:"-" db:"password_hash"`
	Role                string    `json:"role" db:"role"`
	Status              string    `json:"status" db:"status"`
	MFAEnabled          bool      `json:"mfa_enabled" db:"mfa_enabled"`
	LastLoginAt         time.Time `json:"last_login_at" db:"last_login_at"`
	FailedLoginAttempts int       `json:"failed_login_attempts" db:"failed_login_attempts"`
}

// UserFilter represents user-specific filters.
type UserFilter struct {
	TenantID string
	Email    string
	Username string
	Roles    []string
	Statuses []string
	GroupID  string
}

// UserRepository defines PostgreSQL user operations.
type UserRepository interface {
	Repository[User]
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByUsername(ctx context.Context, tenantID, username string) (*User, error)
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	UpdateLastLogin(ctx context.Context, userID string, ip string) error
	IncrementFailedLogin(ctx context.Context, userID string) error
	ResetFailedLogin(ctx context.Context, userID string) error
	ListByTenant(ctx context.Context, tenantID string, opts QueryOptions) ([]*User, int, error)
	GetUserGroups(ctx context.Context, userID string) ([]string, error)
}

// ============================================================================
// Tenant Repository Interface (PostgreSQL)
// ============================================================================

// Tenant represents an organization/tenant.
type Tenant struct {
	BaseEntity
	Name           string                 `json:"name" db:"name"`
	Slug           string                 `json:"slug" db:"slug"`
	DisplayName    string                 `json:"display_name" db:"display_name"`
	Tier           string                 `json:"tier" db:"tier"`
	Status         string                 `json:"status" db:"status"`
	MaxUsers       int                    `json:"max_users" db:"max_users"`
	MaxEventsPerDay int64                 `json:"max_events_per_day" db:"max_events_per_day"`
	RetentionDays  int                    `json:"retention_days" db:"retention_days"`
	Features       map[string]bool        `json:"features" db:"features"`
	Settings       map[string]interface{} `json:"settings" db:"settings"`
}

// TenantRepository defines PostgreSQL tenant operations.
type TenantRepository interface {
	Repository[Tenant]
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	UpdateFeatures(ctx context.Context, tenantID string, features map[string]bool) error
	UpdateSettings(ctx context.Context, tenantID string, settings map[string]interface{}) error
	GetUsage(ctx context.Context, tenantID string, date time.Time) (*TenantUsage, error)
	RecordUsage(ctx context.Context, usage *TenantUsage) error
}

// TenantUsage represents daily tenant usage.
type TenantUsage struct {
	TenantID       string    `json:"tenant_id" db:"tenant_id"`
	Date           time.Time `json:"date" db:"date"`
	EventsIngested int64     `json:"events_ingested" db:"events_ingested"`
	BytesIngested  int64     `json:"bytes_ingested" db:"bytes_ingested"`
	ActiveUsers    int       `json:"active_users" db:"active_users"`
	APICalls       int64     `json:"api_calls" db:"api_calls"`
	AlertsGenerated int      `json:"alerts_generated" db:"alerts_generated"`
}

// ============================================================================
// Detection Rule Repository Interface (PostgreSQL)
// ============================================================================

// DetectionRule represents a detection rule.
type DetectionRule struct {
	TenantEntity
	RuleID        string   `json:"rule_id" db:"rule_id"`
	Name          string   `json:"name" db:"name"`
	Description   string   `json:"description" db:"description"`
	RuleType      string   `json:"rule_type" db:"rule_type"`
	Severity      string   `json:"severity" db:"severity"`
	RuleContent   string   `json:"rule_content" db:"rule_content"`
	CompiledQuery string   `json:"compiled_query,omitempty" db:"compiled_query"`
	Status        string   `json:"status" db:"status"`
	IsEnabled     bool     `json:"is_enabled" db:"is_enabled"`
	MITRETactics  []string `json:"mitre_tactics" db:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques" db:"mitre_techniques"`
	Tags          []string `json:"tags" db:"tags"`
	Version       int      `json:"version" db:"version"`
}

// DetectionRuleFilter represents rule-specific filters.
type DetectionRuleFilter struct {
	TenantID  string
	RuleTypes []string
	Severities []string
	Statuses  []string
	Enabled   *bool
	Tags      []string
	Search    string
}

// DetectionRuleRepository defines PostgreSQL detection rule operations.
type DetectionRuleRepository interface {
	Repository[DetectionRule]
	GetByRuleID(ctx context.Context, tenantID, ruleID string) (*DetectionRule, error)
	ListEnabled(ctx context.Context, tenantID string) ([]*DetectionRule, error)
	UpdateStatus(ctx context.Context, tenantID, ruleID, status string) error
	Enable(ctx context.Context, tenantID, ruleID string) error
	Disable(ctx context.Context, tenantID, ruleID string) error
	IncrementExecutions(ctx context.Context, tenantID, ruleID string, matches int64) error
	CreateVersion(ctx context.Context, rule *DetectionRule) error
	GetVersions(ctx context.Context, tenantID, ruleID string) ([]*DetectionRule, error)
}

// ============================================================================
// Case Repository Interface (PostgreSQL)
// ============================================================================

// Case represents a security case/incident.
type Case struct {
	TenantEntity
	CaseNumber     string    `json:"case_number" db:"case_number"`
	Title          string    `json:"title" db:"title"`
	Summary        string    `json:"summary" db:"summary"`
	CaseType       string    `json:"case_type" db:"case_type"`
	Severity       string    `json:"severity" db:"severity"`
	Priority       string    `json:"priority" db:"priority"`
	Status         string    `json:"status" db:"status"`
	Resolution     string    `json:"resolution" db:"resolution"`
	AssigneeID     string    `json:"assignee_id" db:"assignee_id"`
	OwnerID        string    `json:"owner_id" db:"owner_id"`
	AlertCount     int       `json:"alert_count" db:"alert_count"`
	DetectedAt     time.Time `json:"detected_at" db:"detected_at"`
	ClosedAt       time.Time `json:"closed_at" db:"closed_at"`
	MITRETactics   []string  `json:"mitre_tactics" db:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques" db:"mitre_techniques"`
	Tags           []string  `json:"tags" db:"tags"`
}

// CaseFilter represents case-specific filters.
type CaseFilter struct {
	TenantID     string
	CaseTypes    []string
	Statuses     []string
	Severities   []string
	Priorities   []string
	AssigneeIDs  []string
	OwnerIDs     []string
	HasAlerts    *bool
	TimeRange    TimeRange
	Search       string
}

// CaseRepository defines PostgreSQL case operations.
type CaseRepository interface {
	Repository[Case]
	GetByNumber(ctx context.Context, tenantID, caseNumber string) (*Case, error)
	UpdateStatus(ctx context.Context, tenantID, caseID, status, resolution string) error
	AssignTo(ctx context.Context, tenantID, caseID, assigneeID string) error
	LinkAlert(ctx context.Context, tenantID, caseID, alertID string) error
	UnlinkAlert(ctx context.Context, tenantID, caseID, alertID string) error
	GetAlerts(ctx context.Context, tenantID, caseID string) ([]string, error)
	AddTimeline(ctx context.Context, tenantID, caseID string, entry *TimelineEntry) error
	GetTimeline(ctx context.Context, tenantID, caseID string, opts QueryOptions) ([]*TimelineEntry, error)
	GetStats(ctx context.Context, filter CaseFilter) (*CaseStats, error)
}

// TimelineEntry represents a case timeline entry.
type TimelineEntry struct {
	ID          string    `json:"id"`
	CaseID      string    `json:"case_id"`
	EventTime   time.Time `json:"event_time"`
	EventType   string    `json:"event_type"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	ActorID     string    `json:"actor_id"`
	ActorName   string    `json:"actor_name"`
}

// CaseStats represents case statistics.
type CaseStats struct {
	TotalCases       int64            `json:"total_cases"`
	OpenCases        int64            `json:"open_cases"`
	CasesByStatus    map[string]int64 `json:"cases_by_status"`
	CasesBySeverity  map[string]int64 `json:"cases_by_severity"`
	CasesByType      map[string]int64 `json:"cases_by_type"`
	MTTD             float64          `json:"mttd_minutes"` // Mean time to detect
	MTTC             float64          `json:"mttc_minutes"` // Mean time to contain
	MTTR             float64          `json:"mttr_minutes"` // Mean time to resolve
}

// ============================================================================
// Playbook Repository Interface (PostgreSQL)
// ============================================================================

// Playbook represents a SOAR playbook.
type Playbook struct {
	TenantEntity
	Name            string                 `json:"name" db:"name"`
	DisplayName     string                 `json:"display_name" db:"display_name"`
	Description     string                 `json:"description" db:"description"`
	Category        string                 `json:"category" db:"category"`
	Definition      map[string]interface{} `json:"definition" db:"definition"`
	TriggerType     string                 `json:"trigger_type" db:"trigger_type"`
	TriggerConfig   map[string]interface{} `json:"trigger_config" db:"trigger_config"`
	Status          string                 `json:"status" db:"status"`
	IsEnabled       bool                   `json:"is_enabled" db:"is_enabled"`
	RequiresApproval bool                  `json:"requires_approval" db:"requires_approval"`
	ExecutionCount  int64                  `json:"execution_count" db:"execution_count"`
	SuccessCount    int64                  `json:"success_count" db:"success_count"`
	FailureCount    int64                  `json:"failure_count" db:"failure_count"`
	Version         int                    `json:"version" db:"version"`
	Tags            []string               `json:"tags" db:"tags"`
}

// PlaybookRepository defines PostgreSQL playbook operations.
type PlaybookRepository interface {
	Repository[Playbook]
	GetByName(ctx context.Context, tenantID, name string) (*Playbook, error)
	ListEnabled(ctx context.Context, tenantID string) ([]*Playbook, error)
	ListByTrigger(ctx context.Context, tenantID, triggerType string) ([]*Playbook, error)
	UpdateStatus(ctx context.Context, tenantID, playbookID, status string) error
	Enable(ctx context.Context, tenantID, playbookID string) error
	Disable(ctx context.Context, tenantID, playbookID string) error
	IncrementExecution(ctx context.Context, tenantID, playbookID string, success bool) error
	CreateVersion(ctx context.Context, playbook *Playbook) error
}
