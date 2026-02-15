// Package model provides data models for case management.
package model

import (
	"encoding/json"
	"time"
)

// CaseSeverity represents case severity levels.
type CaseSeverity string

const (
	SeverityInformational CaseSeverity = "informational"
	SeverityLow           CaseSeverity = "low"
	SeverityMedium        CaseSeverity = "medium"
	SeverityHigh          CaseSeverity = "high"
	SeverityCritical      CaseSeverity = "critical"
)

// CaseStatus represents case status values.
type CaseStatus string

const (
	StatusNew          CaseStatus = "new"
	StatusOpen         CaseStatus = "open"
	StatusInProgress   CaseStatus = "in_progress"
	StatusPending      CaseStatus = "pending"
	StatusOnHold       CaseStatus = "on_hold"
	StatusResolved     CaseStatus = "resolved"
	StatusClosed       CaseStatus = "closed"
	StatusReopened     CaseStatus = "reopened"
)

// CaseType represents the type of case.
type CaseType string

const (
	TypeIncident       CaseType = "incident"
	TypeInvestigation  CaseType = "investigation"
	TypeVulnerability  CaseType = "vulnerability"
	TypeThreatHunt     CaseType = "threat_hunt"
	TypeCompliance     CaseType = "compliance"
	TypeOther          CaseType = "other"
)

// CasePriority represents case priority levels.
type CasePriority string

const (
	PriorityP1 CasePriority = "P1"
	PriorityP2 CasePriority = "P2"
	PriorityP3 CasePriority = "P3"
	PriorityP4 CasePriority = "P4"
)

// Case represents a security case/incident.
type Case struct {
	ID          string       `json:"id" db:"id"`
	Number      string       `json:"number" db:"number"` // Human-readable case number (e.g., CASE-2024-0001)
	Title       string       `json:"title" db:"title"`
	Description string       `json:"description" db:"description"`
	Type        CaseType     `json:"type" db:"type"`
	Severity    CaseSeverity `json:"severity" db:"severity"`
	Priority    CasePriority `json:"priority" db:"priority"`
	Status      CaseStatus   `json:"status" db:"status"`

	// Assignment
	Assignee       string   `json:"assignee,omitempty" db:"assignee"`
	AssigneeEmail  string   `json:"assignee_email,omitempty" db:"assignee_email"`
	Team           string   `json:"team,omitempty" db:"team"`
	Collaborators  []string `json:"collaborators,omitempty"`

	// Source
	Source           string   `json:"source,omitempty" db:"source"` // alert, manual, external, playbook
	SourceID         string   `json:"source_id,omitempty" db:"source_id"`
	AlertIDs         []string `json:"alert_ids,omitempty"`
	PlaybookID       string   `json:"playbook_id,omitempty" db:"playbook_id"`

	// Classification
	Classification       string   `json:"classification,omitempty" db:"classification"` // true_positive, false_positive, benign
	ClassificationReason string   `json:"classification_reason,omitempty" db:"classification_reason"`
	Tags                 []string `json:"tags,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`

	// MITRE ATT&CK
	Tactics    []string `json:"tactics,omitempty"`
	Techniques []string `json:"techniques,omitempty"`

	// Impact
	ImpactScore     int      `json:"impact_score,omitempty" db:"impact_score"`
	AffectedAssets  []string `json:"affected_assets,omitempty"`
	AffectedUsers   []string `json:"affected_users,omitempty"`
	DataBreached    bool     `json:"data_breached" db:"data_breached"`
	BusinessImpact  string   `json:"business_impact,omitempty" db:"business_impact"`

	// Resolution
	Resolution       string    `json:"resolution,omitempty" db:"resolution"`
	ResolutionNotes  string    `json:"resolution_notes,omitempty" db:"resolution_notes"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty" db:"resolved_at"`
	ResolvedBy       string    `json:"resolved_by,omitempty" db:"resolved_by"`
	RootCause        string    `json:"root_cause,omitempty" db:"root_cause"`
	LessonsLearned   string    `json:"lessons_learned,omitempty" db:"lessons_learned"`

	// SLA
	SLADeadline     *time.Time `json:"sla_deadline,omitempty" db:"sla_deadline"`
	SLABreached     bool       `json:"sla_breached" db:"sla_breached"`
	ResponseTime    int64      `json:"response_time_minutes,omitempty" db:"response_time"`
	ResolutionTime  int64      `json:"resolution_time_minutes,omitempty" db:"resolution_time"`

	// External references
	TicketID     string `json:"ticket_id,omitempty" db:"ticket_id"`
	TicketURL    string `json:"ticket_url,omitempty" db:"ticket_url"`
	ExternalRefs map[string]string `json:"external_refs,omitempty"`

	// Statistics
	EvidenceCount int `json:"evidence_count" db:"evidence_count"`
	CommentCount  int `json:"comment_count" db:"comment_count"`
	TaskCount     int `json:"task_count" db:"task_count"`

	// Audit
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy  string     `json:"created_by" db:"created_by"`
	UpdatedBy  string     `json:"updated_by,omitempty" db:"updated_by"`
	ClosedAt   *time.Time `json:"closed_at,omitempty" db:"closed_at"`
	ClosedBy   string     `json:"closed_by,omitempty" db:"closed_by"`

	// Multi-tenancy
	TenantID string `json:"tenant_id,omitempty" db:"tenant_id"`

	// Custom fields
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
}

// CreateCaseRequest represents a request to create a new case.
type CreateCaseRequest struct {
	Title          string            `json:"title" validate:"required,min=5,max=500"`
	Description    string            `json:"description"`
	Type           CaseType          `json:"type" validate:"required"`
	Severity       CaseSeverity      `json:"severity" validate:"required"`
	Priority       CasePriority      `json:"priority,omitempty"`
	Assignee       string            `json:"assignee,omitempty"`
	Team           string            `json:"team,omitempty"`
	AlertIDs       []string          `json:"alert_ids,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Tactics        []string          `json:"tactics,omitempty"`
	Techniques     []string          `json:"techniques,omitempty"`
	AffectedAssets []string          `json:"affected_assets,omitempty"`
	AffectedUsers  []string          `json:"affected_users,omitempty"`
	SLADeadline    *time.Time        `json:"sla_deadline,omitempty"`
	CustomFields   map[string]interface{} `json:"custom_fields,omitempty"`
}

// UpdateCaseRequest represents a request to update a case.
type UpdateCaseRequest struct {
	Title               *string           `json:"title,omitempty"`
	Description         *string           `json:"description,omitempty"`
	Severity            *CaseSeverity     `json:"severity,omitempty"`
	Priority            *CasePriority     `json:"priority,omitempty"`
	Status              *CaseStatus       `json:"status,omitempty"`
	Assignee            *string           `json:"assignee,omitempty"`
	Team                *string           `json:"team,omitempty"`
	Classification      *string           `json:"classification,omitempty"`
	ClassificationReason *string          `json:"classification_reason,omitempty"`
	Tags                []string          `json:"tags,omitempty"`
	Labels              map[string]string `json:"labels,omitempty"`
	Tactics             []string          `json:"tactics,omitempty"`
	Techniques          []string          `json:"techniques,omitempty"`
	Resolution          *string           `json:"resolution,omitempty"`
	ResolutionNotes     *string           `json:"resolution_notes,omitempty"`
	RootCause           *string           `json:"root_cause,omitempty"`
	LessonsLearned      *string           `json:"lessons_learned,omitempty"`
	CustomFields        map[string]interface{} `json:"custom_fields,omitempty"`
}

// CaseFilter defines filters for listing cases.
type CaseFilter struct {
	Status      []CaseStatus   `json:"status,omitempty"`
	Severity    []CaseSeverity `json:"severity,omitempty"`
	Priority    []CasePriority `json:"priority,omitempty"`
	Type        []CaseType     `json:"type,omitempty"`
	Assignee    string         `json:"assignee,omitempty"`
	Team        string         `json:"team,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Search      string         `json:"search,omitempty"`
	CreatedFrom *time.Time     `json:"created_from,omitempty"`
	CreatedTo   *time.Time     `json:"created_to,omitempty"`
	SLABreached *bool          `json:"sla_breached,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
	Limit       int            `json:"limit,omitempty"`
	Offset      int            `json:"offset,omitempty"`
	SortBy      string         `json:"sort_by,omitempty"`
	SortOrder   string         `json:"sort_order,omitempty"` // asc, desc
}

// CaseListResult contains paginated case results.
type CaseListResult struct {
	Cases   []*Case `json:"cases"`
	Total   int64   `json:"total"`
	Limit   int     `json:"limit"`
	Offset  int     `json:"offset"`
	HasMore bool    `json:"has_more"`
}

// CaseSummary provides case statistics.
type CaseSummary struct {
	TotalCases      int64 `json:"total_cases"`
	OpenCases       int64 `json:"open_cases"`
	CriticalCases   int64 `json:"critical_cases"`
	HighCases       int64 `json:"high_cases"`
	OverdueCases    int64 `json:"overdue_cases"`
	AvgResponseTime int64 `json:"avg_response_time_minutes"`
	AvgResolutionTime int64 `json:"avg_resolution_time_minutes"`
	ByStatus        map[CaseStatus]int64   `json:"by_status"`
	BySeverity      map[CaseSeverity]int64 `json:"by_severity"`
	ByAssignee      map[string]int64       `json:"by_assignee"`
}

// CaseHistory records case changes.
type CaseHistory struct {
	ID        string          `json:"id"`
	CaseID    string          `json:"case_id"`
	Action    string          `json:"action"` // created, updated, assigned, status_changed, commented, etc.
	Field     string          `json:"field,omitempty"`
	OldValue  json.RawMessage `json:"old_value,omitempty"`
	NewValue  json.RawMessage `json:"new_value,omitempty"`
	Actor     string          `json:"actor"`
	ActorName string          `json:"actor_name,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// RelatedCase represents a relationship between cases.
type RelatedCase struct {
	ID           string    `json:"id"`
	CaseID       string    `json:"case_id"`
	RelatedID    string    `json:"related_id"`
	RelationType string    `json:"relation_type"` // parent, child, duplicate, related
	CreatedAt    time.Time `json:"created_at"`
	CreatedBy    string    `json:"created_by"`
}

// CaseMergeRequest represents a request to merge cases.
type CaseMergeRequest struct {
	TargetCaseID string   `json:"target_case_id" validate:"required"`
	SourceCaseIDs []string `json:"source_case_ids" validate:"required,min=1"`
	MergeComments bool     `json:"merge_comments"`
	MergeEvidence bool     `json:"merge_evidence"`
	MergeTasks    bool     `json:"merge_tasks"`
	Comment       string   `json:"comment,omitempty"`
}
