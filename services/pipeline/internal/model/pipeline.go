// Package model defines domain models for the pipeline service.
package model

import (
	"time"
)

// PipelineStage represents a stage in the pipeline.
type PipelineStage string

const (
	StageEventReceive   PipelineStage = "event_receive"
	StageClassification PipelineStage = "classification"
	StagePlaybookSelect PipelineStage = "playbook_select"
	StageFlowExecution  PipelineStage = "flow_execution"
)

// String returns the string representation of the stage.
func (s PipelineStage) String() string {
	return string(s)
}

// IsValid checks if the stage is a valid pipeline stage.
func (s PipelineStage) IsValid() bool {
	switch s {
	case StageEventReceive, StageClassification, StagePlaybookSelect, StageFlowExecution:
		return true
	}
	return false
}

// PipelineEvent represents an event flowing through the pipeline.
type PipelineEvent struct {
	ID             string           `json:"id"`
	TenantID       string           `json:"tenant_id"`
	RawLog         string           `json:"raw_log"`
	Source         string           `json:"source"`
	Severity       string           `json:"severity"`
	Stage          PipelineStage    `json:"stage"`
	Classification *Classification  `json:"classification,omitempty"`
	PlaybookMatch  *PlaybookMatch   `json:"playbook_match,omitempty"`
	Execution      *ExecutionStatus `json:"execution,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at,omitempty"`
}

// Classification represents the AI/Rule classification result.
type Classification struct {
	Label            string   `json:"label"`
	Confidence       float32  `json:"confidence"`
	Method           string   `json:"method"` // SIGMA, TI_IOC, HYBRID
	MatchedRules     []string `json:"matched_rules"`
	MatchedIOCs      []string `json:"matched_iocs"`
	MITRETactics     []string `json:"mitre_tactics"`
	MITRETechniques  []string `json:"mitre_techniques"`
	ProcessingTimeMs int      `json:"processing_time_ms"`
}

// ClassificationMethod constants.
const (
	MethodSIGMA  = "SIGMA"
	MethodTIIOC  = "TI_IOC"
	MethodHYBRID = "HYBRID"
)

// PlaybookMatch represents the matched playbook info.
type PlaybookMatch struct {
	PlaybookID   string   `json:"playbook_id"`
	PlaybookName string   `json:"playbook_name"`
	MatchScore   float32  `json:"match_score"`
	TriggerTags  []string `json:"trigger_tags"`
	StepCount    int      `json:"step_count"`
}

// ExecutionStatus represents the playbook execution status.
type ExecutionStatus struct {
	ExecutionID  string        `json:"execution_id"`
	Status       string        `json:"status"` // PENDING, RUNNING, WAITING_APPROVAL, COMPLETED, FAILED
	CurrentStep  int           `json:"current_step"`
	TotalSteps   int           `json:"total_steps"`
	ApprovalInfo *ApprovalInfo `json:"approval_info,omitempty"`
	StartedAt    time.Time     `json:"started_at,omitempty"`
	CompletedAt  time.Time     `json:"completed_at,omitempty"`
}

// ExecutionStatus constants.
const (
	StatusPending         = "PENDING"
	StatusRunning         = "RUNNING"
	StatusWaitingApproval = "WAITING_APPROVAL"
	StatusCompleted       = "COMPLETED"
	StatusFailed          = "FAILED"
)

// ApprovalInfo represents approval gate information.
type ApprovalInfo struct {
	ApprovalID   string    `json:"approval_id"`
	StepName     string    `json:"step_name"`
	RequiredRole string    `json:"required_role"`
	Approver     string    `json:"approver,omitempty"`
	Status       string    `json:"status"` // PENDING, APPROVED, REJECTED
	RequestedAt  time.Time `json:"requested_at"`
	ResolvedAt   time.Time `json:"resolved_at,omitempty"`
}

// ApprovalStatus constants.
const (
	ApprovalPending  = "PENDING"
	ApprovalApproved = "APPROVED"
	ApprovalRejected = "REJECTED"
)

// PipelineStats represents pipeline statistics.
type PipelineStats struct {
	TotalEvents      int64   `json:"total_events"`
	ProcessedEvents  int64   `json:"processed_events"`
	AutoClassified   int64   `json:"auto_classified"`
	ManualClassified int64   `json:"manual_classified"`
	AutomationRate   float32 `json:"automation_rate"`
	AvgProcessingMs  float32 `json:"avg_processing_ms"`
	TimeRange        struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"time_range"`
	ByStage    map[string]StageStat `json:"by_stage,omitempty"`
	BySeverity map[string]int64     `json:"by_severity,omitempty"`
}

// StageStat represents statistics for a single pipeline stage.
type StageStat struct {
	Entered   int64   `json:"entered"`
	Completed int64   `json:"completed"`
	Failed    int64   `json:"failed"`
	AvgTimeMs float32 `json:"avg_time_ms"`
}

// PipelineStatus represents the overall pipeline health status.
type PipelineStatus struct {
	Status       string        `json:"status"` // healthy, degraded, error
	IsProcessing bool          `json:"is_processing"`
	LastEventAt  time.Time     `json:"last_event_at"`
	Stages       []StageStatus `json:"stages"`
}

// StageStatus represents the status of a single pipeline stage.
type StageStatus struct {
	Name             string `json:"name"`
	Status           string `json:"status"` // active, idle, error
	CurrentCount     int    `json:"current_count"`
	ProcessedLast5Min int    `json:"processed_5min"`
}

// StageDetail represents detailed information about a pipeline stage.
type StageDetail struct {
	Name         string         `json:"name"`
	DisplayName  string         `json:"display_name"`
	Description  string         `json:"description"`
	Status       string         `json:"status"`
	RecentEvents []EventSummary `json:"recent_events"`
	Stats        StageStat      `json:"stats"`
}

// EventSummary represents a summary of a pipeline event.
type EventSummary struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Severity  string    `json:"severity"`
	Label     string    `json:"label,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// StageDisplayInfo provides display metadata for pipeline stages.
var StageDisplayInfo = map[PipelineStage]struct {
	DisplayName string
	Description string
}{
	StageEventReceive:   {DisplayName: "Event Receive", Description: "Initial event ingestion and validation"},
	StageClassification: {DisplayName: "Classification", Description: "AI/Rule-based threat classification"},
	StagePlaybookSelect: {DisplayName: "Playbook Select", Description: "Automated playbook matching"},
	StageFlowExecution:  {DisplayName: "Flow Execution", Description: "SOAR workflow execution"},
}

// AuditLog represents a pipeline audit log entry.
type AuditLog struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	EventType      string    `json:"event_type"`
	ActorType      string    `json:"actor_type"` // AI, SYSTEM, SOAR, USER
	ActorID        string    `json:"actor_id"`
	Message        string    `json:"message"`
	Details        string    `json:"details"`
	RelatedEventID string    `json:"related_event_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// ActorType constants.
const (
	ActorAI     = "AI"
	ActorSystem = "SYSTEM"
	ActorSOAR   = "SOAR"
	ActorUser   = "USER"
)

// PipelineEventFilter represents filters for querying pipeline events.
type PipelineEventFilter struct {
	TenantID  string        `json:"tenant_id,omitempty"`
	Source    string        `json:"source,omitempty"`
	Severity  string        `json:"severity,omitempty"`
	Stage     PipelineStage `json:"stage,omitempty"`
	StartTime time.Time     `json:"start_time,omitempty"`
	EndTime   time.Time     `json:"end_time,omitempty"`
	Limit     int           `json:"limit,omitempty"`
	Offset    int           `json:"offset,omitempty"`
}

// DefaultFilter returns default filter values.
func DefaultFilter() PipelineEventFilter {
	return PipelineEventFilter{
		Limit:  100,
		Offset: 0,
	}
}
