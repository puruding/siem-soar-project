// Package connector provides common types for SIEM connector integrations.
package connector

import (
	"context"
	"encoding/json"
	"time"
)

// SIEMType represents the type of SIEM system.
type SIEMType string

// SIEM types
const (
	SIEMSplunk   SIEMType = "splunk"
	SIEMElastic  SIEMType = "elastic"
	SIEMSentinel SIEMType = "sentinel"
)

// QueryLanguage represents the query language used by a SIEM.
type QueryLanguage string

// Query languages
const (
	QueryLanguageSPL QueryLanguage = "spl"   // Splunk Processing Language
	QueryLanguageKQL QueryLanguage = "kql"   // Kusto Query Language (Sentinel)
	QueryLanguageEQL QueryLanguage = "eql"   // Event Query Language (Elastic)
	QueryLanguageDSL QueryLanguage = "dsl"   // Elasticsearch DSL
	QueryLanguageSQL QueryLanguage = "sql"   // Standard SQL
)

// SIEMConfig is the base configuration for SIEM connectors.
type SIEMConfig struct {
	Type        SIEMType          `json:"type"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Endpoint    string            `json:"endpoint"`
	Credentials CredentialConfig  `json:"credentials"`
	TLS         TLSConfig         `json:"tls,omitempty"`
	Retry       RetryConfig       `json:"retry,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// CredentialConfig holds authentication credentials.
type CredentialConfig struct {
	Type           string `json:"type"` // "basic", "token", "oauth", "certificate", "managed_identity"
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	Token          string `json:"token,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	ClientSecret   string `json:"client_secret,omitempty"`
	TenantID       string `json:"tenant_id,omitempty"`
	CertPath       string `json:"cert_path,omitempty"`
	KeyPath        string `json:"key_path,omitempty"`
	WorkspaceID    string `json:"workspace_id,omitempty"`    // For Sentinel
	SubscriptionID string `json:"subscription_id,omitempty"` // For Azure
	ResourceGroup  string `json:"resource_group,omitempty"`  // For Azure
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled            bool   `json:"enabled"`
	SkipVerify         bool   `json:"skip_verify,omitempty"`
	CACertPath         string `json:"ca_cert_path,omitempty"`
	ClientCertPath     string `json:"client_cert_path,omitempty"`
	ClientKeyPath      string `json:"client_key_path,omitempty"`
	MinVersion         string `json:"min_version,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
}

// RetryConfig holds retry configuration.
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries"`
	InitialInterval time.Duration `json:"initial_interval"`
	MaxInterval     time.Duration `json:"max_interval"`
	Multiplier      float64       `json:"multiplier"`
}

// DefaultRetryConfig returns default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		Multiplier:      2.0,
	}
}

// QueryRequest represents a unified query request.
type QueryRequest struct {
	ID          string                 `json:"id"`
	Query       string                 `json:"query"`
	Language    QueryLanguage          `json:"language"`
	TimeRange   TimeRange              `json:"time_range"`
	MaxResults  int                    `json:"max_results,omitempty"`
	Fields      []string               `json:"fields,omitempty"`
	SortBy      []SortField            `json:"sort_by,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Timeout     time.Duration          `json:"timeout,omitempty"`
}

// TimeRange represents a time range for queries.
type TimeRange struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Relative string    `json:"relative,omitempty"` // e.g., "-24h", "-7d"
}

// SortField represents a field to sort by.
type SortField struct {
	Field     string `json:"field"`
	Ascending bool   `json:"ascending"`
}

// QueryResult represents a unified query result.
type QueryResult struct {
	ID          string                   `json:"id"`
	Status      QueryStatus              `json:"status"`
	Query       string                   `json:"query"`
	Language    QueryLanguage            `json:"language"`
	Results     []map[string]interface{} `json:"results"`
	Metadata    QueryMetadata            `json:"metadata"`
	Error       string                   `json:"error,omitempty"`
	StartTime   time.Time                `json:"start_time"`
	EndTime     time.Time                `json:"end_time"`
}

// QueryStatus represents the status of a query.
type QueryStatus string

// Query statuses
const (
	QueryStatusPending   QueryStatus = "pending"
	QueryStatusRunning   QueryStatus = "running"
	QueryStatusCompleted QueryStatus = "completed"
	QueryStatusFailed    QueryStatus = "failed"
	QueryStatusCancelled QueryStatus = "cancelled"
)

// QueryMetadata holds metadata about query results.
type QueryMetadata struct {
	TotalResults    int64         `json:"total_results"`
	ReturnedResults int           `json:"returned_results"`
	ExecutionTime   time.Duration `json:"execution_time_ms"`
	SIEM            SIEMType      `json:"siem"`
	Warnings        []string      `json:"warnings,omitempty"`
}

// Event represents a normalized security event for ingestion.
type Event struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Source     string                 `json:"source"`
	SourceType string                 `json:"source_type"`
	Host       string                 `json:"host,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Fields     map[string]interface{} `json:"fields"`
	Raw        string                 `json:"raw,omitempty"`
	Tags       []string               `json:"tags,omitempty"`
}

// EventBatch represents a batch of events for bulk ingestion.
type EventBatch struct {
	Events    []Event `json:"events"`
	Source    string  `json:"source"`
	BatchID   string  `json:"batch_id"`
	Timestamp time.Time `json:"timestamp"`
}

// IngestResult represents the result of an ingestion operation.
type IngestResult struct {
	BatchID       string        `json:"batch_id"`
	TotalEvents   int           `json:"total_events"`
	SuccessCount  int           `json:"success_count"`
	FailedCount   int           `json:"failed_count"`
	Errors        []IngestError `json:"errors,omitempty"`
	ExecutionTime time.Duration `json:"execution_time_ms"`
}

// IngestError represents an error during ingestion.
type IngestError struct {
	EventID string `json:"event_id"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// Alert represents a security alert from a SIEM.
type Alert struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Severity    AlertSeverity          `json:"severity"`
	Status      AlertStatus            `json:"status"`
	Source      SIEMType               `json:"source"`
	RuleID      string                 `json:"rule_id,omitempty"`
	RuleName    string                 `json:"rule_name,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
	AssignedTo  string                 `json:"assigned_to,omitempty"`
	Entities    []AlertEntity          `json:"entities,omitempty"`
	Evidence    []AlertEvidence        `json:"evidence,omitempty"`
	Tactics     []string               `json:"tactics,omitempty"`
	Techniques  []string               `json:"techniques,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Custom      map[string]interface{} `json:"custom,omitempty"`
}

// AlertSeverity represents alert severity levels.
type AlertSeverity string

// Alert severities
const (
	AlertSeverityInformational AlertSeverity = "informational"
	AlertSeverityLow           AlertSeverity = "low"
	AlertSeverityMedium        AlertSeverity = "medium"
	AlertSeverityHigh          AlertSeverity = "high"
	AlertSeverityCritical      AlertSeverity = "critical"
)

// AlertStatus represents alert status.
type AlertStatus string

// Alert statuses
const (
	AlertStatusNew          AlertStatus = "new"
	AlertStatusInProgress   AlertStatus = "in_progress"
	AlertStatusResolved     AlertStatus = "resolved"
	AlertStatusClosed       AlertStatus = "closed"
	AlertStatusFalsePositive AlertStatus = "false_positive"
)

// AlertEntity represents an entity involved in an alert.
type AlertEntity struct {
	Type  string `json:"type"` // "ip", "hostname", "user", "file", "process", "url", "domain"
	Value string `json:"value"`
	Role  string `json:"role,omitempty"` // "source", "destination", "actor", "target"
}

// AlertEvidence represents evidence for an alert.
type AlertEvidence struct {
	Type        string    `json:"type"` // "event", "file", "process", "network"
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Data        json.RawMessage `json:"data,omitempty"`
}

// Incident represents a security incident (Sentinel-specific).
type Incident struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Severity        AlertSeverity          `json:"severity"`
	Status          IncidentStatus         `json:"status"`
	Classification  string                 `json:"classification,omitempty"`
	ClassificationReason string            `json:"classification_reason,omitempty"`
	Owner           *IncidentOwner         `json:"owner,omitempty"`
	Labels          []IncidentLabel        `json:"labels,omitempty"`
	AlertCount      int                    `json:"alert_count"`
	BookmarkCount   int                    `json:"bookmark_count"`
	CommentCount    int                    `json:"comment_count"`
	CreatedTime     time.Time              `json:"created_time"`
	LastModifiedTime time.Time             `json:"last_modified_time"`
	FirstActivityTime time.Time            `json:"first_activity_time,omitempty"`
	LastActivityTime time.Time             `json:"last_activity_time,omitempty"`
	Tactics         []string               `json:"tactics,omitempty"`
	RelatedAlertIDs []string               `json:"related_alert_ids,omitempty"`
	Custom          map[string]interface{} `json:"custom,omitempty"`
}

// IncidentStatus represents incident status.
type IncidentStatus string

// Incident statuses
const (
	IncidentStatusNew    IncidentStatus = "new"
	IncidentStatusActive IncidentStatus = "active"
	IncidentStatusClosed IncidentStatus = "closed"
)

// IncidentOwner represents the owner of an incident.
type IncidentOwner struct {
	AssignedTo          string `json:"assigned_to,omitempty"`
	Email               string `json:"email,omitempty"`
	ObjectID            string `json:"object_id,omitempty"`
	UserPrincipalName   string `json:"user_principal_name,omitempty"`
	OwnerType           string `json:"owner_type,omitempty"` // "user", "group", "unassigned"
}

// IncidentLabel represents a label on an incident.
type IncidentLabel struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // "user", "system"
}

// SIEMConnector is the interface for SIEM-specific connectors.
type SIEMConnector interface {
	Connector

	// SIEM returns the SIEM type.
	SIEM() SIEMType

	// QueryLanguages returns supported query languages.
	QueryLanguages() []QueryLanguage

	// Query executes a query and returns results.
	Query(ctx context.Context, req *QueryRequest) (*QueryResult, error)

	// AsyncQuery starts an asynchronous query.
	AsyncQuery(ctx context.Context, req *QueryRequest) (string, error)

	// GetQueryStatus gets the status of an async query.
	GetQueryStatus(ctx context.Context, queryID string) (*QueryResult, error)

	// CancelQuery cancels a running query.
	CancelQuery(ctx context.Context, queryID string) error
}

// EventIngester is an interface for event ingestion.
type EventIngester interface {
	// Ingest sends events to the SIEM.
	Ingest(ctx context.Context, events []Event) (*IngestResult, error)

	// IngestBatch sends a batch of events.
	IngestBatch(ctx context.Context, batch *EventBatch) (*IngestResult, error)
}

// AlertFetcher is an interface for fetching alerts.
type AlertFetcher interface {
	// GetAlerts retrieves alerts matching the criteria.
	GetAlerts(ctx context.Context, filter *AlertFilter) ([]Alert, error)

	// GetAlert retrieves a specific alert.
	GetAlert(ctx context.Context, alertID string) (*Alert, error)

	// UpdateAlert updates an alert's status or properties.
	UpdateAlert(ctx context.Context, alertID string, update *AlertUpdate) error
}

// AlertFilter represents filters for alert queries.
type AlertFilter struct {
	Severities []AlertSeverity `json:"severities,omitempty"`
	Statuses   []AlertStatus   `json:"statuses,omitempty"`
	TimeRange  TimeRange       `json:"time_range,omitempty"`
	RuleIDs    []string        `json:"rule_ids,omitempty"`
	Limit      int             `json:"limit,omitempty"`
	Offset     int             `json:"offset,omitempty"`
}

// AlertUpdate represents an update to an alert.
type AlertUpdate struct {
	Status     *AlertStatus `json:"status,omitempty"`
	AssignedTo *string      `json:"assigned_to,omitempty"`
	Tags       []string     `json:"tags,omitempty"`
	Comment    string       `json:"comment,omitempty"`
}

// IncidentManager is an interface for incident management (Sentinel-specific).
type IncidentManager interface {
	// GetIncidents retrieves incidents matching the criteria.
	GetIncidents(ctx context.Context, filter *IncidentFilter) ([]Incident, error)

	// GetIncident retrieves a specific incident.
	GetIncident(ctx context.Context, incidentID string) (*Incident, error)

	// UpdateIncident updates an incident.
	UpdateIncident(ctx context.Context, incidentID string, update *IncidentUpdate) error

	// AddIncidentComment adds a comment to an incident.
	AddIncidentComment(ctx context.Context, incidentID string, comment string) error

	// GetIncidentAlerts gets alerts related to an incident.
	GetIncidentAlerts(ctx context.Context, incidentID string) ([]Alert, error)
}

// IncidentFilter represents filters for incident queries.
type IncidentFilter struct {
	Severities []AlertSeverity  `json:"severities,omitempty"`
	Statuses   []IncidentStatus `json:"statuses,omitempty"`
	TimeRange  TimeRange        `json:"time_range,omitempty"`
	Limit      int              `json:"limit,omitempty"`
	Offset     int              `json:"offset,omitempty"`
}

// IncidentUpdate represents an update to an incident.
type IncidentUpdate struct {
	Status       *IncidentStatus `json:"status,omitempty"`
	Severity     *AlertSeverity  `json:"severity,omitempty"`
	Owner        *IncidentOwner  `json:"owner,omitempty"`
	Labels       []IncidentLabel `json:"labels,omitempty"`
	Classification string        `json:"classification,omitempty"`
	ClassificationReason string  `json:"classification_reason,omitempty"`
}


// ConnectorType represents the type of connector.
type ConnectorType string

// Connector types
const (
	ConnectorTypeSplunk   ConnectorType = "splunk"
	ConnectorTypeElastic  ConnectorType = "elastic"
	ConnectorTypeSentinel ConnectorType = "sentinel"
)

// ConnectorStatus represents the status of a connector.
type ConnectorStatus string

// Connector statuses
const (
	ConnectorStatusActive   ConnectorStatus = "active"
	ConnectorStatusInactive ConnectorStatus = "inactive"
	ConnectorStatusError    ConnectorStatus = "error"
)

// ConnectorConfig is the configuration for a connector.
type ConnectorConfig struct {
	ID          string            `json:"id"`
	Type        ConnectorType     `json:"type"`
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Endpoint    string            `json:"endpoint"`
	Credentials CredentialConfig  `json:"credentials"`
	TLS         TLSConfig         `json:"tls,omitempty"`
	Retry       RetryConfig       `json:"retry,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// ConnectorFactory creates connector instances.
type ConnectorFactory func(config ConnectorConfig) (Connector, error)

// ConnectorHealth represents the health status of a connector.
type ConnectorHealth struct {
	Status    ConnectorStatus `json:"status"`
	Message   string          `json:"message,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Status constants for backward compatibility
const (
	StatusActive   = ConnectorStatusActive
	StatusInactive = ConnectorStatusInactive
	StatusError    = ConnectorStatusError
)

