// Package model provides evidence model definitions.
package model

import (
	"encoding/json"
	"time"
)

// EvidenceType represents the type of evidence.
type EvidenceType string

const (
	EvidenceTypeFile       EvidenceType = "file"
	EvidenceTypeLog        EvidenceType = "log"
	EvidenceTypeScreenshot EvidenceType = "screenshot"
	EvidenceTypeNetwork    EvidenceType = "network"
	EvidenceTypeProcess    EvidenceType = "process"
	EvidenceTypeMemory     EvidenceType = "memory"
	EvidenceTypeArtifact   EvidenceType = "artifact"
	EvidenceTypeEmail      EvidenceType = "email"
	EvidenceTypeURL        EvidenceType = "url"
	EvidenceTypeIOC        EvidenceType = "ioc"
	EvidenceTypeNote       EvidenceType = "note"
	EvidenceTypeOther      EvidenceType = "other"
)

// EvidenceSource represents where the evidence came from.
type EvidenceSource string

const (
	SourceManual    EvidenceSource = "manual"
	SourcePlaybook  EvidenceSource = "playbook"
	SourceAlert     EvidenceSource = "alert"
	SourceSIEM      EvidenceSource = "siem"
	SourceEDR       EvidenceSource = "edr"
	SourceFirewall  EvidenceSource = "firewall"
	SourceThreatIntel EvidenceSource = "threat_intel"
	SourceExternal  EvidenceSource = "external"
)

// Evidence represents a piece of evidence attached to a case.
type Evidence struct {
	ID          string         `json:"id" db:"id"`
	CaseID      string         `json:"case_id" db:"case_id"`
	Type        EvidenceType   `json:"type" db:"type"`
	Source      EvidenceSource `json:"source" db:"source"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description,omitempty" db:"description"`

	// Content
	Content     []byte `json:"-" db:"content"` // Not included in JSON by default
	ContentType string `json:"content_type,omitempty" db:"content_type"` // MIME type
	ContentHash string `json:"content_hash,omitempty" db:"content_hash"` // SHA-256
	Size        int64  `json:"size" db:"size"`

	// Storage
	StorageType string `json:"storage_type,omitempty" db:"storage_type"` // inline, s3, file
	StoragePath string `json:"storage_path,omitempty" db:"storage_path"`

	// File metadata
	FileName    string `json:"file_name,omitempty" db:"file_name"`
	FileExt     string `json:"file_extension,omitempty" db:"file_ext"`

	// Structured data
	Data json.RawMessage `json:"data,omitempty" db:"data"` // JSON data for structured evidence

	// Tags and labels
	Tags   []string          `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	// Related entities
	RelatedAlertID  string `json:"related_alert_id,omitempty" db:"related_alert_id"`
	RelatedEntityID string `json:"related_entity_id,omitempty" db:"related_entity_id"`
	RelatedEntityType string `json:"related_entity_type,omitempty" db:"related_entity_type"`

	// Timeline
	OccurredAt *time.Time `json:"occurred_at,omitempty" db:"occurred_at"` // When the evidence was captured/occurred
	CollectedAt time.Time `json:"collected_at" db:"collected_at"`

	// Audit
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy string    `json:"created_by" db:"created_by"`

	// Multi-tenancy
	TenantID string `json:"tenant_id,omitempty" db:"tenant_id"`
}

// CreateEvidenceRequest represents a request to add evidence.
type CreateEvidenceRequest struct {
	Type        EvidenceType   `json:"type" validate:"required"`
	Source      EvidenceSource `json:"source" validate:"required"`
	Name        string         `json:"name" validate:"required,min=1,max=255"`
	Description string         `json:"description,omitempty"`
	Content     []byte         `json:"content,omitempty"` // Base64 encoded if file
	ContentType string         `json:"content_type,omitempty"`
	FileName    string         `json:"file_name,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	OccurredAt  *time.Time     `json:"occurred_at,omitempty"`
}

// UpdateEvidenceRequest represents a request to update evidence.
type UpdateEvidenceRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	OccurredAt  *time.Time        `json:"occurred_at,omitempty"`
}

// EvidenceFilter defines filters for listing evidence.
type EvidenceFilter struct {
	CaseID  string         `json:"case_id,omitempty"`
	Type    []EvidenceType `json:"type,omitempty"`
	Source  []EvidenceSource `json:"source,omitempty"`
	Tags    []string       `json:"tags,omitempty"`
	Search  string         `json:"search,omitempty"`
	Limit   int            `json:"limit,omitempty"`
	Offset  int            `json:"offset,omitempty"`
}

// EvidenceListResult contains paginated evidence results.
type EvidenceListResult struct {
	Evidence []*Evidence `json:"evidence"`
	Total    int64       `json:"total"`
	Limit    int         `json:"limit"`
	Offset   int         `json:"offset"`
	HasMore  bool        `json:"has_more"`
}

// IOCEvidence represents IOC evidence data.
type IOCEvidence struct {
	Type      string                 `json:"type"` // ip, domain, hash, url, email
	Value     string                 `json:"value"`
	Confidence int                   `json:"confidence,omitempty"` // 0-100
	Source    string                 `json:"source,omitempty"`
	FirstSeen *time.Time             `json:"first_seen,omitempty"`
	LastSeen  *time.Time             `json:"last_seen,omitempty"`
	ThreatType string                `json:"threat_type,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessEvidence represents process evidence data.
type ProcessEvidence struct {
	ProcessID   int    `json:"process_id"`
	ProcessName string `json:"process_name"`
	CommandLine string `json:"command_line,omitempty"`
	Path        string `json:"path,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	User        string `json:"user,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Hash        string `json:"hash,omitempty"`
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
}

// NetworkEvidence represents network connection evidence.
type NetworkEvidence struct {
	SourceIP       string     `json:"source_ip"`
	SourcePort     int        `json:"source_port,omitempty"`
	DestinationIP  string     `json:"destination_ip"`
	DestinationPort int       `json:"destination_port,omitempty"`
	Protocol       string     `json:"protocol"`
	Direction      string     `json:"direction"` // inbound, outbound
	BytesSent      int64      `json:"bytes_sent,omitempty"`
	BytesReceived  int64      `json:"bytes_received,omitempty"`
	Application    string     `json:"application,omitempty"`
	Action         string     `json:"action,omitempty"` // allow, deny, drop
	Timestamp      *time.Time `json:"timestamp,omitempty"`
}

// FileEvidence represents file evidence data.
type FileEvidence struct {
	FileName     string     `json:"file_name"`
	FilePath     string     `json:"file_path"`
	FileSize     int64      `json:"file_size"`
	MD5          string     `json:"md5,omitempty"`
	SHA1         string     `json:"sha1,omitempty"`
	SHA256       string     `json:"sha256,omitempty"`
	MimeType     string     `json:"mime_type,omitempty"`
	Owner        string     `json:"owner,omitempty"`
	Permissions  string     `json:"permissions,omitempty"`
	CreatedTime  *time.Time `json:"created_time,omitempty"`
	ModifiedTime *time.Time `json:"modified_time,omitempty"`
	AccessedTime *time.Time `json:"accessed_time,omitempty"`
	IsMalicious  bool       `json:"is_malicious,omitempty"`
	Signatures   []string   `json:"signatures,omitempty"`
}

// EmailEvidence represents email evidence data.
type EmailEvidence struct {
	MessageID   string     `json:"message_id"`
	Subject     string     `json:"subject"`
	From        string     `json:"from"`
	To          []string   `json:"to"`
	CC          []string   `json:"cc,omitempty"`
	ReplyTo     string     `json:"reply_to,omitempty"`
	Date        *time.Time `json:"date,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []string   `json:"attachments,omitempty"`
	URLs        []string   `json:"urls,omitempty"`
	IsPhishing  bool       `json:"is_phishing,omitempty"`
}
