// Package model provides data models for asset management.
package model

import (
	"encoding/json"
	"time"
)

// AssetType represents the type of asset.
type AssetType string

const (
	AssetTypeServer      AssetType = "server"
	AssetTypeWorkstation AssetType = "workstation"
	AssetTypeNetwork     AssetType = "network"
	AssetTypeDatabase    AssetType = "database"
	AssetTypeApplication AssetType = "application"
	AssetTypeCloud       AssetType = "cloud"
	AssetTypeContainer   AssetType = "container"
	AssetTypeIoT         AssetType = "iot"
	AssetTypeMobile      AssetType = "mobile"
	AssetTypeUnknown     AssetType = "unknown"
)

// AssetStatus represents the status of an asset.
type AssetStatus string

const (
	AssetStatusActive       AssetStatus = "active"
	AssetStatusInactive     AssetStatus = "inactive"
	AssetStatusMaintenance  AssetStatus = "maintenance"
	AssetStatusDecommission AssetStatus = "decommissioned"
	AssetStatusUnknown      AssetStatus = "unknown"
)

// Criticality represents the criticality level of an asset.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Asset represents a managed asset in the system.
type Asset struct {
	ID          string      `json:"id" db:"id"`
	TenantID    string      `json:"tenant_id" db:"tenant_id"`
	Name        string      `json:"name" db:"name"`
	Hostname    string      `json:"hostname,omitempty" db:"hostname"`
	Description string      `json:"description,omitempty" db:"description"`
	Type        AssetType   `json:"type" db:"type"`
	Status      AssetStatus `json:"status" db:"status"`
	Criticality Criticality `json:"criticality" db:"criticality"`

	// Network Information
	IPAddresses  []string `json:"ip_addresses,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`
	FQDN         string   `json:"fqdn,omitempty" db:"fqdn"`

	// System Information
	OS            string `json:"os,omitempty" db:"os"`
	OSVersion     string `json:"os_version,omitempty" db:"os_version"`
	Vendor        string `json:"vendor,omitempty" db:"vendor"`
	Model         string `json:"model,omitempty" db:"model"`
	SerialNumber  string `json:"serial_number,omitempty" db:"serial_number"`
	AssetTag      string `json:"asset_tag,omitempty" db:"asset_tag"`

	// Location
	Location     string `json:"location,omitempty" db:"location"`
	DataCenter   string `json:"data_center,omitempty" db:"data_center"`
	Rack         string `json:"rack,omitempty" db:"rack"`
	Zone         string `json:"zone,omitempty" db:"zone"`
	Environment  string `json:"environment,omitempty" db:"environment"` // production, staging, development

	// Cloud Information
	CloudProvider  string `json:"cloud_provider,omitempty" db:"cloud_provider"`
	CloudRegion    string `json:"cloud_region,omitempty" db:"cloud_region"`
	CloudAccountID string `json:"cloud_account_id,omitempty" db:"cloud_account_id"`
	CloudInstanceID string `json:"cloud_instance_id,omitempty" db:"cloud_instance_id"`

	// Ownership
	Owner       string   `json:"owner,omitempty" db:"owner"`
	OwnerEmail  string   `json:"owner_email,omitempty" db:"owner_email"`
	Team        string   `json:"team,omitempty" db:"team"`
	Department  string   `json:"department,omitempty" db:"department"`
	CostCenter  string   `json:"cost_center,omitempty" db:"cost_center"`

	// Group Membership
	GroupIDs []string `json:"group_ids,omitempty"`

	// Tags and Labels
	Tags   []string          `json:"tags,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	// Security
	RiskScore       int      `json:"risk_score" db:"risk_score"`
	Vulnerabilities int      `json:"vulnerabilities_count" db:"vulnerabilities_count"`
	ComplianceScore int      `json:"compliance_score" db:"compliance_score"`
	LastScanTime    *time.Time `json:"last_scan_time,omitempty" db:"last_scan_time"`

	// Agent Information
	AgentID        string     `json:"agent_id,omitempty" db:"agent_id"`
	AgentVersion   string     `json:"agent_version,omitempty" db:"agent_version"`
	AgentStatus    string     `json:"agent_status,omitempty" db:"agent_status"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty" db:"last_seen_at"`

	// Discovery
	DiscoverySource string     `json:"discovery_source,omitempty" db:"discovery_source"` // manual, agent, scanner, integration
	DiscoveredAt    *time.Time `json:"discovered_at,omitempty" db:"discovered_at"`
	FirstSeenAt     *time.Time `json:"first_seen_at,omitempty" db:"first_seen_at"`

	// Custom Fields
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Audit
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy string     `json:"created_by" db:"created_by"`
	UpdatedBy string     `json:"updated_by,omitempty" db:"updated_by"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
	Version   int        `json:"version" db:"version"`
}

// AssetIdentifier represents an identifier for an asset.
type AssetIdentifier struct {
	ID           string    `json:"id" db:"id"`
	AssetID      string    `json:"asset_id" db:"asset_id"`
	Type         string    `json:"type" db:"type"` // ip, mac, hostname, fqdn, serial, agent_id, cloud_instance_id
	Value        string    `json:"value" db:"value"`
	IsPrimary    bool      `json:"is_primary" db:"is_primary"`
	ValidFrom    time.Time `json:"valid_from" db:"valid_from"`
	ValidTo      *time.Time `json:"valid_to,omitempty" db:"valid_to"`
	LastSeenAt   time.Time `json:"last_seen_at" db:"last_seen_at"`
	Confidence   float64   `json:"confidence" db:"confidence"` // 0-1
	Source       string    `json:"source" db:"source"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// AssetGroup represents a group of assets.
type AssetGroup struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	Type        string    `json:"type" db:"type"` // static, dynamic

	// For dynamic groups
	Query       string `json:"query,omitempty" db:"query"`

	// For static groups
	AssetIDs    []string `json:"asset_ids,omitempty"`

	// Group hierarchy
	ParentID    string   `json:"parent_id,omitempty" db:"parent_id"`
	ChildIDs    []string `json:"child_ids,omitempty"`

	// Metadata
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`

	// Statistics
	AssetCount  int `json:"asset_count" db:"asset_count"`

	// Audit
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy   string     `json:"created_by" db:"created_by"`
	UpdatedBy   string     `json:"updated_by,omitempty" db:"updated_by"`
}

// AssetHistory records changes to an asset.
type AssetHistory struct {
	ID        string          `json:"id" db:"id"`
	AssetID   string          `json:"asset_id" db:"asset_id"`
	Action    string          `json:"action" db:"action"` // created, updated, deleted, status_changed
	Field     string          `json:"field,omitempty" db:"field"`
	OldValue  json.RawMessage `json:"old_value,omitempty" db:"old_value"`
	NewValue  json.RawMessage `json:"new_value,omitempty" db:"new_value"`
	Actor     string          `json:"actor" db:"actor"`
	ActorName string          `json:"actor_name,omitempty" db:"actor_name"`
	Source    string          `json:"source,omitempty" db:"source"` // api, agent, scanner
	IPAddress string          `json:"ip_address,omitempty" db:"ip_address"`
	Timestamp time.Time       `json:"timestamp" db:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CreateAssetRequest represents a request to create a new asset.
type CreateAssetRequest struct {
	Name          string            `json:"name" validate:"required,min=1,max=255"`
	Hostname      string            `json:"hostname,omitempty"`
	Description   string            `json:"description,omitempty"`
	Type          AssetType         `json:"type" validate:"required"`
	Status        AssetStatus       `json:"status,omitempty"`
	Criticality   Criticality       `json:"criticality,omitempty"`
	IPAddresses   []string          `json:"ip_addresses,omitempty"`
	MACAddresses  []string          `json:"mac_addresses,omitempty"`
	FQDN          string            `json:"fqdn,omitempty"`
	OS            string            `json:"os,omitempty"`
	OSVersion     string            `json:"os_version,omitempty"`
	Vendor        string            `json:"vendor,omitempty"`
	Model         string            `json:"model,omitempty"`
	SerialNumber  string            `json:"serial_number,omitempty"`
	AssetTag      string            `json:"asset_tag,omitempty"`
	Location      string            `json:"location,omitempty"`
	DataCenter    string            `json:"data_center,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	CloudProvider string            `json:"cloud_provider,omitempty"`
	CloudRegion   string            `json:"cloud_region,omitempty"`
	CloudAccountID string           `json:"cloud_account_id,omitempty"`
	CloudInstanceID string          `json:"cloud_instance_id,omitempty"`
	Owner         string            `json:"owner,omitempty"`
	OwnerEmail    string            `json:"owner_email,omitempty"`
	Team          string            `json:"team,omitempty"`
	Department    string            `json:"department,omitempty"`
	GroupIDs      []string          `json:"group_ids,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	AgentID       string            `json:"agent_id,omitempty"`
	CustomFields  map[string]interface{} `json:"custom_fields,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateAssetRequest represents a request to update an asset.
type UpdateAssetRequest struct {
	Name          *string           `json:"name,omitempty"`
	Hostname      *string           `json:"hostname,omitempty"`
	Description   *string           `json:"description,omitempty"`
	Type          *AssetType        `json:"type,omitempty"`
	Status        *AssetStatus      `json:"status,omitempty"`
	Criticality   *Criticality      `json:"criticality,omitempty"`
	IPAddresses   []string          `json:"ip_addresses,omitempty"`
	MACAddresses  []string          `json:"mac_addresses,omitempty"`
	FQDN          *string           `json:"fqdn,omitempty"`
	OS            *string           `json:"os,omitempty"`
	OSVersion     *string           `json:"os_version,omitempty"`
	Vendor        *string           `json:"vendor,omitempty"`
	Model         *string           `json:"model,omitempty"`
	Location      *string           `json:"location,omitempty"`
	Environment   *string           `json:"environment,omitempty"`
	Owner         *string           `json:"owner,omitempty"`
	OwnerEmail    *string           `json:"owner_email,omitempty"`
	Team          *string           `json:"team,omitempty"`
	GroupIDs      []string          `json:"group_ids,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	CustomFields  map[string]interface{} `json:"custom_fields,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AssetFilter defines filters for listing assets.
type AssetFilter struct {
	Types       []AssetType   `json:"types,omitempty"`
	Statuses    []AssetStatus `json:"statuses,omitempty"`
	Criticalities []Criticality `json:"criticalities,omitempty"`
	IPAddress   string        `json:"ip_address,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`
	OS          string        `json:"os,omitempty"`
	Location    string        `json:"location,omitempty"`
	Environment string        `json:"environment,omitempty"`
	Owner       string        `json:"owner,omitempty"`
	Team        string        `json:"team,omitempty"`
	GroupID     string        `json:"group_id,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	Search      string        `json:"search,omitempty"`
	TenantID    string        `json:"tenant_id,omitempty"`
	Limit       int           `json:"limit,omitempty"`
	Offset      int           `json:"offset,omitempty"`
	SortBy      string        `json:"sort_by,omitempty"`
	SortOrder   string        `json:"sort_order,omitempty"`
}

// AssetListResult contains paginated asset results.
type AssetListResult struct {
	Assets  []*Asset `json:"assets"`
	Total   int64    `json:"total"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
	HasMore bool     `json:"has_more"`
}

// CreateAssetGroupRequest represents a request to create an asset group.
type CreateAssetGroupRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=255"`
	Description string            `json:"description,omitempty"`
	Type        string            `json:"type" validate:"required,oneof=static dynamic"`
	Query       string            `json:"query,omitempty"`
	AssetIDs    []string          `json:"asset_ids,omitempty"`
	ParentID    string            `json:"parent_id,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// AddIdentifierRequest represents a request to add an identifier.
type AddIdentifierRequest struct {
	Type       string  `json:"type" validate:"required,oneof=ip mac hostname fqdn serial agent_id cloud_instance_id"`
	Value      string  `json:"value" validate:"required"`
	IsPrimary  bool    `json:"is_primary,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// LookupRequest represents a request to lookup an asset by identifier.
type LookupRequest struct {
	Type  string `json:"type" validate:"required"`
	Value string `json:"value" validate:"required"`
}

// UnknownIPRequest represents a request to register an unknown IP.
type UnknownIPRequest struct {
	IPAddress       string    `json:"ip_address" validate:"required,ip"`
	MACAddress      string    `json:"mac_address,omitempty"`
	Hostname        string    `json:"hostname,omitempty"`
	DiscoverySource string    `json:"discovery_source,omitempty"`
	FirstSeenAt     time.Time `json:"first_seen_at,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}
