// Package model provides data models for asset group management.
package model

import "time"

// UpdateAssetGroupRequest represents a request to update an asset group.
type UpdateAssetGroupRequest struct {
	Name        *string           `json:"name,omitempty"`
	Description *string           `json:"description,omitempty"`
	Query       *string           `json:"query,omitempty"`
	AssetIDs    []string          `json:"asset_ids,omitempty"`
	ParentID    *string           `json:"parent_id,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// AddGroupMembersRequest represents a request to add members to a group.
type AddGroupMembersRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1"`
}

// RemoveGroupMembersRequest represents a request to remove members from a group.
type RemoveGroupMembersRequest struct {
	AssetIDs []string `json:"asset_ids" validate:"required,min=1"`
}

// IdentifyAssetRequest represents a request to identify an asset.
type IdentifyAssetRequest struct {
	IP       string `json:"ip,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	FQDN     string `json:"fqdn,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
}

// IdentifyAssetResponse represents the response of asset identification.
type IdentifyAssetResponse struct {
	Found       bool     `json:"found"`
	Asset       *Asset   `json:"asset,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	MatchedBy   string   `json:"matched_by,omitempty"` // ip, hostname, mac, fqdn, agent_id
	Suggestions []*Asset `json:"suggestions,omitempty"`
}

// AssetSearchRequest represents an asset search request.
type AssetSearchRequest struct {
	Query       string   `json:"query" validate:"required,min=1"`
	Types       []string `json:"types,omitempty"`
	Statuses    []string `json:"statuses,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	Offset      int      `json:"offset,omitempty"`
	IncludeDeleted bool  `json:"include_deleted,omitempty"`
}

// AssetSearchResult represents search results.
type AssetSearchResult struct {
	Query    string   `json:"query"`
	Assets   []*Asset `json:"assets"`
	Total    int64    `json:"total"`
	Duration string   `json:"duration"`
}

// GroupMember represents a member of an asset group.
type GroupMember struct {
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	AssetType AssetType `json:"asset_type"`
	JoinedAt  time.Time `json:"joined_at"`
}

// GroupMembersResponse represents the members of a group.
type GroupMembersResponse struct {
	GroupID   string        `json:"group_id"`
	GroupName string        `json:"group_name"`
	Members   []GroupMember `json:"members"`
	Total     int           `json:"total"`
	Limit     int           `json:"limit"`
	Offset    int           `json:"offset"`
}
