// Package model provides version management models for policies.
package model

import (
	"encoding/json"
	"time"
)

// PolicyVersionInfo contains information about a policy version.
type PolicyVersionInfo struct {
	Version     int       `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	ChangeLog   string    `json:"change_log,omitempty"`
	IsActive    bool      `json:"is_active"`
	RuleCount   int       `json:"rule_count"`
}

// PolicyVersionHistory represents the version history of a policy.
type PolicyVersionHistory struct {
	PolicyID     string              `json:"policy_id"`
	PolicyName   string              `json:"policy_name"`
	CurrentVersion int               `json:"current_version"`
	Versions     []PolicyVersionInfo `json:"versions"`
}

// PolicyDiff represents the difference between two policy versions.
type PolicyDiff struct {
	OldVersion int                    `json:"old_version"`
	NewVersion int                    `json:"new_version"`
	Changes    []PolicyChange         `json:"changes"`
}

// PolicyChange represents a single change between versions.
type PolicyChange struct {
	Field     string          `json:"field"`
	Type      string          `json:"type"` // added, removed, modified
	OldValue  json.RawMessage `json:"old_value,omitempty"`
	NewValue  json.RawMessage `json:"new_value,omitempty"`
}

// PolicySnapshot represents a complete snapshot of a policy at a version.
type PolicySnapshot struct {
	ID          string          `json:"id" db:"id"`
	PolicyID    string          `json:"policy_id" db:"policy_id"`
	Version     int             `json:"version" db:"version"`
	Data        json.RawMessage `json:"data" db:"data"`
	ChangeLog   string          `json:"change_log,omitempty" db:"change_log"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	CreatedBy   string          `json:"created_by" db:"created_by"`
}

// ActivateRequest represents a request to activate a policy.
type ActivateRequest struct {
	Force   bool   `json:"force,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// DeactivateRequest represents a request to deactivate a policy.
type DeactivateRequest struct {
	Reason string `json:"reason,omitempty"`
}

// CloneRequest represents a request to clone a policy.
type CloneRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
}
