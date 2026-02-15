// Package model provides data models for parser management.
package model

import (
	"time"
)

// Product represents a security product.
type Product struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	Name        string    `json:"name" db:"name"`
	Vendor      string    `json:"vendor" db:"vendor"`
	Version     string    `json:"version,omitempty" db:"version"`
	Description string    `json:"description,omitempty" db:"description"`
	Category    string    `json:"category,omitempty" db:"category"` // firewall, edr, ips, etc.

	// Log format information
	LogFormats  []string `json:"log_formats,omitempty"`  // syslog, json, cef, etc.
	SampleLogs  []string `json:"sample_logs,omitempty"`

	// Metadata
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Parser count
	ParserCount int `json:"parser_count" db:"parser_count"`

	// Audit
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy   string    `json:"created_by" db:"created_by"`
	UpdatedBy   string    `json:"updated_by,omitempty" db:"updated_by"`
}

// CreateProductRequest represents a request to create a product.
type CreateProductRequest struct {
	Name        string            `json:"name" validate:"required,min=1,max=255"`
	Vendor      string            `json:"vendor" validate:"required"`
	Version     string            `json:"version,omitempty"`
	Description string            `json:"description,omitempty"`
	Category    string            `json:"category,omitempty"`
	LogFormats  []string          `json:"log_formats,omitempty"`
	SampleLogs  []string          `json:"sample_logs,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// UpdateProductRequest represents a request to update a product.
type UpdateProductRequest struct {
	Name        *string           `json:"name,omitempty"`
	Vendor      *string           `json:"vendor,omitempty"`
	Version     *string           `json:"version,omitempty"`
	Description *string           `json:"description,omitempty"`
	Category    *string           `json:"category,omitempty"`
	LogFormats  []string          `json:"log_formats,omitempty"`
	SampleLogs  []string          `json:"sample_logs,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// ProductFilter defines filters for listing products.
type ProductFilter struct {
	Vendor     string   `json:"vendor,omitempty"`
	Category   string   `json:"category,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Search     string   `json:"search,omitempty"`
	TenantID   string   `json:"tenant_id,omitempty"`
	Limit      int      `json:"limit,omitempty"`
	Offset     int      `json:"offset,omitempty"`
	SortBy     string   `json:"sort_by,omitempty"`
	SortOrder  string   `json:"sort_order,omitempty"`
}

// ProductListResult contains paginated product results.
type ProductListResult struct {
	Products []*Product `json:"products"`
	Total    int64      `json:"total"`
	Limit    int        `json:"limit"`
	Offset   int        `json:"offset"`
	HasMore  bool       `json:"has_more"`
}
