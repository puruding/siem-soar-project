// Package models provides data models for the query service.
package models

import (
	"time"
)

// QueryExecution represents a query execution record for history.
type QueryExecution struct {
	ID            string                 `json:"id"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id"`
	Query         string                 `json:"query"`
	Database      string                 `json:"database"`
	Status        string                 `json:"status"`
	RowCount      int64                  `json:"row_count"`
	TotalCount    int64                  `json:"total_count"`
	ExecutionMS   int64                  `json:"execution_ms"`
	BytesRead     int64                  `json:"bytes_read"`
	Error         string                 `json:"error,omitempty"`
	ExecutedAt    time.Time              `json:"executed_at"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
}

// SavedQuery represents a saved query.
type SavedQuery struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Query       string    `json:"query"`
	Database    string    `json:"database"`
	Tags        []string  `json:"tags,omitempty"`
	IsPublic    bool      `json:"is_public"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// QueryRequest represents an incoming query request.
type QueryRequest struct {
	Query      string                 `json:"query"`
	Database   string                 `json:"database,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
	Format     string                 `json:"format,omitempty"`
	Timeout    int                    `json:"timeout,omitempty"`
}

// QueryResponse represents a query response.
type QueryResponse struct {
	Success bool            `json:"success"`
	Data    *QueryData      `json:"data,omitempty"`
	Error   *ErrorResponse  `json:"error,omitempty"`
}

// QueryData holds query result data.
type QueryData struct {
	Columns         []ColumnInfo             `json:"columns"`
	Rows            [][]interface{}          `json:"rows"`
	Total           int64                    `json:"total"`
	ExecutionTimeMS int64                    `json:"execution_time_ms"`
	QueryID         string                   `json:"query_id,omitempty"`
	Warnings        []string                 `json:"warnings,omitempty"`
	Metadata        map[string]interface{}   `json:"metadata,omitempty"`
}

// ColumnInfo represents column metadata.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable,omitempty"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// SaveQueryRequest represents a request to save a query.
type SaveQueryRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Query       string   `json:"query"`
	Database    string   `json:"database,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	IsPublic    bool     `json:"is_public"`
}

// QueryHistoryFilter represents filters for query history.
type QueryHistoryFilter struct {
	UserID    string    `json:"user_id,omitempty"`
	Database  string    `json:"database,omitempty"`
	Status    string    `json:"status,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}

// SavedQueryFilter represents filters for saved queries.
type SavedQueryFilter struct {
	UserID      string   `json:"user_id,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	IsPublic    *bool    `json:"is_public,omitempty"`
	SearchQuery string   `json:"search_query,omitempty"`
	Limit       int      `json:"limit,omitempty"`
	Offset      int      `json:"offset,omitempty"`
}

// PaginatedResponse represents a paginated response.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int64       `json:"total"`
	Page       int         `json:"page"`
	PageSize   int         `json:"page_size"`
	TotalPages int         `json:"total_pages"`
}

// AsyncQueryResponse represents an async query submission response.
type AsyncQueryResponse struct {
	QueryID string `json:"query_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// QueryStatusResponse represents a query status response.
type QueryStatusResponse struct {
	QueryID     string  `json:"query_id"`
	Status      string  `json:"status"`
	Progress    int     `json:"progress"`
	RowsRead    int64   `json:"rows_read,omitempty"`
	BytesRead   int64   `json:"bytes_read,omitempty"`
	ElapsedMS   int64   `json:"elapsed_ms,omitempty"`
	Error       string  `json:"error,omitempty"`
}
