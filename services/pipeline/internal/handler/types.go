// Package handler provides HTTP handlers for the pipeline service.
package handler

// Pagination represents pagination information for list responses.
type Pagination struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	PageSize   int   `json:"page_size,omitempty"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}
