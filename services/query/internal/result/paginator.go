// Package result provides query result pagination capabilities.
package result

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// PaginationConfig holds pagination configuration.
type PaginationConfig struct {
	DefaultPageSize int           `json:"default_page_size"`
	MaxPageSize     int           `json:"max_page_size"`
	CursorTTL       time.Duration `json:"cursor_ttl"`
	MaxCursors      int           `json:"max_cursors"`
}

// DefaultPaginationConfig returns default pagination configuration.
func DefaultPaginationConfig() PaginationConfig {
	return PaginationConfig{
		DefaultPageSize: 100,
		MaxPageSize:     10000,
		CursorTTL:       30 * time.Minute,
		MaxCursors:      10000,
	}
}

// PaginationRequest represents a pagination request.
type PaginationRequest struct {
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"page_size,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Sort     string `json:"sort,omitempty"`
	Order    string `json:"order,omitempty"` // asc, desc
}

// PagedResult represents a paginated result.
type PagedResult struct {
	Data       []map[string]interface{} `json:"data"`
	Pagination PaginationInfo           `json:"pagination"`
}

// PaginationInfo holds pagination metadata.
type PaginationInfo struct {
	Page         int    `json:"page"`
	PageSize     int    `json:"page_size"`
	TotalPages   int    `json:"total_pages"`
	TotalItems   int64  `json:"total_items"`
	HasNext      bool   `json:"has_next"`
	HasPrevious  bool   `json:"has_previous"`
	NextCursor   string `json:"next_cursor,omitempty"`
	PrevCursor   string `json:"prev_cursor,omitempty"`
	FirstCursor  string `json:"first_cursor,omitempty"`
	LastCursor   string `json:"last_cursor,omitempty"`
}

// Cursor represents a pagination cursor.
type Cursor struct {
	ID         string                 `json:"id"`
	QueryHash  string                 `json:"query_hash"`
	Position   int                    `json:"position"`
	Sort       string                 `json:"sort"`
	Order      string                 `json:"order"`
	LastValues map[string]interface{} `json:"last_values,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
}

// Paginator provides pagination capabilities.
type Paginator struct {
	config  PaginationConfig
	cursors sync.Map
}

// NewPaginator creates a new paginator.
func NewPaginator(config PaginationConfig) *Paginator {
	p := &Paginator{config: config}

	// Start cursor cleanup
	go p.cleanupLoop()

	return p
}

// Paginate paginates a result set.
func (p *Paginator) Paginate(data []map[string]interface{}, totalCount int64, req PaginationRequest) *PagedResult {
	// Validate and normalize request
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = p.config.DefaultPageSize
	}
	if pageSize > p.config.MaxPageSize {
		pageSize = p.config.MaxPageSize
	}

	page := req.Page
	if page < 1 {
		page = 1
	}

	// Calculate pagination
	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))
	if totalPages < 1 {
		totalPages = 1
	}

	if page > totalPages {
		page = totalPages
	}

	// Get page data (assuming data is already sliced or we need to slice it)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > len(data) {
		start = len(data)
	}
	if end > len(data) {
		end = len(data)
	}

	pageData := data[start:end]

	// Build pagination info
	pagination := PaginationInfo{
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
		TotalItems:  totalCount,
		HasNext:     page < totalPages,
		HasPrevious: page > 1,
	}

	// Generate cursors if there are results
	if len(pageData) > 0 {
		queryHash := p.generateQueryHash(req.Sort + req.Order)

		// Next cursor
		if pagination.HasNext {
			nextCursor := p.createCursor(queryHash, end, req.Sort, req.Order, pageData[len(pageData)-1])
			pagination.NextCursor = p.encodeCursor(nextCursor)
		}

		// Previous cursor
		if pagination.HasPrevious {
			prevCursor := p.createCursor(queryHash, start-pageSize, req.Sort, req.Order, pageData[0])
			pagination.PrevCursor = p.encodeCursor(prevCursor)
		}
	}

	return &PagedResult{
		Data:       pageData,
		Pagination: pagination,
	}
}

// PaginateWithCursor paginates using cursor-based pagination.
func (p *Paginator) PaginateWithCursor(data []map[string]interface{}, totalCount int64, cursorStr string, pageSize int) (*PagedResult, error) {
	// Validate page size
	if pageSize <= 0 {
		pageSize = p.config.DefaultPageSize
	}
	if pageSize > p.config.MaxPageSize {
		pageSize = p.config.MaxPageSize
	}

	var start int
	var cursor *Cursor

	if cursorStr != "" {
		var err error
		cursor, err = p.decodeCursor(cursorStr)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}

		// Validate cursor
		if time.Now().After(cursor.ExpiresAt) {
			return nil, fmt.Errorf("cursor has expired")
		}

		start = cursor.Position
	}

	// Get page data
	end := start + pageSize
	if start > len(data) {
		start = len(data)
	}
	if end > len(data) {
		end = len(data)
	}

	pageData := data[start:end]

	// Calculate pagination
	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))
	currentPage := (start / pageSize) + 1

	pagination := PaginationInfo{
		Page:        currentPage,
		PageSize:    pageSize,
		TotalPages:  totalPages,
		TotalItems:  totalCount,
		HasNext:     end < len(data),
		HasPrevious: start > 0,
	}

	// Generate cursors
	queryHash := ""
	sort := ""
	order := ""
	if cursor != nil {
		queryHash = cursor.QueryHash
		sort = cursor.Sort
		order = cursor.Order
	} else {
		queryHash = p.generateQueryHash("")
	}

	if len(pageData) > 0 {
		if pagination.HasNext {
			nextCursor := p.createCursor(queryHash, end, sort, order, pageData[len(pageData)-1])
			pagination.NextCursor = p.encodeCursor(nextCursor)
		}

		if pagination.HasPrevious {
			prevStart := start - pageSize
			if prevStart < 0 {
				prevStart = 0
			}
			prevCursor := p.createCursor(queryHash, prevStart, sort, order, pageData[0])
			pagination.PrevCursor = p.encodeCursor(prevCursor)
		}
	}

	return &PagedResult{
		Data:       pageData,
		Pagination: pagination,
	}, nil
}

// KeysetPaginate performs keyset (seek) pagination.
func (p *Paginator) KeysetPaginate(data []map[string]interface{}, totalCount int64, keyColumn string, lastKey interface{}, pageSize int, ascending bool) *PagedResult {
	// Validate page size
	if pageSize <= 0 {
		pageSize = p.config.DefaultPageSize
	}
	if pageSize > p.config.MaxPageSize {
		pageSize = p.config.MaxPageSize
	}

	// Find starting position based on last key
	start := 0
	if lastKey != nil {
		for i, row := range data {
			if val, ok := row[keyColumn]; ok {
				if p.compareValues(val, lastKey, ascending) {
					start = i + 1
					break
				}
			}
		}
	}

	// Get page data
	end := start + pageSize
	if start > len(data) {
		start = len(data)
	}
	if end > len(data) {
		end = len(data)
	}

	pageData := data[start:end]

	// Calculate pagination
	totalPages := int((totalCount + int64(pageSize) - 1) / int64(pageSize))
	currentPage := (start / pageSize) + 1

	pagination := PaginationInfo{
		Page:        currentPage,
		PageSize:    pageSize,
		TotalPages:  totalPages,
		TotalItems:  totalCount,
		HasNext:     end < len(data),
		HasPrevious: start > 0,
	}

	// Generate cursors based on key values
	if len(pageData) > 0 {
		order := "asc"
		if !ascending {
			order = "desc"
		}

		if pagination.HasNext {
			lastRow := pageData[len(pageData)-1]
			nextCursor := &Cursor{
				ID:         p.generateCursorID(),
				Position:   end,
				Sort:       keyColumn,
				Order:      order,
				LastValues: map[string]interface{}{keyColumn: lastRow[keyColumn]},
				CreatedAt:  time.Now(),
				ExpiresAt:  time.Now().Add(p.config.CursorTTL),
			}
			pagination.NextCursor = p.encodeCursor(nextCursor)
		}

		if pagination.HasPrevious {
			firstRow := pageData[0]
			prevCursor := &Cursor{
				ID:         p.generateCursorID(),
				Position:   start - pageSize,
				Sort:       keyColumn,
				Order:      order,
				LastValues: map[string]interface{}{keyColumn: firstRow[keyColumn]},
				CreatedAt:  time.Now(),
				ExpiresAt:  time.Now().Add(p.config.CursorTTL),
			}
			pagination.PrevCursor = p.encodeCursor(prevCursor)
		}
	}

	return &PagedResult{
		Data:       pageData,
		Pagination: pagination,
	}
}

// createCursor creates a new cursor.
func (p *Paginator) createCursor(queryHash string, position int, sort, order string, lastRow map[string]interface{}) *Cursor {
	cursor := &Cursor{
		ID:        p.generateCursorID(),
		QueryHash: queryHash,
		Position:  position,
		Sort:      sort,
		Order:     order,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(p.config.CursorTTL),
	}

	// Store last values for keyset pagination
	if sort != "" && lastRow != nil {
		cursor.LastValues = map[string]interface{}{
			sort: lastRow[sort],
		}
	}

	// Store cursor
	p.cursors.Store(cursor.ID, cursor)

	return cursor
}

// encodeCursor encodes a cursor to a string.
func (p *Paginator) encodeCursor(cursor *Cursor) string {
	data, err := json.Marshal(cursor)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(data)
}

// decodeCursor decodes a cursor from a string.
func (p *Paginator) decodeCursor(encoded string) (*Cursor, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor encoding: %w", err)
	}

	var cursor Cursor
	if err := json.Unmarshal(data, &cursor); err != nil {
		return nil, fmt.Errorf("invalid cursor format: %w", err)
	}

	return &cursor, nil
}

// generateCursorID generates a unique cursor ID.
func (p *Paginator) generateCursorID() string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond())))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:16]
}

// generateQueryHash generates a hash for the query context.
func (p *Paginator) generateQueryHash(context string) string {
	h := sha256.New()
	h.Write([]byte(context))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:8]
}

// compareValues compares two values for ordering.
func (p *Paginator) compareValues(a, b interface{}, ascending bool) bool {
	// Handle different types
	switch va := a.(type) {
	case int:
		if vb, ok := b.(int); ok {
			if ascending {
				return va >= vb
			}
			return va <= vb
		}
	case int64:
		if vb, ok := b.(int64); ok {
			if ascending {
				return va >= vb
			}
			return va <= vb
		}
	case float64:
		if vb, ok := b.(float64); ok {
			if ascending {
				return va >= vb
			}
			return va <= vb
		}
	case string:
		if vb, ok := b.(string); ok {
			if ascending {
				return va >= vb
			}
			return va <= vb
		}
	case time.Time:
		if vb, ok := b.(time.Time); ok {
			if ascending {
				return !va.Before(vb)
			}
			return !va.After(vb)
		}
	}

	return false
}

// cleanupLoop periodically cleans up expired cursors.
func (p *Paginator) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		p.cursors.Range(func(key, value interface{}) bool {
			cursor := value.(*Cursor)
			if now.After(cursor.ExpiresAt) {
				p.cursors.Delete(key)
			}
			return true
		})
	}
}

// InfiniteScrollResult represents an infinite scroll result.
type InfiniteScrollResult struct {
	Data         []map[string]interface{} `json:"data"`
	HasMore      bool                     `json:"has_more"`
	NextCursor   string                   `json:"next_cursor,omitempty"`
	TotalItems   int64                    `json:"total_items"`
	ItemsLoaded  int                      `json:"items_loaded"`
}

// InfiniteScroll provides infinite scroll pagination.
func (p *Paginator) InfiniteScroll(data []map[string]interface{}, totalCount int64, cursorStr string, batchSize int) (*InfiniteScrollResult, error) {
	if batchSize <= 0 {
		batchSize = p.config.DefaultPageSize
	}
	if batchSize > p.config.MaxPageSize {
		batchSize = p.config.MaxPageSize
	}

	var start int
	if cursorStr != "" {
		cursor, err := p.decodeCursor(cursorStr)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		if time.Now().After(cursor.ExpiresAt) {
			return nil, fmt.Errorf("cursor has expired")
		}
		start = cursor.Position
	}

	end := start + batchSize
	if start > len(data) {
		start = len(data)
	}
	if end > len(data) {
		end = len(data)
	}

	pageData := data[start:end]
	hasMore := end < len(data)

	result := &InfiniteScrollResult{
		Data:        pageData,
		HasMore:     hasMore,
		TotalItems:  totalCount,
		ItemsLoaded: end,
	}

	if hasMore && len(pageData) > 0 {
		cursor := p.createCursor("", end, "", "", nil)
		result.NextCursor = p.encodeCursor(cursor)
	}

	return result, nil
}

// WindowedResult represents a windowed result for virtual scrolling.
type WindowedResult struct {
	Data        []map[string]interface{} `json:"data"`
	StartIndex  int                      `json:"start_index"`
	EndIndex    int                      `json:"end_index"`
	TotalItems  int64                    `json:"total_items"`
	WindowSize  int                      `json:"window_size"`
}

// WindowedPaginate provides windowed pagination for virtual scrolling.
func (p *Paginator) WindowedPaginate(data []map[string]interface{}, totalCount int64, startIndex, windowSize int) *WindowedResult {
	if windowSize <= 0 {
		windowSize = p.config.DefaultPageSize
	}
	if windowSize > p.config.MaxPageSize {
		windowSize = p.config.MaxPageSize
	}

	if startIndex < 0 {
		startIndex = 0
	}
	if startIndex > len(data) {
		startIndex = len(data)
	}

	endIndex := startIndex + windowSize
	if endIndex > len(data) {
		endIndex = len(data)
	}

	return &WindowedResult{
		Data:       data[startIndex:endIndex],
		StartIndex: startIndex,
		EndIndex:   endIndex,
		TotalItems: totalCount,
		WindowSize: windowSize,
	}
}
