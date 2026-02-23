// Package storage provides storage for query history and saved queries.
package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/services/query/internal/models"
)

// Storage interface for query data persistence.
type Storage interface {
	// Query history
	SaveExecution(ctx context.Context, exec *models.QueryExecution) error
	GetExecution(ctx context.Context, tenantID, executionID string) (*models.QueryExecution, error)
	ListExecutions(ctx context.Context, tenantID string, filter models.QueryHistoryFilter) ([]*models.QueryExecution, int64, error)
	DeleteExecution(ctx context.Context, tenantID, executionID string) error

	// Saved queries
	SaveQuery(ctx context.Context, query *models.SavedQuery) error
	GetSavedQuery(ctx context.Context, tenantID, queryID string) (*models.SavedQuery, error)
	ListSavedQueries(ctx context.Context, tenantID string, filter models.SavedQueryFilter) ([]*models.SavedQuery, int64, error)
	UpdateSavedQuery(ctx context.Context, query *models.SavedQuery) error
	DeleteSavedQuery(ctx context.Context, tenantID, queryID string) error
}

// InMemoryStorage provides an in-memory implementation of Storage.
// For production, use PostgreSQL or ClickHouse.
type InMemoryStorage struct {
	executions   map[string]*models.QueryExecution // key: tenantID:executionID
	savedQueries map[string]*models.SavedQuery     // key: tenantID:queryID
	mu           sync.RWMutex
}

// NewInMemoryStorage creates a new in-memory storage.
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		executions:   make(map[string]*models.QueryExecution),
		savedQueries: make(map[string]*models.SavedQuery),
	}
}

// SaveExecution saves a query execution record.
func (s *InMemoryStorage) SaveExecution(ctx context.Context, exec *models.QueryExecution) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exec.ID == "" {
		exec.ID = uuid.New().String()
	}
	if exec.ExecutedAt.IsZero() {
		exec.ExecutedAt = time.Now().UTC()
	}

	key := fmt.Sprintf("%s:%s", exec.TenantID, exec.ID)
	s.executions[key] = exec
	return nil
}

// GetExecution retrieves a query execution by ID.
func (s *InMemoryStorage) GetExecution(ctx context.Context, tenantID, executionID string) (*models.QueryExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", tenantID, executionID)
	exec, ok := s.executions[key]
	if !ok {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}
	return exec, nil
}

// ListExecutions lists query executions with filters.
func (s *InMemoryStorage) ListExecutions(ctx context.Context, tenantID string, filter models.QueryHistoryFilter) ([]*models.QueryExecution, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*models.QueryExecution

	for key, exec := range s.executions {
		// Check tenant
		if !hasPrefix(key, tenantID+":") {
			continue
		}

		// Apply filters
		if filter.UserID != "" && exec.UserID != filter.UserID {
			continue
		}
		if filter.Database != "" && exec.Database != filter.Database {
			continue
		}
		if filter.Status != "" && exec.Status != filter.Status {
			continue
		}
		if !filter.StartTime.IsZero() && exec.ExecutedAt.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && exec.ExecutedAt.After(filter.EndTime) {
			continue
		}

		filtered = append(filtered, exec)
	}

	// Sort by executed_at desc
	sortExecutions(filtered)

	total := int64(len(filtered))

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	if offset >= len(filtered) {
		return []*models.QueryExecution{}, total, nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
}

// DeleteExecution deletes a query execution.
func (s *InMemoryStorage) DeleteExecution(ctx context.Context, tenantID, executionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", tenantID, executionID)
	delete(s.executions, key)
	return nil
}

// SaveQuery saves a query.
func (s *InMemoryStorage) SaveQuery(ctx context.Context, query *models.SavedQuery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if query.ID == "" {
		query.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	if query.CreatedAt.IsZero() {
		query.CreatedAt = now
	}
	query.UpdatedAt = now

	key := fmt.Sprintf("%s:%s", query.TenantID, query.ID)
	s.savedQueries[key] = query
	return nil
}

// GetSavedQuery retrieves a saved query by ID.
func (s *InMemoryStorage) GetSavedQuery(ctx context.Context, tenantID, queryID string) (*models.SavedQuery, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", tenantID, queryID)
	query, ok := s.savedQueries[key]
	if !ok {
		return nil, fmt.Errorf("saved query not found: %s", queryID)
	}
	return query, nil
}

// ListSavedQueries lists saved queries with filters.
func (s *InMemoryStorage) ListSavedQueries(ctx context.Context, tenantID string, filter models.SavedQueryFilter) ([]*models.SavedQuery, int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*models.SavedQuery

	for key, query := range s.savedQueries {
		// Check tenant
		if !hasPrefix(key, tenantID+":") {
			continue
		}

		// Apply filters
		if filter.UserID != "" && query.UserID != filter.UserID && !query.IsPublic {
			continue
		}
		if filter.IsPublic != nil && query.IsPublic != *filter.IsPublic {
			continue
		}
		if len(filter.Tags) > 0 && !hasAnyTag(query.Tags, filter.Tags) {
			continue
		}
		if filter.SearchQuery != "" {
			if !containsIgnoreCase(query.Name, filter.SearchQuery) &&
				!containsIgnoreCase(query.Description, filter.SearchQuery) &&
				!containsIgnoreCase(query.Query, filter.SearchQuery) {
				continue
			}
		}

		filtered = append(filtered, query)
	}

	// Sort by updated_at desc
	sortSavedQueries(filtered)

	total := int64(len(filtered))

	// Apply pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	if offset >= len(filtered) {
		return []*models.SavedQuery{}, total, nil
	}

	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
}

// UpdateSavedQuery updates a saved query.
func (s *InMemoryStorage) UpdateSavedQuery(ctx context.Context, query *models.SavedQuery) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", query.TenantID, query.ID)
	existing, ok := s.savedQueries[key]
	if !ok {
		return fmt.Errorf("saved query not found: %s", query.ID)
	}

	query.CreatedAt = existing.CreatedAt
	query.UpdatedAt = time.Now().UTC()
	s.savedQueries[key] = query
	return nil
}

// DeleteSavedQuery deletes a saved query.
func (s *InMemoryStorage) DeleteSavedQuery(ctx context.Context, tenantID, queryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s", tenantID, queryID)
	delete(s.savedQueries, key)
	return nil
}

// Helper functions

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		findIgnoreCase(s, substr) >= 0)
}

func findIgnoreCase(s, substr string) int {
	sLower := toLower(s)
	subLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(subLower); i++ {
		if sLower[i:i+len(subLower)] == subLower {
			return i
		}
	}
	return -1
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func hasAnyTag(queryTags, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, qt := range queryTags {
			if qt == ft {
				return true
			}
		}
	}
	return false
}

func sortExecutions(execs []*models.QueryExecution) {
	// Simple bubble sort for small datasets
	for i := 0; i < len(execs)-1; i++ {
		for j := i + 1; j < len(execs); j++ {
			if execs[j].ExecutedAt.After(execs[i].ExecutedAt) {
				execs[i], execs[j] = execs[j], execs[i]
			}
		}
	}
}

func sortSavedQueries(queries []*models.SavedQuery) {
	for i := 0; i < len(queries)-1; i++ {
		for j := i + 1; j < len(queries); j++ {
			if queries[j].UpdatedAt.After(queries[i].UpdatedAt) {
				queries[i], queries[j] = queries[j], queries[i]
			}
		}
	}
}
