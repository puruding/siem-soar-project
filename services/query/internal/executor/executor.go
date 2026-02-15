// Package executor provides query execution capabilities.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// QueryType represents the type of query.
type QueryType string

const (
	QueryTypeSelect    QueryType = "SELECT"
	QueryTypeAggregate QueryType = "AGGREGATE"
	QueryTypeTimeSeries QueryType = "TIMESERIES"
	QueryTypeSearch    QueryType = "SEARCH"
)

// QueryStatus represents the status of a query.
type QueryStatus string

const (
	QueryStatusPending   QueryStatus = "pending"
	QueryStatusRunning   QueryStatus = "running"
	QueryStatusCompleted QueryStatus = "completed"
	QueryStatusFailed    QueryStatus = "failed"
	QueryStatusCancelled QueryStatus = "cancelled"
)

// ExecutorConfig holds executor configuration.
type ExecutorConfig struct {
	MaxConcurrent      int           `json:"max_concurrent"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	MaxResultSize      int64         `json:"max_result_size"`
	QueryCacheTTL      time.Duration `json:"query_cache_ttl"`
	EnableQueryLog     bool          `json:"enable_query_log"`
	MaxQueryLength     int           `json:"max_query_length"`
	ConnectionPoolSize int           `json:"connection_pool_size"`
}

// DefaultExecutorConfig returns default executor configuration.
func DefaultExecutorConfig() ExecutorConfig {
	return ExecutorConfig{
		MaxConcurrent:      100,
		DefaultTimeout:     5 * time.Minute,
		MaxResultSize:      10000000, // 10M rows
		QueryCacheTTL:      5 * time.Minute,
		EnableQueryLog:     true,
		MaxQueryLength:     100000,
		ConnectionPoolSize: 20,
	}
}

// QueryRequest represents a query request.
type QueryRequest struct {
	ID         string                 `json:"id"`
	Query      string                 `json:"query"`
	Type       QueryType              `json:"type"`
	Database   string                 `json:"database"`
	Table      string                 `json:"table,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Timeout    time.Duration          `json:"timeout,omitempty"`
	MaxResults int64                  `json:"max_results,omitempty"`
	TenantID   string                 `json:"tenant_id"`
	UserID     string                 `json:"user_id"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// QueryResult represents a query result.
type QueryResult struct {
	ID           string                   `json:"id"`
	Status       QueryStatus              `json:"status"`
	Rows         []map[string]interface{} `json:"rows,omitempty"`
	RowCount     int64                    `json:"row_count"`
	TotalCount   int64                    `json:"total_count"`
	Columns      []ColumnInfo             `json:"columns,omitempty"`
	Error        string                   `json:"error,omitempty"`
	ExecutionMS  int64                    `json:"execution_ms"`
	BytesRead    int64                    `json:"bytes_read"`
	BytesWritten int64                    `json:"bytes_written"`
	Metadata     QueryMetadata            `json:"metadata"`
}

// ColumnInfo represents column metadata.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

// QueryMetadata holds query metadata.
type QueryMetadata struct {
	OptimizedQuery string            `json:"optimized_query,omitempty"`
	QueryPlan      string            `json:"query_plan,omitempty"`
	CacheHit       bool              `json:"cache_hit"`
	PartitionsRead int               `json:"partitions_read"`
	TablesRead     []string          `json:"tables_read,omitempty"`
	Warnings       []string          `json:"warnings,omitempty"`
	Hints          map[string]string `json:"hints,omitempty"`
}

// Backend defines the interface for query backends.
type Backend interface {
	Execute(ctx context.Context, req *QueryRequest) (*QueryResult, error)
	Health(ctx context.Context) error
	Close() error
}

// Executor executes queries against backends.
type Executor struct {
	config    ExecutorConfig
	backends  map[string]Backend
	optimizer *Optimizer
	cache     *queryCache
	logger    *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	totalQueries   atomic.Uint64
	successQueries atomic.Uint64
	failedQueries  atomic.Uint64
	cacheHits      atomic.Uint64
	cacheMisses    atomic.Uint64
	totalBytes     atomic.Uint64
}

// NewExecutor creates a new query executor.
func NewExecutor(cfg ExecutorConfig, logger *slog.Logger) *Executor {
	ctx, cancel := context.WithCancel(context.Background())

	return &Executor{
		config:    cfg,
		backends:  make(map[string]Backend),
		optimizer: NewOptimizer(),
		cache:     newQueryCache(cfg.QueryCacheTTL),
		logger:    logger.With("component", "query-executor"),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// RegisterBackend registers a query backend.
func (e *Executor) RegisterBackend(name string, backend Backend) {
	e.backends[name] = backend
	e.logger.Info("registered query backend", "name", name)
}

// Execute executes a query.
func (e *Executor) Execute(ctx context.Context, req *QueryRequest) (*QueryResult, error) {
	startTime := time.Now()
	e.totalQueries.Add(1)

	// Validate request
	if err := e.validateRequest(req); err != nil {
		e.failedQueries.Add(1)
		return &QueryResult{
			ID:     req.ID,
			Status: QueryStatusFailed,
			Error:  err.Error(),
		}, err
	}

	// Set default timeout
	if req.Timeout == 0 {
		req.Timeout = e.config.DefaultTimeout
	}

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	// Check cache
	cacheKey := e.buildCacheKey(req)
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		e.successQueries.Add(1)
		cached.Metadata.CacheHit = true
		return cached, nil
	}
	e.cacheMisses.Add(1)

	// Optimize query
	optimizedQuery, hints := e.optimizer.Optimize(req.Query, req.Type)
	req.Query = optimizedQuery

	// Get backend
	backend, err := e.getBackend(req.Database)
	if err != nil {
		e.failedQueries.Add(1)
		return &QueryResult{
			ID:     req.ID,
			Status: QueryStatusFailed,
			Error:  err.Error(),
		}, err
	}

	// Execute query
	result, err := backend.Execute(ctx, req)
	if err != nil {
		e.failedQueries.Add(1)
		return &QueryResult{
			ID:          req.ID,
			Status:      QueryStatusFailed,
			Error:       err.Error(),
			ExecutionMS: time.Since(startTime).Milliseconds(),
		}, err
	}

	// Update result
	result.ID = req.ID
	result.ExecutionMS = time.Since(startTime).Milliseconds()
	result.Metadata.OptimizedQuery = optimizedQuery
	result.Metadata.Hints = hints

	// Update metrics
	e.successQueries.Add(1)
	e.totalBytes.Add(uint64(result.BytesRead))

	// Cache result if successful
	if result.Status == QueryStatusCompleted {
		e.cache.set(cacheKey, result)
	}

	// Log query
	if e.config.EnableQueryLog {
		e.logQuery(req, result)
	}

	return result, nil
}

// ExecuteAsync executes a query asynchronously.
func (e *Executor) ExecuteAsync(ctx context.Context, req *QueryRequest) (<-chan *QueryResult, error) {
	resultCh := make(chan *QueryResult, 1)

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer close(resultCh)

		result, err := e.Execute(ctx, req)
		if err != nil && result == nil {
			result = &QueryResult{
				ID:     req.ID,
				Status: QueryStatusFailed,
				Error:  err.Error(),
			}
		}
		resultCh <- result
	}()

	return resultCh, nil
}

// Cancel cancels a running query.
func (e *Executor) Cancel(queryID string) error {
	// Implementation depends on backend support for cancellation
	e.logger.Info("cancelling query", "query_id", queryID)
	return nil
}

// Stats returns executor statistics.
func (e *Executor) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_queries":   e.totalQueries.Load(),
		"success_queries": e.successQueries.Load(),
		"failed_queries":  e.failedQueries.Load(),
		"cache_hits":      e.cacheHits.Load(),
		"cache_misses":    e.cacheMisses.Load(),
		"total_bytes":     e.totalBytes.Load(),
		"cache_hit_rate":  e.calculateCacheHitRate(),
	}
}

// Close closes the executor.
func (e *Executor) Close() error {
	e.cancel()
	e.wg.Wait()

	for name, backend := range e.backends {
		if err := backend.Close(); err != nil {
			e.logger.Error("failed to close backend", "name", name, "error", err)
		}
	}

	return nil
}

func (e *Executor) validateRequest(req *QueryRequest) error {
	if req.Query == "" {
		return fmt.Errorf("query is required")
	}
	if len(req.Query) > e.config.MaxQueryLength {
		return fmt.Errorf("query exceeds maximum length of %d", e.config.MaxQueryLength)
	}
	if req.Database == "" {
		return fmt.Errorf("database is required")
	}
	return nil
}

func (e *Executor) getBackend(database string) (Backend, error) {
	backend, ok := e.backends[database]
	if !ok {
		return nil, fmt.Errorf("no backend registered for database: %s", database)
	}
	return backend, nil
}

func (e *Executor) buildCacheKey(req *QueryRequest) string {
	return fmt.Sprintf("%s:%s:%s", req.Database, req.TenantID, req.Query)
}

func (e *Executor) calculateCacheHitRate() float64 {
	hits := e.cacheHits.Load()
	misses := e.cacheMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

func (e *Executor) logQuery(req *QueryRequest, result *QueryResult) {
	e.logger.Info("query executed",
		"query_id", req.ID,
		"database", req.Database,
		"tenant_id", req.TenantID,
		"user_id", req.UserID,
		"status", result.Status,
		"execution_ms", result.ExecutionMS,
		"row_count", result.RowCount,
		"bytes_read", result.BytesRead,
	)
}

// queryCache implements a simple query cache.
type queryCache struct {
	entries sync.Map
	ttl     time.Duration
}

type cacheEntry struct {
	result    *QueryResult
	expiresAt time.Time
}

func newQueryCache(ttl time.Duration) *queryCache {
	return &queryCache{ttl: ttl}
}

func (c *queryCache) get(key string) *QueryResult {
	if entry, ok := c.entries.Load(key); ok {
		e := entry.(*cacheEntry)
		if time.Now().Before(e.expiresAt) {
			// Return a copy to prevent modifications
			result := *e.result
			return &result
		}
		c.entries.Delete(key)
	}
	return nil
}

func (c *queryCache) set(key string, result *QueryResult) {
	entry := &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.entries.Store(key, entry)
}
