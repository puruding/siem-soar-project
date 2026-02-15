// Package federation provides cross-SIEM query federation capabilities.
package federation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/siem-soar-platform/pkg/connector"
)

// Federation manages federated queries across multiple SIEMs.
type Federation struct {
	registry   *connector.Registry
	translator *Translator
	merger     *Merger
	cache      *Cache
	config     *Config
}

// Config holds federation configuration.
type Config struct {
	// Query settings
	DefaultTimeout    time.Duration `json:"default_timeout"`
	MaxConcurrent     int           `json:"max_concurrent"`
	EnableCache       bool          `json:"enable_cache"`
	CacheTTL          time.Duration `json:"cache_ttl"`

	// Result settings
	MaxResultsPerSIEM int  `json:"max_results_per_siem"`
	MergeResults      bool `json:"merge_results"`
	NormalizeFields   bool `json:"normalize_fields"`
}

// DefaultConfig returns default federation configuration.
func DefaultConfig() *Config {
	return &Config{
		DefaultTimeout:    5 * time.Minute,
		MaxConcurrent:     5,
		EnableCache:       true,
		CacheTTL:          5 * time.Minute,
		MaxResultsPerSIEM: 10000,
		MergeResults:      true,
		NormalizeFields:   true,
	}
}

// NewFederation creates a new federation instance.
func NewFederation(registry *connector.Registry, config *Config) *Federation {
	if config == nil {
		config = DefaultConfig()
	}

	return &Federation{
		registry:   registry,
		translator: NewTranslator(),
		merger:     NewMerger(config.NormalizeFields),
		cache:      NewCache(config.CacheTTL),
		config:     config,
	}
}

// FederatedQuery represents a federated query request.
type FederatedQuery struct {
	ID         string                   `json:"id"`
	Query      string                   `json:"query"`
	Language   connector.QueryLanguage  `json:"language"` // Source language
	Targets    []connector.SIEMType     `json:"targets"`  // Target SIEMs (empty = all)
	TimeRange  connector.TimeRange      `json:"time_range"`
	MaxResults int                      `json:"max_results"`
	Options    FederatedQueryOptions    `json:"options"`
}

// FederatedQueryOptions holds additional query options.
type FederatedQueryOptions struct {
	Timeout       time.Duration `json:"timeout"`
	UseCache      bool          `json:"use_cache"`
	MergeResults  bool          `json:"merge_results"`
	FailFast      bool          `json:"fail_fast"`      // Stop on first error
	RequireAll    bool          `json:"require_all"`    // All SIEMs must succeed
}

// FederatedResult represents a federated query result.
type FederatedResult struct {
	ID          string                    `json:"id"`
	Status      FederatedStatus           `json:"status"`
	Results     []map[string]interface{}  `json:"results,omitempty"`
	SIEMResults map[connector.SIEMType]*SIEMResult `json:"siem_results"`
	Metadata    FederatedMetadata         `json:"metadata"`
	StartTime   time.Time                 `json:"start_time"`
	EndTime     time.Time                 `json:"end_time"`
}

// FederatedStatus represents the status of a federated query.
type FederatedStatus string

const (
	FederatedStatusPending   FederatedStatus = "pending"
	FederatedStatusRunning   FederatedStatus = "running"
	FederatedStatusCompleted FederatedStatus = "completed"
	FederatedStatusPartial   FederatedStatus = "partial" // Some SIEMs succeeded
	FederatedStatusFailed    FederatedStatus = "failed"
)

// SIEMResult represents results from a single SIEM.
type SIEMResult struct {
	SIEM        connector.SIEMType       `json:"siem"`
	Status      connector.QueryStatus    `json:"status"`
	Results     []map[string]interface{} `json:"results,omitempty"`
	ResultCount int64                    `json:"result_count"`
	Error       string                   `json:"error,omitempty"`
	Duration    time.Duration            `json:"duration_ms"`
	Query       string                   `json:"query"` // Translated query
	FromCache   bool                     `json:"from_cache"`
}

// FederatedMetadata holds metadata about the federated query.
type FederatedMetadata struct {
	TotalResults    int64                        `json:"total_results"`
	ReturnedResults int                          `json:"returned_results"`
	ExecutionTime   time.Duration                `json:"execution_time_ms"`
	SIEMsQueried    []connector.SIEMType         `json:"siems_queried"`
	SIEMsSucceeded  []connector.SIEMType         `json:"siems_succeeded"`
	SIEMsFailed     []connector.SIEMType         `json:"siems_failed"`
	CacheHits       int                          `json:"cache_hits"`
	Warnings        []string                     `json:"warnings,omitempty"`
}

// Query executes a federated query across multiple SIEMs.
func (f *Federation) Query(ctx context.Context, req *FederatedQuery) (*FederatedResult, error) {
	startTime := time.Now()

	// Determine target SIEMs
	targets := req.Targets
	if len(targets) == 0 {
		targets = f.registry.ListSIEMTypes()
	}

	// Apply options
	timeout := req.Options.Timeout
	if timeout == 0 {
		timeout = f.config.DefaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Check cache
	useCache := req.Options.UseCache || f.config.EnableCache
	if useCache {
		if cached := f.cache.Get(req.ID); cached != nil {
			cached.Metadata.CacheHits++
			return cached, nil
		}
	}

	// Execute queries in parallel
	result := &FederatedResult{
		ID:          req.ID,
		Status:      FederatedStatusRunning,
		SIEMResults: make(map[connector.SIEMType]*SIEMResult),
		StartTime:   startTime,
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	errCh := make(chan error, len(targets))

	semaphore := make(chan struct{}, f.config.MaxConcurrent)

	for _, siemType := range targets {
		wg.Add(1)
		go func(st connector.SIEMType) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			siemResult := f.querySIEM(ctx, st, req)

			mu.Lock()
			result.SIEMResults[st] = siemResult
			mu.Unlock()

			if siemResult.Status == connector.QueryStatusFailed && req.Options.FailFast {
				errCh <- fmt.Errorf("query failed for %s: %s", st, siemResult.Error)
			}
		}(siemType)
	}

	// Wait for completion or failure
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		result.Status = FederatedStatusFailed
		result.Metadata.Warnings = append(result.Metadata.Warnings, "query timed out")
	case err := <-errCh:
		if req.Options.FailFast {
			result.Status = FederatedStatusFailed
			result.Metadata.Warnings = append(result.Metadata.Warnings, err.Error())
		}
	case <-done:
		// All queries completed
	}

	result.EndTime = time.Now()

	// Analyze results
	f.analyzeResults(result, req)

	// Merge results if requested
	if req.Options.MergeResults || f.config.MergeResults {
		result.Results = f.merger.Merge(result.SIEMResults)
	}

	// Apply result limit
	if req.MaxResults > 0 && len(result.Results) > req.MaxResults {
		result.Results = result.Results[:req.MaxResults]
	}

	// Cache result
	if useCache && result.Status == FederatedStatusCompleted {
		f.cache.Set(req.ID, result)
	}

	return result, nil
}

// querySIEM executes a query against a single SIEM.
func (f *Federation) querySIEM(ctx context.Context, siemType connector.SIEMType, req *FederatedQuery) *SIEMResult {
	startTime := time.Now()
	result := &SIEMResult{
		SIEM:   siemType,
		Status: connector.QueryStatusRunning,
	}

	// Get connector
	connectors := f.registry.GetAllSIEMConnectors()
	var conn connector.SIEMConnector
	for _, c := range connectors {
		if c.SIEM() == siemType {
			conn = c
			break
		}
	}

	if conn == nil {
		result.Status = connector.QueryStatusFailed
		result.Error = fmt.Sprintf("no connector available for %s", siemType)
		result.Duration = time.Since(startTime)
		return result
	}

	// Translate query
	targetLang := getPreferredLanguage(siemType)
	translatedQuery, err := f.translator.Translate(req.Query, req.Language, targetLang)
	if err != nil {
		result.Status = connector.QueryStatusFailed
		result.Error = fmt.Sprintf("translation failed: %s", err.Error())
		result.Duration = time.Since(startTime)
		return result
	}
	result.Query = translatedQuery

	// Execute query
	queryReq := &connector.QueryRequest{
		ID:         fmt.Sprintf("%s-%s", req.ID, siemType),
		Query:      translatedQuery,
		Language:   targetLang,
		TimeRange:  req.TimeRange,
		MaxResults: f.config.MaxResultsPerSIEM,
	}

	queryResult, err := conn.Query(ctx, queryReq)
	if err != nil {
		result.Status = connector.QueryStatusFailed
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result
	}

	result.Status = queryResult.Status
	result.Results = queryResult.Results
	result.ResultCount = queryResult.Metadata.TotalResults
	result.Duration = time.Since(startTime)

	return result
}

// analyzeResults analyzes the results and updates metadata.
func (f *Federation) analyzeResults(result *FederatedResult, req *FederatedQuery) {
	metadata := &result.Metadata
	metadata.ExecutionTime = result.EndTime.Sub(result.StartTime)

	var totalResults int64
	succeededCount := 0
	failedCount := 0

	for siemType, siemResult := range result.SIEMResults {
		metadata.SIEMsQueried = append(metadata.SIEMsQueried, siemType)

		if siemResult.Status == connector.QueryStatusCompleted {
			metadata.SIEMsSucceeded = append(metadata.SIEMsSucceeded, siemType)
			totalResults += siemResult.ResultCount
			succeededCount++
		} else {
			metadata.SIEMsFailed = append(metadata.SIEMsFailed, siemType)
			failedCount++
		}
	}

	metadata.TotalResults = totalResults

	// Determine overall status
	if failedCount == 0 {
		result.Status = FederatedStatusCompleted
	} else if succeededCount == 0 {
		result.Status = FederatedStatusFailed
	} else {
		result.Status = FederatedStatusPartial
	}

	// Check if all required
	if req.Options.RequireAll && failedCount > 0 {
		result.Status = FederatedStatusFailed
	}
}

// getPreferredLanguage returns the preferred query language for a SIEM.
func getPreferredLanguage(siemType connector.SIEMType) connector.QueryLanguage {
	switch siemType {
	case connector.SIEMSplunk:
		return connector.QueryLanguageSPL
	case connector.SIEMElastic:
		return connector.QueryLanguageDSL
	case connector.SIEMSentinel:
		return connector.QueryLanguageKQL
	default:
		return connector.QueryLanguageSQL
	}
}

// GetConnectedSIEMs returns a list of connected SIEMs.
func (f *Federation) GetConnectedSIEMs() []connector.SIEMType {
	connected := make([]connector.SIEMType, 0)
	for _, conn := range f.registry.GetAllSIEMConnectors() {
		if conn.IsConnected() {
			connected = append(connected, conn.SIEM())
		}
	}
	return connected
}

// HealthCheck performs a health check on all connected SIEMs.
func (f *Federation) HealthCheck(ctx context.Context) map[connector.SIEMType]*connector.ConnectorHealth {
	results := make(map[connector.SIEMType]*connector.ConnectorHealth)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, conn := range f.registry.GetAllSIEMConnectors() {
		wg.Add(1)
		go func(c connector.SIEMConnector) {
			defer wg.Done()

			health, err := c.Health(ctx)
			if err != nil {
				health = &connector.ConnectorHealth{
					Status:    connector.StatusError,
					Message:   err.Error(),
					Timestamp: time.Now(),
				}
			}

			mu.Lock()
			results[c.SIEM()] = health
			mu.Unlock()
		}(conn)
	}

	wg.Wait()
	return results
}
