// Package feed provides threat intelligence feed management.
package feed

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// FeedType represents the type of TI feed.
type FeedType string

const (
	FeedTypeSTIX   FeedType = "stix"
	FeedTypeTAXII  FeedType = "taxii"
	FeedTypeMISP   FeedType = "misp"
	FeedTypeCSV    FeedType = "csv"
	FeedTypeJSON   FeedType = "json"
	FeedTypeOTX    FeedType = "otx"
	FeedTypeCustom FeedType = "custom"
)

// FeedStatus represents the status of a feed.
type FeedStatus string

const (
	StatusActive    FeedStatus = "active"
	StatusInactive  FeedStatus = "inactive"
	StatusError     FeedStatus = "error"
	StatusSyncing   FeedStatus = "syncing"
)

// Feed represents a threat intelligence feed configuration.
type Feed struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Type           FeedType          `json:"type"`
	URL            string            `json:"url"`
	APIKey         string            `json:"api_key,omitempty"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	CollectionID   string            `json:"collection_id,omitempty"`   // For TAXII
	Headers        map[string]string `json:"headers,omitempty"`

	// Scheduling
	Enabled        bool              `json:"enabled"`
	Schedule       string            `json:"schedule"` // Cron expression
	SyncInterval   time.Duration     `json:"sync_interval"`

	// Filtering
	IOCTypes       []string          `json:"ioc_types,omitempty"`
	MinConfidence  int               `json:"min_confidence,omitempty"`
	Tags           []string          `json:"tags,omitempty"`

	// Runtime state
	Status         FeedStatus        `json:"status"`
	LastSync       time.Time         `json:"last_sync"`
	LastError      string            `json:"last_error,omitempty"`
	IOCCount       int64             `json:"ioc_count"`
}

// FeedResult represents the result of a feed sync.
type FeedResult struct {
	FeedID     string        `json:"feed_id"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Success    bool          `json:"success"`
	Error      string        `json:"error,omitempty"`
	IOCsAdded  int64         `json:"iocs_added"`
	IOCsUpdated int64        `json:"iocs_updated"`
	IOCsRemoved int64        `json:"iocs_removed"`
	IOCsTotal  int64         `json:"iocs_total"`
}

// FeedHandler processes IOCs from a feed.
type FeedHandler interface {
	HandleIOC(ctx context.Context, ioc *IOC) error
	HandleBatch(ctx context.Context, iocs []*IOC) error
	Commit(ctx context.Context) error
}

// FeedClient interface for feed-specific implementations.
type FeedClient interface {
	Fetch(ctx context.Context, feed *Feed, lastSync time.Time) ([]*IOC, error)
	Test(ctx context.Context, feed *Feed) error
}

// ManagerConfig holds feed manager configuration.
type ManagerConfig struct {
	MaxConcurrentSyncs int           `json:"max_concurrent_syncs"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	RetryAttempts      int           `json:"retry_attempts"`
	RetryDelay         time.Duration `json:"retry_delay"`
}

// DefaultManagerConfig returns default manager configuration.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		MaxConcurrentSyncs: 5,
		DefaultTimeout:     30 * time.Minute,
		RetryAttempts:      3,
		RetryDelay:         time.Minute,
	}
}

// Manager manages threat intelligence feeds.
type Manager struct {
	config      ManagerConfig
	feeds       map[string]*Feed
	feedsMu     sync.RWMutex
	clients     map[FeedType]FeedClient
	handler     FeedHandler
	semaphore   chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	logger      *slog.Logger

	// Metrics
	syncCount   atomic.Uint64
	syncErrors  atomic.Uint64
	iocsTotal   atomic.Int64
}

// NewManager creates a new feed manager.
func NewManager(cfg ManagerConfig, handler FeedHandler, logger *slog.Logger) *Manager {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		config:    cfg,
		feeds:     make(map[string]*Feed),
		clients:   make(map[FeedType]FeedClient),
		handler:   handler,
		semaphore: make(chan struct{}, cfg.MaxConcurrentSyncs),
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger.With("component", "feed-manager"),
	}

	// Register default clients
	m.clients[FeedTypeSTIX] = NewSTIXParser(logger)
	m.clients[FeedTypeTAXII] = NewTAXIIClient(logger)
	m.clients[FeedTypeMISP] = NewMISPClient(logger)

	return m
}

// Start starts the feed manager.
func (m *Manager) Start() error {
	m.logger.Info("starting feed manager")

	// Start scheduler
	m.wg.Add(1)
	go m.scheduler()

	return nil
}

// Stop stops the feed manager.
func (m *Manager) Stop() error {
	m.logger.Info("stopping feed manager")
	m.cancel()
	m.wg.Wait()
	return nil
}

// RegisterFeed registers a new feed.
func (m *Manager) RegisterFeed(feed *Feed) error {
	if feed.ID == "" {
		return fmt.Errorf("feed ID is required")
	}

	m.feedsMu.Lock()
	defer m.feedsMu.Unlock()

	feed.Status = StatusActive
	m.feeds[feed.ID] = feed

	m.logger.Info("feed registered", "feed_id", feed.ID, "name", feed.Name)
	return nil
}

// UnregisterFeed removes a feed.
func (m *Manager) UnregisterFeed(feedID string) {
	m.feedsMu.Lock()
	defer m.feedsMu.Unlock()

	delete(m.feeds, feedID)
	m.logger.Info("feed unregistered", "feed_id", feedID)
}

// GetFeed returns a feed by ID.
func (m *Manager) GetFeed(feedID string) *Feed {
	m.feedsMu.RLock()
	defer m.feedsMu.RUnlock()
	return m.feeds[feedID]
}

// ListFeeds returns all registered feeds.
func (m *Manager) ListFeeds() []*Feed {
	m.feedsMu.RLock()
	defer m.feedsMu.RUnlock()

	feeds := make([]*Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		feeds = append(feeds, f)
	}
	return feeds
}

// SyncFeed synchronizes a specific feed.
func (m *Manager) SyncFeed(ctx context.Context, feedID string) (*FeedResult, error) {
	m.feedsMu.RLock()
	feed, ok := m.feeds[feedID]
	m.feedsMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("feed not found: %s", feedID)
	}

	return m.syncFeed(ctx, feed)
}

// SyncAll synchronizes all enabled feeds.
func (m *Manager) SyncAll(ctx context.Context) []*FeedResult {
	m.feedsMu.RLock()
	feeds := make([]*Feed, 0)
	for _, f := range m.feeds {
		if f.Enabled {
			feeds = append(feeds, f)
		}
	}
	m.feedsMu.RUnlock()

	var results []*FeedResult
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	for _, feed := range feeds {
		wg.Add(1)
		go func(f *Feed) {
			defer wg.Done()

			result, err := m.syncFeed(ctx, f)
			if err != nil {
				m.logger.Error("feed sync failed", "feed_id", f.ID, "error", err)
			}

			resultsMu.Lock()
			results = append(results, result)
			resultsMu.Unlock()
		}(feed)
	}

	wg.Wait()
	return results
}

// TestFeed tests connectivity to a feed.
func (m *Manager) TestFeed(ctx context.Context, feed *Feed) error {
	client, ok := m.clients[feed.Type]
	if !ok {
		return fmt.Errorf("unsupported feed type: %s", feed.Type)
	}

	return client.Test(ctx, feed)
}

// RegisterClient registers a custom feed client.
func (m *Manager) RegisterClient(feedType FeedType, client FeedClient) {
	m.clients[feedType] = client
}

// Stats returns manager statistics.
func (m *Manager) Stats() map[string]interface{} {
	m.feedsMu.RLock()
	feedCount := len(m.feeds)
	m.feedsMu.RUnlock()

	return map[string]interface{}{
		"feeds_total":  feedCount,
		"sync_count":   m.syncCount.Load(),
		"sync_errors":  m.syncErrors.Load(),
		"iocs_total":   m.iocsTotal.Load(),
	}
}

func (m *Manager) syncFeed(ctx context.Context, feed *Feed) (*FeedResult, error) {
	// Acquire semaphore
	select {
	case m.semaphore <- struct{}{}:
		defer func() { <-m.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	result := &FeedResult{
		FeedID:    feed.ID,
		StartTime: time.Now(),
	}

	// Update feed status
	m.updateFeedStatus(feed.ID, StatusSyncing, "")

	logger := m.logger.With("feed_id", feed.ID, "feed_name", feed.Name)
	logger.Info("starting feed sync")

	// Get client for feed type
	client, ok := m.clients[feed.Type]
	if !ok {
		err := fmt.Errorf("unsupported feed type: %s", feed.Type)
		m.updateFeedStatus(feed.ID, StatusError, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Error = err.Error()
		m.syncErrors.Add(1)
		return result, err
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, m.config.DefaultTimeout)
	defer cancel()

	// Fetch IOCs with retry
	var iocs []*IOC
	var err error

	for attempt := 0; attempt <= m.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(m.config.RetryDelay)
			logger.Info("retrying feed sync", "attempt", attempt)
		}

		iocs, err = client.Fetch(timeoutCtx, feed, feed.LastSync)
		if err == nil {
			break
		}
	}

	if err != nil {
		m.updateFeedStatus(feed.ID, StatusError, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Error = err.Error()
		m.syncErrors.Add(1)
		return result, err
	}

	// Process IOCs
	if err := m.handler.HandleBatch(ctx, iocs); err != nil {
		m.updateFeedStatus(feed.ID, StatusError, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Error = err.Error()
		m.syncErrors.Add(1)
		return result, err
	}

	// Commit changes
	if err := m.handler.Commit(ctx); err != nil {
		m.updateFeedStatus(feed.ID, StatusError, err.Error())
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		result.Error = err.Error()
		m.syncErrors.Add(1)
		return result, err
	}

	// Update success state
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Success = true
	result.IOCsTotal = int64(len(iocs))
	result.IOCsAdded = int64(len(iocs)) // Simplified

	m.updateFeedStatus(feed.ID, StatusActive, "")
	m.updateFeedLastSync(feed.ID, result.EndTime, int64(len(iocs)))

	m.syncCount.Add(1)
	m.iocsTotal.Add(int64(len(iocs)))

	logger.Info("feed sync completed",
		"duration", result.Duration,
		"iocs_total", result.IOCsTotal)

	return result, nil
}

func (m *Manager) updateFeedStatus(feedID string, status FeedStatus, lastError string) {
	m.feedsMu.Lock()
	defer m.feedsMu.Unlock()

	if feed, ok := m.feeds[feedID]; ok {
		feed.Status = status
		feed.LastError = lastError
	}
}

func (m *Manager) updateFeedLastSync(feedID string, syncTime time.Time, iocCount int64) {
	m.feedsMu.Lock()
	defer m.feedsMu.Unlock()

	if feed, ok := m.feeds[feedID]; ok {
		feed.LastSync = syncTime
		feed.IOCCount = iocCount
	}
}

func (m *Manager) scheduler() {
	defer m.wg.Done()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkScheduledFeeds()
		}
	}
}

func (m *Manager) checkScheduledFeeds() {
	m.feedsMu.RLock()
	feeds := make([]*Feed, 0)
	for _, f := range m.feeds {
		if f.Enabled && m.shouldSync(f) {
			feeds = append(feeds, f)
		}
	}
	m.feedsMu.RUnlock()

	for _, feed := range feeds {
		go func(f *Feed) {
			ctx, cancel := context.WithTimeout(m.ctx, m.config.DefaultTimeout)
			defer cancel()

			if _, err := m.syncFeed(ctx, f); err != nil {
				m.logger.Error("scheduled sync failed", "feed_id", f.ID, "error", err)
			}
		}(feed)
	}
}

func (m *Manager) shouldSync(feed *Feed) bool {
	if feed.SyncInterval <= 0 {
		return false
	}
	return time.Since(feed.LastSync) >= feed.SyncInterval
}
