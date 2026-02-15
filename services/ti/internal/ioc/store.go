// Package ioc provides IOC storage and retrieval.
package ioc

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// StoreConfig holds store configuration.
type StoreConfig struct {
	MaxIOCs          int           `json:"max_iocs"`
	DefaultTTL       time.Duration `json:"default_ttl"`
	CleanupInterval  time.Duration `json:"cleanup_interval"`
	PersistInterval  time.Duration `json:"persist_interval"`
}

// DefaultStoreConfig returns default store configuration.
func DefaultStoreConfig() StoreConfig {
	return StoreConfig{
		MaxIOCs:         10000000, // 10 million
		DefaultTTL:      90 * 24 * time.Hour, // 90 days
		CleanupInterval: time.Hour,
		PersistInterval: 5 * time.Minute,
	}
}

// Repository defines the persistence interface for IOCs.
type Repository interface {
	Save(ctx context.Context, ioc *IOC) error
	SaveBatch(ctx context.Context, iocs []*IOC) error
	GetByID(ctx context.Context, id string) (*IOC, error)
	GetByTypeAndValue(ctx context.Context, iocType IOCType, value string) (*IOC, error)
	List(ctx context.Context, filter IOCFilter, limit, offset int) ([]*IOC, int64, error)
	Delete(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) (int64, error)
	GetStats(ctx context.Context, tenantID string) (*IOCStats, error)
}

// Store provides in-memory IOC storage with persistence.
type Store struct {
	config     StoreConfig
	repository Repository
	iocs       sync.Map // map[string]*IOC (keyed by type:value)
	byID       sync.Map // map[string]*IOC (keyed by ID)
	logger     *slog.Logger

	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup

	// Metrics
	totalIOCs   atomic.Int64
	lookups     atomic.Uint64
	hits        atomic.Uint64
	misses      atomic.Uint64
	additions   atomic.Uint64
	deletions   atomic.Uint64
}

// NewStore creates a new IOC store.
func NewStore(cfg StoreConfig, repo Repository, logger *slog.Logger) *Store {
	ctx, cancel := context.WithCancel(context.Background())

	return &Store{
		config:     cfg,
		repository: repo,
		logger:     logger.With("component", "ioc-store"),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start starts the store background tasks.
func (s *Store) Start() error {
	// Load initial data from repository
	if err := s.loadFromRepository(); err != nil {
		s.logger.Error("failed to load IOCs from repository", "error", err)
	}

	// Start cleanup task
	s.wg.Add(1)
	go s.cleanupLoop()

	// Start persist task
	if s.repository != nil {
		s.wg.Add(1)
		go s.persistLoop()
	}

	s.logger.Info("IOC store started", "iocs_loaded", s.totalIOCs.Load())
	return nil
}

// Stop stops the store.
func (s *Store) Stop() error {
	s.cancel()
	s.wg.Wait()

	s.logger.Info("IOC store stopped")
	return nil
}

// Add adds an IOC to the store.
func (s *Store) Add(ioc *IOC) error {
	if ioc == nil {
		return fmt.Errorf("ioc is nil")
	}

	key := s.buildKey(ioc.Type, ioc.Value)

	// Check for existing IOC
	if existing, loaded := s.iocs.Load(key); loaded {
		existingIOC := existing.(*IOC)
		existingIOC.Merge(ioc)
		s.iocs.Store(key, existingIOC)
		return nil
	}

	// Set defaults
	if ioc.ExpiresAt.IsZero() {
		ioc.ExpiresAt = time.Now().Add(s.config.DefaultTTL)
	}

	s.iocs.Store(key, ioc)
	if ioc.ID != "" {
		s.byID.Store(ioc.ID, ioc)
	}

	s.totalIOCs.Add(1)
	s.additions.Add(1)

	return nil
}

// AddBatch adds multiple IOCs to the store.
func (s *Store) AddBatch(iocs []*IOC) error {
	for _, ioc := range iocs {
		if err := s.Add(ioc); err != nil {
			s.logger.Warn("failed to add IOC", "ioc_value", ioc.Value, "error", err)
		}
	}
	return nil
}

// Get retrieves an IOC by type and value.
func (s *Store) Get(iocType IOCType, value string) *IOC {
	s.lookups.Add(1)
	key := s.buildKey(iocType, value)

	if ioc, ok := s.iocs.Load(key); ok {
		s.hits.Add(1)
		return ioc.(*IOC)
	}

	s.misses.Add(1)
	return nil
}

// GetByID retrieves an IOC by ID.
func (s *Store) GetByID(id string) *IOC {
	s.lookups.Add(1)

	if ioc, ok := s.byID.Load(id); ok {
		s.hits.Add(1)
		return ioc.(*IOC)
	}

	s.misses.Add(1)
	return nil
}

// Lookup performs a lookup and records a hit if found.
func (s *Store) Lookup(iocType IOCType, value string) (*IOC, bool) {
	ioc := s.Get(iocType, value)
	if ioc == nil {
		return nil, false
	}

	if !ioc.IsValid() {
		return nil, false
	}

	ioc.RecordHit()
	return ioc, true
}

// Delete removes an IOC from the store.
func (s *Store) Delete(iocType IOCType, value string) {
	key := s.buildKey(iocType, value)

	if ioc, loaded := s.iocs.LoadAndDelete(key); loaded {
		i := ioc.(*IOC)
		if i.ID != "" {
			s.byID.Delete(i.ID)
		}
		s.totalIOCs.Add(-1)
		s.deletions.Add(1)
	}
}

// DeleteByID removes an IOC by ID.
func (s *Store) DeleteByID(id string) {
	if ioc, loaded := s.byID.LoadAndDelete(id); loaded {
		i := ioc.(*IOC)
		key := s.buildKey(i.Type, i.Value)
		s.iocs.Delete(key)
		s.totalIOCs.Add(-1)
		s.deletions.Add(1)
	}
}

// Contains checks if an IOC exists in the store.
func (s *Store) Contains(iocType IOCType, value string) bool {
	key := s.buildKey(iocType, value)
	_, ok := s.iocs.Load(key)
	return ok
}

// List returns IOCs matching the filter.
func (s *Store) List(filter IOCFilter, limit int) []*IOC {
	var results []*IOC
	count := 0

	s.iocs.Range(func(key, value interface{}) bool {
		if limit > 0 && count >= limit {
			return false
		}

		ioc := value.(*IOC)
		if s.matchesFilter(ioc, filter) {
			results = append(results, ioc)
			count++
		}

		return true
	})

	return results
}

// Stats returns store statistics.
func (s *Store) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_iocs": s.totalIOCs.Load(),
		"lookups":    s.lookups.Load(),
		"hits":       s.hits.Load(),
		"misses":     s.misses.Load(),
		"additions":  s.additions.Load(),
		"deletions":  s.deletions.Load(),
		"hit_rate":   s.calculateHitRate(),
	}
}

// Count returns the total number of IOCs.
func (s *Store) Count() int64 {
	return s.totalIOCs.Load()
}

// Clear removes all IOCs from the store.
func (s *Store) Clear() {
	s.iocs.Range(func(key, value interface{}) bool {
		s.iocs.Delete(key)
		return true
	})
	s.byID.Range(func(key, value interface{}) bool {
		s.byID.Delete(key)
		return true
	})
	s.totalIOCs.Store(0)
}

func (s *Store) buildKey(iocType IOCType, value string) string {
	return fmt.Sprintf("%s:%s", iocType, value)
}

func (s *Store) matchesFilter(ioc *IOC, filter IOCFilter) bool {
	// Type filter
	if len(filter.Types) > 0 {
		found := false
		for _, t := range filter.Types {
			if ioc.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Threat type filter
	if len(filter.ThreatTypes) > 0 {
		found := false
		for _, t := range filter.ThreatTypes {
			if ioc.ThreatType == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Severity filter
	if len(filter.Severities) > 0 {
		found := false
		for _, s := range filter.Severities {
			if ioc.Severity == s {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Confidence filter
	if filter.MinConfidence > 0 && ioc.Confidence < filter.MinConfidence {
		return false
	}

	// Active filter
	if filter.IsActive != nil && *filter.IsActive != ioc.IsActive {
		return false
	}

	// Whitelisted filter
	if filter.IsWhitelisted != nil && *filter.IsWhitelisted != ioc.IsWhitelisted {
		return false
	}

	// Validity filter
	if !filter.ValidAt.IsZero() {
		if !ioc.ValidFrom.IsZero() && filter.ValidAt.Before(ioc.ValidFrom) {
			return false
		}
		if !ioc.ValidUntil.IsZero() && filter.ValidAt.After(ioc.ValidUntil) {
			return false
		}
	}

	return true
}

func (s *Store) calculateHitRate() float64 {
	total := s.lookups.Load()
	if total == 0 {
		return 0
	}
	return float64(s.hits.Load()) / float64(total) * 100
}

func (s *Store) loadFromRepository() error {
	if s.repository == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	defer cancel()

	// Load active IOCs
	filter := IOCFilter{
		IsActive: boolPtr(true),
	}

	offset := 0
	batchSize := 10000

	for {
		iocs, _, err := s.repository.List(ctx, filter, batchSize, offset)
		if err != nil {
			return fmt.Errorf("failed to load IOCs: %w", err)
		}

		if len(iocs) == 0 {
			break
		}

		for _, ioc := range iocs {
			key := s.buildKey(ioc.Type, ioc.Value)
			s.iocs.Store(key, ioc)
			if ioc.ID != "" {
				s.byID.Store(ioc.ID, ioc)
			}
			s.totalIOCs.Add(1)
		}

		offset += len(iocs)

		if len(iocs) < batchSize {
			break
		}
	}

	return nil
}

func (s *Store) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

func (s *Store) cleanup() {
	now := time.Now()
	var expired int64

	s.iocs.Range(func(key, value interface{}) bool {
		ioc := value.(*IOC)
		if ioc.IsExpired() || (!ioc.ValidUntil.IsZero() && now.After(ioc.ValidUntil)) {
			s.iocs.Delete(key)
			if ioc.ID != "" {
				s.byID.Delete(ioc.ID)
			}
			expired++
		}
		return true
	})

	if expired > 0 {
		s.totalIOCs.Add(-expired)
		s.logger.Debug("cleaned up expired IOCs", "count", expired)
	}
}

func (s *Store) persistLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.PersistInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.persist()
		}
	}
}

func (s *Store) persist() {
	// Persist dirty IOCs to repository
	// This is a simplified implementation
	// In production, track dirty IOCs and batch persist them
}

func boolPtr(b bool) *bool {
	return &b
}
