// Package federation provides query result caching.
package federation

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Cache provides caching for federated query results.
type Cache struct {
	ttl     time.Duration
	items   map[string]*cacheItem
	mu      sync.RWMutex
	maxSize int
	stats   CacheStats
}

// cacheItem represents a cached item.
type cacheItem struct {
	result    *FederatedResult
	createdAt time.Time
	expiresAt time.Time
	hitCount  int
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Hits       int64
	Misses     int64
	Evictions  int64
	Size       int
	mu         sync.Mutex
}

// NewCache creates a new cache with the specified TTL.
func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		ttl:     ttl,
		items:   make(map[string]*cacheItem),
		maxSize: 1000, // Default max items
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Get retrieves a cached result.
func (c *Cache) Get(key string) *FederatedResult {
	c.mu.RLock()
	item, exists := c.items[key]
	c.mu.RUnlock()

	if !exists {
		c.stats.mu.Lock()
		c.stats.Misses++
		c.stats.mu.Unlock()
		return nil
	}

	// Check expiration
	if time.Now().After(item.expiresAt) {
		c.Delete(key)
		c.stats.mu.Lock()
		c.stats.Misses++
		c.stats.mu.Unlock()
		return nil
	}

	// Update hit count
	c.mu.Lock()
	item.hitCount++
	c.mu.Unlock()

	c.stats.mu.Lock()
	c.stats.Hits++
	c.stats.mu.Unlock()

	return item.result
}

// Set stores a result in the cache.
func (c *Cache) Set(key string, result *FederatedResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict
	if len(c.items) >= c.maxSize {
		c.evictLRU()
	}

	c.items[key] = &cacheItem{
		result:    result,
		createdAt: time.Now(),
		expiresAt: time.Now().Add(c.ttl),
		hitCount:  0,
	}

	c.stats.mu.Lock()
	c.stats.Size = len(c.items)
	c.stats.mu.Unlock()
}

// Delete removes an item from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)

	c.stats.mu.Lock()
	c.stats.Size = len(c.items)
	c.stats.mu.Unlock()
}

// Clear removes all items from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*cacheItem)

	c.stats.mu.Lock()
	c.stats.Size = 0
	c.stats.mu.Unlock()
}

// evictLRU removes the least recently used item.
func (c *Cache) evictLRU() {
	var lruKey string
	var lruItem *cacheItem

	for key, item := range c.items {
		if lruItem == nil || item.hitCount < lruItem.hitCount {
			lruKey = key
			lruItem = item
		}
	}

	if lruKey != "" {
		delete(c.items, lruKey)
		c.stats.mu.Lock()
		c.stats.Evictions++
		c.stats.mu.Unlock()
	}
}

// cleanup periodically removes expired items.
func (c *Cache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		c.removeExpired()
	}
}

// removeExpired removes all expired items.
func (c *Cache) removeExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, item := range c.items {
		if now.After(item.expiresAt) {
			delete(c.items, key)
		}
	}

	c.stats.mu.Lock()
	c.stats.Size = len(c.items)
	c.stats.mu.Unlock()
}

// GetStats returns cache statistics.
func (c *Cache) GetStats() CacheStats {
	c.stats.mu.Lock()
	defer c.stats.mu.Unlock()
	return c.stats
}

// SetMaxSize sets the maximum cache size.
func (c *Cache) SetMaxSize(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxSize = size
}

// SetTTL sets the cache TTL.
func (c *Cache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// QueryCacheKey generates a cache key for a query.
func QueryCacheKey(query *FederatedQuery) string {
	// Build a unique key from query parameters
	data := query.Query + "|" + string(query.Language)

	for _, t := range query.Targets {
		data += "|" + string(t)
	}

	if !query.TimeRange.Start.IsZero() {
		data += "|" + query.TimeRange.Start.Format(time.RFC3339)
	}
	if !query.TimeRange.End.IsZero() {
		data += "|" + query.TimeRange.End.Format(time.RFC3339)
	}
	if query.TimeRange.Relative != "" {
		data += "|" + query.TimeRange.Relative
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// CachedQuery represents metadata about a cached query.
type CachedQuery struct {
	Key       string    `json:"key"`
	Query     string    `json:"query"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	HitCount  int       `json:"hit_count"`
}

// ListCachedQueries returns information about all cached queries.
func (c *Cache) ListCachedQueries() []CachedQuery {
	c.mu.RLock()
	defer c.mu.RUnlock()

	queries := make([]CachedQuery, 0, len(c.items))
	for key, item := range c.items {
		queries = append(queries, CachedQuery{
			Key:       key,
			Query:     item.result.ID,
			CreatedAt: item.createdAt,
			ExpiresAt: item.expiresAt,
			HitCount:  item.hitCount,
		})
	}

	return queries
}
