// Package cache provides Redis-based caching for IOC lookups.
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
	"github.com/siem-soar-platform/services/ti/internal/matcher"
)

const (
	// Key prefixes
	prefixIOC       = "ti:ioc:"
	prefixIOCByType = "ti:ioc:type:"
	prefixIOCLookup = "ti:lookup:"
	prefixBloom     = "ti:bloom"
	prefixStats     = "ti:stats"

	// Default TTL values
	defaultIOCTTL    = 24 * time.Hour
	defaultLookupTTL = 5 * time.Minute
	negativeResultTTL = 1 * time.Minute
)

// CacheConfig holds cache configuration.
type CacheConfig struct {
	IOCTTL         time.Duration `json:"ioc_ttl"`
	LookupTTL      time.Duration `json:"lookup_ttl"`
	NegativeTTL    time.Duration `json:"negative_ttl"`
	BloomCapacity  uint          `json:"bloom_capacity"`
	BloomFPRate    float64       `json:"bloom_fp_rate"`
	EnableBloom    bool          `json:"enable_bloom"`
}

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		IOCTTL:        defaultIOCTTL,
		LookupTTL:     defaultLookupTTL,
		NegativeTTL:   negativeResultTTL,
		BloomCapacity: 100_000_000, // 100M IOC capacity
		BloomFPRate:   0.01,        // 1% false positive rate
		EnableBloom:   true,
	}
}

// IOCCache provides Redis-backed caching for IOCs with Bloom filter.
type IOCCache struct {
	client  *redis.Client
	config  CacheConfig
	bloom   *matcher.BloomFilter
	logger  *slog.Logger

	// Metrics
	hits   atomic.Uint64
	misses atomic.Uint64
	sets   atomic.Uint64
}

// NewIOCCache creates a new IOC cache.
func NewIOCCache(client *redis.Client, cfg CacheConfig, logger *slog.Logger) *IOCCache {
	var bloom *matcher.BloomFilter
	if cfg.EnableBloom {
		bloom = matcher.NewBloomFilterWithFPRate(cfg.BloomCapacity, cfg.BloomFPRate)
	}

	return &IOCCache{
		client: client,
		config: cfg,
		bloom:  bloom,
		logger: logger.With("component", "ioc-cache"),
	}
}

// Get retrieves an IOC from cache by ID.
func (c *IOCCache) Get(ctx context.Context, id string) (*ioc.IOC, error) {
	key := prefixIOC + id

	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			c.misses.Add(1)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get IOC from cache: %w", err)
	}

	c.hits.Add(1)

	var i ioc.IOC
	if err := json.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to unmarshal IOC: %w", err)
	}

	return &i, nil
}

// Set stores an IOC in the cache.
func (c *IOCCache) Set(ctx context.Context, i *ioc.IOC) error {
	if i == nil || i.ID == "" {
		return fmt.Errorf("invalid IOC")
	}

	data, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("failed to marshal IOC: %w", err)
	}

	key := prefixIOC + i.ID
	if err := c.client.Set(ctx, key, data, c.config.IOCTTL).Err(); err != nil {
		return fmt.Errorf("failed to set IOC in cache: %w", err)
	}

	// Also set lookup key for type:value
	lookupKey := c.buildLookupKey(i.Type, i.Value)
	if err := c.client.Set(ctx, lookupKey, i.ID, c.config.IOCTTL).Err(); err != nil {
		c.logger.Warn("failed to set lookup key", "error", err)
	}

	// Add to bloom filter
	if c.bloom != nil {
		c.bloom.Add(i.Value)
	}

	c.sets.Add(1)

	return nil
}

// SetBatch stores multiple IOCs in the cache.
func (c *IOCCache) SetBatch(ctx context.Context, iocs []*ioc.IOC) error {
	if len(iocs) == 0 {
		return nil
	}

	pipe := c.client.Pipeline()

	for _, i := range iocs {
		if i == nil || i.ID == "" {
			continue
		}

		data, err := json.Marshal(i)
		if err != nil {
			c.logger.Warn("failed to marshal IOC", "id", i.ID, "error", err)
			continue
		}

		key := prefixIOC + i.ID
		pipe.Set(ctx, key, data, c.config.IOCTTL)

		// Lookup key
		lookupKey := c.buildLookupKey(i.Type, i.Value)
		pipe.Set(ctx, lookupKey, i.ID, c.config.IOCTTL)

		// Bloom filter
		if c.bloom != nil {
			c.bloom.Add(i.Value)
		}
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute batch set: %w", err)
	}

	c.sets.Add(uint64(len(iocs)))

	return nil
}

// Delete removes an IOC from the cache.
func (c *IOCCache) Delete(ctx context.Context, id string) error {
	key := prefixIOC + id
	return c.client.Del(ctx, key).Err()
}

// Lookup performs a fast IOC lookup by type and value.
func (c *IOCCache) Lookup(ctx context.Context, iocType ioc.IOCType, value string) (*ioc.IOC, bool, error) {
	// Fast negative check with bloom filter
	if c.bloom != nil && !c.bloom.Contains(value) {
		c.misses.Add(1)
		return nil, false, nil // Definitely not in cache
	}

	// Check lookup key
	lookupKey := c.buildLookupKey(iocType, value)
	id, err := c.client.Get(ctx, lookupKey).Result()
	if err != nil {
		if err == redis.Nil {
			c.misses.Add(1)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get lookup key: %w", err)
	}

	// Get full IOC
	i, err := c.Get(ctx, id)
	if err != nil {
		return nil, false, err
	}

	if i == nil {
		c.misses.Add(1)
		return nil, false, nil
	}

	c.hits.Add(1)
	return i, true, nil
}

// LookupResult stores IOC lookup result with metadata.
type LookupResult struct {
	IOC       *ioc.IOC `json:"ioc,omitempty"`
	Found     bool     `json:"found"`
	CacheHit  bool     `json:"cache_hit"`
	BloomHit  bool     `json:"bloom_hit"`
	Timestamp time.Time `json:"timestamp"`
}

// CachedLookup performs a lookup with result caching.
func (c *IOCCache) CachedLookup(ctx context.Context, iocType ioc.IOCType, value string) (*LookupResult, error) {
	// Check cached result first
	resultKey := prefixIOCLookup + string(iocType) + ":" + value
	data, err := c.client.Get(ctx, resultKey).Bytes()
	if err == nil {
		var result LookupResult
		if err := json.Unmarshal(data, &result); err == nil {
			result.CacheHit = true
			c.hits.Add(1)
			return &result, nil
		}
	}

	// Bloom filter check
	bloomHit := true
	if c.bloom != nil && !c.bloom.Contains(value) {
		bloomHit = false
		// Cache negative result
		result := &LookupResult{
			Found:     false,
			CacheHit:  false,
			BloomHit:  false,
			Timestamp: time.Now(),
		}
		c.cacheResult(ctx, resultKey, result, c.config.NegativeTTL)
		c.misses.Add(1)
		return result, nil
	}

	// Lookup in cache
	i, found, err := c.Lookup(ctx, iocType, value)
	if err != nil {
		return nil, err
	}

	result := &LookupResult{
		IOC:       i,
		Found:     found,
		CacheHit:  false,
		BloomHit:  bloomHit,
		Timestamp: time.Now(),
	}

	// Cache the result
	ttl := c.config.NegativeTTL
	if found {
		ttl = c.config.LookupTTL
	}
	c.cacheResult(ctx, resultKey, result, ttl)

	return result, nil
}

// BatchLookup performs multiple IOC lookups.
func (c *IOCCache) BatchLookup(ctx context.Context, indicators []struct {
	Type  ioc.IOCType
	Value string
}) (map[string]*LookupResult, error) {
	results := make(map[string]*LookupResult)

	for _, ind := range indicators {
		key := string(ind.Type) + ":" + ind.Value
		result, err := c.CachedLookup(ctx, ind.Type, ind.Value)
		if err != nil {
			c.logger.Warn("batch lookup failed for indicator", "type", ind.Type, "value", ind.Value, "error", err)
			results[key] = &LookupResult{Found: false, Timestamp: time.Now()}
			continue
		}
		results[key] = result
	}

	return results, nil
}

// MightContain checks the bloom filter for a value (fast negative check).
func (c *IOCCache) MightContain(value string) bool {
	if c.bloom == nil {
		return true // Conservative: assume it might exist
	}
	return c.bloom.Contains(value)
}

// AddToBloom adds a value to the bloom filter.
func (c *IOCCache) AddToBloom(value string) {
	if c.bloom != nil {
		c.bloom.Add(value)
	}
}

// AddBatchToBloom adds multiple values to the bloom filter.
func (c *IOCCache) AddBatchToBloom(values []string) {
	if c.bloom == nil {
		return
	}
	for _, v := range values {
		c.bloom.Add(v)
	}
}

// RebuildBloom rebuilds the bloom filter from a list of values.
func (c *IOCCache) RebuildBloom(values []string) {
	if c.bloom == nil {
		return
	}
	c.bloom.Clear()
	for _, v := range values {
		c.bloom.Add(v)
	}
	c.logger.Info("rebuilt bloom filter", "count", len(values))
}

// BloomStats returns bloom filter statistics.
func (c *IOCCache) BloomStats() map[string]interface{} {
	if c.bloom == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":       true,
		"size":          c.bloom.Size(),
		"count":         c.bloom.Count(),
		"fill_ratio":    c.bloom.FillRatio(),
		"fp_rate":       c.bloom.EstimateFalsePositiveRate(),
	}
}

// Stats returns cache statistics.
func (c *IOCCache) Stats() map[string]interface{} {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses

	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"hits":      hits,
		"misses":    misses,
		"sets":      c.sets.Load(),
		"hit_rate":  hitRate,
		"bloom":     c.BloomStats(),
	}
}

// Clear clears all IOC cache entries.
func (c *IOCCache) Clear(ctx context.Context) error {
	// Clear IOC keys
	iter := c.client.Scan(ctx, 0, prefixIOC+"*", 1000).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			c.logger.Warn("failed to delete cache key", "key", iter.Val(), "error", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan cache keys: %w", err)
	}

	// Clear lookup keys
	iter = c.client.Scan(ctx, 0, prefixIOCLookup+"*", 1000).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			c.logger.Warn("failed to delete lookup key", "key", iter.Val(), "error", err)
		}
	}

	// Clear bloom filter
	if c.bloom != nil {
		c.bloom.Clear()
	}

	c.logger.Info("cache cleared")
	return nil
}

// Ping checks Redis connectivity.
func (c *IOCCache) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the cache connection.
func (c *IOCCache) Close() error {
	return c.client.Close()
}

func (c *IOCCache) buildLookupKey(iocType ioc.IOCType, value string) string {
	return prefixIOCByType + string(iocType) + ":" + value
}

func (c *IOCCache) cacheResult(ctx context.Context, key string, result *LookupResult, ttl time.Duration) {
	data, err := json.Marshal(result)
	if err != nil {
		c.logger.Warn("failed to marshal lookup result", "error", err)
		return
	}
	if err := c.client.Set(ctx, key, data, ttl).Err(); err != nil {
		c.logger.Warn("failed to cache lookup result", "error", err)
	}
}

// Warmup loads IOCs from repository into cache.
func (c *IOCCache) Warmup(ctx context.Context, iocs []*ioc.IOC) error {
	if len(iocs) == 0 {
		return nil
	}

	c.logger.Info("warming up cache", "ioc_count", len(iocs))

	// Batch set IOCs
	if err := c.SetBatch(ctx, iocs); err != nil {
		return fmt.Errorf("failed to warm up cache: %w", err)
	}

	// Rebuild bloom filter
	values := make([]string, len(iocs))
	for i, ioc := range iocs {
		values[i] = ioc.Value
	}
	c.RebuildBloom(values)

	c.logger.Info("cache warmup complete", "ioc_count", len(iocs), "bloom_count", c.bloom.Count())

	return nil
}

// InvalidateByType invalidates all IOCs of a specific type.
func (c *IOCCache) InvalidateByType(ctx context.Context, iocType ioc.IOCType) error {
	pattern := prefixIOCByType + string(iocType) + ":*"
	iter := c.client.Scan(ctx, 0, pattern, 1000).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			c.logger.Warn("failed to delete cache key", "key", iter.Val(), "error", err)
		}
	}
	return iter.Err()
}

// RecordHit updates hit statistics in Redis for distributed tracking.
func (c *IOCCache) RecordHit(ctx context.Context, iocID string) error {
	key := prefixStats + ":hits:" + iocID
	return c.client.Incr(ctx, key).Err()
}

// GetHitCounts retrieves hit counts for multiple IOCs.
func (c *IOCCache) GetHitCounts(ctx context.Context, iocIDs []string) (map[string]int64, error) {
	if len(iocIDs) == 0 {
		return make(map[string]int64), nil
	}

	keys := make([]string, len(iocIDs))
	for i, id := range iocIDs {
		keys[i] = prefixStats + ":hits:" + id
	}

	vals, err := c.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get hit counts: %w", err)
	}

	result := make(map[string]int64)
	for i, id := range iocIDs {
		if vals[i] != nil {
			if count, ok := vals[i].(string); ok {
				var n int64
				fmt.Sscanf(count, "%d", &n)
				result[id] = n
			}
		}
	}

	return result, nil
}
