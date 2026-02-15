// Package alert provides deduplication functionality for alerts.
package alert

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DedupCache provides alert deduplication using a time-based cache.
type DedupCache struct {
	entries   map[string]*dedupEntry
	mu        sync.RWMutex
	window    time.Duration
}

type dedupEntry struct {
	key       string
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// NewDedupCache creates a new deduplication cache.
func NewDedupCache(window time.Duration) *DedupCache {
	return &DedupCache{
		entries: make(map[string]*dedupEntry),
		window:  window,
	}
}

// IsDuplicate checks if the key represents a duplicate alert.
func (c *DedupCache) IsDuplicate(key string) bool {
	hash := c.hashKey(key)

	c.mu.RLock()
	entry, exists := c.entries[hash]
	c.mu.RUnlock()

	if !exists {
		return false
	}

	// Check if entry is still within the dedup window
	if time.Since(entry.lastSeen) > c.window {
		return false
	}

	return true
}

// Add adds a key to the deduplication cache.
func (c *DedupCache) Add(key string) {
	hash := c.hashKey(key)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[hash]; exists {
		entry.count++
		entry.lastSeen = now
	} else {
		c.entries[hash] = &dedupEntry{
			key:       key,
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
	}
}

// AddAndCheck adds a key and returns true if it was a duplicate.
func (c *DedupCache) AddAndCheck(key string) bool {
	hash := c.hashKey(key)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[hash]; exists {
		if time.Since(entry.lastSeen) <= c.window {
			entry.count++
			entry.lastSeen = now
			return true
		}
		// Entry expired, reset
		entry.count = 1
		entry.firstSeen = now
		entry.lastSeen = now
		return false
	}

	c.entries[hash] = &dedupEntry{
		key:       key,
		count:     1,
		firstSeen: now,
		lastSeen:  now,
	}
	return false
}

// GetCount returns the count for a key.
func (c *DedupCache) GetCount(key string) int {
	hash := c.hashKey(key)

	c.mu.RLock()
	defer c.mu.RUnlock()

	if entry, exists := c.entries[hash]; exists {
		return entry.count
	}
	return 0
}

// Size returns the number of entries in the cache.
func (c *DedupCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Cleanup removes expired entries from the cache.
func (c *DedupCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for hash, entry := range c.entries {
		if now.Sub(entry.lastSeen) > c.window {
			delete(c.entries, hash)
			removed++
		}
	}

	return removed
}

// Clear removes all entries from the cache.
func (c *DedupCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*dedupEntry)
}

// Stats returns cache statistics.
func (c *DedupCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalCount int
	var oldestEntry *dedupEntry
	var newestEntry *dedupEntry

	for _, entry := range c.entries {
		totalCount += entry.count

		if oldestEntry == nil || entry.firstSeen.Before(oldestEntry.firstSeen) {
			oldestEntry = entry
		}
		if newestEntry == nil || entry.lastSeen.After(newestEntry.lastSeen) {
			newestEntry = entry
		}
	}

	stats := map[string]interface{}{
		"size":        len(c.entries),
		"total_count": totalCount,
		"window_ms":   c.window.Milliseconds(),
	}

	if oldestEntry != nil {
		stats["oldest_entry_age_ms"] = time.Since(oldestEntry.firstSeen).Milliseconds()
	}
	if newestEntry != nil {
		stats["newest_entry_age_ms"] = time.Since(newestEntry.lastSeen).Milliseconds()
	}

	return stats
}

func (c *DedupCache) hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// BloomDedupCache provides memory-efficient deduplication using Bloom filter principles.
type BloomDedupCache struct {
	buckets    []uint64
	numBuckets int
	numHashes  int
	window     time.Duration
	timestamps []int64 // Unix timestamp for each bucket
	mu         sync.RWMutex
}

// NewBloomDedupCache creates a new Bloom filter-based dedup cache.
func NewBloomDedupCache(expectedItems int, falsePositiveRate float64, window time.Duration) *BloomDedupCache {
	// Calculate optimal number of buckets and hashes
	// m = -n*ln(p) / (ln(2)^2)
	// k = m/n * ln(2)
	numBuckets := int(float64(-expectedItems) * 2.302585 / (0.480453 * falsePositiveRate)) // ln(p) / ln(2)^2
	if numBuckets < 64 {
		numBuckets = 64
	}
	// Round up to next power of 2
	numBuckets = nextPowerOf2(numBuckets)

	numHashes := 3 // Good balance for most use cases

	return &BloomDedupCache{
		buckets:    make([]uint64, numBuckets/64+1),
		numBuckets: numBuckets,
		numHashes:  numHashes,
		window:     window,
		timestamps: make([]int64, numBuckets),
	}
}

// IsDuplicate checks if the key is likely a duplicate.
func (c *BloomDedupCache) IsDuplicate(key string) bool {
	hashes := c.getHashes(key)
	now := time.Now().Unix()

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, h := range hashes {
		idx := h % uint64(c.numBuckets)
		bucketIdx := idx / 64
		bitIdx := idx % 64

		// Check if bit is set and timestamp is within window
		if c.buckets[bucketIdx]&(1<<bitIdx) == 0 {
			return false
		}
		if now-c.timestamps[idx] > int64(c.window.Seconds()) {
			return false
		}
	}

	return true
}

// Add adds a key to the filter.
func (c *BloomDedupCache) Add(key string) {
	hashes := c.getHashes(key)
	now := time.Now().Unix()

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, h := range hashes {
		idx := h % uint64(c.numBuckets)
		bucketIdx := idx / 64
		bitIdx := idx % 64

		c.buckets[bucketIdx] |= 1 << bitIdx
		c.timestamps[idx] = now
	}
}

// Clear resets the filter.
func (c *BloomDedupCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.buckets {
		c.buckets[i] = 0
	}
	for i := range c.timestamps {
		c.timestamps[i] = 0
	}
}

func (c *BloomDedupCache) getHashes(key string) []uint64 {
	h1 := fnv64a(key)
	h2 := murmur64(key)

	hashes := make([]uint64, c.numHashes)
	for i := 0; i < c.numHashes; i++ {
		hashes[i] = h1 + uint64(i)*h2
	}
	return hashes
}

// FNV-1a 64-bit hash
func fnv64a(s string) uint64 {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211

	hash := uint64(offset64)
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime64
	}
	return hash
}

// Simple Murmur-like hash
func murmur64(s string) uint64 {
	const c1 = 0x87c37b91114253d5
	const c2 = 0x4cf5ad432745937f

	h := uint64(len(s)) * c1

	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h = rotl64(h, 31)
		h *= c2
	}

	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33

	return h
}

func rotl64(x uint64, r uint64) uint64 {
	return (x << r) | (x >> (64 - r))
}

func nextPowerOf2(n int) int {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}
