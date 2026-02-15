// Package matcher provides Bloom filter for fast IOC lookups.
package matcher

import (
	"hash/fnv"
	"math"
	"sync"
	"sync/atomic"
)

// BloomFilter implements a thread-safe Bloom filter.
type BloomFilter struct {
	bits      []uint64
	size      uint
	hashCount uint
	count     atomic.Uint64
	mu        sync.RWMutex
}

// NewBloomFilter creates a new Bloom filter.
func NewBloomFilter(size, hashCount uint) *BloomFilter {
	// Round up to multiple of 64
	numWords := (size + 63) / 64

	return &BloomFilter{
		bits:      make([]uint64, numWords),
		size:      numWords * 64,
		hashCount: hashCount,
	}
}

// NewBloomFilterWithFPRate creates a Bloom filter for expected items and FP rate.
func NewBloomFilterWithFPRate(expectedItems uint, fpRate float64) *BloomFilter {
	// Calculate optimal size: m = -n*ln(p) / (ln(2)^2)
	m := uint(math.Ceil(-float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))

	// Calculate optimal hash count: k = (m/n) * ln(2)
	k := uint(math.Ceil(float64(m) / float64(expectedItems) * math.Ln2))

	// Ensure reasonable values
	if k < 1 {
		k = 1
	}
	if k > 20 {
		k = 20
	}

	return NewBloomFilter(m, k)
}

// Add adds an item to the Bloom filter.
func (bf *BloomFilter) Add(item string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	locations := bf.getLocations(item)
	for _, loc := range locations {
		word := loc / 64
		bit := loc % 64
		bf.bits[word] |= 1 << bit
	}

	bf.count.Add(1)
}

// AddBytes adds a byte slice to the Bloom filter.
func (bf *BloomFilter) AddBytes(item []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	locations := bf.getLocationBytes(item)
	for _, loc := range locations {
		word := loc / 64
		bit := loc % 64
		bf.bits[word] |= 1 << bit
	}

	bf.count.Add(1)
}

// Contains checks if an item might be in the Bloom filter.
func (bf *BloomFilter) Contains(item string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	locations := bf.getLocations(item)
	for _, loc := range locations {
		word := loc / 64
		bit := loc % 64
		if bf.bits[word]&(1<<bit) == 0 {
			return false
		}
	}

	return true
}

// ContainsBytes checks if a byte slice might be in the Bloom filter.
func (bf *BloomFilter) ContainsBytes(item []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	locations := bf.getLocationBytes(item)
	for _, loc := range locations {
		word := loc / 64
		bit := loc % 64
		if bf.bits[word]&(1<<bit) == 0 {
			return false
		}
	}

	return true
}

// Count returns the number of items added.
func (bf *BloomFilter) Count() uint64 {
	return bf.count.Load()
}

// Size returns the size of the bit array.
func (bf *BloomFilter) Size() uint {
	return bf.size
}

// HashCount returns the number of hash functions.
func (bf *BloomFilter) HashCount() uint {
	return bf.hashCount
}

// Clear resets the Bloom filter.
func (bf *BloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count.Store(0)
}

// FillRatio returns the ratio of set bits.
func (bf *BloomFilter) FillRatio() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	var setBits uint
	for _, word := range bf.bits {
		setBits += uint(popCount(word))
	}

	return float64(setBits) / float64(bf.size)
}

// EstimateFalsePositiveRate estimates the current false positive rate.
func (bf *BloomFilter) EstimateFalsePositiveRate() float64 {
	fillRatio := bf.FillRatio()
	return math.Pow(fillRatio, float64(bf.hashCount))
}

// getLocations returns the bit positions for an item.
func (bf *BloomFilter) getLocations(item string) []uint {
	return bf.getLocationBytes([]byte(item))
}

// getLocationBytes returns the bit positions for a byte slice.
func (bf *BloomFilter) getLocationBytes(item []byte) []uint {
	locations := make([]uint, bf.hashCount)

	// Use double hashing: h(i) = h1 + i*h2
	h1 := bf.hash1(item)
	h2 := bf.hash2(item)

	for i := uint(0); i < bf.hashCount; i++ {
		locations[i] = (h1 + i*h2) % bf.size
	}

	return locations
}

// hash1 computes the first hash using FNV-1a.
func (bf *BloomFilter) hash1(data []byte) uint {
	h := fnv.New64a()
	h.Write(data)
	return uint(h.Sum64() % uint64(bf.size))
}

// hash2 computes the second hash using FNV-1.
func (bf *BloomFilter) hash2(data []byte) uint {
	h := fnv.New64()
	h.Write(data)
	return uint(h.Sum64() % uint64(bf.size))
}

// popCount counts the number of set bits in a uint64.
func popCount(x uint64) int {
	count := 0
	for x != 0 {
		count++
		x &= x - 1
	}
	return count
}

// ScalableBloomFilter implements a scalable Bloom filter that grows as needed.
type ScalableBloomFilter struct {
	filters       []*BloomFilter
	expectedItems uint
	fpRate        float64
	growthRate    float64
	mu            sync.RWMutex
}

// NewScalableBloomFilter creates a new scalable Bloom filter.
func NewScalableBloomFilter(expectedItems uint, fpRate, growthRate float64) *ScalableBloomFilter {
	sbf := &ScalableBloomFilter{
		filters:       make([]*BloomFilter, 0),
		expectedItems: expectedItems,
		fpRate:        fpRate,
		growthRate:    growthRate,
	}

	// Create initial filter
	sbf.addFilter()

	return sbf
}

// Add adds an item to the scalable Bloom filter.
func (sbf *ScalableBloomFilter) Add(item string) {
	sbf.mu.Lock()
	defer sbf.mu.Unlock()

	// Check if current filter is getting full
	currentFilter := sbf.filters[len(sbf.filters)-1]
	if currentFilter.FillRatio() > 0.5 {
		sbf.addFilter()
		currentFilter = sbf.filters[len(sbf.filters)-1]
	}

	currentFilter.Add(item)
}

// Contains checks if an item might be in any of the filters.
func (sbf *ScalableBloomFilter) Contains(item string) bool {
	sbf.mu.RLock()
	defer sbf.mu.RUnlock()

	for _, bf := range sbf.filters {
		if bf.Contains(item) {
			return true
		}
	}

	return false
}

// Count returns the total number of items added.
func (sbf *ScalableBloomFilter) Count() uint64 {
	sbf.mu.RLock()
	defer sbf.mu.RUnlock()

	var total uint64
	for _, bf := range sbf.filters {
		total += bf.Count()
	}
	return total
}

func (sbf *ScalableBloomFilter) addFilter() {
	// Each new filter has tighter FP rate: fpRate * (growthRate ^ numFilters)
	filterFP := sbf.fpRate * math.Pow(sbf.growthRate, float64(len(sbf.filters)))

	// Each new filter handles more items
	filterItems := uint(float64(sbf.expectedItems) * math.Pow(sbf.growthRate, float64(len(sbf.filters))))

	bf := NewBloomFilterWithFPRate(filterItems, filterFP)
	sbf.filters = append(sbf.filters, bf)
}

// CountingBloomFilter implements a counting Bloom filter that supports removal.
type CountingBloomFilter struct {
	counts    []uint8
	size      uint
	hashCount uint
	count     atomic.Uint64
	mu        sync.RWMutex
}

// NewCountingBloomFilter creates a new counting Bloom filter.
func NewCountingBloomFilter(size, hashCount uint) *CountingBloomFilter {
	return &CountingBloomFilter{
		counts:    make([]uint8, size),
		size:      size,
		hashCount: hashCount,
	}
}

// Add adds an item to the counting Bloom filter.
func (cbf *CountingBloomFilter) Add(item string) {
	cbf.mu.Lock()
	defer cbf.mu.Unlock()

	locations := cbf.getLocations(item)
	for _, loc := range locations {
		if cbf.counts[loc] < 255 { // Prevent overflow
			cbf.counts[loc]++
		}
	}

	cbf.count.Add(1)
}

// Remove removes an item from the counting Bloom filter.
func (cbf *CountingBloomFilter) Remove(item string) bool {
	cbf.mu.Lock()
	defer cbf.mu.Unlock()

	locations := cbf.getLocations(item)

	// Check if item might exist
	for _, loc := range locations {
		if cbf.counts[loc] == 0 {
			return false
		}
	}

	// Decrement counters
	for _, loc := range locations {
		if cbf.counts[loc] > 0 {
			cbf.counts[loc]--
		}
	}

	return true
}

// Contains checks if an item might be in the counting Bloom filter.
func (cbf *CountingBloomFilter) Contains(item string) bool {
	cbf.mu.RLock()
	defer cbf.mu.RUnlock()

	locations := cbf.getLocations(item)
	for _, loc := range locations {
		if cbf.counts[loc] == 0 {
			return false
		}
	}

	return true
}

func (cbf *CountingBloomFilter) getLocations(item string) []uint {
	data := []byte(item)
	locations := make([]uint, cbf.hashCount)

	h1 := cbf.hash1(data)
	h2 := cbf.hash2(data)

	for i := uint(0); i < cbf.hashCount; i++ {
		locations[i] = (h1 + i*h2) % cbf.size
	}

	return locations
}

func (cbf *CountingBloomFilter) hash1(data []byte) uint {
	h := fnv.New64a()
	h.Write(data)
	return uint(h.Sum64() % uint64(cbf.size))
}

func (cbf *CountingBloomFilter) hash2(data []byte) uint {
	h := fnv.New64()
	h.Write(data)
	return uint(h.Sum64() % uint64(cbf.size))
}
