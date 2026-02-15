// Package matcher provides high-performance IOC matching.
package matcher

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/ti/internal/ioc"
)

// MatchResult represents an IOC match result.
type MatchResult struct {
	IOC       *ioc.IOC               `json:"ioc"`
	MatchType string                 `json:"match_type"` // exact, prefix, cidr
	Field     string                 `json:"field"`
	Value     string                 `json:"value"`
	Score     float64                `json:"score"`
	Timestamp time.Time              `json:"timestamp"`
	Context   map[string]interface{} `json:"context,omitempty"`
}

// MatcherConfig holds matcher configuration.
type MatcherConfig struct {
	// Bloom filter settings
	BloomSize         uint          `json:"bloom_size"`
	BloomHashCount    uint          `json:"bloom_hash_count"`
	BloomFalsePositive float64      `json:"bloom_false_positive"`

	// Cache settings
	CacheSize int           `json:"cache_size"`
	CacheTTL  time.Duration `json:"cache_ttl"`

	// Performance settings
	MaxConcurrent int `json:"max_concurrent"`
}

// DefaultMatcherConfig returns default matcher configuration.
func DefaultMatcherConfig() MatcherConfig {
	return MatcherConfig{
		BloomSize:          10000000,
		BloomHashCount:     7,
		BloomFalsePositive: 0.01,
		CacheSize:          100000,
		CacheTTL:           5 * time.Minute,
		MaxConcurrent:      100,
	}
}

// Matcher provides high-performance IOC matching.
type Matcher struct {
	config    MatcherConfig
	store     *ioc.Store
	bloom     *BloomFilter
	domainTrie *Trie
	ipRadix   *RadixTree
	hashSet   sync.Map // For exact hash matching
	resultCh  chan *MatchResult
	logger    *slog.Logger

	ctx       context.Context
	cancel    context.CancelFunc

	// Metrics
	queries     atomic.Uint64
	matches     atomic.Uint64
	bloomHits   atomic.Uint64
	bloomMisses atomic.Uint64
}

// NewMatcher creates a new IOC matcher.
func NewMatcher(cfg MatcherConfig, store *ioc.Store, logger *slog.Logger) *Matcher {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Matcher{
		config:     cfg,
		store:      store,
		bloom:      NewBloomFilter(cfg.BloomSize, cfg.BloomHashCount),
		domainTrie: NewTrie(),
		ipRadix:    NewRadixTree(),
		resultCh:   make(chan *MatchResult, 10000),
		logger:     logger.With("component", "ioc-matcher"),
		ctx:        ctx,
		cancel:     cancel,
	}

	return m
}

// Start starts the matcher.
func (m *Matcher) Start() error {
	// Build indices from store
	if err := m.buildIndices(); err != nil {
		return err
	}

	m.logger.Info("IOC matcher started",
		"bloom_size", m.config.BloomSize,
		"domain_entries", m.domainTrie.Count(),
		"ip_entries", m.ipRadix.Count())

	return nil
}

// Stop stops the matcher.
func (m *Matcher) Stop() error {
	m.cancel()
	close(m.resultCh)
	return nil
}

// Rebuild rebuilds all indices from the store.
func (m *Matcher) Rebuild() error {
	m.bloom.Clear()
	m.domainTrie.Clear()
	m.ipRadix.Clear()
	m.hashSet = sync.Map{}

	return m.buildIndices()
}

// Match performs IOC matching against a set of indicators.
func (m *Matcher) Match(ctx context.Context, indicators map[string][]string) []*MatchResult {
	var results []*MatchResult
	m.queries.Add(1)

	for field, values := range indicators {
		for _, value := range values {
			if result := m.matchValue(ctx, field, value); result != nil {
				results = append(results, result)
				m.matches.Add(1)
			}
		}
	}

	return results
}

// MatchSingle matches a single indicator.
func (m *Matcher) MatchSingle(ctx context.Context, indicatorType ioc.IOCType, value string) *MatchResult {
	m.queries.Add(1)

	result := m.matchByType(ctx, indicatorType, value, string(indicatorType))
	if result != nil {
		m.matches.Add(1)
	}

	return result
}

// MatchIP matches an IP address.
func (m *Matcher) MatchIP(ctx context.Context, ip string) *MatchResult {
	return m.MatchSingle(ctx, ioc.TypeIP, ip)
}

// MatchDomain matches a domain name.
func (m *Matcher) MatchDomain(ctx context.Context, domain string) *MatchResult {
	return m.MatchSingle(ctx, ioc.TypeDomain, domain)
}

// MatchHash matches a file hash.
func (m *Matcher) MatchHash(ctx context.Context, hash string) *MatchResult {
	hashType := ioc.DetectIOCType(hash)
	return m.MatchSingle(ctx, hashType, hash)
}

// MatchURL matches a URL.
func (m *Matcher) MatchURL(ctx context.Context, url string) *MatchResult {
	return m.MatchSingle(ctx, ioc.TypeURL, url)
}

// Results returns the results channel.
func (m *Matcher) Results() <-chan *MatchResult {
	return m.resultCh
}

// Stats returns matcher statistics.
func (m *Matcher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"queries":       m.queries.Load(),
		"matches":       m.matches.Load(),
		"bloom_hits":    m.bloomHits.Load(),
		"bloom_misses":  m.bloomMisses.Load(),
		"domain_count":  m.domainTrie.Count(),
		"ip_count":      m.ipRadix.Count(),
		"bloom_entries": m.bloom.Count(),
	}
}

// AddIOC adds an IOC to the matcher indices.
func (m *Matcher) AddIOC(i *ioc.IOC) {
	// Add to bloom filter
	m.bloom.Add(i.Value)

	// Add to type-specific index
	switch i.Type {
	case ioc.TypeIP:
		m.ipRadix.Insert(i.Value, i)
	case ioc.TypeDomain:
		m.domainTrie.Insert(i.Value, i)
	case ioc.TypeMD5, ioc.TypeSHA1, ioc.TypeSHA256, ioc.TypeHash:
		m.hashSet.Store(i.Value, i)
	}
}

// RemoveIOC removes an IOC from the matcher indices.
func (m *Matcher) RemoveIOC(i *ioc.IOC) {
	// Note: Bloom filters don't support removal
	// For hash set and trie, we can remove
	switch i.Type {
	case ioc.TypeIP:
		m.ipRadix.Delete(i.Value)
	case ioc.TypeDomain:
		m.domainTrie.Delete(i.Value)
	case ioc.TypeMD5, ioc.TypeSHA1, ioc.TypeSHA256, ioc.TypeHash:
		m.hashSet.Delete(i.Value)
	}
}

func (m *Matcher) buildIndices() error {
	// Get all IOCs from store
	filter := ioc.IOCFilter{
		IsActive: boolPtr(true),
	}

	iocs := m.store.List(filter, 0) // 0 = no limit

	for _, i := range iocs {
		m.AddIOC(i)
	}

	m.logger.Debug("built indices",
		"total_iocs", len(iocs),
		"bloom_entries", m.bloom.Count(),
		"domain_entries", m.domainTrie.Count(),
		"ip_entries", m.ipRadix.Count())

	return nil
}

func (m *Matcher) matchValue(ctx context.Context, field, value string) *MatchResult {
	if value == "" {
		return nil
	}

	// Quick bloom filter check
	if !m.bloom.Contains(value) {
		m.bloomMisses.Add(1)
		return nil
	}
	m.bloomHits.Add(1)

	// Detect IOC type and match accordingly
	iocType := ioc.DetectIOCType(value)
	return m.matchByType(ctx, iocType, value, field)
}

func (m *Matcher) matchByType(ctx context.Context, iocType ioc.IOCType, value, field string) *MatchResult {
	switch iocType {
	case ioc.TypeIP:
		return m.matchIP(ctx, value, field)
	case ioc.TypeDomain:
		return m.matchDomain(ctx, value, field)
	case ioc.TypeMD5, ioc.TypeSHA1, ioc.TypeSHA256, ioc.TypeHash:
		return m.matchHash(ctx, value, field)
	case ioc.TypeURL:
		return m.matchURL(ctx, value, field)
	case ioc.TypeEmail:
		return m.matchEmail(ctx, value, field)
	default:
		return m.matchExact(ctx, iocType, value, field)
	}
}

func (m *Matcher) matchIP(ctx context.Context, ip, field string) *MatchResult {
	// Try exact match first
	if i := m.ipRadix.Search(ip); i != nil {
		return m.buildResult(i, "exact", field, ip)
	}

	// Try CIDR match
	if i := m.ipRadix.SearchCIDR(ip); i != nil {
		return m.buildResult(i, "cidr", field, ip)
	}

	// Fallback to store lookup
	if i, found := m.store.Lookup(ioc.TypeIP, ip); found {
		return m.buildResult(i, "exact", field, ip)
	}

	return nil
}

func (m *Matcher) matchDomain(ctx context.Context, domain, field string) *MatchResult {
	// Try exact match
	if i := m.domainTrie.Search(domain); i != nil {
		return m.buildResult(i, "exact", field, domain)
	}

	// Try subdomain match (domain suffix)
	if i := m.domainTrie.SearchSuffix(domain); i != nil {
		return m.buildResult(i, "subdomain", field, domain)
	}

	// Fallback to store lookup
	if i, found := m.store.Lookup(ioc.TypeDomain, domain); found {
		return m.buildResult(i, "exact", field, domain)
	}

	return nil
}

func (m *Matcher) matchHash(ctx context.Context, hash, field string) *MatchResult {
	// Check hash set
	if i, ok := m.hashSet.Load(hash); ok {
		return m.buildResult(i.(*ioc.IOC), "exact", field, hash)
	}

	// Fallback to store lookup
	hashType := ioc.DetectIOCType(hash)
	if i, found := m.store.Lookup(hashType, hash); found {
		return m.buildResult(i, "exact", field, hash)
	}

	return nil
}

func (m *Matcher) matchURL(ctx context.Context, url, field string) *MatchResult {
	// Extract domain from URL and check
	domain := extractDomainFromURL(url)
	if domain != "" {
		if result := m.matchDomain(ctx, domain, field); result != nil {
			result.MatchType = "url_domain"
			result.Value = url
			return result
		}
	}

	// Exact URL match
	if i, found := m.store.Lookup(ioc.TypeURL, url); found {
		return m.buildResult(i, "exact", field, url)
	}

	return nil
}

func (m *Matcher) matchEmail(ctx context.Context, email, field string) *MatchResult {
	// Extract domain from email and check
	domain := extractDomainFromEmail(email)
	if domain != "" {
		if result := m.matchDomain(ctx, domain, field); result != nil {
			result.MatchType = "email_domain"
			result.Value = email
			return result
		}
	}

	// Exact email match
	if i, found := m.store.Lookup(ioc.TypeEmail, email); found {
		return m.buildResult(i, "exact", field, email)
	}

	return nil
}

func (m *Matcher) matchExact(ctx context.Context, iocType ioc.IOCType, value, field string) *MatchResult {
	if i, found := m.store.Lookup(iocType, value); found {
		return m.buildResult(i, "exact", field, value)
	}
	return nil
}

func (m *Matcher) buildResult(i *ioc.IOC, matchType, field, value string) *MatchResult {
	return &MatchResult{
		IOC:       i,
		MatchType: matchType,
		Field:     field,
		Value:     value,
		Score:     calculateScore(i, matchType),
		Timestamp: time.Now(),
	}
}

func calculateScore(i *ioc.IOC, matchType string) float64 {
	// Base score from confidence
	score := float64(i.Confidence) / 100.0

	// Adjust based on match type
	switch matchType {
	case "exact":
		score *= 1.0
	case "cidr":
		score *= 0.9
	case "subdomain":
		score *= 0.8
	case "url_domain":
		score *= 0.7
	case "email_domain":
		score *= 0.7
	default:
		score *= 0.6
	}

	// Adjust based on severity
	switch i.Severity {
	case ioc.SeverityCritical:
		score *= 1.0
	case ioc.SeverityHigh:
		score *= 0.9
	case ioc.SeverityMedium:
		score *= 0.8
	case ioc.SeverityLow:
		score *= 0.7
	default:
		score *= 0.6
	}

	return score
}

func extractDomainFromURL(url string) string {
	// Simple domain extraction
	start := 0
	if len(url) > 8 && url[:8] == "https://" {
		start = 8
	} else if len(url) > 7 && url[:7] == "http://" {
		start = 7
	}

	end := start
	for i := start; i < len(url); i++ {
		if url[i] == '/' || url[i] == ':' || url[i] == '?' {
			end = i
			break
		}
		end = i + 1
	}

	return url[start:end]
}

func extractDomainFromEmail(email string) string {
	for i, c := range email {
		if c == '@' {
			return email[i+1:]
		}
	}
	return ""
}

func boolPtr(b bool) *bool {
	return &b
}
