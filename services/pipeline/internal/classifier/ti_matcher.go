// Package classifier provides event classification and IOC matching.
package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

// IOCType represents the type of indicator.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeHash   IOCType = "hash"
	IOCTypeURL    IOCType = "url"
	IOCTypeEmail  IOCType = "email"
	IOCTypeMD5    IOCType = "md5"
	IOCTypeSHA1   IOCType = "sha1"
	IOCTypeSHA256 IOCType = "sha256"
)

// ThreatType represents the type of threat.
type ThreatType string

const (
	ThreatMalware    ThreatType = "malware"
	ThreatC2         ThreatType = "c2"
	ThreatPhishing   ThreatType = "phishing"
	ThreatBotnet     ThreatType = "botnet"
	ThreatRansomware ThreatType = "ransomware"
	ThreatScanning   ThreatType = "scanning"
	ThreatSpam       ThreatType = "spam"
	ThreatUnknown    ThreatType = "unknown"
)

// IOCEntry represents a threat intelligence IOC.
type IOCEntry struct {
	Type       IOCType    `json:"type"`
	Value      string     `json:"value"`
	Source     string     `json:"source"`      // threatfox, abuseipdb, misp, kisa
	ThreatType ThreatType `json:"threat_type"` // malware, c2, phishing, etc.
	Confidence float32    `json:"confidence"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Tags       []string   `json:"tags"`
}

// IOCMatch represents a matched IOC.
type IOCMatch struct {
	IOC          *IOCEntry `json:"ioc"`
	MatchedIn    string    `json:"matched_in"`    // field name where IOC was found
	MatchedValue string    `json:"matched_value"` // actual value that matched
}

// ExtractedIOC represents an extracted potential IOC from event data.
type ExtractedIOC struct {
	Type  IOCType `json:"type"`
	Value string  `json:"value"`
	Field string  `json:"field"`
}

// CIDREntry represents a CIDR range IOC.
type CIDREntry struct {
	Network *net.IPNet
	IOC     *IOCEntry
}

// IPStore stores IP IOCs with CIDR support.
type IPStore struct {
	ips   map[string]*IOCEntry // exact match
	cidrs []CIDREntry          // CIDR range match
	mu    sync.RWMutex
}

// NewIPStore creates a new IP store.
func NewIPStore() *IPStore {
	return &IPStore{
		ips:   make(map[string]*IOCEntry),
		cidrs: make([]CIDREntry, 0),
	}
}

// Add adds an IP or CIDR to the store.
func (s *IPStore) Add(ipStr string, ioc *IOCEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if CIDR
	if strings.Contains(ipStr, "/") {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err == nil {
			s.cidrs = append(s.cidrs, CIDREntry{Network: ipNet, IOC: ioc})
			return
		}
	}

	// Exact IP
	s.ips[ipStr] = ioc
}

// Search searches for an IP match.
func (s *IPStore) Search(ipStr string) *IOCEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact match
	if ioc, ok := s.ips[ipStr]; ok {
		return ioc
	}

	// CIDR match
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	for _, entry := range s.cidrs {
		if entry.Network.Contains(ip) {
			return entry.IOC
		}
	}

	return nil
}

// Count returns the number of IPs in the store.
func (s *IPStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ips) + len(s.cidrs)
}

// Clear removes all entries.
func (s *IPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ips = make(map[string]*IOCEntry)
	s.cidrs = make([]CIDREntry, 0)
}

// DomainStore stores domain IOCs with subdomain matching using a trie.
type DomainStore struct {
	domains map[string]*IOCEntry
	mu      sync.RWMutex
}

// NewDomainStore creates a new domain store.
func NewDomainStore() *DomainStore {
	return &DomainStore{
		domains: make(map[string]*IOCEntry),
	}
}

// Add adds a domain to the store.
func (s *DomainStore) Add(domain string, ioc *IOCEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains[strings.ToLower(domain)] = ioc
}

// Search searches for a domain match including subdomain matching.
func (s *DomainStore) Search(domain string) *IOCEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	domain = strings.ToLower(domain)

	// Exact match
	if ioc, ok := s.domains[domain]; ok {
		return ioc
	}

	// Subdomain match (check if any stored domain is a suffix)
	for storedDomain, ioc := range s.domains {
		if strings.HasSuffix(domain, "."+storedDomain) {
			return ioc
		}
	}

	return nil
}

// Count returns the number of domains in the store.
func (s *DomainStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.domains)
}

// Clear removes all entries.
func (s *DomainStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = make(map[string]*IOCEntry)
}

// HashStore stores file hash IOCs.
type HashStore struct {
	md5    map[string]*IOCEntry
	sha1   map[string]*IOCEntry
	sha256 map[string]*IOCEntry
	mu     sync.RWMutex
}

// NewHashStore creates a new hash store.
func NewHashStore() *HashStore {
	return &HashStore{
		md5:    make(map[string]*IOCEntry),
		sha1:   make(map[string]*IOCEntry),
		sha256: make(map[string]*IOCEntry),
	}
}

// Add adds a hash to the store.
func (s *HashStore) Add(hash string, ioc *IOCEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	hash = strings.ToLower(hash)
	switch len(hash) {
	case 32:
		s.md5[hash] = ioc
	case 40:
		s.sha1[hash] = ioc
	case 64:
		s.sha256[hash] = ioc
	}
}

// Search searches for a hash match.
func (s *HashStore) Search(hash string) *IOCEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	hash = strings.ToLower(hash)
	switch len(hash) {
	case 32:
		return s.md5[hash]
	case 40:
		return s.sha1[hash]
	case 64:
		return s.sha256[hash]
	}
	return nil
}

// Count returns the total number of hashes.
func (s *HashStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.md5) + len(s.sha1) + len(s.sha256)
}

// Clear removes all entries.
func (s *HashStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.md5 = make(map[string]*IOCEntry)
	s.sha1 = make(map[string]*IOCEntry)
	s.sha256 = make(map[string]*IOCEntry)
}

// BloomFilter implements a simple bloom filter for fast IOC lookups.
type BloomFilter struct {
	bits      []uint64
	size      uint
	hashCount uint
	mu        sync.RWMutex
}

// NewBloomFilter creates a new bloom filter.
func NewBloomFilter(size, hashCount uint) *BloomFilter {
	numWords := (size + 63) / 64
	return &BloomFilter{
		bits:      make([]uint64, numWords),
		size:      numWords * 64,
		hashCount: hashCount,
	}
}

// Add adds an item to the bloom filter.
func (bf *BloomFilter) Add(item string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for _, loc := range bf.getLocations(item) {
		word := loc / 64
		bit := loc % 64
		bf.bits[word] |= 1 << bit
	}
}

// Contains checks if an item might be in the bloom filter.
func (bf *BloomFilter) Contains(item string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	for _, loc := range bf.getLocations(item) {
		word := loc / 64
		bit := loc % 64
		if bf.bits[word]&(1<<bit) == 0 {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) getLocations(item string) []uint {
	locations := make([]uint, bf.hashCount)
	h1 := bf.hash1(item)
	h2 := bf.hash2(item)

	for i := uint(0); i < bf.hashCount; i++ {
		locations[i] = (h1 + i*h2) % bf.size
	}
	return locations
}

func (bf *BloomFilter) hash1(item string) uint {
	h := fnv.New64a()
	h.Write([]byte(item))
	return uint(h.Sum64() % uint64(bf.size))
}

func (bf *BloomFilter) hash2(item string) uint {
	h := fnv.New64()
	h.Write([]byte(item))
	return uint(h.Sum64() % uint64(bf.size))
}

// TIMatcherConfig holds configuration for TIMatcher.
type TIMatcherConfig struct {
	BloomSize     uint          `json:"bloom_size"`
	BloomHashCnt  uint          `json:"bloom_hash_count"`
	CacheTTL      time.Duration `json:"cache_ttl"`
	EnableCaching bool          `json:"enable_caching"`
}

// DefaultTIMatcherConfig returns default configuration.
func DefaultTIMatcherConfig() TIMatcherConfig {
	return TIMatcherConfig{
		BloomSize:     10000000,
		BloomHashCnt:  7,
		CacheTTL:      time.Hour,
		EnableCaching: true,
	}
}

// TIMatcher handles IOC matching against events.
type TIMatcher struct {
	ipStore     *IPStore
	domainStore *DomainStore
	hashStore   *HashStore
	bloom       *BloomFilter
	redis       *redis.Client
	config      TIMatcherConfig

	// Metrics
	queries atomic.Uint64
	hits    atomic.Uint64
	misses  atomic.Uint64

	// Compiled regex patterns
	ipv4Regex   *regexp.Regexp
	ipv6Regex   *regexp.Regexp
	md5Regex    *regexp.Regexp
	sha1Regex   *regexp.Regexp
	sha256Regex *regexp.Regexp
	domainRegex *regexp.Regexp
	urlRegex    *regexp.Regexp
	emailRegex  *regexp.Regexp
}

// NewTIMatcher creates a new TI matcher.
func NewTIMatcher(redisClient *redis.Client) *TIMatcher {
	return NewTIMatcherWithConfig(redisClient, DefaultTIMatcherConfig())
}

// NewTIMatcherWithConfig creates a new TI matcher with custom configuration.
func NewTIMatcherWithConfig(redisClient *redis.Client, cfg TIMatcherConfig) *TIMatcher {
	return &TIMatcher{
		ipStore:     NewIPStore(),
		domainStore: NewDomainStore(),
		hashStore:   NewHashStore(),
		bloom:       NewBloomFilter(cfg.BloomSize, cfg.BloomHashCnt),
		redis:       redisClient,
		config:      cfg,

		// Compile regex patterns
		ipv4Regex:   regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
		ipv6Regex:   regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b`),
		md5Regex:    regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`),
		sha1Regex:   regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`),
		sha256Regex: regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`),
		domainRegex: regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`),
		urlRegex:    regexp.MustCompile(`https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`),
		emailRegex:  regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
	}
}

// LoadFromFeed loads IOCs from a TI feed.
func (t *TIMatcher) LoadFromFeed(ctx context.Context, feedName string, entries []IOCEntry) error {
	for i := range entries {
		entry := &entries[i]
		entry.Source = feedName

		// Add to bloom filter for fast negative lookups
		t.bloom.Add(entry.Value)

		// Add to type-specific store
		switch entry.Type {
		case IOCTypeIP:
			t.ipStore.Add(entry.Value, entry)
		case IOCTypeDomain:
			t.domainStore.Add(entry.Value, entry)
		case IOCTypeMD5, IOCTypeSHA1, IOCTypeSHA256, IOCTypeHash:
			t.hashStore.Add(entry.Value, entry)
		}

		// Cache in Redis if available
		if t.redis != nil && t.config.EnableCaching {
			if err := t.cacheIOC(ctx, entry); err != nil {
				// Log but don't fail
				continue
			}
		}
	}

	return nil
}

// cacheIOC caches an IOC entry in Redis.
func (t *TIMatcher) cacheIOC(ctx context.Context, entry *IOCEntry) error {
	key := fmt.Sprintf("ti:ioc:%s:%s", entry.Type, entry.Value)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return t.redis.Set(ctx, key, data, t.config.CacheTTL).Err()
}

// getCachedIOC retrieves an IOC from Redis cache.
func (t *TIMatcher) getCachedIOC(ctx context.Context, iocType IOCType, value string) (*IOCEntry, error) {
	if t.redis == nil || !t.config.EnableCaching {
		return nil, nil
	}

	key := fmt.Sprintf("ti:ioc:%s:%s", iocType, value)
	data, err := t.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var entry IOCEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// MatchEvent checks if event contains any known IOCs.
func (t *TIMatcher) MatchEvent(ctx context.Context, event *model.PipelineEvent) ([]IOCMatch, error) {
	t.queries.Add(1)

	// Extract potential IOCs from the event
	indicators := t.ExtractIndicators(event)

	var matches []IOCMatch
	for _, indicator := range indicators {
		// Quick bloom filter check first
		if !t.bloom.Contains(indicator.Value) {
			t.misses.Add(1)
			continue
		}

		// Search in type-specific store
		var entry *IOCEntry
		switch indicator.Type {
		case IOCTypeIP:
			entry = t.ipStore.Search(indicator.Value)
		case IOCTypeDomain:
			entry = t.domainStore.Search(indicator.Value)
		case IOCTypeMD5, IOCTypeSHA1, IOCTypeSHA256, IOCTypeHash:
			entry = t.hashStore.Search(indicator.Value)
		default:
			// Try cache for other types
			if cached, err := t.getCachedIOC(ctx, indicator.Type, indicator.Value); err == nil && cached != nil {
				entry = cached
			}
		}

		if entry != nil {
			t.hits.Add(1)
			matches = append(matches, IOCMatch{
				IOC:          entry,
				MatchedIn:    indicator.Field,
				MatchedValue: indicator.Value,
			})
		} else {
			t.misses.Add(1)
		}
	}

	return matches, nil
}

// ExtractIndicators extracts potential IOCs from event.
func (t *TIMatcher) ExtractIndicators(event *model.PipelineEvent) []ExtractedIOC {
	var indicators []ExtractedIOC
	seen := make(map[string]bool)

	// Extract from RawLog
	if event.RawLog != "" {
		indicators = append(indicators, t.extractFromText(event.RawLog, "raw_log", seen)...)
	}

	// Extract from Source
	if event.Source != "" {
		indicators = append(indicators, t.extractFromText(event.Source, "source", seen)...)
	}

	return indicators
}

// extractFromText extracts IOCs from a text field.
func (t *TIMatcher) extractFromText(text, field string, seen map[string]bool) []ExtractedIOC {
	var indicators []ExtractedIOC

	// Extract IPv4 addresses
	for _, match := range t.ipv4Regex.FindAllString(text, -1) {
		if !seen[match] && !t.isPrivateIP(match) {
			seen[match] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeIP,
				Value: match,
				Field: field,
			})
		}
	}

	// Extract IPv6 addresses
	for _, match := range t.ipv6Regex.FindAllString(text, -1) {
		if !seen[match] {
			seen[match] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeIP,
				Value: match,
				Field: field,
			})
		}
	}

	// Extract MD5 hashes
	for _, match := range t.md5Regex.FindAllString(text, -1) {
		lower := strings.ToLower(match)
		if !seen[lower] && t.isValidHash(lower) {
			seen[lower] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeMD5,
				Value: lower,
				Field: field,
			})
		}
	}

	// Extract SHA1 hashes
	for _, match := range t.sha1Regex.FindAllString(text, -1) {
		lower := strings.ToLower(match)
		if !seen[lower] && t.isValidHash(lower) {
			seen[lower] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeSHA1,
				Value: lower,
				Field: field,
			})
		}
	}

	// Extract SHA256 hashes
	for _, match := range t.sha256Regex.FindAllString(text, -1) {
		lower := strings.ToLower(match)
		if !seen[lower] && t.isValidHash(lower) {
			seen[lower] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeSHA256,
				Value: lower,
				Field: field,
			})
		}
	}

	// Extract URLs
	for _, match := range t.urlRegex.FindAllString(text, -1) {
		if !seen[match] {
			seen[match] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeURL,
				Value: match,
				Field: field,
			})

			// Also extract domain from URL
			if domain := t.extractDomainFromURL(match); domain != "" && !seen[domain] {
				seen[domain] = true
				indicators = append(indicators, ExtractedIOC{
					Type:  IOCTypeDomain,
					Value: domain,
					Field: field,
				})
			}
		}
	}

	// Extract domains (but exclude IPs and already seen URLs)
	for _, match := range t.domainRegex.FindAllString(text, -1) {
		lower := strings.ToLower(match)
		if !seen[lower] && !t.isIPAddress(lower) {
			seen[lower] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeDomain,
				Value: lower,
				Field: field,
			})
		}
	}

	// Extract emails
	for _, match := range t.emailRegex.FindAllString(text, -1) {
		lower := strings.ToLower(match)
		if !seen[lower] {
			seen[lower] = true
			indicators = append(indicators, ExtractedIOC{
				Type:  IOCTypeEmail,
				Value: lower,
				Field: field,
			})
		}
	}

	return indicators
}

// isPrivateIP checks if an IP is in a private range.
func (t *TIMatcher) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// isIPAddress checks if a string looks like an IP address.
func (t *TIMatcher) isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// isValidHash checks if a hash string looks valid (not all same chars).
func (t *TIMatcher) isValidHash(hash string) bool {
	if len(hash) == 0 {
		return false
	}

	// Check for all same characters (e.g., "00000000000000000000000000000000")
	firstChar := hash[0]
	allSame := true
	for i := 1; i < len(hash); i++ {
		if hash[i] != firstChar {
			allSame = false
			break
		}
	}

	return !allSame
}

// extractDomainFromURL extracts the domain from a URL.
func (t *TIMatcher) extractDomainFromURL(url string) string {
	// Remove protocol
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	// Find end of domain
	for i, c := range url {
		if c == '/' || c == ':' || c == '?' || c == '#' {
			url = url[:i]
			break
		}
	}

	return strings.ToLower(url)
}

// GetConfidenceBoost calculates confidence boost based on IOC matches.
// High confidence IOCs boost classification confidence.
func (t *TIMatcher) GetConfidenceBoost(matches []IOCMatch) float32 {
	if len(matches) == 0 {
		return 0
	}

	var totalBoost float32 = 0

	for _, match := range matches {
		// Source-based boost
		switch match.IOC.Source {
		case "threatfox":
			if match.IOC.ThreatType == ThreatC2 {
				totalBoost += 0.15 // ThreatFox C2: +0.15
			} else {
				totalBoost += 0.10
			}
		case "abuseipdb":
			if match.IOC.Confidence >= 0.90 {
				totalBoost += 0.10 // AbuseIPDB 90%+: +0.10
			} else if match.IOC.Confidence >= 0.70 {
				totalBoost += 0.07
			} else {
				totalBoost += 0.05
			}
		case "misp":
			if match.IOC.Confidence >= 0.80 {
				totalBoost += 0.12 // MISP high confidence: +0.12
			} else {
				totalBoost += 0.08
			}
		case "kisa":
			totalBoost += 0.10 // KISA (Korean TI): +0.10
		default:
			totalBoost += 0.05
		}

		// Threat type boost
		switch match.IOC.ThreatType {
		case ThreatRansomware, ThreatC2:
			totalBoost += 0.05
		case ThreatMalware, ThreatBotnet:
			totalBoost += 0.03
		}
	}

	// Multiple IOC matches: +0.05 per additional match (max +0.15)
	if len(matches) > 1 {
		additionalBoost := float32(len(matches)-1) * 0.05
		if additionalBoost > 0.15 {
			additionalBoost = 0.15
		}
		totalBoost += additionalBoost
	}

	// Cap total boost at 0.50
	if totalBoost > 0.50 {
		totalBoost = 0.50
	}

	return totalBoost
}

// InvalidateCache invalidates cache for a specific IOC or entire feed.
func (t *TIMatcher) InvalidateCache(ctx context.Context, iocType IOCType, value string) error {
	if t.redis == nil {
		return nil
	}

	key := fmt.Sprintf("ti:ioc:%s:%s", iocType, value)
	return t.redis.Del(ctx, key).Err()
}

// InvalidateFeedCache invalidates all cache entries for a feed.
func (t *TIMatcher) InvalidateFeedCache(ctx context.Context, feedName string) error {
	if t.redis == nil {
		return nil
	}

	// Use SCAN to find and delete keys matching pattern
	pattern := fmt.Sprintf("ti:ioc:*:%s:*", feedName)
	iter := t.redis.Scan(ctx, 0, pattern, 1000).Iterator()
	for iter.Next(ctx) {
		if err := t.redis.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}

// Stats returns matcher statistics.
func (t *TIMatcher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"queries":      t.queries.Load(),
		"hits":         t.hits.Load(),
		"misses":       t.misses.Load(),
		"ip_count":     t.ipStore.Count(),
		"domain_count": t.domainStore.Count(),
		"hash_count":   t.hashStore.Count(),
		"hit_rate":     t.calculateHitRate(),
	}
}

func (t *TIMatcher) calculateHitRate() float64 {
	total := t.hits.Load() + t.misses.Load()
	if total == 0 {
		return 0
	}
	return float64(t.hits.Load()) / float64(total) * 100
}

// Clear removes all IOCs from the matcher.
func (t *TIMatcher) Clear() {
	t.ipStore.Clear()
	t.domainStore.Clear()
	t.hashStore.Clear()
	t.bloom = NewBloomFilter(t.config.BloomSize, t.config.BloomHashCnt)
}

// AddIOC adds a single IOC entry to the matcher.
func (t *TIMatcher) AddIOC(entry *IOCEntry) {
	// Add to bloom filter
	t.bloom.Add(entry.Value)

	// Add to type-specific store
	switch entry.Type {
	case IOCTypeIP:
		t.ipStore.Add(entry.Value, entry)
	case IOCTypeDomain:
		t.domainStore.Add(entry.Value, entry)
	case IOCTypeMD5, IOCTypeSHA1, IOCTypeSHA256, IOCTypeHash:
		t.hashStore.Add(entry.Value, entry)
	}
}

// MatchIP matches a single IP address.
func (t *TIMatcher) MatchIP(ctx context.Context, ip string) *IOCMatch {
	if !t.bloom.Contains(ip) {
		return nil
	}

	entry := t.ipStore.Search(ip)
	if entry != nil {
		return &IOCMatch{
			IOC:          entry,
			MatchedIn:    "direct",
			MatchedValue: ip,
		}
	}
	return nil
}

// MatchDomain matches a single domain.
func (t *TIMatcher) MatchDomain(ctx context.Context, domain string) *IOCMatch {
	domain = strings.ToLower(domain)
	if !t.bloom.Contains(domain) {
		// Also check parent domains for subdomain matching
		parts := strings.Split(domain, ".")
		found := false
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if t.bloom.Contains(parent) {
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}

	entry := t.domainStore.Search(domain)
	if entry != nil {
		return &IOCMatch{
			IOC:          entry,
			MatchedIn:    "direct",
			MatchedValue: domain,
		}
	}
	return nil
}

// MatchHash matches a single hash.
func (t *TIMatcher) MatchHash(ctx context.Context, hash string) *IOCMatch {
	hash = strings.ToLower(hash)
	if !t.bloom.Contains(hash) {
		return nil
	}

	entry := t.hashStore.Search(hash)
	if entry != nil {
		return &IOCMatch{
			IOC:          entry,
			MatchedIn:    "direct",
			MatchedValue: hash,
		}
	}
	return nil
}
