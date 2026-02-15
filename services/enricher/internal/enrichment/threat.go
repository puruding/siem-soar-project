// Package enrichment provides data enrichment capabilities.
package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatInfo represents threat intelligence data.
type ThreatInfo struct {
	IOC            string            `json:"ioc"`
	IOCType        string            `json:"ioc_type"` // ip, domain, hash, url, email
	ThreatType     string            `json:"threat_type"` // malware, phishing, c2, botnet, etc.
	ThreatName     string            `json:"threat_name"`
	Confidence     int               `json:"confidence"` // 0-100
	Severity       string            `json:"severity"` // critical, high, medium, low
	Sources        []ThreatSource    `json:"sources"`
	Tags           []string          `json:"tags"`
	FirstSeen      time.Time         `json:"first_seen"`
	LastSeen       time.Time         `json:"last_seen"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Attributes     map[string]string `json:"attributes"`
	RelatedIOCs    []string          `json:"related_iocs"`
	MalwareFamilies []string         `json:"malware_families"`
	AttackPatterns []string          `json:"attack_patterns"` // MITRE ATT&CK
}

// ThreatSource represents a threat intelligence source.
type ThreatSource struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Confidence int       `json:"confidence"`
	LastSeen   time.Time `json:"last_seen"`
}

// ThreatEnricherConfig holds threat enricher configuration.
type ThreatEnricherConfig struct {
	// Local TI store
	LocalDBPath string

	// External TI APIs
	MISPEndpoint    string
	MISPAPIKey      string
	OTXEndpoint     string
	OTXAPIKey       string
	VirusTotalKey   string
	AbuseIPDBKey    string

	// Cache settings
	CacheSize      int
	CacheTTL       time.Duration
	NegativeCacheTTL time.Duration

	// Request settings
	RequestTimeout time.Duration
	MaxConcurrent  int
}

// ThreatEnricher provides threat intelligence lookup.
type ThreatEnricher struct {
	config      ThreatEnricherConfig
	client      *http.Client
	cache       *threatCache
	logger      *slog.Logger

	// Local TI store
	localTI     map[string]*ThreatInfo
	localMu     sync.RWMutex

	// Metrics
	lookups      atomic.Uint64
	cacheHits    atomic.Uint64
	cacheMisses  atomic.Uint64
	matches      atomic.Uint64
	errors       atomic.Uint64
}

// NewThreatEnricher creates a new threat enricher.
func NewThreatEnricher(cfg ThreatEnricherConfig, logger *slog.Logger) *ThreatEnricher {
	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &ThreatEnricher{
		config:  cfg,
		client:  &http.Client{Timeout: timeout},
		cache:   newThreatCache(cfg.CacheSize, cfg.CacheTTL, cfg.NegativeCacheTTL),
		logger:  logger.With("component", "threat-enricher"),
		localTI: make(map[string]*ThreatInfo),
	}
}

// LookupIP looks up threat intel for an IP address.
func (e *ThreatEnricher) LookupIP(ctx context.Context, ip string) (*ThreatInfo, error) {
	return e.lookup(ctx, "ip", ip)
}

// LookupDomain looks up threat intel for a domain.
func (e *ThreatEnricher) LookupDomain(ctx context.Context, domain string) (*ThreatInfo, error) {
	return e.lookup(ctx, "domain", domain)
}

// LookupHash looks up threat intel for a file hash.
func (e *ThreatEnricher) LookupHash(ctx context.Context, hash string) (*ThreatInfo, error) {
	hashType := detectHashType(hash)
	return e.lookup(ctx, hashType, hash)
}

// LookupURL looks up threat intel for a URL.
func (e *ThreatEnricher) LookupURL(ctx context.Context, url string) (*ThreatInfo, error) {
	return e.lookup(ctx, "url", url)
}

// LookupEmail looks up threat intel for an email address.
func (e *ThreatEnricher) LookupEmail(ctx context.Context, email string) (*ThreatInfo, error) {
	return e.lookup(ctx, "email", email)
}

func (e *ThreatEnricher) lookup(ctx context.Context, iocType, value string) (*ThreatInfo, error) {
	e.lookups.Add(1)
	cacheKey := fmt.Sprintf("%s:%s", iocType, value)

	// Check cache
	if info, found := e.cache.get(cacheKey); found {
		e.cacheHits.Add(1)
		if info != nil {
			e.matches.Add(1)
		}
		return info, nil
	}
	e.cacheMisses.Add(1)

	// Check local TI store
	e.localMu.RLock()
	if info, ok := e.localTI[cacheKey]; ok {
		e.localMu.RUnlock()
		e.cache.set(cacheKey, info)
		if info != nil {
			e.matches.Add(1)
		}
		return info, nil
	}
	e.localMu.RUnlock()

	// Query external TI sources
	info, err := e.queryExternalSources(ctx, iocType, value)
	if err != nil {
		e.errors.Add(1)
		// Cache negative result
		e.cache.setNegative(cacheKey)
		return nil, err
	}

	// Cache result
	if info != nil {
		e.cache.set(cacheKey, info)
		e.matches.Add(1)
	} else {
		e.cache.setNegative(cacheKey)
	}

	return info, nil
}

func (e *ThreatEnricher) queryExternalSources(ctx context.Context, iocType, value string) (*ThreatInfo, error) {
	var results []*ThreatInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Query MISP
	if e.config.MISPEndpoint != "" && e.config.MISPAPIKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result := e.queryMISP(ctx, iocType, value); result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	// Query OTX
	if e.config.OTXEndpoint != "" && e.config.OTXAPIKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result := e.queryOTX(ctx, iocType, value); result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	// Query VirusTotal (for hashes)
	if e.config.VirusTotalKey != "" && (iocType == "md5" || iocType == "sha1" || iocType == "sha256") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result := e.queryVirusTotal(ctx, iocType, value); result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	// Query AbuseIPDB (for IPs)
	if e.config.AbuseIPDBKey != "" && iocType == "ip" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if result := e.queryAbuseIPDB(ctx, value); result != nil {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if len(results) == 0 {
		return nil, nil
	}

	// Merge results
	return e.mergeResults(iocType, value, results), nil
}

func (e *ThreatEnricher) queryMISP(ctx context.Context, iocType, value string) *ThreatInfo {
	url := fmt.Sprintf("%s/attributes/restSearch", e.config.MISPEndpoint)

	body := fmt.Sprintf(`{"returnFormat":"json","type":"%s","value":"%s"}`, iocType, value)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Authorization", e.config.MISPAPIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	_ = body // Would be set in actual implementation

	// Simplified - actual implementation would parse response
	return nil
}

func (e *ThreatEnricher) queryOTX(ctx context.Context, iocType, value string) *ThreatInfo {
	var endpoint string
	switch iocType {
	case "ip":
		endpoint = fmt.Sprintf("%s/api/v1/indicators/IPv4/%s/general", e.config.OTXEndpoint, value)
	case "domain":
		endpoint = fmt.Sprintf("%s/api/v1/indicators/domain/%s/general", e.config.OTXEndpoint, value)
	case "md5", "sha1", "sha256":
		endpoint = fmt.Sprintf("%s/api/v1/indicators/file/%s/general", e.config.OTXEndpoint, value)
	default:
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("X-OTX-API-KEY", e.config.OTXAPIKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var otxResp struct {
		Indicator   string `json:"indicator"`
		PulseInfo   struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name        string    `json:"name"`
				Description string    `json:"description"`
				Created     time.Time `json:"created"`
				Modified    time.Time `json:"modified"`
				Tags        []string  `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&otxResp); err != nil {
		return nil
	}

	if otxResp.PulseInfo.Count == 0 {
		return nil
	}

	var tags []string
	for _, pulse := range otxResp.PulseInfo.Pulses {
		tags = append(tags, pulse.Tags...)
	}

	return &ThreatInfo{
		IOC:        value,
		IOCType:    iocType,
		ThreatType: "unknown",
		Confidence: min(otxResp.PulseInfo.Count*10, 100),
		Sources: []ThreatSource{{
			Name:       "AlienVault OTX",
			URL:        endpoint,
			Confidence: 70,
			LastSeen:   time.Now(),
		}},
		Tags:      uniqueStrings(tags),
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func (e *ThreatEnricher) queryVirusTotal(ctx context.Context, hashType, hash string) *ThreatInfo {
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("x-apikey", e.config.VirusTotalKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Tags              []string `json:"tags"`
				PopularThreatName string   `json:"popular_threat_classification.suggested_threat_label"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return nil
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	if stats.Malicious == 0 && stats.Suspicious == 0 {
		return nil
	}

	total := stats.Malicious + stats.Suspicious + stats.Harmless
	confidence := 0
	if total > 0 {
		confidence = (stats.Malicious + stats.Suspicious) * 100 / total
	}

	return &ThreatInfo{
		IOC:        hash,
		IOCType:    hashType,
		ThreatType: "malware",
		ThreatName: vtResp.Data.Attributes.PopularThreatName,
		Confidence: confidence,
		Sources: []ThreatSource{{
			Name:       "VirusTotal",
			URL:        url,
			Confidence: confidence,
			LastSeen:   time.Now(),
		}},
		Tags:      vtResp.Data.Attributes.Tags,
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func (e *ThreatEnricher) queryAbuseIPDB(ctx context.Context, ip string) *ThreatInfo {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("Key", e.config.AbuseIPDBKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var abuseResp struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&abuseResp); err != nil {
		return nil
	}

	if abuseResp.Data.AbuseConfidenceScore == 0 {
		return nil
	}

	return &ThreatInfo{
		IOC:        ip,
		IOCType:    "ip",
		ThreatType: "malicious_ip",
		Confidence: abuseResp.Data.AbuseConfidenceScore,
		Sources: []ThreatSource{{
			Name:       "AbuseIPDB",
			URL:        url,
			Confidence: abuseResp.Data.AbuseConfidenceScore,
			LastSeen:   time.Now(),
		}},
		Attributes: map[string]string{
			"country":    abuseResp.Data.CountryCode,
			"usage_type": abuseResp.Data.UsageType,
			"isp":        abuseResp.Data.ISP,
			"domain":     abuseResp.Data.Domain,
		},
		LastSeen:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func (e *ThreatEnricher) mergeResults(iocType, value string, results []*ThreatInfo) *ThreatInfo {
	if len(results) == 0 {
		return nil
	}

	merged := &ThreatInfo{
		IOC:        value,
		IOCType:    iocType,
		Sources:    []ThreatSource{},
		Tags:       []string{},
		Attributes: make(map[string]string),
		LastSeen:   time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	var totalConfidence int
	for _, r := range results {
		if r.ThreatType != "" && merged.ThreatType == "" {
			merged.ThreatType = r.ThreatType
		}
		if r.ThreatName != "" && merged.ThreatName == "" {
			merged.ThreatName = r.ThreatName
		}
		totalConfidence += r.Confidence
		merged.Sources = append(merged.Sources, r.Sources...)
		merged.Tags = append(merged.Tags, r.Tags...)
		for k, v := range r.Attributes {
			merged.Attributes[k] = v
		}
	}

	merged.Confidence = totalConfidence / len(results)
	merged.Tags = uniqueStrings(merged.Tags)

	// Determine severity based on confidence
	switch {
	case merged.Confidence >= 80:
		merged.Severity = "critical"
	case merged.Confidence >= 60:
		merged.Severity = "high"
	case merged.Confidence >= 40:
		merged.Severity = "medium"
	default:
		merged.Severity = "low"
	}

	return merged
}

// RegisterLocalIOC registers an IOC in local TI store.
func (e *ThreatEnricher) RegisterLocalIOC(info *ThreatInfo) {
	e.localMu.Lock()
	defer e.localMu.Unlock()
	key := fmt.Sprintf("%s:%s", info.IOCType, info.IOC)
	e.localTI[key] = info
}

// Stats returns enricher statistics.
func (e *ThreatEnricher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"lookups":      e.lookups.Load(),
		"cache_hits":   e.cacheHits.Load(),
		"cache_misses": e.cacheMisses.Load(),
		"matches":      e.matches.Load(),
		"errors":       e.errors.Load(),
		"cache_size":   e.cache.size(),
	}
}

func detectHashType(hash string) string {
	switch len(hash) {
	case 32:
		return "md5"
	case 40:
		return "sha1"
	case 64:
		return "sha256"
	default:
		return "hash"
	}
}

func uniqueStrings(strs []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// threatCache is a TTL cache with negative caching.
type threatCache struct {
	items          map[string]*threatCacheItem
	maxSize        int
	ttl            time.Duration
	negativeTTL    time.Duration
	mu             sync.RWMutex
}

type threatCacheItem struct {
	info      *ThreatInfo
	isNegative bool
	expiresAt time.Time
}

func newThreatCache(maxSize int, ttl, negativeTTL time.Duration) *threatCache {
	if maxSize <= 0 {
		maxSize = 100000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	if negativeTTL <= 0 {
		negativeTTL = 5 * time.Minute
	}

	c := &threatCache{
		items:       make(map[string]*threatCacheItem),
		maxSize:     maxSize,
		ttl:         ttl,
		negativeTTL: negativeTTL,
	}

	go c.cleanup()

	return c
}

func (c *threatCache) get(key string) (*ThreatInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return nil, false
	}
	return item.info, true
}

func (c *threatCache) set(key string, info *ThreatInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = &threatCacheItem{
		info:      info,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *threatCache) setNegative(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = &threatCacheItem{
		info:       nil,
		isNegative: true,
		expiresAt:  time.Now().Add(c.negativeTTL),
	}
}

func (c *threatCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *threatCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, item := range c.items {
		if oldestKey == "" || item.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.expiresAt
		}
	}

	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}

func (c *threatCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.expiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}
