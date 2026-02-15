// Package enricher provides alert enrichment capabilities.
package enricher

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// EnricherConfig holds enricher configuration.
type EnricherConfig struct {
	EnableGeoIP         bool          `json:"enable_geoip"`
	EnableASN           bool          `json:"enable_asn"`
	EnableReverseDNS    bool          `json:"enable_reverse_dns"`
	EnableThreatIntel   bool          `json:"enable_threat_intel"`
	EnableAssetLookup   bool          `json:"enable_asset_lookup"`
	EnableUserLookup    bool          `json:"enable_user_lookup"`
	MaxConcurrent       int           `json:"max_concurrent"`
	Timeout             time.Duration `json:"timeout"`
	CacheTTL            time.Duration `json:"cache_ttl"`
}

// DefaultEnricherConfig returns default enricher configuration.
func DefaultEnricherConfig() EnricherConfig {
	return EnricherConfig{
		EnableGeoIP:       true,
		EnableASN:         true,
		EnableReverseDNS:  true,
		EnableThreatIntel: true,
		EnableAssetLookup: true,
		EnableUserLookup:  true,
		MaxConcurrent:     50,
		Timeout:           10 * time.Second,
		CacheTTL:          1 * time.Hour,
	}
}

// Alert interface for enrichment.
type Alert interface {
	GetID() string
	GetEntities() []Entity
	AddContext(key string, value interface{})
	AddTag(tag string)
	SetAssets([]Asset)
}

// Entity represents an entity to enrich.
type Entity struct {
	Type  string
	Value string
	Role  string
}

// Asset represents an enriched asset.
type Asset struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Name        string            `json:"name"`
	Hostname    string            `json:"hostname,omitempty"`
	IP          string            `json:"ip,omitempty"`
	OS          string            `json:"os,omitempty"`
	Owner       string            `json:"owner,omitempty"`
	Department  string            `json:"department,omitempty"`
	Criticality string            `json:"criticality,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// GeoIPInfo represents GeoIP information.
type GeoIPInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp,omitempty"`
	Org         string  `json:"org,omitempty"`
}

// ASNInfo represents ASN information.
type ASNInfo struct {
	IP     string `json:"ip"`
	ASN    int    `json:"asn"`
	ASName string `json:"as_name"`
	ASOrg  string `json:"as_org,omitempty"`
}

// ThreatIntelInfo represents threat intelligence information.
type ThreatIntelInfo struct {
	Indicator    string   `json:"indicator"`
	Type         string   `json:"type"`
	Confidence   float64  `json:"confidence"`
	Severity     string   `json:"severity"`
	ThreatTypes  []string `json:"threat_types"`
	Sources      []string `json:"sources"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Tags         []string `json:"tags,omitempty"`
}

// UserInfo represents user information.
type UserInfo struct {
	Username   string   `json:"username"`
	FullName   string   `json:"full_name,omitempty"`
	Email      string   `json:"email,omitempty"`
	Department string   `json:"department,omitempty"`
	Title      string   `json:"title,omitempty"`
	Manager    string   `json:"manager,omitempty"`
	Groups     []string `json:"groups,omitempty"`
	RiskScore  float64  `json:"risk_score,omitempty"`
	IsPrivileged bool   `json:"is_privileged"`
}

// EnrichmentProvider provides enrichment data.
type EnrichmentProvider interface {
	LookupGeoIP(ctx context.Context, ip string) (*GeoIPInfo, error)
	LookupASN(ctx context.Context, ip string) (*ASNInfo, error)
	LookupThreatIntel(ctx context.Context, indicator, indicatorType string) (*ThreatIntelInfo, error)
	LookupAsset(ctx context.Context, identifier, identifierType string) (*Asset, error)
	LookupUser(ctx context.Context, username string) (*UserInfo, error)
}

// Enricher enriches alerts with additional context.
type Enricher struct {
	config   EnricherConfig
	provider EnrichmentProvider
	cache    *enrichmentCache
	logger   *slog.Logger

	// Metrics
	totalEnriched atomic.Uint64
	totalFailed   atomic.Uint64
	cacheHits     atomic.Uint64
	cacheMisses   atomic.Uint64
}

// NewEnricher creates a new alert enricher.
func NewEnricher(cfg EnricherConfig, provider EnrichmentProvider, logger *slog.Logger) *Enricher {
	return &Enricher{
		config:   cfg,
		provider: provider,
		cache:    newEnrichmentCache(cfg.CacheTTL),
		logger:   logger.With("component", "alert-enricher"),
	}
}

// Enrich enriches an alert with additional context.
func (e *Enricher) Enrich(ctx context.Context, alert Alert) error {
	ctx, cancel := context.WithTimeout(ctx, e.config.Timeout)
	defer cancel()

	entities := alert.GetEntities()
	if len(entities) == 0 {
		return nil
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, e.config.MaxConcurrent)

	var mu sync.Mutex
	var assets []Asset
	var errors []error

	for _, entity := range entities {
		wg.Add(1)
		go func(ent Entity) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				return
			}

			if err := e.enrichEntity(ctx, alert, ent, &mu, &assets); err != nil {
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
			}
		}(entity)
	}

	wg.Wait()

	if len(assets) > 0 {
		alert.SetAssets(assets)
	}

	if len(errors) > 0 {
		e.totalFailed.Add(uint64(len(errors)))
		e.logger.Warn("some enrichments failed",
			"alert_id", alert.GetID(),
			"error_count", len(errors))
	}

	e.totalEnriched.Add(1)
	return nil
}

// enrichEntity enriches a single entity.
func (e *Enricher) enrichEntity(ctx context.Context, alert Alert, entity Entity, mu *sync.Mutex, assets *[]Asset) error {
	switch entity.Type {
	case "ip":
		return e.enrichIP(ctx, alert, entity.Value, mu, assets)
	case "domain":
		return e.enrichDomain(ctx, alert, entity.Value)
	case "user":
		return e.enrichUser(ctx, alert, entity.Value, mu, assets)
	case "host":
		return e.enrichHost(ctx, alert, entity.Value, mu, assets)
	case "file":
		return e.enrichFile(ctx, alert, entity.Value)
	case "hash":
		return e.enrichHash(ctx, alert, entity.Value)
	default:
		return nil
	}
}

// enrichIP enriches an IP address.
func (e *Enricher) enrichIP(ctx context.Context, alert Alert, ip string, mu *sync.Mutex, assets *[]Asset) error {
	// Check cache
	cacheKey := "ip:" + ip
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		e.applyIPEnrichment(alert, ip, cached, mu, assets)
		return nil
	}
	e.cacheMisses.Add(1)

	enrichment := make(map[string]interface{})

	// GeoIP lookup
	if e.config.EnableGeoIP && e.provider != nil {
		if geoIP, err := e.provider.LookupGeoIP(ctx, ip); err == nil && geoIP != nil {
			enrichment["geoip"] = geoIP
		}
	}

	// ASN lookup
	if e.config.EnableASN && e.provider != nil {
		if asn, err := e.provider.LookupASN(ctx, ip); err == nil && asn != nil {
			enrichment["asn"] = asn
		}
	}

	// Reverse DNS
	if e.config.EnableReverseDNS {
		if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
			enrichment["reverse_dns"] = names[0]
		}
	}

	// Threat intel lookup
	if e.config.EnableThreatIntel && e.provider != nil {
		if ti, err := e.provider.LookupThreatIntel(ctx, ip, "ip"); err == nil && ti != nil {
			enrichment["threat_intel"] = ti
			alert.AddTag("threat_intel_match")
		}
	}

	// Asset lookup
	if e.config.EnableAssetLookup && e.provider != nil {
		if asset, err := e.provider.LookupAsset(ctx, ip, "ip"); err == nil && asset != nil {
			mu.Lock()
			*assets = append(*assets, *asset)
			mu.Unlock()
		}
	}

	// Cache enrichment
	e.cache.set(cacheKey, enrichment)

	// Apply enrichment
	e.applyIPEnrichment(alert, ip, enrichment, mu, assets)

	return nil
}

// applyIPEnrichment applies IP enrichment to an alert.
func (e *Enricher) applyIPEnrichment(alert Alert, ip string, enrichment map[string]interface{}, mu *sync.Mutex, assets *[]Asset) {
	if geoIP, ok := enrichment["geoip"].(*GeoIPInfo); ok {
		alert.AddContext("geoip_"+ip, geoIP)
		if geoIP.Country != "" {
			alert.AddTag("geo:" + geoIP.CountryCode)
		}
	}

	if asn, ok := enrichment["asn"].(*ASNInfo); ok {
		alert.AddContext("asn_"+ip, asn)
	}

	if rdns, ok := enrichment["reverse_dns"].(string); ok {
		alert.AddContext("rdns_"+ip, rdns)
	}

	if ti, ok := enrichment["threat_intel"].(*ThreatIntelInfo); ok {
		alert.AddContext("threat_intel_"+ip, ti)
		for _, tag := range ti.Tags {
			alert.AddTag(tag)
		}
	}
}

// enrichDomain enriches a domain.
func (e *Enricher) enrichDomain(ctx context.Context, alert Alert, domain string) error {
	// Check cache
	cacheKey := "domain:" + domain
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		e.applyDomainEnrichment(alert, domain, cached)
		return nil
	}
	e.cacheMisses.Add(1)

	enrichment := make(map[string]interface{})

	// DNS lookup
	if ips, err := net.LookupHost(domain); err == nil && len(ips) > 0 {
		enrichment["resolved_ips"] = ips
	}

	// Threat intel lookup
	if e.config.EnableThreatIntel && e.provider != nil {
		if ti, err := e.provider.LookupThreatIntel(ctx, domain, "domain"); err == nil && ti != nil {
			enrichment["threat_intel"] = ti
			alert.AddTag("threat_intel_match")
		}
	}

	// Cache enrichment
	e.cache.set(cacheKey, enrichment)

	// Apply enrichment
	e.applyDomainEnrichment(alert, domain, enrichment)

	return nil
}

// applyDomainEnrichment applies domain enrichment to an alert.
func (e *Enricher) applyDomainEnrichment(alert Alert, domain string, enrichment map[string]interface{}) {
	if ips, ok := enrichment["resolved_ips"].([]string); ok {
		alert.AddContext("resolved_ips_"+domain, ips)
	}

	if ti, ok := enrichment["threat_intel"].(*ThreatIntelInfo); ok {
		alert.AddContext("threat_intel_"+domain, ti)
		for _, tag := range ti.Tags {
			alert.AddTag(tag)
		}
	}
}

// enrichUser enriches a user.
func (e *Enricher) enrichUser(ctx context.Context, alert Alert, username string, mu *sync.Mutex, assets *[]Asset) error {
	if !e.config.EnableUserLookup || e.provider == nil {
		return nil
	}

	// Check cache
	cacheKey := "user:" + username
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		e.applyUserEnrichment(alert, username, cached)
		return nil
	}
	e.cacheMisses.Add(1)

	enrichment := make(map[string]interface{})

	// User lookup
	if user, err := e.provider.LookupUser(ctx, username); err == nil && user != nil {
		enrichment["user_info"] = user

		if user.IsPrivileged {
			alert.AddTag("privileged_user")
		}
	}

	// Cache enrichment
	e.cache.set(cacheKey, enrichment)

	// Apply enrichment
	e.applyUserEnrichment(alert, username, enrichment)

	return nil
}

// applyUserEnrichment applies user enrichment to an alert.
func (e *Enricher) applyUserEnrichment(alert Alert, username string, enrichment map[string]interface{}) {
	if user, ok := enrichment["user_info"].(*UserInfo); ok {
		alert.AddContext("user_info_"+username, user)
		if user.IsPrivileged {
			alert.AddTag("privileged_user")
		}
		if user.RiskScore > 0.7 {
			alert.AddTag("high_risk_user")
		}
	}
}

// enrichHost enriches a host.
func (e *Enricher) enrichHost(ctx context.Context, alert Alert, hostname string, mu *sync.Mutex, assets *[]Asset) error {
	if !e.config.EnableAssetLookup || e.provider == nil {
		return nil
	}

	// Check cache
	cacheKey := "host:" + hostname
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		if asset, ok := cached["asset"].(*Asset); ok {
			mu.Lock()
			*assets = append(*assets, *asset)
			mu.Unlock()
		}
		return nil
	}
	e.cacheMisses.Add(1)

	enrichment := make(map[string]interface{})

	// Asset lookup
	if asset, err := e.provider.LookupAsset(ctx, hostname, "hostname"); err == nil && asset != nil {
		enrichment["asset"] = asset
		mu.Lock()
		*assets = append(*assets, *asset)
		mu.Unlock()

		if asset.Criticality == "critical" || asset.Criticality == "high" {
			alert.AddTag("critical_asset")
		}
	}

	// Cache enrichment
	e.cache.set(cacheKey, enrichment)

	return nil
}

// enrichFile enriches a file.
func (e *Enricher) enrichFile(ctx context.Context, alert Alert, filePath string) error {
	// File enrichment (hash lookup, etc.)
	// Implementation depends on file hash database availability
	return nil
}

// enrichHash enriches a file hash.
func (e *Enricher) enrichHash(ctx context.Context, alert Alert, hash string) error {
	if !e.config.EnableThreatIntel || e.provider == nil {
		return nil
	}

	// Check cache
	cacheKey := "hash:" + hash
	if cached := e.cache.get(cacheKey); cached != nil {
		e.cacheHits.Add(1)
		if ti, ok := cached["threat_intel"].(*ThreatIntelInfo); ok {
			alert.AddContext("threat_intel_"+hash, ti)
			alert.AddTag("threat_intel_match")
		}
		return nil
	}
	e.cacheMisses.Add(1)

	enrichment := make(map[string]interface{})

	// Determine hash type
	hashType := "hash"
	switch len(hash) {
	case 32:
		hashType = "md5"
	case 40:
		hashType = "sha1"
	case 64:
		hashType = "sha256"
	}

	// Threat intel lookup
	if ti, err := e.provider.LookupThreatIntel(ctx, hash, hashType); err == nil && ti != nil {
		enrichment["threat_intel"] = ti
		alert.AddContext("threat_intel_"+hash, ti)
		alert.AddTag("threat_intel_match")
		for _, tag := range ti.Tags {
			alert.AddTag(tag)
		}
	}

	// Cache enrichment
	e.cache.set(cacheKey, enrichment)

	return nil
}

// Stats returns enricher statistics.
func (e *Enricher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"total_enriched": e.totalEnriched.Load(),
		"total_failed":   e.totalFailed.Load(),
		"cache_hits":     e.cacheHits.Load(),
		"cache_misses":   e.cacheMisses.Load(),
		"cache_hit_rate": e.calculateCacheHitRate(),
	}
}

func (e *Enricher) calculateCacheHitRate() float64 {
	hits := e.cacheHits.Load()
	misses := e.cacheMisses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}

// enrichmentCache provides caching for enrichment data.
type enrichmentCache struct {
	entries sync.Map
	ttl     time.Duration
}

type cacheEntry struct {
	data      map[string]interface{}
	expiresAt time.Time
}

func newEnrichmentCache(ttl time.Duration) *enrichmentCache {
	c := &enrichmentCache{ttl: ttl}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			c.entries.Range(func(k, v interface{}) bool {
				entry := v.(*cacheEntry)
				if now.After(entry.expiresAt) {
					c.entries.Delete(k)
				}
				return true
			})
		}
	}()

	return c
}

func (c *enrichmentCache) get(key string) map[string]interface{} {
	if val, ok := c.entries.Load(key); ok {
		entry := val.(*cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.data
		}
		c.entries.Delete(key)
	}
	return nil
}

func (c *enrichmentCache) set(key string, data map[string]interface{}) {
	entry := &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.entries.Store(key, entry)
}

// DefaultProvider is a no-op enrichment provider.
type DefaultProvider struct{}

func (p *DefaultProvider) LookupGeoIP(ctx context.Context, ip string) (*GeoIPInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *DefaultProvider) LookupASN(ctx context.Context, ip string) (*ASNInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *DefaultProvider) LookupThreatIntel(ctx context.Context, indicator, indicatorType string) (*ThreatIntelInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *DefaultProvider) LookupAsset(ctx context.Context, identifier, identifierType string) (*Asset, error) {
	return nil, fmt.Errorf("not implemented")
}

func (p *DefaultProvider) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	return nil, fmt.Errorf("not implemented")
}
