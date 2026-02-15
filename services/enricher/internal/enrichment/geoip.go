// Package enrichment provides data enrichment capabilities.
package enrichment

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPResult represents GeoIP lookup result.
type GeoIPResult struct {
	IP            string    `json:"ip"`
	Country       string    `json:"country"`
	CountryCode   string    `json:"country_code"`
	City          string    `json:"city"`
	Region        string    `json:"region"`
	PostalCode    string    `json:"postal_code"`
	Latitude      float64   `json:"latitude"`
	Longitude     float64   `json:"longitude"`
	Timezone      string    `json:"timezone"`
	ASN           uint      `json:"asn"`
	ASOrg         string    `json:"as_org"`
	ISP           string    `json:"isp"`
	IsAnonymous   bool      `json:"is_anonymous"`
	IsAnonymousVPN bool     `json:"is_anonymous_vpn"`
	IsHosting     bool      `json:"is_hosting"`
	IsProxy       bool      `json:"is_proxy"`
	IsTorExitNode bool      `json:"is_tor_exit_node"`
	LookedUpAt    time.Time `json:"looked_up_at"`
}

// GeoIPConfig holds GeoIP enricher configuration.
type GeoIPConfig struct {
	CityDBPath      string
	ASNDBPath       string
	AnonymousDBPath string
	CacheSize       int
	CacheTTL        time.Duration
}

// GeoIPEnricher provides GeoIP lookup functionality.
type GeoIPEnricher struct {
	cityDB      *geoip2.Reader
	asnDB       *geoip2.Reader
	anonymousDB *geoip2.Reader
	cache       *geoipCache
	logger      *slog.Logger

	// Metrics
	lookups     atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
	errors      atomic.Uint64
}

// NewGeoIPEnricher creates a new GeoIP enricher.
func NewGeoIPEnricher(cfg GeoIPConfig, logger *slog.Logger) (*GeoIPEnricher, error) {
	enricher := &GeoIPEnricher{
		logger: logger.With("component", "geoip-enricher"),
	}

	// Load City database
	if cfg.CityDBPath != "" {
		db, err := geoip2.Open(cfg.CityDBPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open city database: %w", err)
		}
		enricher.cityDB = db
	}

	// Load ASN database
	if cfg.ASNDBPath != "" {
		db, err := geoip2.Open(cfg.ASNDBPath)
		if err != nil {
			logger.Warn("failed to open ASN database", "error", err)
		} else {
			enricher.asnDB = db
		}
	}

	// Load Anonymous IP database
	if cfg.AnonymousDBPath != "" {
		db, err := geoip2.Open(cfg.AnonymousDBPath)
		if err != nil {
			logger.Warn("failed to open anonymous IP database", "error", err)
		} else {
			enricher.anonymousDB = db
		}
	}

	// Initialize cache
	if cfg.CacheSize > 0 {
		enricher.cache = newGeoIPCache(cfg.CacheSize, cfg.CacheTTL)
	}

	return enricher, nil
}

// Close closes the GeoIP databases.
func (e *GeoIPEnricher) Close() error {
	var errs []error
	if e.cityDB != nil {
		if err := e.cityDB.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if e.asnDB != nil {
		if err := e.asnDB.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if e.anonymousDB != nil {
		if err := e.anonymousDB.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing databases: %v", errs)
	}
	return nil
}

// Lookup performs GeoIP lookup for an IP address.
func (e *GeoIPEnricher) Lookup(ctx context.Context, ipStr string) (*GeoIPResult, error) {
	e.lookups.Add(1)

	// Check cache
	if e.cache != nil {
		if result := e.cache.get(ipStr); result != nil {
			e.cacheHits.Add(1)
			return result, nil
		}
		e.cacheMisses.Add(1)
	}

	// Parse IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		e.errors.Add(1)
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Skip private/reserved IPs
	if isPrivateIP(ip) {
		return &GeoIPResult{
			IP:         ipStr,
			Country:    "Private",
			LookedUpAt: time.Now(),
		}, nil
	}

	result := &GeoIPResult{
		IP:         ipStr,
		LookedUpAt: time.Now(),
	}

	// City lookup
	if e.cityDB != nil {
		city, err := e.cityDB.City(ip)
		if err == nil {
			result.Country = city.Country.Names["en"]
			result.CountryCode = city.Country.IsoCode
			result.City = city.City.Names["en"]
			if len(city.Subdivisions) > 0 {
				result.Region = city.Subdivisions[0].Names["en"]
			}
			result.PostalCode = city.Postal.Code
			result.Latitude = city.Location.Latitude
			result.Longitude = city.Location.Longitude
			result.Timezone = city.Location.TimeZone
		}
	}

	// ASN lookup
	if e.asnDB != nil {
		asn, err := e.asnDB.ASN(ip)
		if err == nil {
			result.ASN = asn.AutonomousSystemNumber
			result.ASOrg = asn.AutonomousSystemOrganization
		}
	}

	// Anonymous IP lookup
	if e.anonymousDB != nil {
		anon, err := e.anonymousDB.AnonymousIP(ip)
		if err == nil {
			result.IsAnonymous = anon.IsAnonymous
			result.IsAnonymousVPN = anon.IsAnonymousVPN
			result.IsHosting = anon.IsHostingProvider
			result.IsProxy = anon.IsPublicProxy
			result.IsTorExitNode = anon.IsTorExitNode
		}
	}

	// Cache result
	if e.cache != nil {
		e.cache.set(ipStr, result)
	}

	return result, nil
}

// LookupBatch performs batch GeoIP lookups.
func (e *GeoIPEnricher) LookupBatch(ctx context.Context, ips []string) map[string]*GeoIPResult {
	results := make(map[string]*GeoIPResult)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			result, err := e.Lookup(ctx, ipAddr)
			if err != nil {
				return
			}

			mu.Lock()
			results[ipAddr] = result
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// Stats returns enricher statistics.
func (e *GeoIPEnricher) Stats() map[string]interface{} {
	stats := map[string]interface{}{
		"lookups":      e.lookups.Load(),
		"cache_hits":   e.cacheHits.Load(),
		"cache_misses": e.cacheMisses.Load(),
		"errors":       e.errors.Load(),
	}

	if e.cache != nil {
		stats["cache_size"] = e.cache.size()
	}

	return stats
}

// isPrivateIP checks if an IP is private or reserved.
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}

	// Check for link-local
	if ip4 := ip.To4(); ip4 != nil {
		// 169.254.0.0/16
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
	}

	return false
}

// geoipCache is a simple TTL cache for GeoIP results.
type geoipCache struct {
	items   map[string]*cacheItem
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type cacheItem struct {
	result    *GeoIPResult
	expiresAt time.Time
}

func newGeoIPCache(maxSize int, ttl time.Duration) *geoipCache {
	c := &geoipCache{
		items:   make(map[string]*cacheItem),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

func (c *geoipCache) get(ip string) *GeoIPResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[ip]
	if !ok {
		return nil
	}

	if time.Now().After(item.expiresAt) {
		return nil
	}

	return item.result
}

func (c *geoipCache) set(ip string, result *GeoIPResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[ip] = &cacheItem{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *geoipCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *geoipCache) evictOldest() {
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

func (c *geoipCache) cleanup() {
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
