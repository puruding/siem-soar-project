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

// AssetInfo represents asset information from CMDB.
type AssetInfo struct {
	AssetID            string            `json:"asset_id"`
	Hostname           string            `json:"hostname"`
	FQDN               string            `json:"fqdn"`
	IPAddresses        []string          `json:"ip_addresses"`
	MACAddresses       []string          `json:"mac_addresses"`
	AssetType          string            `json:"asset_type"` // server, workstation, network_device, etc.
	OS                 string            `json:"os"`
	OSVersion          string            `json:"os_version"`
	Owner              string            `json:"owner"`
	OwnerEmail         string            `json:"owner_email"`
	Department         string            `json:"department"`
	BusinessUnit       string            `json:"business_unit"`
	Location           string            `json:"location"`
	Criticality        string            `json:"criticality"` // critical, high, medium, low
	Classification     string            `json:"classification"` // public, internal, confidential, restricted
	Environment        string            `json:"environment"` // production, staging, development
	Applications       []string          `json:"applications"`
	Tags               map[string]string `json:"tags"`
	FirstSeen          time.Time         `json:"first_seen"`
	LastSeen           time.Time         `json:"last_seen"`
	LastUpdated        time.Time         `json:"last_updated"`
}

// AssetEnricherConfig holds asset enricher configuration.
type AssetEnricherConfig struct {
	CMDBEndpoint   string
	CMDBAPIKey     string
	CacheSize      int
	CacheTTL       time.Duration
	RequestTimeout time.Duration
}

// AssetEnricher provides asset lookup functionality.
type AssetEnricher struct {
	config   AssetEnricherConfig
	client   *http.Client
	cache    *assetCache
	logger   *slog.Logger

	// In-memory fallback (for development/testing)
	localAssets map[string]*AssetInfo
	localMu     sync.RWMutex

	// Metrics
	lookups     atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
	errors      atomic.Uint64
}

// NewAssetEnricher creates a new asset enricher.
func NewAssetEnricher(cfg AssetEnricherConfig, logger *slog.Logger) *AssetEnricher {
	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	return &AssetEnricher{
		config: cfg,
		client: &http.Client{Timeout: timeout},
		cache:  newAssetCache(cfg.CacheSize, cfg.CacheTTL),
		logger: logger.With("component", "asset-enricher"),
		localAssets: make(map[string]*AssetInfo),
	}
}

// LookupByHostname looks up asset by hostname.
func (e *AssetEnricher) LookupByHostname(ctx context.Context, hostname string) (*AssetInfo, error) {
	return e.lookup(ctx, "hostname", hostname)
}

// LookupByIP looks up asset by IP address.
func (e *AssetEnricher) LookupByIP(ctx context.Context, ip string) (*AssetInfo, error) {
	return e.lookup(ctx, "ip", ip)
}

// LookupByMAC looks up asset by MAC address.
func (e *AssetEnricher) LookupByMAC(ctx context.Context, mac string) (*AssetInfo, error) {
	return e.lookup(ctx, "mac", mac)
}

// LookupByAssetID looks up asset by asset ID.
func (e *AssetEnricher) LookupByAssetID(ctx context.Context, assetID string) (*AssetInfo, error) {
	return e.lookup(ctx, "asset_id", assetID)
}

func (e *AssetEnricher) lookup(ctx context.Context, field, value string) (*AssetInfo, error) {
	e.lookups.Add(1)
	cacheKey := fmt.Sprintf("%s:%s", field, value)

	// Check cache
	if asset := e.cache.get(cacheKey); asset != nil {
		e.cacheHits.Add(1)
		return asset, nil
	}
	e.cacheMisses.Add(1)

	// Check local assets (for development)
	e.localMu.RLock()
	if asset := e.findLocalAsset(field, value); asset != nil {
		e.localMu.RUnlock()
		e.cache.set(cacheKey, asset)
		return asset, nil
	}
	e.localMu.RUnlock()

	// Call CMDB API
	if e.config.CMDBEndpoint == "" {
		return nil, fmt.Errorf("asset not found and CMDB not configured")
	}

	asset, err := e.fetchFromCMDB(ctx, field, value)
	if err != nil {
		e.errors.Add(1)
		return nil, err
	}

	// Cache result
	e.cache.set(cacheKey, asset)

	return asset, nil
}

func (e *AssetEnricher) findLocalAsset(field, value string) *AssetInfo {
	for _, asset := range e.localAssets {
		switch field {
		case "hostname":
			if asset.Hostname == value || asset.FQDN == value {
				return asset
			}
		case "ip":
			for _, ip := range asset.IPAddresses {
				if ip == value {
					return asset
				}
			}
		case "mac":
			for _, mac := range asset.MACAddresses {
				if mac == value {
					return asset
				}
			}
		case "asset_id":
			if asset.AssetID == value {
				return asset
			}
		}
	}
	return nil
}

func (e *AssetEnricher) fetchFromCMDB(ctx context.Context, field, value string) (*AssetInfo, error) {
	url := fmt.Sprintf("%s/api/v1/assets?%s=%s", e.config.CMDBEndpoint, field, value)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if e.config.CMDBAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.config.CMDBAPIKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CMDB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("asset not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CMDB returned status %d", resp.StatusCode)
	}

	var asset AssetInfo
	if err := json.NewDecoder(resp.Body).Decode(&asset); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &asset, nil
}

// RegisterLocalAsset registers an asset in local cache (for development/testing).
func (e *AssetEnricher) RegisterLocalAsset(asset *AssetInfo) {
	e.localMu.Lock()
	defer e.localMu.Unlock()
	e.localAssets[asset.AssetID] = asset
}

// Stats returns enricher statistics.
func (e *AssetEnricher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"lookups":      e.lookups.Load(),
		"cache_hits":   e.cacheHits.Load(),
		"cache_misses": e.cacheMisses.Load(),
		"errors":       e.errors.Load(),
		"cache_size":   e.cache.size(),
	}
}

// assetCache is a TTL cache for asset info.
type assetCache struct {
	items   map[string]*assetCacheItem
	maxSize int
	ttl     time.Duration
	mu      sync.RWMutex
}

type assetCacheItem struct {
	asset     *AssetInfo
	expiresAt time.Time
}

func newAssetCache(maxSize int, ttl time.Duration) *assetCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	c := &assetCache{
		items:   make(map[string]*assetCacheItem),
		maxSize: maxSize,
		ttl:     ttl,
	}

	go c.cleanup()

	return c
}

func (c *assetCache) get(key string) *AssetInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		return nil
	}
	return item.asset
}

func (c *assetCache) set(key string, asset *AssetInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.items) >= c.maxSize {
		c.evictOldest()
	}

	c.items[key] = &assetCacheItem{
		asset:     asset,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *assetCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *assetCache) evictOldest() {
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

func (c *assetCache) cleanup() {
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
