// Package repository provides caching for asset management.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/siem-soar-platform/services/asset-registry/internal/model"
)

// CacheConfig holds cache configuration.
type CacheConfig struct {
	AssetTTL       time.Duration
	IdentifierTTL  time.Duration
	GroupTTL       time.Duration
	LookupTTL      time.Duration
}

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		AssetTTL:      15 * time.Minute,
		IdentifierTTL: 5 * time.Minute,
		GroupTTL:      30 * time.Minute,
		LookupTTL:     1 * time.Minute,
	}
}

// AssetCache provides caching for asset data.
type AssetCache struct {
	client redis.UniversalClient
	config CacheConfig
	prefix string
}

// NewAssetCache creates a new asset cache.
func NewAssetCache(client redis.UniversalClient, config CacheConfig) *AssetCache {
	return &AssetCache{
		client: client,
		config: config,
		prefix: "asset",
	}
}

// key generates a cache key.
func (c *AssetCache) key(parts ...string) string {
	key := c.prefix
	for _, p := range parts {
		key += ":" + p
	}
	return key
}

// GetAsset retrieves an asset from cache.
func (c *AssetCache) GetAsset(ctx context.Context, id string) (*model.Asset, error) {
	data, err := c.client.Get(ctx, c.key("id", id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var asset model.Asset
	if err := json.Unmarshal(data, &asset); err != nil {
		return nil, err
	}

	return &asset, nil
}

// SetAsset caches an asset.
func (c *AssetCache) SetAsset(ctx context.Context, asset *model.Asset) error {
	data, err := json.Marshal(asset)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.key("id", asset.ID), data, c.config.AssetTTL).Err()
}

// DeleteAsset removes an asset from cache.
func (c *AssetCache) DeleteAsset(ctx context.Context, id string) error {
	return c.client.Del(ctx, c.key("id", id)).Err()
}

// GetLookup retrieves a lookup result from cache.
func (c *AssetCache) GetLookup(ctx context.Context, identType, value string) (string, error) {
	assetID, err := c.client.Get(ctx, c.key("lookup", identType, value)).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}
	return assetID, nil
}

// SetLookup caches a lookup result.
func (c *AssetCache) SetLookup(ctx context.Context, identType, value, assetID string) error {
	return c.client.Set(ctx, c.key("lookup", identType, value), assetID, c.config.LookupTTL).Err()
}

// InvalidateLookup removes a lookup from cache.
func (c *AssetCache) InvalidateLookup(ctx context.Context, identType, value string) error {
	return c.client.Del(ctx, c.key("lookup", identType, value)).Err()
}

// GetGroup retrieves a group from cache.
func (c *AssetCache) GetGroup(ctx context.Context, id string) (*model.AssetGroup, error) {
	data, err := c.client.Get(ctx, c.key("group", id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var group model.AssetGroup
	if err := json.Unmarshal(data, &group); err != nil {
		return nil, err
	}

	return &group, nil
}

// SetGroup caches a group.
func (c *AssetCache) SetGroup(ctx context.Context, group *model.AssetGroup) error {
	data, err := json.Marshal(group)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.key("group", group.ID), data, c.config.GroupTTL).Err()
}

// DeleteGroup removes a group from cache.
func (c *AssetCache) DeleteGroup(ctx context.Context, id string) error {
	return c.client.Del(ctx, c.key("group", id)).Err()
}

// IncrementStats increments cache statistics.
func (c *AssetCache) IncrementStats(ctx context.Context, stat string) error {
	return c.client.Incr(ctx, c.key("stats", stat)).Err()
}

// GetStats retrieves cache statistics.
func (c *AssetCache) GetStats(ctx context.Context) (map[string]int64, error) {
	stats := make(map[string]int64)

	keys := []string{"hits", "misses", "lookups", "invalidations"}
	for _, k := range keys {
		val, err := c.client.Get(ctx, c.key("stats", k)).Int64()
		if err != nil && err != redis.Nil {
			return nil, err
		}
		stats[k] = val
	}

	return stats, nil
}

// CachedAssetRepository wraps AssetRepository with caching.
type CachedAssetRepository struct {
	repo  AssetRepository
	cache *AssetCache
}

// NewCachedAssetRepository creates a new cached asset repository.
func NewCachedAssetRepository(repo AssetRepository, cache *AssetCache) *CachedAssetRepository {
	return &CachedAssetRepository{
		repo:  repo,
		cache: cache,
	}
}

// Create creates a new asset and caches it.
func (r *CachedAssetRepository) Create(ctx context.Context, asset *model.Asset) error {
	err := r.repo.Create(ctx, asset)
	if err != nil {
		return err
	}

	// Cache the new asset
	r.cache.SetAsset(ctx, asset)

	// Cache identifier lookups
	for _, ip := range asset.IPAddresses {
		r.cache.SetLookup(ctx, "ip", ip, asset.ID)
	}

	return nil
}

// GetByID retrieves an asset, checking cache first.
func (r *CachedAssetRepository) GetByID(ctx context.Context, id string) (*model.Asset, error) {
	// Check cache first
	cached, err := r.cache.GetAsset(ctx, id)
	if err == nil && cached != nil {
		r.cache.IncrementStats(ctx, "hits")
		return cached, nil
	}

	r.cache.IncrementStats(ctx, "misses")

	// Get from database
	asset, err := r.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if asset != nil {
		// Cache for next time
		r.cache.SetAsset(ctx, asset)
	}

	return asset, nil
}

// Update updates an asset and invalidates cache.
func (r *CachedAssetRepository) Update(ctx context.Context, asset *model.Asset) error {
	// Get old asset for identifier invalidation
	oldAsset, _ := r.repo.GetByID(ctx, asset.ID)

	err := r.repo.Update(ctx, asset)
	if err != nil {
		return err
	}

	// Update cache
	r.cache.SetAsset(ctx, asset)
	r.cache.IncrementStats(ctx, "invalidations")

	// Invalidate old identifier lookups
	if oldAsset != nil {
		for _, ip := range oldAsset.IPAddresses {
			r.cache.InvalidateLookup(ctx, "ip", ip)
		}
	}

	// Cache new identifier lookups
	for _, ip := range asset.IPAddresses {
		r.cache.SetLookup(ctx, "ip", ip, asset.ID)
	}

	return nil
}

// Delete deletes an asset and invalidates cache.
func (r *CachedAssetRepository) Delete(ctx context.Context, id string) error {
	// Get asset for identifier invalidation
	asset, _ := r.repo.GetByID(ctx, id)

	err := r.repo.Delete(ctx, id)
	if err != nil {
		return err
	}

	// Invalidate cache
	r.cache.DeleteAsset(ctx, id)
	r.cache.IncrementStats(ctx, "invalidations")

	// Invalidate identifier lookups
	if asset != nil {
		for _, ip := range asset.IPAddresses {
			r.cache.InvalidateLookup(ctx, "ip", ip)
		}
	}

	return nil
}

// List retrieves assets (not cached due to complexity).
func (r *CachedAssetRepository) List(ctx context.Context, filter *model.AssetFilter) (*model.AssetListResult, error) {
	return r.repo.List(ctx, filter)
}

// LookupByIdentifier looks up an asset by identifier, checking cache first.
func (r *CachedAssetRepository) LookupByIdentifier(ctx context.Context, identType, value string) (*model.Asset, error) {
	r.cache.IncrementStats(ctx, "lookups")

	// Check lookup cache first
	assetID, err := r.cache.GetLookup(ctx, identType, value)
	if err == nil && assetID != "" {
		r.cache.IncrementStats(ctx, "hits")
		return r.GetByID(ctx, assetID)
	}

	r.cache.IncrementStats(ctx, "misses")

	// Query database
	asset, err := r.repo.LookupByIdentifier(ctx, identType, value)
	if err != nil {
		return nil, err
	}

	if asset != nil {
		// Cache for next time
		r.cache.SetLookup(ctx, identType, value, asset.ID)
		r.cache.SetAsset(ctx, asset)
	}

	return asset, nil
}

// Delegate other methods to the underlying repository

func (r *CachedAssetRepository) AddIdentifier(ctx context.Context, assetID string, identifier *model.AssetIdentifier) error {
	err := r.repo.AddIdentifier(ctx, assetID, identifier)
	if err != nil {
		return err
	}

	// Cache lookup
	r.cache.SetLookup(ctx, identifier.Type, identifier.Value, assetID)
	// Invalidate asset cache
	r.cache.DeleteAsset(ctx, assetID)

	return nil
}

func (r *CachedAssetRepository) GetIdentifiers(ctx context.Context, assetID string) ([]*model.AssetIdentifier, error) {
	return r.repo.GetIdentifiers(ctx, assetID)
}

func (r *CachedAssetRepository) RemoveIdentifier(ctx context.Context, identifierID string) error {
	return r.repo.RemoveIdentifier(ctx, identifierID)
}

func (r *CachedAssetRepository) CreateGroup(ctx context.Context, group *model.AssetGroup) error {
	err := r.repo.CreateGroup(ctx, group)
	if err != nil {
		return err
	}
	r.cache.SetGroup(ctx, group)
	return nil
}

func (r *CachedAssetRepository) GetGroup(ctx context.Context, id string) (*model.AssetGroup, error) {
	// Check cache first
	cached, err := r.cache.GetGroup(ctx, id)
	if err == nil && cached != nil {
		return cached, nil
	}

	group, err := r.repo.GetGroup(ctx, id)
	if err != nil {
		return nil, err
	}

	if group != nil {
		r.cache.SetGroup(ctx, group)
	}

	return group, nil
}

func (r *CachedAssetRepository) ListGroups(ctx context.Context, tenantID string, limit, offset int) ([]*model.AssetGroup, int, error) {
	return r.repo.ListGroups(ctx, tenantID, limit, offset)
}

func (r *CachedAssetRepository) UpdateGroup(ctx context.Context, group *model.AssetGroup) error {
	err := r.repo.UpdateGroup(ctx, group)
	if err != nil {
		return err
	}
	r.cache.SetGroup(ctx, group)
	return nil
}

func (r *CachedAssetRepository) DeleteGroup(ctx context.Context, id string) error {
	err := r.repo.DeleteGroup(ctx, id)
	if err != nil {
		return err
	}
	r.cache.DeleteGroup(ctx, id)
	return nil
}

func (r *CachedAssetRepository) AddToGroup(ctx context.Context, assetID, groupID string) error {
	err := r.repo.AddToGroup(ctx, assetID, groupID)
	if err != nil {
		return err
	}
	r.cache.DeleteGroup(ctx, groupID)
	r.cache.DeleteAsset(ctx, assetID)
	return nil
}

func (r *CachedAssetRepository) RemoveFromGroup(ctx context.Context, assetID, groupID string) error {
	err := r.repo.RemoveFromGroup(ctx, assetID, groupID)
	if err != nil {
		return err
	}
	r.cache.DeleteGroup(ctx, groupID)
	r.cache.DeleteAsset(ctx, assetID)
	return nil
}

func (r *CachedAssetRepository) RecordHistory(ctx context.Context, history *model.AssetHistory) error {
	return r.repo.RecordHistory(ctx, history)
}

func (r *CachedAssetRepository) GetHistory(ctx context.Context, assetID string, limit int) ([]*model.AssetHistory, error) {
	return r.repo.GetHistory(ctx, assetID, limit)
}

func (r *CachedAssetRepository) RegisterUnknownIP(ctx context.Context, req *model.UnknownIPRequest) (*model.Asset, error) {
	asset, err := r.repo.RegisterUnknownIP(ctx, req)
	if err != nil {
		return nil, err
	}

	if asset != nil {
		r.cache.SetAsset(ctx, asset)
		r.cache.SetLookup(ctx, "ip", req.IPAddress, asset.ID)
	}

	return asset, nil
}

func (r *CachedAssetRepository) UpdateLastSeen(ctx context.Context, assetID string, lastSeen time.Time) error {
	err := r.repo.UpdateLastSeen(ctx, assetID, lastSeen)
	if err != nil {
		return err
	}
	r.cache.DeleteAsset(ctx, assetID)
	return nil
}

// CacheStats returns cache statistics.
func (r *CachedAssetRepository) CacheStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := r.cache.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"hits":          stats["hits"],
		"misses":        stats["misses"],
		"lookups":       stats["lookups"],
		"invalidations": stats["invalidations"],
	}

	// Calculate hit rate
	total := stats["hits"] + stats["misses"]
	if total > 0 {
		result["hit_rate"] = fmt.Sprintf("%.2f%%", float64(stats["hits"])/float64(total)*100)
	} else {
		result["hit_rate"] = "0.00%"
	}

	return result, nil
}
