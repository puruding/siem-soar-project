// Package repository provides caching for policy management.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/siem-soar-platform/services/policy-engine/internal/model"
)

// CacheConfig holds cache configuration.
type CacheConfig struct {
	PolicyTTL    time.Duration
	ActiveTTL    time.Duration
	VersionTTL   time.Duration
}

// DefaultCacheConfig returns default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		PolicyTTL:  15 * time.Minute,
		ActiveTTL:  5 * time.Minute,
		VersionTTL: 30 * time.Minute,
	}
}

// PolicyCache provides caching for policy data.
type PolicyCache struct {
	client redis.UniversalClient
	config CacheConfig
	prefix string
}

// NewPolicyCache creates a new policy cache.
func NewPolicyCache(client redis.UniversalClient, config CacheConfig) *PolicyCache {
	return &PolicyCache{
		client: client,
		config: config,
		prefix: "policy",
	}
}

// key generates a cache key.
func (c *PolicyCache) key(parts ...string) string {
	key := c.prefix
	for _, p := range parts {
		key += ":" + p
	}
	return key
}

// GetPolicy retrieves a policy from cache.
func (c *PolicyCache) GetPolicy(ctx context.Context, id string) (*model.Policy, error) {
	data, err := c.client.Get(ctx, c.key("id", id)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var policy model.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

// SetPolicy caches a policy.
func (c *PolicyCache) SetPolicy(ctx context.Context, policy *model.Policy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.key("id", policy.ID), data, c.config.PolicyTTL).Err()
}

// DeletePolicy removes a policy from cache.
func (c *PolicyCache) DeletePolicy(ctx context.Context, id string) error {
	return c.client.Del(ctx, c.key("id", id)).Err()
}

// GetActivePolicies retrieves active policies from cache.
func (c *PolicyCache) GetActivePolicies(ctx context.Context, policyType model.PolicyType) ([]*model.Policy, error) {
	data, err := c.client.Get(ctx, c.key("active", string(policyType))).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var policies []*model.Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return nil, err
	}

	return policies, nil
}

// SetActivePolicies caches active policies.
func (c *PolicyCache) SetActivePolicies(ctx context.Context, policyType model.PolicyType, policies []*model.Policy) error {
	data, err := json.Marshal(policies)
	if err != nil {
		return err
	}

	return c.client.Set(ctx, c.key("active", string(policyType)), data, c.config.ActiveTTL).Err()
}

// InvalidateActive invalidates active policies cache for a type.
func (c *PolicyCache) InvalidateActive(ctx context.Context, policyType model.PolicyType) error {
	return c.client.Del(ctx, c.key("active", string(policyType))).Err()
}

// GetStats retrieves cache statistics.
func (c *PolicyCache) GetStats(ctx context.Context) (map[string]int64, error) {
	stats := make(map[string]int64)

	keys := []string{"hits", "misses", "invalidations"}
	for _, k := range keys {
		val, err := c.client.Get(ctx, c.key("stats", k)).Int64()
		if err != nil && err != redis.Nil {
			return nil, err
		}
		stats[k] = val
	}

	return stats, nil
}

// IncrementStats increments cache statistics.
func (c *PolicyCache) IncrementStats(ctx context.Context, stat string) error {
	return c.client.Incr(ctx, c.key("stats", stat)).Err()
}

// CachedPolicyRepository wraps PolicyRepository with caching.
type CachedPolicyRepository struct {
	repo  PolicyRepository
	cache *PolicyCache
}

// NewCachedPolicyRepository creates a new cached policy repository.
func NewCachedPolicyRepository(repo PolicyRepository, cache *PolicyCache) *CachedPolicyRepository {
	return &CachedPolicyRepository{
		repo:  repo,
		cache: cache,
	}
}

// Create creates a new policy and caches it.
func (r *CachedPolicyRepository) Create(ctx context.Context, policy *model.Policy) error {
	err := r.repo.Create(ctx, policy)
	if err != nil {
		return err
	}

	r.cache.SetPolicy(ctx, policy)
	r.cache.InvalidateActive(ctx, policy.Type)
	return nil
}

// GetByID retrieves a policy, checking cache first.
func (r *CachedPolicyRepository) GetByID(ctx context.Context, id string) (*model.Policy, error) {
	// Check cache first
	cached, err := r.cache.GetPolicy(ctx, id)
	if err == nil && cached != nil {
		r.cache.IncrementStats(ctx, "hits")
		return cached, nil
	}

	r.cache.IncrementStats(ctx, "misses")

	// Get from database
	policy, err := r.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if policy != nil {
		r.cache.SetPolicy(ctx, policy)
	}

	return policy, nil
}

// Update updates a policy and invalidates cache.
func (r *CachedPolicyRepository) Update(ctx context.Context, policy *model.Policy) error {
	err := r.repo.Update(ctx, policy)
	if err != nil {
		return err
	}

	r.cache.SetPolicy(ctx, policy)
	r.cache.InvalidateActive(ctx, policy.Type)
	r.cache.IncrementStats(ctx, "invalidations")
	return nil
}

// Delete deletes a policy and invalidates cache.
func (r *CachedPolicyRepository) Delete(ctx context.Context, id string) error {
	// Get policy type for cache invalidation
	policy, _ := r.repo.GetByID(ctx, id)

	err := r.repo.Delete(ctx, id)
	if err != nil {
		return err
	}

	r.cache.DeletePolicy(ctx, id)
	if policy != nil {
		r.cache.InvalidateActive(ctx, policy.Type)
	}
	r.cache.IncrementStats(ctx, "invalidations")
	return nil
}

// List retrieves policies (not cached due to complexity).
func (r *CachedPolicyRepository) List(ctx context.Context, filter *model.PolicyFilter) (*model.PolicyListResult, error) {
	return r.repo.List(ctx, filter)
}

// GetActive retrieves active policies with caching.
func (r *CachedPolicyRepository) GetActive(ctx context.Context, policyType model.PolicyType) ([]*model.Policy, error) {
	// Check cache first
	cached, err := r.cache.GetActivePolicies(ctx, policyType)
	if err == nil && cached != nil {
		r.cache.IncrementStats(ctx, "hits")
		return cached, nil
	}

	r.cache.IncrementStats(ctx, "misses")

	// Get from database
	policies, err := r.repo.GetActive(ctx, policyType)
	if err != nil {
		return nil, err
	}

	if len(policies) > 0 {
		r.cache.SetActivePolicies(ctx, policyType, policies)
	}

	return policies, nil
}

// Activate activates a policy and invalidates cache.
func (r *CachedPolicyRepository) Activate(ctx context.Context, id, activatedBy string) error {
	policy, _ := r.repo.GetByID(ctx, id)

	err := r.repo.Activate(ctx, id, activatedBy)
	if err != nil {
		return err
	}

	r.cache.DeletePolicy(ctx, id)
	if policy != nil {
		r.cache.InvalidateActive(ctx, policy.Type)
	}
	return nil
}

// Deactivate deactivates a policy and invalidates cache.
func (r *CachedPolicyRepository) Deactivate(ctx context.Context, id string) error {
	policy, _ := r.repo.GetByID(ctx, id)

	err := r.repo.Deactivate(ctx, id)
	if err != nil {
		return err
	}

	r.cache.DeletePolicy(ctx, id)
	if policy != nil {
		r.cache.InvalidateActive(ctx, policy.Type)
	}
	return nil
}

// Delegate remaining methods

func (r *CachedPolicyRepository) AddRule(ctx context.Context, policyID string, rule *model.Rule) error {
	err := r.repo.AddRule(ctx, policyID, rule)
	if err == nil {
		r.cache.DeletePolicy(ctx, policyID)
	}
	return err
}

func (r *CachedPolicyRepository) UpdateRule(ctx context.Context, policyID string, rule *model.Rule) error {
	err := r.repo.UpdateRule(ctx, policyID, rule)
	if err == nil {
		r.cache.DeletePolicy(ctx, policyID)
	}
	return err
}

func (r *CachedPolicyRepository) DeleteRule(ctx context.Context, policyID, ruleID string) error {
	err := r.repo.DeleteRule(ctx, policyID, ruleID)
	if err == nil {
		r.cache.DeletePolicy(ctx, policyID)
	}
	return err
}

func (r *CachedPolicyRepository) CreateVersion(ctx context.Context, snapshot *model.PolicySnapshot) error {
	return r.repo.CreateVersion(ctx, snapshot)
}

func (r *CachedPolicyRepository) GetVersion(ctx context.Context, policyID string, version int) (*model.PolicySnapshot, error) {
	return r.repo.GetVersion(ctx, policyID, version)
}

func (r *CachedPolicyRepository) ListVersions(ctx context.Context, policyID string, limit int) ([]model.PolicyVersionInfo, error) {
	return r.repo.ListVersions(ctx, policyID, limit)
}

func (r *CachedPolicyRepository) IncrementEvaluationCount(ctx context.Context, id string) error {
	return r.repo.IncrementEvaluationCount(ctx, id)
}

func (r *CachedPolicyRepository) IncrementMatchCount(ctx context.Context, id string) error {
	return r.repo.IncrementMatchCount(ctx, id)
}

func (r *CachedPolicyRepository) UpdateLastEvaluated(ctx context.Context, id string, timestamp time.Time) error {
	return r.repo.UpdateLastEvaluated(ctx, id, timestamp)
}

// CacheStats returns cache statistics.
func (r *CachedPolicyRepository) CacheStats(ctx context.Context) (map[string]interface{}, error) {
	stats, err := r.cache.GetStats(ctx)
	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"hits":          stats["hits"],
		"misses":        stats["misses"],
		"invalidations": stats["invalidations"],
	}

	total := stats["hits"] + stats["misses"]
	if total > 0 {
		result["hit_rate"] = fmt.Sprintf("%.2f%%", float64(stats["hits"])/float64(total)*100)
	} else {
		result["hit_rate"] = "0.00%"
	}

	return result, nil
}
