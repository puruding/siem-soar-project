// Package connector provides the connector registry.
package connector

import (
	"context"
	"fmt"
	"sync"
)

// GlobalRegistry is the global connector registry instance.
var globalRegistry *Registry
var registryOnce sync.Once

// GetGlobalRegistry returns the global registry instance.
func GetGlobalRegistry() *Registry {
	registryOnce.Do(func() {
		globalRegistry = NewRegistry()
		registerBuiltinFactories(globalRegistry)
	})
	return globalRegistry
}

// registerBuiltinFactories registers all built-in connector factories.
func registerBuiltinFactories(r *Registry) {
	// Email connector
	r.RegisterFactory("email", NewEmailConnector)

	// Slack connector
	r.RegisterFactory("slack", NewSlackConnector)

	// Jira connector
	r.RegisterFactory("jira", NewJiraConnector)

	// Firewall connector
	r.RegisterFactory("firewall", NewFirewallConnector)

	// EDR connector
	r.RegisterFactory("edr", NewEDRConnector)

	// Active Directory connector
	r.RegisterFactory("active_directory", NewADConnector)

	// Threat Intel connector
	r.RegisterFactory("threat_intel", NewThreatIntelConnector)

	// HTTP connector (generic)
	r.RegisterFactory("http", NewHTTPConnector)

	// ServiceNow connector
	r.RegisterFactory("servicenow", NewServiceNowConnector)

	// PagerDuty connector
	r.RegisterFactory("pagerduty", NewPagerDutyConnector)

	// AWS connector
	r.RegisterFactory("aws", NewAWSConnector)

	// Azure connector
	r.RegisterFactory("azure", NewAzureConnector)

	// GCP connector
	r.RegisterFactory("gcp", NewGCPConnector)
}

// RegistryAdapter adapts the Registry to the executor's ConnectorRegistry interface.
type RegistryAdapter struct {
	registry *Registry
}

// NewRegistryAdapter creates a new registry adapter.
func NewRegistryAdapter(registry *Registry) *RegistryAdapter {
	return &RegistryAdapter{registry: registry}
}

// GetConnector retrieves a connector.
func (a *RegistryAdapter) GetConnector(name string) (interface{}, error) {
	return a.registry.GetConnector(name)
}

// ListConnectors lists all connectors.
func (a *RegistryAdapter) ListConnectors() []string {
	return a.registry.ListConnectors()
}

// ConnectorCapabilities describes connector capabilities.
type ConnectorCapabilities struct {
	SupportsAsync      bool `json:"supports_async"`
	SupportsBatch      bool `json:"supports_batch"`
	SupportsWebhook    bool `json:"supports_webhook"`
	RequiresAuth       bool `json:"requires_auth"`
	MaxConcurrent      int  `json:"max_concurrent"`
}

// ConnectorMetrics contains connector metrics.
type ConnectorMetrics struct {
	TotalExecutions    int64   `json:"total_executions"`
	SuccessfulExecs    int64   `json:"successful_executions"`
	FailedExecs        int64   `json:"failed_executions"`
	AverageDuration    float64 `json:"average_duration_ms"`
	LastExecutionTime  int64   `json:"last_execution_time"`
	CurrentExecutions  int     `json:"current_executions"`
}

// MetricsCollector collects connector metrics.
type MetricsCollector struct {
	mu      sync.RWMutex
	metrics map[string]*ConnectorMetrics
}

// NewMetricsCollector creates a new metrics collector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]*ConnectorMetrics),
	}
}

// RecordExecution records an execution.
func (c *MetricsCollector) RecordExecution(connector string, duration int64, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.metrics[connector]; !exists {
		c.metrics[connector] = &ConnectorMetrics{}
	}

	m := c.metrics[connector]
	m.TotalExecutions++
	if success {
		m.SuccessfulExecs++
	} else {
		m.FailedExecs++
	}

	// Update average duration
	m.AverageDuration = (m.AverageDuration*float64(m.TotalExecutions-1) + float64(duration)) / float64(m.TotalExecutions)
	m.LastExecutionTime = duration
}

// GetMetrics retrieves metrics for a connector.
func (c *MetricsCollector) GetMetrics(connector string) *ConnectorMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if m, exists := c.metrics[connector]; exists {
		return m
	}
	return &ConnectorMetrics{}
}

// GetAllMetrics retrieves all connector metrics.
func (c *MetricsCollector) GetAllMetrics() map[string]*ConnectorMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*ConnectorMetrics, len(c.metrics))
	for k, v := range c.metrics {
		result[k] = v
	}
	return result
}

// ConnectorPool manages a pool of connector instances.
type ConnectorPool struct {
	mu         sync.RWMutex
	factory    ConnectorFactory
	config     *ConnectorConfig
	pool       []ActionConnector
	maxSize    int
	available  chan ActionConnector
}

// NewConnectorPool creates a new connector pool.
func NewConnectorPool(factory ConnectorFactory, config *ConnectorConfig, maxSize int) (*ConnectorPool, error) {
	p := &ConnectorPool{
		factory:   factory,
		config:    config,
		pool:      make([]ActionConnector, 0, maxSize),
		maxSize:   maxSize,
		available: make(chan ActionConnector, maxSize),
	}

	// Pre-create some connectors
	initialSize := maxSize / 2
	if initialSize < 1 {
		initialSize = 1
	}

	for i := 0; i < initialSize; i++ {
		conn, err := factory(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create connector: %w", err)
		}
		p.pool = append(p.pool, conn)
		p.available <- conn
	}

	return p, nil
}

// Acquire acquires a connector from the pool.
func (p *ConnectorPool) Acquire(ctx context.Context) (ActionConnector, error) {
	select {
	case conn := <-p.available:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Try to create a new connector
		p.mu.Lock()
		if len(p.pool) < p.maxSize {
			conn, err := p.factory(p.config)
			if err != nil {
				p.mu.Unlock()
				return nil, err
			}
			p.pool = append(p.pool, conn)
			p.mu.Unlock()
			return conn, nil
		}
		p.mu.Unlock()

		// Wait for an available connector
		select {
		case conn := <-p.available:
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Release releases a connector back to the pool.
func (p *ConnectorPool) Release(conn ActionConnector) {
	p.available <- conn
}

// Close closes all connectors in the pool.
func (p *ConnectorPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for _, conn := range p.pool {
		if err := conn.Close(); err != nil {
			lastErr = err
		}
	}

	p.pool = nil
	close(p.available)
	return lastErr
}

// ConnectorCache caches connector results.
type ConnectorCache struct {
	mu      sync.RWMutex
	cache   map[string]*CacheEntry
	maxAge  int64 // seconds
}

// CacheEntry represents a cache entry.
type CacheEntry struct {
	Value     interface{}
	ExpiresAt int64
}

// NewConnectorCache creates a new connector cache.
func NewConnectorCache(maxAge int64) *ConnectorCache {
	return &ConnectorCache{
		cache:  make(map[string]*CacheEntry),
		maxAge: maxAge,
	}
}

// Get retrieves a value from the cache.
func (c *ConnectorCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[key]
	if !exists {
		return nil, false
	}

	// Check expiration
	if entry.ExpiresAt > 0 && entry.ExpiresAt < currentTimeUnix() {
		return nil, false
	}

	return entry.Value, true
}

// Set stores a value in the cache.
func (c *ConnectorCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: currentTimeUnix() + c.maxAge,
	}
}

// Delete removes a value from the cache.
func (c *ConnectorCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
}

// Clear clears the cache.
func (c *ConnectorCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*CacheEntry)
}

// currentTimeUnix returns the current Unix timestamp.
func currentTimeUnix() int64 {
	return 0 // Placeholder - use time.Now().Unix() in production
}
