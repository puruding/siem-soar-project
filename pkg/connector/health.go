// Package connector provides health check functionality for connectors.
package connector

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// HealthChecker manages periodic health checks for connectors.
type HealthChecker struct {
	registry      *Registry
	interval      time.Duration
	timeout       time.Duration
	results       map[string]*HealthCheckResult
	mu            sync.RWMutex
	stopCh        chan struct{}
	callbacks     []HealthCheckCallback
	callbackMu    sync.RWMutex
	running       bool
}

// HealthCheckResult represents the result of a health check.
type HealthCheckResult struct {
	ConnectorID   string          `json:"connector_id"`
	ConnectorType ConnectorType   `json:"connector_type"`
	SIEMType      SIEMType        `json:"siem_type,omitempty"`
	Status        ConnectorStatus `json:"status"`
	Healthy       bool            `json:"healthy"`
	Latency       time.Duration   `json:"latency_ms"`
	LastCheck     time.Time       `json:"last_check"`
	LastSuccess   time.Time       `json:"last_success,omitempty"`
	LastFailure   time.Time       `json:"last_failure,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`
	FailureCount  int             `json:"failure_count"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// HealthCheckCallback is called when health check results are updated.
type HealthCheckCallback func(result *HealthCheckResult)

// HealthCheckerConfig holds configuration for the health checker.
type HealthCheckerConfig struct {
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
}

// DefaultHealthCheckerConfig returns default health checker configuration.
func DefaultHealthCheckerConfig() *HealthCheckerConfig {
	return &HealthCheckerConfig{
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
	}
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(registry *Registry, config *HealthCheckerConfig) *HealthChecker {
	if config == nil {
		config = DefaultHealthCheckerConfig()
	}

	return &HealthChecker{
		registry:  registry,
		interval:  config.Interval,
		timeout:   config.Timeout,
		results:   make(map[string]*HealthCheckResult),
		stopCh:    make(chan struct{}),
		callbacks: make([]HealthCheckCallback, 0),
	}
}

// Start starts the periodic health checker.
func (h *HealthChecker) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return fmt.Errorf("health checker already running")
	}
	h.running = true
	h.stopCh = make(chan struct{})
	h.mu.Unlock()

	// Run initial check
	h.checkAll(ctx)

	// Start periodic checks
	go h.runPeriodic(ctx)

	return nil
}

// Stop stops the health checker.
func (h *HealthChecker) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return
	}

	close(h.stopCh)
	h.running = false
}

// runPeriodic runs periodic health checks.
func (h *HealthChecker) runPeriodic(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkAll(ctx)
		}
	}
}

// checkAll performs health checks on all connectors.
func (h *HealthChecker) checkAll(ctx context.Context) {
	var wg sync.WaitGroup

	// Check regular connectors
	for _, id := range h.registry.ListInstances() {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			h.checkConnector(ctx, id)
		}(id)
	}

	// Check SIEM connectors
	for _, name := range h.registry.ListSIEMInstances() {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			h.checkSIEMConnector(ctx, name)
		}(name)
	}

	wg.Wait()
}

// checkConnector performs a health check on a single connector.
func (h *HealthChecker) checkConnector(ctx context.Context, id string) {
	conn, ok := h.registry.Get(id)
	if !ok {
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	start := time.Now()
	health, err := conn.Health(checkCtx)
	latency := time.Since(start)

	result := h.getOrCreateResult(id)
	result.ConnectorType = conn.Type()
	result.Latency = latency
	result.LastCheck = time.Now()

	if err != nil {
		result.Healthy = false
		result.Status = StatusError
		result.ErrorMessage = err.Error()
		result.LastFailure = time.Now()
		result.FailureCount++
	} else if health != nil {
		result.Healthy = health.Status == StatusActive
		result.Status = health.Status
		result.ErrorMessage = health.Message
		if result.Healthy {
			result.LastSuccess = time.Now()
			result.FailureCount = 0
		} else {
			result.LastFailure = time.Now()
			result.FailureCount++
		}
	}

	h.storeResult(id, result)
	h.notifyCallbacks(result)
}

// checkSIEMConnector performs a health check on a SIEM connector.
func (h *HealthChecker) checkSIEMConnector(ctx context.Context, name string) {
	conn, ok := h.registry.GetSIEM(name)
	if !ok {
		return
	}

	checkCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	start := time.Now()
	health, err := conn.Health(checkCtx)
	latency := time.Since(start)

	result := h.getOrCreateResult("siem:" + name)
	result.ConnectorID = "siem:" + name
	result.SIEMType = conn.SIEM()
	result.Latency = latency
	result.LastCheck = time.Now()

	if err != nil {
		result.Healthy = false
		result.Status = StatusError
		result.ErrorMessage = err.Error()
		result.LastFailure = time.Now()
		result.FailureCount++
	} else if health != nil {
		result.Healthy = health.Status == StatusActive
		result.Status = health.Status
		result.ErrorMessage = health.Message
		if result.Healthy {
			result.LastSuccess = time.Now()
			result.FailureCount = 0
		} else {
			result.LastFailure = time.Now()
			result.FailureCount++
		}
	}

	h.storeResult("siem:"+name, result)
	h.notifyCallbacks(result)
}

// getOrCreateResult gets or creates a health check result.
func (h *HealthChecker) getOrCreateResult(id string) *HealthCheckResult {
	h.mu.RLock()
	result, exists := h.results[id]
	h.mu.RUnlock()

	if exists {
		return result
	}

	return &HealthCheckResult{
		ConnectorID: id,
	}
}

// storeResult stores a health check result.
func (h *HealthChecker) storeResult(id string, result *HealthCheckResult) {
	h.mu.Lock()
	h.results[id] = result
	h.mu.Unlock()
}

// GetResult returns the latest health check result for a connector.
func (h *HealthChecker) GetResult(id string) (*HealthCheckResult, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result, exists := h.results[id]
	return result, exists
}

// GetAllResults returns all health check results.
func (h *HealthChecker) GetAllResults() map[string]*HealthCheckResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	results := make(map[string]*HealthCheckResult, len(h.results))
	for id, result := range h.results {
		results[id] = result
	}
	return results
}

// RegisterCallback registers a callback for health check updates.
func (h *HealthChecker) RegisterCallback(callback HealthCheckCallback) {
	h.callbackMu.Lock()
	defer h.callbackMu.Unlock()
	h.callbacks = append(h.callbacks, callback)
}

// notifyCallbacks notifies all registered callbacks.
func (h *HealthChecker) notifyCallbacks(result *HealthCheckResult) {
	h.callbackMu.RLock()
	callbacks := h.callbacks
	h.callbackMu.RUnlock()

	for _, cb := range callbacks {
		go cb(result)
	}
}

// CheckNow performs an immediate health check on a specific connector.
func (h *HealthChecker) CheckNow(ctx context.Context, id string) (*HealthCheckResult, error) {
	// Check if it's a SIEM connector
	if len(id) > 5 && id[:5] == "siem:" {
		h.checkSIEMConnector(ctx, id[5:])
	} else {
		h.checkConnector(ctx, id)
	}

	result, ok := h.GetResult(id)
	if !ok {
		return nil, fmt.Errorf("connector %s not found", id)
	}

	return result, nil
}

// IsHealthy returns true if the connector is healthy.
func (h *HealthChecker) IsHealthy(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result, exists := h.results[id]
	if !exists {
		return false
	}

	return result.Healthy
}

// GetUnhealthyConnectors returns a list of unhealthy connectors.
func (h *HealthChecker) GetUnhealthyConnectors() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	unhealthy := make([]string, 0)
	for id, result := range h.results {
		if !result.Healthy {
			unhealthy = append(unhealthy, id)
		}
	}
	return unhealthy
}

// GetHealthSummary returns a summary of connector health.
type HealthSummary struct {
	TotalConnectors    int     `json:"total_connectors"`
	HealthyConnectors  int     `json:"healthy_connectors"`
	UnhealthyConnectors int    `json:"unhealthy_connectors"`
	HealthPercentage   float64 `json:"health_percentage"`
	LastCheck          time.Time `json:"last_check"`
}

// GetHealthSummary returns a summary of all connector health.
func (h *HealthChecker) GetHealthSummary() *HealthSummary {
	h.mu.RLock()
	defer h.mu.RUnlock()

	summary := &HealthSummary{
		TotalConnectors: len(h.results),
	}

	var lastCheck time.Time
	for _, result := range h.results {
		if result.Healthy {
			summary.HealthyConnectors++
		} else {
			summary.UnhealthyConnectors++
		}
		if result.LastCheck.After(lastCheck) {
			lastCheck = result.LastCheck
		}
	}

	summary.LastCheck = lastCheck
	if summary.TotalConnectors > 0 {
		summary.HealthPercentage = float64(summary.HealthyConnectors) / float64(summary.TotalConnectors) * 100
	}

	return summary
}
