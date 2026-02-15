// Package integration provides the Integration Hub for managing connectors.
package integration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/siem-soar-platform/services/soar/internal/connector"
)

// Hub is the central integration hub for managing connectors.
type Hub struct {
	connectors      map[string]connector.ActionConnector
	configs         map[string]*connector.ConnectorConfig
	healthCache     map[string]*HealthStatus
	healthCacheTTL  time.Duration
	circuitBreakers map[string]*CircuitBreaker
	rateLimiters    map[string]*RateLimiter
	logger          *slog.Logger
	mu              sync.RWMutex
}

// HealthStatus represents the health status of a connector.
type HealthStatus struct {
	Status      string                 `json:"status"` // healthy, degraded, unhealthy
	LastCheck   time.Time              `json:"last_check"`
	Latency     time.Duration          `json:"latency_ms"`
	Error       string                 `json:"error,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Consecutive int                    `json:"consecutive_failures"`
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	Name          string
	State         CircuitState
	Failures      int
	Successes     int
	Threshold     int
	ResetTimeout  time.Duration
	LastStateChange time.Time
	HalfOpenMax   int
	mu            sync.Mutex
}

// CircuitState represents the state of a circuit breaker.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

// RateLimiter implements rate limiting for connector calls.
type RateLimiter struct {
	Name        string
	MaxRequests int
	Window      time.Duration
	Tokens      int
	LastRefill  time.Time
	mu          sync.Mutex
}

// HubConfig configures the integration hub.
type HubConfig struct {
	HealthCheckInterval time.Duration
	HealthCacheTTL      time.Duration
	CircuitThreshold    int
	CircuitResetTimeout time.Duration
	RateLimitWindow     time.Duration
	DefaultRateLimit    int
}

// DefaultHubConfig returns default hub configuration.
func DefaultHubConfig() *HubConfig {
	return &HubConfig{
		HealthCheckInterval: 30 * time.Second,
		HealthCacheTTL:      60 * time.Second,
		CircuitThreshold:    5,
		CircuitResetTimeout: 60 * time.Second,
		RateLimitWindow:     time.Minute,
		DefaultRateLimit:    100,
	}
}

// NewHub creates a new integration hub.
func NewHub(config *HubConfig, logger *slog.Logger) *Hub {
	if config == nil {
		config = DefaultHubConfig()
	}

	return &Hub{
		connectors:      make(map[string]connector.ActionConnector),
		configs:         make(map[string]*connector.ConnectorConfig),
		healthCache:     make(map[string]*HealthStatus),
		healthCacheTTL:  config.HealthCacheTTL,
		circuitBreakers: make(map[string]*CircuitBreaker),
		rateLimiters:    make(map[string]*RateLimiter),
		logger:          logger,
	}
}

// RegisterConnector registers a connector with the hub.
func (h *Hub) RegisterConnector(name string, conn connector.ActionConnector, config *connector.ConnectorConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.connectors[name]; exists {
		return fmt.Errorf("connector %s already registered", name)
	}

	h.connectors[name] = conn
	h.configs[name] = config

	// Initialize circuit breaker
	h.circuitBreakers[name] = &CircuitBreaker{
		Name:          name,
		State:         CircuitClosed,
		Threshold:     5,
		ResetTimeout:  60 * time.Second,
		HalfOpenMax:   3,
	}

	// Initialize rate limiter
	h.rateLimiters[name] = &RateLimiter{
		Name:        name,
		MaxRequests: 100,
		Window:      time.Minute,
		Tokens:      100,
		LastRefill:  time.Now(),
	}

	h.logger.Info("Registered connector",
		"name", name,
		"type", config.Type,
		"actions", len(conn.Actions()),
	)

	return nil
}

// UnregisterConnector removes a connector from the hub.
func (h *Hub) UnregisterConnector(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.connectors[name]; !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	delete(h.connectors, name)
	delete(h.configs, name)
	delete(h.healthCache, name)
	delete(h.circuitBreakers, name)
	delete(h.rateLimiters, name)

	h.logger.Info("Unregistered connector", "name", name)
	return nil
}

// GetConnector returns a connector by name.
func (h *Hub) GetConnector(name string) (connector.ActionConnector, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	conn, exists := h.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	return conn, nil
}

// Execute executes an action on a connector with circuit breaker and rate limiting.
func (h *Hub) Execute(ctx context.Context, connectorName, action string, params map[string]interface{}) (map[string]interface{}, error) {
	// Check circuit breaker
	if err := h.checkCircuitBreaker(connectorName); err != nil {
		return nil, err
	}

	// Check rate limit
	if err := h.checkRateLimit(connectorName); err != nil {
		return nil, err
	}

	// Get connector
	conn, err := h.GetConnector(connectorName)
	if err != nil {
		return nil, err
	}

	// Execute action
	startTime := time.Now()
	result, err := conn.Execute(ctx, action, params)
	duration := time.Since(startTime)

	// Update circuit breaker
	h.updateCircuitBreaker(connectorName, err == nil)

	// Log execution
	h.logger.Info("Connector action executed",
		"connector", connectorName,
		"action", action,
		"duration_ms", duration.Milliseconds(),
		"success", err == nil,
	)

	return result, err
}

// HealthCheck performs health checks on all connectors.
func (h *Hub) HealthCheck(ctx context.Context) map[string]*HealthStatus {
	h.mu.RLock()
	connectorNames := make([]string, 0, len(h.connectors))
	for name := range h.connectors {
		connectorNames = append(connectorNames, name)
	}
	h.mu.RUnlock()

	var wg sync.WaitGroup
	results := make(map[string]*HealthStatus)
	var mu sync.Mutex

	for _, name := range connectorNames {
		wg.Add(1)
		go func(connName string) {
			defer wg.Done()

			status := h.checkConnectorHealth(ctx, connName)

			mu.Lock()
			results[connName] = status
			mu.Unlock()
		}(name)
	}

	wg.Wait()

	// Update cache
	h.mu.Lock()
	h.healthCache = results
	h.mu.Unlock()

	return results
}

// checkConnectorHealth checks the health of a single connector.
func (h *Hub) checkConnectorHealth(ctx context.Context, name string) *HealthStatus {
	h.mu.RLock()
	conn, exists := h.connectors[name]
	cached, cacheExists := h.healthCache[name]
	h.mu.RUnlock()

	// Return cached if still valid
	if cacheExists && time.Since(cached.LastCheck) < h.healthCacheTTL {
		return cached
	}

	if !exists {
		return &HealthStatus{
			Status:    "unhealthy",
			LastCheck: time.Now(),
			Error:     "connector not found",
		}
	}

	startTime := time.Now()
	healthResult, err := conn.Health(ctx)
	latency := time.Since(startTime)

	status := &HealthStatus{
		LastCheck: time.Now(),
		Latency:   latency,
	}

	if err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
		if cached != nil {
			status.Consecutive = cached.Consecutive + 1
		} else {
			status.Consecutive = 1
		}
	} else {
		status.Status = healthResult.Status
		status.Details = healthResult.Details
		status.Consecutive = 0
	}

	return status
}

// checkCircuitBreaker checks if the circuit breaker allows the request.
func (h *Hub) checkCircuitBreaker(name string) error {
	h.mu.RLock()
	cb, exists := h.circuitBreakers[name]
	h.mu.RUnlock()

	if !exists {
		return nil
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.State {
	case CircuitOpen:
		// Check if reset timeout has passed
		if time.Since(cb.LastStateChange) > cb.ResetTimeout {
			cb.State = CircuitHalfOpen
			cb.Successes = 0
			cb.LastStateChange = time.Now()
			h.logger.Info("Circuit breaker half-open", "connector", name)
			return nil
		}
		return fmt.Errorf("circuit breaker open for connector %s", name)

	case CircuitHalfOpen:
		// Allow limited requests
		if cb.Successes >= cb.HalfOpenMax {
			return fmt.Errorf("circuit breaker half-open limit reached for connector %s", name)
		}
		return nil

	default: // Closed
		return nil
	}
}

// updateCircuitBreaker updates the circuit breaker state based on result.
func (h *Hub) updateCircuitBreaker(name string, success bool) {
	h.mu.RLock()
	cb, exists := h.circuitBreakers[name]
	h.mu.RUnlock()

	if !exists {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if success {
		switch cb.State {
		case CircuitClosed:
			cb.Failures = 0
		case CircuitHalfOpen:
			cb.Successes++
			if cb.Successes >= cb.HalfOpenMax {
				cb.State = CircuitClosed
				cb.Failures = 0
				cb.Successes = 0
				cb.LastStateChange = time.Now()
				h.logger.Info("Circuit breaker closed", "connector", name)
			}
		}
	} else {
		cb.Failures++
		if cb.Failures >= cb.Threshold && cb.State != CircuitOpen {
			cb.State = CircuitOpen
			cb.LastStateChange = time.Now()
			h.logger.Warn("Circuit breaker opened",
				"connector", name,
				"failures", cb.Failures,
			)
		}
	}
}

// checkRateLimit checks if the rate limit allows the request.
func (h *Hub) checkRateLimit(name string) error {
	h.mu.RLock()
	rl, exists := h.rateLimiters[name]
	h.mu.RUnlock()

	if !exists {
		return nil
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens if window has passed
	now := time.Now()
	elapsed := now.Sub(rl.LastRefill)
	if elapsed >= rl.Window {
		rl.Tokens = rl.MaxRequests
		rl.LastRefill = now
	}

	// Check and consume token
	if rl.Tokens <= 0 {
		return fmt.Errorf("rate limit exceeded for connector %s", name)
	}

	rl.Tokens--
	return nil
}

// ListConnectors returns a list of all registered connectors.
func (h *Hub) ListConnectors() []ConnectorInfo {
	h.mu.RLock()
	defer h.mu.RUnlock()

	connectors := make([]ConnectorInfo, 0, len(h.connectors))
	for name, conn := range h.connectors {
		config := h.configs[name]
		health := h.healthCache[name]

		info := ConnectorInfo{
			Name:        name,
			Type:        config.Type,
			Description: config.Description,
			Actions:     conn.AvailableActions(),
			Enabled:     config.Enabled,
		}

		if health != nil {
			info.HealthStatus = health.Status
			info.LastHealthCheck = health.LastCheck
		}

		connectors = append(connectors, info)
	}

	return connectors
}

// ConnectorInfo contains information about a connector.
type ConnectorInfo struct {
	Name            string                   `json:"name"`
	Type            string                   `json:"type"`
	Description     string                   `json:"description"`
	Actions         []connector.ActionDefinition `json:"actions"`
	Enabled         bool                     `json:"enabled"`
	HealthStatus    string                   `json:"health_status,omitempty"`
	LastHealthCheck time.Time                `json:"last_health_check,omitempty"`
}

// GetConnectorActions returns the actions available for a connector.
func (h *Hub) GetConnectorActions(name string) ([]connector.ActionDefinition, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	conn, exists := h.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	return conn.AvailableActions(), nil
}

// GetConnectorConfig returns the configuration for a connector.
func (h *Hub) GetConnectorConfig(name string) (*connector.ConnectorConfig, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	config, exists := h.configs[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	// Return a copy without sensitive data
	safeCopy := *config
	safeCopy.Credentials = connector.Credentials{} // Clear credentials

	return &safeCopy, nil
}

// UpdateConnectorConfig updates the configuration for a connector.
func (h *Hub) UpdateConnectorConfig(name string, config *connector.ConnectorConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.configs[name]; !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	h.configs[name] = config
	return nil
}

// EnableConnector enables a connector.
func (h *Hub) EnableConnector(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	config, exists := h.configs[name]
	if !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	config.Enabled = true
	h.logger.Info("Connector enabled", "name", name)
	return nil
}

// DisableConnector disables a connector.
func (h *Hub) DisableConnector(name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	config, exists := h.configs[name]
	if !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	config.Enabled = false
	h.logger.Info("Connector disabled", "name", name)
	return nil
}

// TestConnector tests the connection to a connector.
func (h *Hub) TestConnector(ctx context.Context, name string) (*HealthStatus, error) {
	h.mu.RLock()
	conn, exists := h.connectors[name]
	h.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	startTime := time.Now()
	healthResult, err := conn.Health(ctx)
	latency := time.Since(startTime)

	status := &HealthStatus{
		LastCheck: time.Now(),
		Latency:   latency,
	}

	if err != nil {
		status.Status = "unhealthy"
		status.Error = err.Error()
	} else {
		status.Status = healthResult.Status
		status.Details = healthResult.Details
	}

	return status, nil
}

// GetCircuitBreakerStatus returns the circuit breaker status for a connector.
func (h *Hub) GetCircuitBreakerStatus(name string) (*CircuitBreakerStatus, error) {
	h.mu.RLock()
	cb, exists := h.circuitBreakers[name]
	h.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	return &CircuitBreakerStatus{
		Name:             name,
		State:            string(cb.State),
		Failures:         cb.Failures,
		Successes:        cb.Successes,
		Threshold:        cb.Threshold,
		ResetTimeout:     cb.ResetTimeout,
		LastStateChange:  cb.LastStateChange,
	}, nil
}

// CircuitBreakerStatus represents the status of a circuit breaker.
type CircuitBreakerStatus struct {
	Name            string        `json:"name"`
	State           string        `json:"state"`
	Failures        int           `json:"failures"`
	Successes       int           `json:"successes"`
	Threshold       int           `json:"threshold"`
	ResetTimeout    time.Duration `json:"reset_timeout_ms"`
	LastStateChange time.Time     `json:"last_state_change"`
}

// ResetCircuitBreaker resets the circuit breaker for a connector.
func (h *Hub) ResetCircuitBreaker(name string) error {
	h.mu.RLock()
	cb, exists := h.circuitBreakers[name]
	h.mu.RUnlock()

	if !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.State = CircuitClosed
	cb.Failures = 0
	cb.Successes = 0
	cb.LastStateChange = time.Now()

	h.logger.Info("Circuit breaker reset", "connector", name)
	return nil
}

// GetRateLimiterStatus returns the rate limiter status for a connector.
func (h *Hub) GetRateLimiterStatus(name string) (*RateLimiterStatus, error) {
	h.mu.RLock()
	rl, exists := h.rateLimiters[name]
	h.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	return &RateLimiterStatus{
		Name:        name,
		MaxRequests: rl.MaxRequests,
		Window:      rl.Window,
		Remaining:   rl.Tokens,
		LastRefill:  rl.LastRefill,
	}, nil
}

// RateLimiterStatus represents the status of a rate limiter.
type RateLimiterStatus struct {
	Name        string        `json:"name"`
	MaxRequests int           `json:"max_requests"`
	Window      time.Duration `json:"window_ms"`
	Remaining   int           `json:"remaining"`
	LastRefill  time.Time     `json:"last_refill"`
}

// UpdateRateLimiter updates the rate limiter configuration.
func (h *Hub) UpdateRateLimiter(name string, maxRequests int, window time.Duration) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	rl, exists := h.rateLimiters[name]
	if !exists {
		return fmt.Errorf("connector %s not found", name)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.MaxRequests = maxRequests
	rl.Window = window
	rl.Tokens = maxRequests
	rl.LastRefill = time.Now()

	h.logger.Info("Rate limiter updated",
		"connector", name,
		"max_requests", maxRequests,
		"window_ms", window.Milliseconds(),
	)

	return nil
}

// ExecutorConnectorAdapter adapts ActionConnector to executor.Connector interface.
type ExecutorConnectorAdapter struct {
	conn connector.ActionConnector
}

// Execute executes an action.
func (a *ExecutorConnectorAdapter) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	return a.conn.Execute(ctx, action, params)
}

// AvailableActions returns a list of action names.
func (a *ExecutorConnectorAdapter) AvailableActions() []string {
	return a.conn.Actions()
}

// ExecutorConnector defines the minimal interface needed by the executor.
// This avoids circular dependencies between integration and executor packages.
type ExecutorConnector interface {
	Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)
	AvailableActions() []string
}

// HubRegistryAdapter adapts Hub to executor.ConnectorRegistry interface.
type HubRegistryAdapter struct {
	hub *Hub
}

// NewHubRegistryAdapter creates a new adapter for the Hub.
func NewHubRegistryAdapter(hub *Hub) *HubRegistryAdapter {
	return &HubRegistryAdapter{hub: hub}
}

// GetConnector returns a connector adapted for the executor.
func (a *HubRegistryAdapter) GetConnector(name string) (ExecutorConnector, error) {
	a.hub.mu.RLock()
	defer a.hub.mu.RUnlock()

	conn, exists := a.hub.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}

	return &ExecutorConnectorAdapter{conn: conn}, nil
}

// ListConnectors lists all available connector names.
func (a *HubRegistryAdapter) ListConnectors() []string {
	a.hub.mu.RLock()
	defer a.hub.mu.RUnlock()

	names := make([]string, 0, len(a.hub.connectors))
	for name := range a.hub.connectors {
		names = append(names, name)
	}
	return names
}
