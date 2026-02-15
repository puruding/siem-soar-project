// Package connector provides the connector framework for SOAR integrations.
package connector

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ActionConnector is the interface for connectors that execute actions.
type ActionConnector interface {
	// Name returns the connector name.
	Name() string

	// Type returns the connector type.
	Type() string

	// Execute executes an action with parameters.
	Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error)

	// AvailableActions returns the list of available actions.
	AvailableActions() []ActionDefinition

	// Actions returns list of action names.
	Actions() []string

	// Validate validates the connector configuration.
	Validate() error

	// Health checks the connector health.
	Health(ctx context.Context) (*HealthStatus, error)

	// Close closes the connector.
	Close() error
}

// ActionDefinition describes an available action.
type ActionDefinition struct {
	Name        string         `json:"name"`
	DisplayName string         `json:"display_name"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Parameters  []ParameterDef `json:"parameters"`
	Returns     []ParameterDef `json:"returns"`
	Examples    []ActionExample `json:"examples,omitempty"`
	Timeout     time.Duration  `json:"timeout,omitempty"`
	RiskLevel   string         `json:"risk_level"` // low, medium, high, critical
}

// ParameterDef describes a parameter.
type ParameterDef struct {
	Name         string      `json:"name"`
	DisplayName  string      `json:"display_name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	Default      interface{} `json:"default,omitempty"`
	Description  string      `json:"description,omitempty"`
	Validation   *Validation `json:"validation,omitempty"`
	Sensitive    bool        `json:"sensitive,omitempty"`
	Options      []string    `json:"options,omitempty"`
}

// Validation defines validation rules.
type Validation struct {
	Pattern   string   `json:"pattern,omitempty"`
	MinLength int      `json:"min_length,omitempty"`
	MaxLength int      `json:"max_length,omitempty"`
	Min       float64  `json:"min,omitempty"`
	Max       float64  `json:"max,omitempty"`
	Enum      []string `json:"enum,omitempty"`
}

// ActionExample provides an example of action usage.
type ActionExample struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Output      map[string]interface{} `json:"output,omitempty"`
}

// HealthStatus represents connector health.
type HealthStatus struct {
	Status     string        `json:"status"` // healthy, degraded, unhealthy
	Message    string        `json:"message,omitempty"`
	LastCheck  time.Time     `json:"last_check"`
	Latency    time.Duration `json:"latency_ms"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// ConnectorConfig holds common connector configuration.
type ConnectorConfig struct {
	Name        string            `json:"name" yaml:"name"`
	Type        string            `json:"type" yaml:"type"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	Endpoint    string            `json:"endpoint" yaml:"endpoint"`
	Timeout     time.Duration     `json:"timeout" yaml:"timeout"`
	Credentials CredentialConfig  `json:"credentials" yaml:"credentials"`
	TLS         *TLSConfig        `json:"tls,omitempty" yaml:"tls,omitempty"`
	Retry       *RetryConfig      `json:"retry,omitempty" yaml:"retry,omitempty"`
	RateLimit   *RateLimitConfig  `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	Extra       map[string]string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// Credentials is an alias for CredentialConfig for backward compatibility
type Credentials = CredentialConfig

// CredentialConfig holds credential configuration.
type CredentialConfig struct {
	Type         string `json:"type" yaml:"type"` // basic, token, oauth, certificate
	Username     string `json:"username,omitempty" yaml:"username,omitempty"`
	Password     string `json:"password,omitempty" yaml:"password,omitempty"`
	Token        string `json:"token,omitempty" yaml:"token,omitempty"`
	APIKey       string `json:"api_key,omitempty" yaml:"api_key,omitempty"`
	ClientID     string `json:"client_id,omitempty" yaml:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	TenantID     string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
	CertPath     string `json:"cert_path,omitempty" yaml:"cert_path,omitempty"`
	KeyPath      string `json:"key_path,omitempty" yaml:"key_path,omitempty"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled        bool   `json:"enabled" yaml:"enabled"`
	SkipVerify     bool   `json:"skip_verify,omitempty" yaml:"skip_verify,omitempty"`
	CACertPath     string `json:"ca_cert_path,omitempty" yaml:"ca_cert_path,omitempty"`
	ClientCertPath string `json:"client_cert_path,omitempty" yaml:"client_cert_path,omitempty"`
	ClientKeyPath  string `json:"client_key_path,omitempty" yaml:"client_key_path,omitempty"`
}

// RetryConfig holds retry configuration.
type RetryConfig struct {
	MaxRetries      int           `json:"max_retries" yaml:"max_retries"`
	InitialInterval time.Duration `json:"initial_interval" yaml:"initial_interval"`
	MaxInterval     time.Duration `json:"max_interval" yaml:"max_interval"`
	Multiplier      float64       `json:"multiplier" yaml:"multiplier"`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second" yaml:"requests_per_second"`
	BurstSize         int     `json:"burst_size" yaml:"burst_size"`
}

// Registry manages connector registrations.
type Registry struct {
	mu          sync.RWMutex
	connectors  map[string]ActionConnector
	factories   map[string]ConnectorFactory
	healthCache map[string]*HealthStatus
}

// ConnectorFactory creates connector instances.
type ConnectorFactory func(config *ConnectorConfig) (ActionConnector, error)

// NewRegistry creates a new connector registry.
func NewRegistry() *Registry {
	return &Registry{
		connectors:  make(map[string]ActionConnector),
		factories:   make(map[string]ConnectorFactory),
		healthCache: make(map[string]*HealthStatus),
	}
}

// RegisterFactory registers a connector factory.
func (r *Registry) RegisterFactory(connectorType string, factory ConnectorFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[connectorType]; exists {
		return fmt.Errorf("factory for type %s already registered", connectorType)
	}

	r.factories[connectorType] = factory
	return nil
}

// Create creates and registers a connector instance.
func (r *Registry) Create(config *ConnectorConfig) (ActionConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	factory, exists := r.factories[config.Type]
	if !exists {
		return nil, fmt.Errorf("no factory for connector type: %s", config.Type)
	}

	connector, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	if err := connector.Validate(); err != nil {
		return nil, fmt.Errorf("connector validation failed: %w", err)
	}

	r.connectors[config.Name] = connector
	return connector, nil
}

// GetConnector retrieves a connector by name.
func (r *Registry) GetConnector(name string) (ActionConnector, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connector, exists := r.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector not found: %s", name)
	}

	return connector, nil
}

// ListConnectors returns all registered connector names.
func (r *Registry) ListConnectors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.connectors))
	for name := range r.connectors {
		names = append(names, name)
	}
	return names
}

// ListConnectorTypes returns all registered connector types.
func (r *Registry) ListConnectorTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.factories))
	for t := range r.factories {
		types = append(types, t)
	}
	return types
}

// Remove removes a connector.
func (r *Registry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	connector, exists := r.connectors[name]
	if !exists {
		return fmt.Errorf("connector not found: %s", name)
	}

	if err := connector.Close(); err != nil {
		return fmt.Errorf("failed to close connector: %w", err)
	}

	delete(r.connectors, name)
	delete(r.healthCache, name)
	return nil
}

// HealthCheck performs health checks on all connectors.
func (r *Registry) HealthCheck(ctx context.Context) map[string]*HealthStatus {
	r.mu.RLock()
	connectors := make(map[string]ActionConnector, len(r.connectors))
	for name, conn := range r.connectors {
		connectors[name] = conn
	}
	r.mu.RUnlock()

	results := make(map[string]*HealthStatus)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for name, conn := range connectors {
		wg.Add(1)
		go func(name string, conn ActionConnector) {
			defer wg.Done()

			status, err := conn.Health(ctx)
			if err != nil {
				status = &HealthStatus{
					Status:    "unhealthy",
					Message:   err.Error(),
					LastCheck: time.Now(),
				}
			}

			mu.Lock()
			results[name] = status
			r.healthCache[name] = status
			mu.Unlock()
		}(name, conn)
	}

	wg.Wait()
	return results
}

// GetHealth returns cached health status for a connector.
func (r *Registry) GetHealth(name string) (*HealthStatus, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	status, exists := r.healthCache[name]
	return status, exists
}

// GetConnectorInfo returns information about a connector.
func (r *Registry) GetConnectorInfo(name string) (*ConnectorInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connector, exists := r.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector not found: %s", name)
	}

	health, _ := r.healthCache[name]

	return &ConnectorInfo{
		Name:    connector.Name(),
		Type:    connector.Type(),
		Actions: connector.AvailableActions(),
		Health:  health,
	}, nil
}

// ConnectorInfo provides information about a connector.
type ConnectorInfo struct {
	Name    string             `json:"name"`
	Type    string             `json:"type"`
	Actions []ActionDefinition `json:"actions"`
	Health  *HealthStatus      `json:"health,omitempty"`
}

// Close closes all connectors.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error
	for name, conn := range r.connectors {
		if err := conn.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close connector %s: %w", name, err)
		}
	}

	r.connectors = make(map[string]ActionConnector)
	r.healthCache = make(map[string]*HealthStatus)
	return lastErr
}

// BaseConnector provides common connector functionality.
type BaseConnector struct {
	config      *ConnectorConfig
	name        string
	connType    string
	actions     map[string]ActionHandler
	actionDefs  []ActionDefinition
}

// ActionHandler handles action execution.
type ActionHandler func(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error)

// NewBaseConnector creates a new base connector.
func NewBaseConnector(config *ConnectorConfig) *BaseConnector {
	return &BaseConnector{
		config:   config,
		name:     config.Name,
		connType: config.Type,
		actions:  make(map[string]ActionHandler),
	}
}

// Name returns the connector name.
func (c *BaseConnector) Name() string {
	return c.name
}

// Type returns the connector type.
func (c *BaseConnector) Type() string {
	return c.connType
}

// Config returns the connector configuration.
func (c *BaseConnector) Config() *ConnectorConfig {
	return c.config
}

// RegisterAction registers an action handler.
func (c *BaseConnector) RegisterAction(def ActionDefinition, handler ActionHandler) {
	c.actions[def.Name] = handler
	c.actionDefs = append(c.actionDefs, def)
}

// Execute executes an action.
func (c *BaseConnector) Execute(ctx context.Context, action string, params map[string]interface{}) (map[string]interface{}, error) {
	handler, exists := c.actions[action]
	if !exists {
		return nil, fmt.Errorf("action not found: %s", action)
	}

	// Validate parameters
	if err := c.validateParams(action, params); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	// Execute with timeout
	timeout := c.config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return handler(ctx, params)
}

// validateParams validates action parameters.
func (c *BaseConnector) validateParams(action string, params map[string]interface{}) error {
	var actionDef *ActionDefinition
	for _, def := range c.actionDefs {
		if def.Name == action {
			actionDef = &def
			break
		}
	}

	if actionDef == nil {
		return nil // No definition, skip validation
	}

	for _, param := range actionDef.Parameters {
		value, exists := params[param.Name]

		if param.Required && !exists {
			return fmt.Errorf("required parameter missing: %s", param.Name)
		}

		if exists && param.Validation != nil {
			if err := validateParamValue(value, param.Validation); err != nil {
				return fmt.Errorf("parameter %s: %w", param.Name, err)
			}
		}
	}

	return nil
}

// validateParamValue validates a parameter value.
func validateParamValue(value interface{}, validation *Validation) error {
	switch v := value.(type) {
	case string:
		if validation.MinLength > 0 && len(v) < validation.MinLength {
			return fmt.Errorf("string too short (min: %d)", validation.MinLength)
		}
		if validation.MaxLength > 0 && len(v) > validation.MaxLength {
			return fmt.Errorf("string too long (max: %d)", validation.MaxLength)
		}
		if len(validation.Enum) > 0 {
			found := false
			for _, e := range validation.Enum {
				if v == e {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("value not in allowed list")
			}
		}
	case float64:
		if validation.Min != 0 && v < validation.Min {
			return fmt.Errorf("value too small (min: %f)", validation.Min)
		}
		if validation.Max != 0 && v > validation.Max {
			return fmt.Errorf("value too large (max: %f)", validation.Max)
		}
	}

	return nil
}

// AvailableActions returns available actions.
func (c *BaseConnector) AvailableActions() []ActionDefinition {
	return c.actionDefs
}

// Validate validates the connector configuration.
func (c *BaseConnector) Validate() error {
	if c.config.Name == "" {
		return fmt.Errorf("connector name is required")
	}
	if c.config.Type == "" {
		return fmt.Errorf("connector type is required")
	}
	return nil
}

// Close closes the connector.
func (c *BaseConnector) Close() error {
	return nil
}
