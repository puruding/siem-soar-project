// Package connector provides connector registry for managing SIEM connectors.
package connector

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Registry manages connector instances and factories.
type Registry struct {
	mu         sync.RWMutex
	factories  map[ConnectorType]ConnectorFactory
	siemFactories map[SIEMType]SIEMConnectorFactory
	instances  map[string]Connector
	siemInstances map[string]SIEMConnector
}

// SIEMConnectorFactory creates SIEM connector instances.
type SIEMConnectorFactory func(config *SIEMConfig) (SIEMConnector, error)

// NewRegistry creates a new connector registry.
func NewRegistry() *Registry {
	return &Registry{
		factories:     make(map[ConnectorType]ConnectorFactory),
		siemFactories: make(map[SIEMType]SIEMConnectorFactory),
		instances:     make(map[string]Connector),
		siemInstances: make(map[string]SIEMConnector),
	}
}

// Global registry instance
var globalRegistry = NewRegistry()

// GlobalRegistry returns the global connector registry.
func GlobalRegistry() *Registry {
	return globalRegistry
}

// RegisterFactory registers a connector factory for a connector type.
func (r *Registry) RegisterFactory(connectorType ConnectorType, factory ConnectorFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[connectorType]; exists {
		return fmt.Errorf("factory for connector type %s already registered", connectorType)
	}

	r.factories[connectorType] = factory
	return nil
}

// RegisterSIEMFactory registers a SIEM connector factory.
func (r *Registry) RegisterSIEMFactory(siemType SIEMType, factory SIEMConnectorFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.siemFactories[siemType]; exists {
		return fmt.Errorf("factory for SIEM type %s already registered", siemType)
	}

	r.siemFactories[siemType] = factory
	return nil
}

// Create creates a new connector instance from config.
func (r *Registry) Create(config ConnectorConfig) (Connector, error) {
	r.mu.RLock()
	factory, exists := r.factories[config.Type]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no factory registered for connector type %s", config.Type)
	}

	connector, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	r.mu.Lock()
	r.instances[config.ID] = connector
	r.mu.Unlock()

	return connector, nil
}

// CreateSIEM creates a new SIEM connector instance.
func (r *Registry) CreateSIEM(config *SIEMConfig) (SIEMConnector, error) {
	r.mu.RLock()
	factory, exists := r.siemFactories[config.Type]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no factory registered for SIEM type %s", config.Type)
	}

	connector, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SIEM connector: %w", err)
	}

	r.mu.Lock()
	r.siemInstances[config.Name] = connector
	r.mu.Unlock()

	return connector, nil
}

// Get retrieves a connector instance by ID.
func (r *Registry) Get(id string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connector, exists := r.instances[id]
	return connector, exists
}

// GetSIEM retrieves a SIEM connector instance by name.
func (r *Registry) GetSIEM(name string) (SIEMConnector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connector, exists := r.siemInstances[name]
	return connector, exists
}

// Remove removes a connector instance.
func (r *Registry) Remove(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	connector, exists := r.instances[id]
	if !exists {
		return fmt.Errorf("connector %s not found", id)
	}

	if err := connector.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect connector: %w", err)
	}

	delete(r.instances, id)
	return nil
}

// RemoveSIEM removes a SIEM connector instance.
func (r *Registry) RemoveSIEM(ctx context.Context, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	connector, exists := r.siemInstances[name]
	if !exists {
		return fmt.Errorf("SIEM connector %s not found", name)
	}

	if err := connector.Disconnect(); err != nil {
		return fmt.Errorf("failed to disconnect SIEM connector: %w", err)
	}

	delete(r.siemInstances, name)
	return nil
}

// List returns all registered connector types.
func (r *Registry) List() []ConnectorType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]ConnectorType, 0, len(r.factories))
	for t := range r.factories {
		types = append(types, t)
	}
	return types
}

// ListSIEMTypes returns all registered SIEM types.
func (r *Registry) ListSIEMTypes() []SIEMType {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]SIEMType, 0, len(r.siemFactories))
	for t := range r.siemFactories {
		types = append(types, t)
	}
	return types
}

// ListInstances returns all connector instance IDs.
func (r *Registry) ListInstances() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.instances))
	for id := range r.instances {
		ids = append(ids, id)
	}
	return ids
}

// ListSIEMInstances returns all SIEM connector instance names.
func (r *Registry) ListSIEMInstances() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.siemInstances))
	for name := range r.siemInstances {
		names = append(names, name)
	}
	return names
}

// GetAllSIEMConnectors returns all active SIEM connector instances.
func (r *Registry) GetAllSIEMConnectors() []SIEMConnector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	connectors := make([]SIEMConnector, 0, len(r.siemInstances))
	for _, conn := range r.siemInstances {
		connectors = append(connectors, conn)
	}
	return connectors
}

// HealthCheckAll performs health checks on all connector instances.
func (r *Registry) HealthCheckAll(ctx context.Context) map[string]*ConnectorHealth {
	r.mu.RLock()
	instances := make(map[string]Connector, len(r.instances))
	for id, conn := range r.instances {
		instances[id] = conn
	}
	r.mu.RUnlock()

	results := make(map[string]*ConnectorHealth)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for id, conn := range instances {
		wg.Add(1)
		go func(id string, conn Connector) {
			defer wg.Done()

			health, err := conn.Health(ctx)
			if err != nil {
				health = &ConnectorHealth{
					Status:    StatusError,
					Message:   err.Error(),
					Timestamp: time.Now(),
				}
			}

			mu.Lock()
			results[id] = health
			mu.Unlock()
		}(id, conn)
	}

	wg.Wait()
	return results
}

// Close closes all connector instances.
func (r *Registry) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var lastErr error

	for id, conn := range r.instances {
		if err := conn.Disconnect(); err != nil {
			lastErr = fmt.Errorf("failed to close connector %s: %w", id, err)
		}
		delete(r.instances, id)
	}

	for name, conn := range r.siemInstances {
		if err := conn.Disconnect(); err != nil {
			lastErr = fmt.Errorf("failed to close SIEM connector %s: %w", name, err)
		}
		delete(r.siemInstances, name)
	}

	return lastErr
}

// ConnectorInfo provides information about a connector.
type ConnectorInfo struct {
	ID        string          `json:"id"`
	Type      ConnectorType   `json:"type"`
	Status    ConnectorStatus `json:"status"`
	Connected bool            `json:"connected"`
}

// SIEMConnectorInfo provides information about a SIEM connector.
type SIEMConnectorInfo struct {
	Name       string          `json:"name"`
	Type       SIEMType        `json:"type"`
	Status     ConnectorStatus `json:"status"`
	Connected  bool            `json:"connected"`
	Languages  []QueryLanguage `json:"languages"`
}

// GetInfo returns information about a connector.
func (r *Registry) GetInfo(id string) (*ConnectorInfo, error) {
	r.mu.RLock()
	conn, exists := r.instances[id]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connector %s not found", id)
	}

	return &ConnectorInfo{
		ID:        id,
		Type:      conn.Type(),
		Connected: conn.IsConnected(),
	}, nil
}

// GetSIEMInfo returns information about a SIEM connector.
func (r *Registry) GetSIEMInfo(name string) (*SIEMConnectorInfo, error) {
	r.mu.RLock()
	conn, exists := r.siemInstances[name]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("SIEM connector %s not found", name)
	}

	return &SIEMConnectorInfo{
		Name:      name,
		Type:      conn.SIEM(),
		Connected: conn.IsConnected(),
		Languages: conn.QueryLanguages(),
	}, nil
}
