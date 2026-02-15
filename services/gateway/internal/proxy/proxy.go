// Package proxy provides reverse proxy and load balancing for the API gateway.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyConfig holds proxy configuration.
type ProxyConfig struct {
	Timeout          time.Duration `json:"timeout"`
	MaxIdleConns     int           `json:"max_idle_conns"`
	IdleConnTimeout  time.Duration `json:"idle_conn_timeout"`
	DisableKeepAlive bool          `json:"disable_keep_alive"`
	RetryCount       int           `json:"retry_count"`
	RetryDelay       time.Duration `json:"retry_delay"`
}

// DefaultProxyConfig returns default proxy configuration.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		Timeout:          30 * time.Second,
		MaxIdleConns:     100,
		IdleConnTimeout:  90 * time.Second,
		DisableKeepAlive: false,
		RetryCount:       3,
		RetryDelay:       100 * time.Millisecond,
	}
}

// LoadBalanceStrategy represents a load balancing strategy.
type LoadBalanceStrategy string

const (
	StrategyRoundRobin   LoadBalanceStrategy = "round_robin"
	StrategyRandom       LoadBalanceStrategy = "random"
	StrategyLeastConn    LoadBalanceStrategy = "least_conn"
	StrategyWeightedRR   LoadBalanceStrategy = "weighted_round_robin"
	StrategyIPHash       LoadBalanceStrategy = "ip_hash"
)

// Backend represents a backend service.
type Backend struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Weight      int               `json:"weight"`
	HealthCheck string            `json:"health_check,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`

	// Runtime state
	healthy     atomic.Bool
	activeConns atomic.Int64
	totalReqs   atomic.Uint64
	lastError   atomic.Value // error
	lastCheck   atomic.Value // time.Time
}

// IsHealthy returns whether the backend is healthy.
func (b *Backend) IsHealthy() bool {
	return b.healthy.Load()
}

// SetHealthy sets the backend health status.
func (b *Backend) SetHealthy(healthy bool) {
	b.healthy.Store(healthy)
}

// ActiveConnections returns the number of active connections.
func (b *Backend) ActiveConnections() int64 {
	return b.activeConns.Load()
}

// IncrementConnections increments the connection count.
func (b *Backend) IncrementConnections() {
	b.activeConns.Add(1)
}

// DecrementConnections decrements the connection count.
func (b *Backend) DecrementConnections() {
	b.activeConns.Add(-1)
}

// Service represents a proxied service.
type Service struct {
	Name      string              `json:"name"`
	Prefix    string              `json:"prefix"`
	Backends  []*Backend          `json:"backends"`
	Strategy  LoadBalanceStrategy `json:"strategy"`
	StripPath bool                `json:"strip_path"`
	Headers   map[string]string   `json:"headers,omitempty"`
	Timeout   time.Duration       `json:"timeout,omitempty"`

	// Runtime state
	currentIndex atomic.Uint64
	mu           sync.RWMutex
}

// Proxy provides reverse proxy functionality.
type Proxy struct {
	config   ProxyConfig
	services map[string]*Service
	client   *http.Client
	logger   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	totalRequests atomic.Uint64
	totalSuccess  atomic.Uint64
	totalFailed   atomic.Uint64
}

// NewProxy creates a new reverse proxy.
func NewProxy(cfg ProxyConfig, logger *slog.Logger) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())

	transport := &http.Transport{
		MaxIdleConns:        cfg.MaxIdleConns,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableKeepAlives:   cfg.DisableKeepAlive,
		MaxIdleConnsPerHost: 10,
	}

	p := &Proxy{
		config:   cfg,
		services: make(map[string]*Service),
		client: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		logger: logger.With("component", "proxy"),
		ctx:    ctx,
		cancel: cancel,
	}

	return p
}

// RegisterService registers a service.
func (p *Proxy) RegisterService(service *Service) {
	p.services[service.Name] = service

	// Mark all backends as healthy initially
	for _, backend := range service.Backends {
		backend.SetHealthy(true)
	}

	p.logger.Info("registered service",
		"name", service.Name,
		"prefix", service.Prefix,
		"backends", len(service.Backends))
}

// Start starts the proxy (health checking, etc.).
func (p *Proxy) Start() error {
	// Start health check loop for each service
	for _, service := range p.services {
		for _, backend := range service.Backends {
			if backend.HealthCheck != "" {
				p.wg.Add(1)
				go p.healthCheckLoop(service.Name, backend)
			}
		}
	}

	p.logger.Info("proxy started")
	return nil
}

// Stop stops the proxy.
func (p *Proxy) Stop() error {
	p.cancel()
	p.wg.Wait()
	p.logger.Info("proxy stopped")
	return nil
}

// ServeHTTP handles proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.totalRequests.Add(1)

	// Find matching service
	service := p.matchService(r.URL.Path)
	if service == nil {
		http.Error(w, "Service not found", http.StatusNotFound)
		p.totalFailed.Add(1)
		return
	}

	// Select backend
	backend := p.selectBackend(service, r)
	if backend == nil {
		http.Error(w, "No healthy backends available", http.StatusServiceUnavailable)
		p.totalFailed.Add(1)
		return
	}

	// Proxy request
	if err := p.proxyRequest(w, r, service, backend); err != nil {
		p.logger.Error("proxy request failed",
			"service", service.Name,
			"backend", backend.ID,
			"error", err)
		p.totalFailed.Add(1)
		return
	}

	p.totalSuccess.Add(1)
}

// matchService finds a service matching the request path.
func (p *Proxy) matchService(path string) *Service {
	for _, service := range p.services {
		if len(path) >= len(service.Prefix) && path[:len(service.Prefix)] == service.Prefix {
			return service
		}
	}
	return nil
}

// selectBackend selects a backend based on the load balancing strategy.
func (p *Proxy) selectBackend(service *Service, r *http.Request) *Backend {
	service.mu.RLock()
	defer service.mu.RUnlock()

	// Get healthy backends
	healthyBackends := make([]*Backend, 0)
	for _, backend := range service.Backends {
		if backend.IsHealthy() {
			healthyBackends = append(healthyBackends, backend)
		}
	}

	if len(healthyBackends) == 0 {
		return nil
	}

	switch service.Strategy {
	case StrategyRoundRobin:
		return p.roundRobin(service, healthyBackends)
	case StrategyRandom:
		return p.randomSelect(healthyBackends)
	case StrategyLeastConn:
		return p.leastConnections(healthyBackends)
	case StrategyWeightedRR:
		return p.weightedRoundRobin(service, healthyBackends)
	case StrategyIPHash:
		return p.ipHash(healthyBackends, r.RemoteAddr)
	default:
		return p.roundRobin(service, healthyBackends)
	}
}

func (p *Proxy) roundRobin(service *Service, backends []*Backend) *Backend {
	index := service.currentIndex.Add(1) - 1
	return backends[index%uint64(len(backends))]
}

func (p *Proxy) randomSelect(backends []*Backend) *Backend {
	return backends[rand.Intn(len(backends))]
}

func (p *Proxy) leastConnections(backends []*Backend) *Backend {
	var selected *Backend
	var minConns int64 = -1

	for _, backend := range backends {
		conns := backend.ActiveConnections()
		if minConns == -1 || conns < minConns {
			minConns = conns
			selected = backend
		}
	}

	return selected
}

func (p *Proxy) weightedRoundRobin(service *Service, backends []*Backend) *Backend {
	// Calculate total weight
	totalWeight := 0
	for _, backend := range backends {
		totalWeight += backend.Weight
	}

	// Select based on weight
	index := int(service.currentIndex.Add(1) - 1)
	weightIndex := index % totalWeight

	currentWeight := 0
	for _, backend := range backends {
		currentWeight += backend.Weight
		if weightIndex < currentWeight {
			return backend
		}
	}

	return backends[0]
}

func (p *Proxy) ipHash(backends []*Backend, remoteAddr string) *Backend {
	// Simple hash based on IP
	hash := uint64(0)
	for _, c := range remoteAddr {
		hash = hash*31 + uint64(c)
	}
	return backends[hash%uint64(len(backends))]
}

// proxyRequest proxies a request to a backend.
func (p *Proxy) proxyRequest(w http.ResponseWriter, r *http.Request, service *Service, backend *Backend) error {
	backend.IncrementConnections()
	defer backend.DecrementConnections()
	backend.totalReqs.Add(1)

	// Build target URL
	targetURL, err := url.Parse(backend.URL)
	if err != nil {
		return fmt.Errorf("invalid backend URL: %w", err)
	}

	// Modify path
	path := r.URL.Path
	if service.StripPath && len(path) >= len(service.Prefix) {
		path = path[len(service.Prefix):]
		if path == "" {
			path = "/"
		}
	}
	targetURL.Path = path
	targetURL.RawQuery = r.URL.RawQuery

	// Create proxy request
	ctx := r.Context()
	if service.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, service.Timeout)
		defer cancel()
	}

	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), r.Body)
	if err != nil {
		return fmt.Errorf("failed to create proxy request: %w", err)
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	// Add service-specific headers
	for key, value := range service.Headers {
		proxyReq.Header.Set(key, value)
	}

	// Add proxy headers
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)
	proxyReq.Header.Set("X-Forwarded-Proto", "http")
	if r.TLS != nil {
		proxyReq.Header.Set("X-Forwarded-Proto", "https")
	}
	proxyReq.Header.Set("X-Real-IP", r.RemoteAddr)

	// Retry loop
	var lastErr error
	for i := 0; i <= p.config.RetryCount; i++ {
		resp, err := p.client.Do(proxyReq)
		if err != nil {
			lastErr = err
			if i < p.config.RetryCount {
				time.Sleep(p.config.RetryDelay)
				continue
			}
			break
		}
		defer resp.Body.Close()

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		// Set status code
		w.WriteHeader(resp.StatusCode)

		// Copy response body
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			return fmt.Errorf("failed to copy response body: %w", err)
		}

		return nil
	}

	// Mark backend as unhealthy on persistent failures
	backend.SetHealthy(false)
	backend.lastError.Store(lastErr)

	return lastErr
}

// healthCheckLoop performs periodic health checks.
func (p *Proxy) healthCheckLoop(serviceName string, backend *Backend) {
	defer p.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.checkHealth(serviceName, backend)
		}
	}
}

// checkHealth checks the health of a backend.
func (p *Proxy) checkHealth(serviceName string, backend *Backend) {
	ctx, cancel := context.WithTimeout(p.ctx, 5*time.Second)
	defer cancel()

	healthURL := backend.URL + backend.HealthCheck

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		backend.SetHealthy(false)
		backend.lastError.Store(err)
		return
	}

	resp, err := p.client.Do(req)
	if err != nil {
		backend.SetHealthy(false)
		backend.lastError.Store(err)
		p.logger.Warn("health check failed",
			"service", serviceName,
			"backend", backend.ID,
			"error", err)
		return
	}
	defer resp.Body.Close()

	wasHealthy := backend.IsHealthy()
	isHealthy := resp.StatusCode >= 200 && resp.StatusCode < 300

	backend.SetHealthy(isHealthy)
	backend.lastCheck.Store(time.Now())

	if !wasHealthy && isHealthy {
		p.logger.Info("backend recovered",
			"service", serviceName,
			"backend", backend.ID)
	} else if wasHealthy && !isHealthy {
		backend.lastError.Store(fmt.Errorf("health check returned %d", resp.StatusCode))
		p.logger.Warn("backend unhealthy",
			"service", serviceName,
			"backend", backend.ID,
			"status", resp.StatusCode)
	}
}

// Stats returns proxy statistics.
func (p *Proxy) Stats() map[string]interface{} {
	serviceStats := make(map[string]interface{})

	for name, service := range p.services {
		backends := make([]map[string]interface{}, 0)
		for _, backend := range service.Backends {
			backends = append(backends, map[string]interface{}{
				"id":          backend.ID,
				"healthy":     backend.IsHealthy(),
				"active_conn": backend.ActiveConnections(),
				"total_reqs":  backend.totalReqs.Load(),
			})
		}
		serviceStats[name] = map[string]interface{}{
			"backends": backends,
		}
	}

	return map[string]interface{}{
		"total_requests": p.totalRequests.Load(),
		"total_success":  p.totalSuccess.Load(),
		"total_failed":   p.totalFailed.Load(),
		"services":       serviceStats,
	}
}

// GetService returns a service by name.
func (p *Proxy) GetService(name string) *Service {
	return p.services[name]
}

// GetBackendHealth returns the health status of all backends.
func (p *Proxy) GetBackendHealth() map[string][]map[string]interface{} {
	result := make(map[string][]map[string]interface{})

	for name, service := range p.services {
		backends := make([]map[string]interface{}, 0)
		for _, backend := range service.Backends {
			lastErr := ""
			if err := backend.lastError.Load(); err != nil {
				lastErr = err.(error).Error()
			}

			var lastCheck time.Time
			if t := backend.lastCheck.Load(); t != nil {
				lastCheck = t.(time.Time)
			}

			backends = append(backends, map[string]interface{}{
				"id":         backend.ID,
				"url":        backend.URL,
				"healthy":    backend.IsHealthy(),
				"last_error": lastErr,
				"last_check": lastCheck,
			})
		}
		result[name] = backends
	}

	return result
}
