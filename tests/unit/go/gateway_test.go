package unit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Gateway Service Unit Tests
// =============================================================================

// HealthResponse represents the health check response
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	JWTSecret      string
	TokenExpiry    time.Duration
	RefreshExpiry  time.Duration
	AllowedOrigins []string
}

// RateLimiter implements a simple rate limiting mechanism
type RateLimiter struct {
	mu       sync.RWMutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Filter requests within the window
	var validRequests []time.Time
	for _, t := range rl.requests[key] {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= rl.limit {
		rl.requests[key] = validRequests
		return false
	}

	rl.requests[key] = append(validRequests, now)
	return true
}

func TestRateLimiter_Allow(t *testing.T) {
	tests := []struct {
		name           string
		limit          int
		window         time.Duration
		requestCount   int
		expectedAllow  int
		expectedDenied int
	}{
		{
			name:           "within limit",
			limit:          10,
			window:         time.Second,
			requestCount:   5,
			expectedAllow:  5,
			expectedDenied: 0,
		},
		{
			name:           "at limit",
			limit:          10,
			window:         time.Second,
			requestCount:   10,
			expectedAllow:  10,
			expectedDenied: 0,
		},
		{
			name:           "exceeds limit",
			limit:          10,
			window:         time.Second,
			requestCount:   15,
			expectedAllow:  10,
			expectedDenied: 5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rl := NewRateLimiter(tc.limit, tc.window)

			allowed := 0
			denied := 0

			for i := 0; i < tc.requestCount; i++ {
				if rl.Allow("test-client") {
					allowed++
				} else {
					denied++
				}
			}

			assert.Equal(t, tc.expectedAllow, allowed, "allowed requests mismatch")
			assert.Equal(t, tc.expectedDenied, denied, "denied requests mismatch")
		})
	}
}

func TestRateLimiter_WindowReset(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond)

	// First two requests should be allowed
	assert.True(t, rl.Allow("test"), "first request should be allowed")
	assert.True(t, rl.Allow("test"), "second request should be allowed")

	// Third request should be denied
	assert.False(t, rl.Allow("test"), "third request should be denied")

	// Wait for window to reset
	time.Sleep(60 * time.Millisecond)

	// Now requests should be allowed again
	assert.True(t, rl.Allow("test"), "request after window reset should be allowed")
}

// JWTValidator validates JWT tokens
type JWTValidator struct {
	Secret []byte
}

type Claims struct {
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	Roles     []string `json:"roles"`
	ExpiresAt int64    `json:"exp"`
}

func (v *JWTValidator) ValidateToken(token string) (*Claims, error) {
	// Simplified validation for testing
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}
	if token == "invalid" {
		return nil, fmt.Errorf("invalid token")
	}
	if token == "expired" {
		return nil, fmt.Errorf("token expired")
	}

	// Return mock claims for valid token
	return &Claims{
		UserID:    "user-123",
		TenantID:  "tenant-456",
		Roles:     []string{"analyst", "viewer"},
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}, nil
}

func TestJWTValidator_ValidateToken(t *testing.T) {
	validator := &JWTValidator{Secret: []byte("test-secret")}

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid token",
			token:       "valid-token",
			expectError: false,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
			errorMsg:    "empty token",
		},
		{
			name:        "invalid token",
			token:       "invalid",
			expectError: true,
			errorMsg:    "invalid token",
		},
		{
			name:        "expired token",
			token:       "expired",
			expectError: true,
			errorMsg:    "token expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := validator.ValidateToken(tc.token)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Equal(t, "user-123", claims.UserID)
			}
		})
	}
}

// RequestRouter routes requests to appropriate services
type RequestRouter struct {
	routes map[string]string
}

func NewRequestRouter() *RequestRouter {
	return &RequestRouter{
		routes: map[string]string{
			"/api/v1/events":     "collector:8086",
			"/api/v1/rules":      "detection:8081",
			"/api/v1/playbooks":  "soar:8082",
			"/api/v1/ti":         "ti:8083",
			"/api/v1/query":      "query:8084",
			"/api/v1/cases":      "case:8085",
			"/api/v1/pipelines":  "pipeline:8087",
			"/api/v1/alerts":     "alert:8088",
		},
	}
}

func (r *RequestRouter) GetRoute(path string) (string, error) {
	for prefix, target := range r.routes {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return target, nil
		}
	}
	return "", fmt.Errorf("no route found for path: %s", path)
}

func TestRequestRouter_GetRoute(t *testing.T) {
	router := NewRequestRouter()

	tests := []struct {
		name        string
		path        string
		expected    string
		expectError bool
	}{
		{
			name:     "events route",
			path:     "/api/v1/events",
			expected: "collector:8086",
		},
		{
			name:     "events sub-path",
			path:     "/api/v1/events/123",
			expected: "collector:8086",
		},
		{
			name:     "rules route",
			path:     "/api/v1/rules",
			expected: "detection:8081",
		},
		{
			name:     "playbooks route",
			path:     "/api/v1/playbooks",
			expected: "soar:8082",
		},
		{
			name:        "unknown route",
			path:        "/api/v1/unknown",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			route, err := router.GetRoute(tc.path)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, route)
			}
		})
	}
}

// APIGateway represents the main gateway handler
type APIGateway struct {
	validator   *JWTValidator
	rateLimiter *RateLimiter
	router      *RequestRouter
}

func NewAPIGateway() *APIGateway {
	return &APIGateway{
		validator:   &JWTValidator{Secret: []byte("test-secret")},
		rateLimiter: NewRateLimiter(100, time.Minute),
		router:      NewRequestRouter(),
	}
}

func (g *APIGateway) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(HealthResponse{
		Status:  "healthy",
		Service: "gateway",
	})
}

func (g *APIGateway) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/ready" {
			next.ServeHTTP(w, r)
			return
		}

		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "missing authorization header"})
			return
		}

		claims, err := g.validator.ValidateToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TestAPIGateway_HealthHandler(t *testing.T) {
	gateway := NewAPIGateway()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	gateway.HealthHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp HealthResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, "healthy", resp.Status)
	assert.Equal(t, "gateway", resp.Service)
}

func TestAPIGateway_AuthMiddleware(t *testing.T) {
	gateway := NewAPIGateway()

	tests := []struct {
		name           string
		path           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "health endpoint skips auth",
			path:           "/health",
			authHeader:     "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing auth header",
			path:           "/api/v1/events",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "invalid token",
			path:           "/api/v1/events",
			authHeader:     "invalid",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "valid token",
			path:           "/api/v1/events",
			authHeader:     "valid-token",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := gateway.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.expectedStatus, rec.Code)
		})
	}
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	mu           sync.RWMutex
	failures     int
	lastFailure  time.Time
	state        string
	threshold    int
	resetTimeout time.Duration
}

const (
	CircuitClosed   = "closed"
	CircuitOpen     = "open"
	CircuitHalfOpen = "half-open"
)

func NewCircuitBreaker(threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:        CircuitClosed,
		threshold:    threshold,
		resetTimeout: resetTimeout,
	}
}

func (cb *CircuitBreaker) State() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.state == CircuitOpen {
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			return CircuitHalfOpen
		}
	}
	return cb.state
}

func (cb *CircuitBreaker) Allow() bool {
	state := cb.State()
	return state == CircuitClosed || state == CircuitHalfOpen
}

func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures = 0
	cb.state = CircuitClosed
}

func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.threshold {
		cb.state = CircuitOpen
	}
}

func TestCircuitBreaker(t *testing.T) {
	t.Run("starts closed", func(t *testing.T) {
		cb := NewCircuitBreaker(3, time.Second)
		assert.Equal(t, CircuitClosed, cb.State())
		assert.True(t, cb.Allow())
	})

	t.Run("opens after threshold failures", func(t *testing.T) {
		cb := NewCircuitBreaker(3, time.Second)

		cb.RecordFailure()
		cb.RecordFailure()
		assert.Equal(t, CircuitClosed, cb.State())

		cb.RecordFailure()
		assert.Equal(t, CircuitOpen, cb.State())
		assert.False(t, cb.Allow())
	})

	t.Run("resets after timeout", func(t *testing.T) {
		cb := NewCircuitBreaker(2, 50*time.Millisecond)

		cb.RecordFailure()
		cb.RecordFailure()
		assert.Equal(t, CircuitOpen, cb.State())

		time.Sleep(60 * time.Millisecond)
		assert.Equal(t, CircuitHalfOpen, cb.State())
		assert.True(t, cb.Allow())
	})

	t.Run("closes on success", func(t *testing.T) {
		cb := NewCircuitBreaker(2, time.Second)

		cb.RecordFailure()
		cb.RecordFailure()
		assert.Equal(t, CircuitOpen, cb.State())

		cb.RecordSuccess()
		assert.Equal(t, CircuitClosed, cb.State())
	})
}

// RequestMetrics tracks request metrics
type RequestMetrics struct {
	mu             sync.RWMutex
	totalRequests  int64
	successCount   int64
	errorCount     int64
	latencies      []time.Duration
	maxLatencies   int
}

func NewRequestMetrics() *RequestMetrics {
	return &RequestMetrics{
		latencies:    make([]time.Duration, 0, 1000),
		maxLatencies: 1000,
	}
}

func (m *RequestMetrics) RecordRequest(duration time.Duration, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalRequests++
	if success {
		m.successCount++
	} else {
		m.errorCount++
	}

	if len(m.latencies) >= m.maxLatencies {
		m.latencies = m.latencies[1:]
	}
	m.latencies = append(m.latencies, duration)
}

func (m *RequestMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_requests": m.totalRequests,
		"success_count":  m.successCount,
		"error_count":    m.errorCount,
	}

	if len(m.latencies) > 0 {
		var sum time.Duration
		for _, l := range m.latencies {
			sum += l
		}
		stats["avg_latency_ms"] = float64(sum.Milliseconds()) / float64(len(m.latencies))
	}

	return stats
}

func TestRequestMetrics(t *testing.T) {
	metrics := NewRequestMetrics()

	// Record some requests
	metrics.RecordRequest(10*time.Millisecond, true)
	metrics.RecordRequest(20*time.Millisecond, true)
	metrics.RecordRequest(30*time.Millisecond, false)

	stats := metrics.GetStats()

	assert.Equal(t, int64(3), stats["total_requests"])
	assert.Equal(t, int64(2), stats["success_count"])
	assert.Equal(t, int64(1), stats["error_count"])
	assert.Equal(t, 20.0, stats["avg_latency_ms"])
}

// CORSHandler handles CORS preflight and headers
type CORSHandler struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

func (c *CORSHandler) IsOriginAllowed(origin string) bool {
	for _, allowed := range c.AllowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (c *CORSHandler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if c.IsOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func TestCORSHandler(t *testing.T) {
	cors := &CORSHandler{
		AllowedOrigins: []string{"https://siem.example.com", "http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
	}

	t.Run("allowed origin", func(t *testing.T) {
		assert.True(t, cors.IsOriginAllowed("https://siem.example.com"))
		assert.True(t, cors.IsOriginAllowed("http://localhost:3000"))
	})

	t.Run("disallowed origin", func(t *testing.T) {
		assert.False(t, cors.IsOriginAllowed("https://malicious.com"))
	})

	t.Run("wildcard origin", func(t *testing.T) {
		wildcardCors := &CORSHandler{AllowedOrigins: []string{"*"}}
		assert.True(t, wildcardCors.IsOriginAllowed("https://any.example.com"))
	})

	t.Run("preflight request", func(t *testing.T) {
		handler := cors.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodOptions, "/api/v1/events", nil)
		req.Header.Set("Origin", "https://siem.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://siem.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

// TenantResolver resolves tenant from request
type TenantResolver struct {
	HeaderName string
}

func (tr *TenantResolver) ResolveTenant(r *http.Request) (string, error) {
	// Try header first
	if tenant := r.Header.Get(tr.HeaderName); tenant != "" {
		return tenant, nil
	}

	// Try from JWT claims in context
	if claims, ok := r.Context().Value("claims").(*Claims); ok && claims != nil {
		return claims.TenantID, nil
	}

	return "", fmt.Errorf("tenant not found")
}

func TestTenantResolver(t *testing.T) {
	resolver := &TenantResolver{HeaderName: "X-Tenant-ID"}

	t.Run("from header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
		req.Header.Set("X-Tenant-ID", "tenant-123")

		tenant, err := resolver.ResolveTenant(req)
		assert.NoError(t, err)
		assert.Equal(t, "tenant-123", tenant)
	})

	t.Run("from context claims", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
		ctx := context.WithValue(req.Context(), "claims", &Claims{TenantID: "tenant-456"})
		req = req.WithContext(ctx)

		tenant, err := resolver.ResolveTenant(req)
		assert.NoError(t, err)
		assert.Equal(t, "tenant-456", tenant)
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)

		_, err := resolver.ResolveTenant(req)
		assert.Error(t, err)
	})
}

// RequestValidator validates incoming requests
type RequestValidator struct{}

func (v *RequestValidator) ValidateJSON(body io.Reader, maxSize int64) ([]byte, error) {
	limitedReader := io.LimitReader(body, maxSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	// Validate JSON syntax
	if !json.Valid(data) {
		return nil, fmt.Errorf("invalid JSON")
	}

	return data, nil
}

func TestRequestValidator_ValidateJSON(t *testing.T) {
	validator := &RequestValidator{}

	tests := []struct {
		name        string
		body        string
		maxSize     int64
		expectError bool
	}{
		{
			name:    "valid JSON",
			body:    `{"key": "value"}`,
			maxSize: 1024,
		},
		{
			name:        "invalid JSON",
			body:        `{"key": value}`,
			maxSize:     1024,
			expectError: true,
		},
		{
			name:        "empty body",
			body:        "",
			maxSize:     1024,
			expectError: true,
		},
		{
			name:    "truncated at max size",
			body:    `{"key": "value", "another": "data"}`,
			maxSize: 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.NewBufferString(tc.body)
			data, err := validator.ValidateJSON(body, tc.maxSize)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, data)
			}
		})
	}
}
