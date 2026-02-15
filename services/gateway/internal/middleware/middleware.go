// Package middleware provides HTTP middleware for the API gateway.
package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/siem-soar-platform/services/gateway/internal/auth"
	"github.com/siem-soar-platform/services/gateway/internal/ratelimit"
)

// Middleware represents an HTTP middleware function.
type Middleware func(http.Handler) http.Handler

// Chain chains multiple middleware together.
func Chain(middlewares ...Middleware) Middleware {
	return func(handler http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			handler = middlewares[i](handler)
		}
		return handler
	}
}

// Logger returns a logging middleware.
func Logger(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status
			wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapper, r)

			// Log request
			duration := time.Since(start)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapper.statusCode,
				"duration_ms", duration.Milliseconds(),
				"size", wrapper.bytesWritten,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture response info.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Recovery returns a panic recovery middleware.
func Recovery(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.Error("panic recovered",
						"error", err,
						"stack", string(debug.Stack()),
						"path", r.URL.Path,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// JWTAuth returns a JWT authentication middleware.
func JWTAuth(authenticator *auth.JWTAuthenticator, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := auth.ExtractToken(r)
			if err != nil {
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			claims, err := authenticator.Authenticate(token)
			if err != nil {
				logger.Debug("JWT authentication failed", "error", err)
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Add claims to context
			ctx := auth.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// APIKeyAuth returns an API key authentication middleware.
func APIKeyAuth(authenticator *auth.APIKeyAuthenticator, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := authenticator.ExtractAPIKey(r)
			if apiKey == "" {
				http.Error(w, "Unauthorized: API key required", http.StatusUnauthorized)
				return
			}

			key, err := authenticator.Authenticate(r.Context(), apiKey)
			if err != nil {
				logger.Debug("API key authentication failed", "error", err)
				http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Add API key to context
			ctx := auth.WithAPIKey(r.Context(), key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CombinedAuth returns a middleware that accepts either JWT or API key.
func CombinedAuth(jwtAuth *auth.JWTAuthenticator, apiKeyAuth *auth.APIKeyAuthenticator, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try JWT first
			if token, err := auth.ExtractToken(r); err == nil && token != "" {
				claims, err := jwtAuth.Authenticate(token)
				if err == nil {
					ctx := auth.WithClaims(r.Context(), claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Try API key
			if apiKey := apiKeyAuth.ExtractAPIKey(r); apiKey != "" {
				key, err := apiKeyAuth.Authenticate(r.Context(), apiKey)
				if err == nil {
					ctx := auth.WithAPIKey(r.Context(), key)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

// RateLimit returns a rate limiting middleware.
func RateLimit(limiter *ratelimit.RateLimiter, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract identifiers
			tenantID := auth.GetTenantID(r.Context())
			ip := extractIP(r)
			apiKey := ""
			if key := auth.GetAPIKey(r.Context()); key != nil {
				apiKey = key.ID
			}

			// Check rate limit
			result := limiter.Check(tenantID, ip, apiKey)

			// Set rate limit headers
			for k, v := range ratelimit.GetRateLimitHeaders(result) {
				w.Header().Set(k, v)
			}

			if !result.Allowed {
				logger.Debug("rate limit exceeded",
					"tenant_id", tenantID,
					"ip", ip,
					"limited_by", result.LimitedBy)
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte("Rate limit exceeded"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractIP extracts the client IP from a request.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP (original client)
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIdx := strings.LastIndex(ip, ":"); colonIdx != -1 {
		ip = ip[:colonIdx]
	}
	return ip
}

// CORS returns a CORS middleware.
func CORS(config CORSConfig) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			if len(config.AllowedOrigins) == 0 || config.AllowedOrigins[0] == "*" {
				allowed = true
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				for _, o := range config.AllowedOrigins {
					if o == origin {
						allowed = true
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}

			if !allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers
			if len(config.AllowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
			}
			if len(config.AllowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
			}
			if len(config.ExposedHeaders) > 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
			}
			if config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			if config.MaxAge > 0 {
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

// DefaultCORSConfig returns default CORS configuration.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization", "X-API-Key", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: false,
		MaxAge:           86400,
	}
}

// RequestID returns a request ID middleware.
func RequestID() Middleware {
	var counter atomic.Uint64

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check for existing request ID
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				// Generate new request ID
				requestID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), counter.Add(1))
			}

			// Set response header
			w.Header().Set("X-Request-ID", requestID)

			// Add to context
			ctx := context.WithValue(r.Context(), contextKeyRequestID, requestID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRequestID retrieves the request ID from context.
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(contextKeyRequestID).(string); ok {
		return id
	}
	return ""
}

type contextKey string

const contextKeyRequestID contextKey = "request_id"

// Timeout returns a timeout middleware.
func Timeout(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r.WithContext(ctx))
				close(done)
			}()

			select {
			case <-done:
				return
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					http.Error(w, "Request timeout", http.StatusGatewayTimeout)
				}
			}
		})
	}
}

// SecurityHeaders returns a middleware that adds security headers.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			next.ServeHTTP(w, r)
		})
	}
}

// Compression returns a gzip compression middleware.
func Compression() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if client accepts gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Note: In production, use gzip.NewWriter for actual compression
			// This is a simplified placeholder
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns a middleware that checks for a required permission.
func RequirePermission(permission string, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check JWT claims
			if claims := auth.GetClaims(r.Context()); claims != nil {
				if claims.HasPermission(permission) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check API key
			if key := auth.GetAPIKey(r.Context()); key != nil {
				if key.HasPermission(permission) {
					next.ServeHTTP(w, r)
					return
				}
			}

			logger.Debug("permission denied",
				"permission", permission,
				"path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// RequireRole returns a middleware that checks for a required role.
func RequireRole(role string, logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := auth.GetClaims(r.Context())
			if claims == nil || !claims.HasRole(role) {
				logger.Debug("role denied",
					"role", role,
					"path", r.URL.Path)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// TenantIsolation returns a middleware that ensures tenant isolation.
func TenantIsolation(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID := auth.GetTenantID(r.Context())
			if tenantID == "" {
				logger.Warn("request without tenant ID", "path", r.URL.Path)
				http.Error(w, "Tenant ID required", http.StatusBadRequest)
				return
			}

			// Add tenant ID header for downstream services
			r.Header.Set("X-Tenant-ID", tenantID)

			next.ServeHTTP(w, r)
		})
	}
}

// Metrics returns a middleware that collects metrics.
func Metrics(collector MetricsCollector) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer
			wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Process request
			next.ServeHTTP(wrapper, r)

			// Record metrics
			duration := time.Since(start)
			collector.RecordRequest(r.Method, r.URL.Path, wrapper.statusCode, duration)
		})
	}
}

// MetricsCollector defines the interface for metrics collection.
type MetricsCollector interface {
	RecordRequest(method, path string, status int, duration time.Duration)
}

// NoOpMetricsCollector is a no-op metrics collector.
type NoOpMetricsCollector struct{}

func (c *NoOpMetricsCollector) RecordRequest(method, path string, status int, duration time.Duration) {}
