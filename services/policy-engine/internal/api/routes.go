// Package api provides route definitions for the policy engine service.
package api

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/siem-soar-platform/services/policy-engine/internal/service"
)

// Router holds the HTTP router and handlers.
type Router struct {
	engine        *gin.Engine
	policyHandler *PolicyHandler
	policyService *service.PolicyService
	logger        *slog.Logger
}

// NewRouter creates a new router with all routes configured.
func NewRouter(policyService *service.PolicyService, logger *slog.Logger) *Router {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	// Add recovery middleware
	engine.Use(gin.Recovery())

	// Add logging middleware
	engine.Use(loggingMiddleware(logger))

	// Add CORS middleware
	engine.Use(corsMiddleware())

	// Create handler
	policyHandler := NewPolicyHandler(policyService, logger)

	router := &Router{
		engine:        engine,
		policyHandler: policyHandler,
		policyService: policyService,
		logger:        logger,
	}

	// Setup routes
	router.setupRoutes()

	return router
}

// setupRoutes configures all routes.
func (r *Router) setupRoutes() {
	// Health endpoints
	r.engine.GET("/health", r.healthHandler)
	r.engine.GET("/ready", r.readyHandler)
	r.engine.GET("/metrics", r.metricsHandler)

	// API v1 routes
	v1 := r.engine.Group("/api/v1")
	{
		r.policyHandler.RegisterRoutes(v1)
	}
}

// Engine returns the underlying Gin engine.
func (r *Router) Engine() *gin.Engine {
	return r.engine
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.engine.ServeHTTP(w, req)
}

// healthHandler returns service health status.
func (r *Router) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "policy-engine",
	})
}

// readyHandler returns service readiness status.
func (r *Router) readyHandler(c *gin.Context) {
	cacheStats, err := r.policyService.GetCacheStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "not_ready",
			"service": "policy-engine",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ready",
		"service": "policy-engine",
		"cache":   cacheStats,
	})
}

// metricsHandler returns service metrics.
func (r *Router) metricsHandler(c *gin.Context) {
	cacheStats, _ := r.policyService.GetCacheStats(c.Request.Context())

	c.JSON(http.StatusOK, gin.H{
		"service": "policy-engine",
		"cache":   cacheStats,
	})
}

// loggingMiddleware logs HTTP requests.
func loggingMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip health checks
		if c.Request.URL.Path == "/health" || c.Request.URL.Path == "/ready" {
			c.Next()
			return
		}

		start := c.Request.Context()
		c.Next()

		logger.Info("http request",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"latency", start,
			"client_ip", c.ClientIP(),
		)
	}
}

// corsMiddleware adds CORS headers.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-User-ID, X-Tenant-ID")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
