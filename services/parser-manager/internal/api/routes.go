// Package api provides route definitions for the parser manager service.
package api

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/siem-soar-platform/services/parser-manager/internal/service"
)

// Router holds the HTTP router and handlers.
type Router struct {
	engine        *gin.Engine
	parserHandler *ParserHandler
	parserService *service.ParserService
	logger        *slog.Logger
}

// NewRouter creates a new router with all routes configured.
func NewRouter(parserService *service.ParserService, logger *slog.Logger) *Router {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	// Add recovery middleware
	engine.Use(gin.Recovery())

	// Add logging middleware
	engine.Use(loggingMiddleware(logger))

	// Add CORS middleware
	engine.Use(corsMiddleware())

	// Create handler
	parserHandler := NewParserHandler(parserService, logger)

	router := &Router{
		engine:        engine,
		parserHandler: parserHandler,
		parserService: parserService,
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
		r.parserHandler.RegisterRoutes(v1)
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
		"service": "parser-manager",
	})
}

// readyHandler returns service readiness status.
func (r *Router) readyHandler(c *gin.Context) {
	reloadStatus := r.parserService.GetReloadStatus()

	c.JSON(http.StatusOK, gin.H{
		"status":  "ready",
		"service": "parser-manager",
		"reload":  reloadStatus,
	})
}

// metricsHandler returns service metrics.
func (r *Router) metricsHandler(c *gin.Context) {
	stats := r.parserService.GetHotReloadStats()

	c.JSON(http.StatusOK, gin.H{
		"service":    "parser-manager",
		"hot_reload": stats,
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
