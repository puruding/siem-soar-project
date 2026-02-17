package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/siem-soar-platform/services/case/internal/config"
	"github.com/siem-soar-platform/services/case/internal/handler"
	"github.com/siem-soar-platform/services/case/internal/repository"
	"github.com/siem-soar-platform/services/case/internal/service"
	"github.com/siem-soar-platform/services/case/internal/timeline"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize logger
	logLevel := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	var logHandler slog.Handler
	if cfg.Logging.Format == "text" {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	slog.Info("starting service",
		"service", cfg.Service.Name,
		"environment", cfg.Service.Environment,
		"port", cfg.Service.HTTPPort,
	)

	// Initialize PostgreSQL connection
	db, err := initDB(cfg)
	if err != nil {
		slog.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	slog.Info("database connection established",
		"host", cfg.Database.Host,
		"database", cfg.Database.Database,
	)

	// Initialize components
	caseRepo := repository.NewCaseRepository(db)
	timelineStore := timeline.NewMemoryStore()
	timelineService := timeline.NewTimelineService(timelineStore)
	caseService := service.NewCaseService(caseRepo, timelineService)
	caseHandler := handler.NewCaseHandler(caseService)

	// Set up HTTP router
	router := mux.NewRouter()

	// Add middleware
	router.Use(loggingMiddleware)
	router.Use(recoveryMiddleware)
	router.Use(corsMiddleware(cfg.CORS))

	// Register health and readiness endpoints
	router.HandleFunc("/health", healthHandler(db)).Methods("GET")
	router.HandleFunc("/ready", readyHandler(db)).Methods("GET")

	// Register API routes
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	caseHandler.RegisterRoutes(apiRouter)

	// Metrics endpoint (Prometheus-compatible)
	router.HandleFunc("/metrics", metricsHandler).Methods("GET")

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Service.HTTPPort,
		Handler:      router,
		ReadTimeout:  cfg.Service.ReadTimeout,
		WriteTimeout: cfg.Service.WriteTimeout,
		IdleTimeout:  cfg.Service.IdleTimeout,
	}

	// Start server in goroutine
	go func() {
		slog.Info("HTTP server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Start metrics server if configured on different port
	var metricsServer *http.Server
	if cfg.Service.MetricsPort != "" && cfg.Service.MetricsPort != cfg.Service.HTTPPort {
		metricsRouter := mux.NewRouter()
		metricsRouter.HandleFunc("/metrics", metricsHandler).Methods("GET")
		metricsRouter.HandleFunc("/health", healthHandler(db)).Methods("GET")

		metricsServer = &http.Server{
			Addr:         ":" + cfg.Service.MetricsPort,
			Handler:      metricsRouter,
			ReadTimeout:  cfg.Service.ReadTimeout,
			WriteTimeout: cfg.Service.WriteTimeout,
		}

		go func() {
			slog.Info("Metrics server listening", "addr", metricsServer.Addr)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Metrics server error", "error", err)
			}
		}()
	}

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down servers")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Service.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("HTTP server forced to shutdown", "error", err)
	}

	if metricsServer != nil {
		if err := metricsServer.Shutdown(ctx); err != nil {
			slog.Error("Metrics server forced to shutdown", "error", err)
		}
	}

	slog.Info("servers exited gracefully")
}

// initDB initializes the PostgreSQL database connection.
func initDB(cfg *config.Config) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", cfg.Database.DSN())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.Database.ConnMaxIdleTime)

	// Verify connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// Middleware

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		slog.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path,
				)
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(cfg config.CORSConfig) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, o := range cfg.AllowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.Header().Set("Access-Control-Allow-Methods", joinStrings(cfg.AllowedMethods))
				w.Header().Set("Access-Control-Allow-Headers", joinStrings(cfg.AllowedHeaders))
				w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", cfg.MaxAge))
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func joinStrings(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += ", " + strs[i]
	}
	return result
}

// Handlers

func healthHandler(db *sqlx.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy","service":"case"}`)
	}
}

func readyHandler(db *sqlx.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Check database connectivity
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"not_ready","service":"case","error":"database connection failed"}`)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ready","service":"case"}`)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Basic Prometheus metrics format
	// In production, use prometheus/client_golang for proper metrics
	metrics := `# HELP case_service_up Service health status
# TYPE case_service_up gauge
case_service_up 1

# HELP case_service_info Service information
# TYPE case_service_info gauge
case_service_info{service="case",version="1.0.0"} 1
`
	fmt.Fprint(w, metrics)
}
