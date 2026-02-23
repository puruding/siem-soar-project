package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/services/pipeline/config"
	"github.com/siem-soar-platform/services/pipeline/internal/handler"
	"github.com/siem-soar-platform/services/pipeline/internal/repository"
	"github.com/siem-soar-platform/services/pipeline/internal/service"
)

const serviceName = "pipeline"

var (
	cfg    *config.Config
	db     *sql.DB
	logger *slog.Logger
)

func main() {
	// Initialize logger
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Initialize OpenTelemetry
	ctx := context.Background()
	otelCfg := observability.DefaultConfig(serviceName)
	otelProvider, err := observability.Init(ctx, otelCfg)
	if err != nil {
		slog.Warn("failed to initialize OpenTelemetry", "error", err)
	}
	if otelProvider != nil {
		defer otelProvider.Shutdown(ctx)
	}

	// Load configuration
	cfg = config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("starting pipeline service",
		"service", serviceName,
		"port", cfg.Server.Port,
		"environment", cfg.Environment,
		"version", cfg.Version,
	)

	// Initialize database connection
	db, err = sql.Open("postgres", cfg.Postgres.ConnectionString())
	if err != nil {
		slog.Warn("failed to connect to database, running without persistence", "error", err)
	} else {
		if err := db.Ping(); err != nil {
			slog.Warn("database ping failed, will retry on requests", "error", err)
		} else {
			slog.Info("connected to database")
		}
	}

	// Initialize repository
	var repo *repository.PipelineRepository
	if db != nil {
		repo = repository.NewPipelineRepository(db)
	}

	// Initialize service
	pipelineService := service.NewPipelineService(repo, cfg, logger)

	// Initialize handler
	pipelineHandler := handler.NewPipelineHandler(pipelineService, logger)

	// Setup HTTP router
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler)
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// Register pipeline routes
	pipelineHandler.RegisterRoutes(mux)

	// Legacy routes for backward compatibility
	mux.HandleFunc("GET /api/v1/pipelines", corsMiddleware(listPipelinesHandler))
	mux.HandleFunc("POST /api/v1/pipelines", corsMiddleware(createPipelineHandler))
	mux.HandleFunc("GET /api/v1/pipelines/{id}", corsMiddleware(getPipelineHandler))
	mux.HandleFunc("PUT /api/v1/pipelines/{id}", corsMiddleware(updatePipelineHandler))
	mux.HandleFunc("DELETE /api/v1/pipelines/{id}", corsMiddleware(deletePipelineHandler))
	mux.HandleFunc("POST /api/v1/pipelines/{id}/start", corsMiddleware(startPipelineHandler))
	mux.HandleFunc("POST /api/v1/pipelines/{id}/stop", corsMiddleware(stopPipelineHandler))
	mux.HandleFunc("GET /api/v1/pipelines/{id}/metrics", corsMiddleware(pipelineMetricsHandler))
	mux.HandleFunc("OPTIONS /api/v1/pipelines", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipelines/{id}", corsPreflightHandler)

	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      otelhttp.NewHandler(mux, serviceName),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server
	go func() {
		slog.Info("starting HTTP server", "port", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down pipeline service")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Close database connection
	if db != nil {
		if err := db.Close(); err != nil {
			slog.Error("failed to close database", "error", err)
		}
	}

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("pipeline service stopped")
}

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func corsPreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"pipeline"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	if db != nil {
		if err := db.Ping(); err != nil {
			status = "degraded"
		}
	} else {
		status = "no_database"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"%s","service":"pipeline"}`, status)
}


// Legacy handlers for backward compatibility
func listPipelinesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"pipelines":[],"total":0}`)
}

func createPipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"message":"pipeline created","id":""}`)
}

func getPipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"id":"","name":"","status":"stopped","stages":[]}`)
}

func updatePipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"pipeline updated"}`)
}

func deletePipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"pipeline deleted"}`)
}

func startPipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"pipeline started"}`)
}

func stopPipelineHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"message":"pipeline stopped"}`)
}

func pipelineMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"events_processed":0,"events_per_second":0,"error_rate":0}`)
}
