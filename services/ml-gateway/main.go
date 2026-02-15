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

	"github.com/siem-soar-platform/services/ml-gateway/internal/client"
	"github.com/siem-soar-platform/services/ml-gateway/internal/config"
	"github.com/siem-soar-platform/services/ml-gateway/internal/handler"
	"github.com/siem-soar-platform/services/ml-gateway/internal/router"
)

const (
	serviceName = "ml-gateway"
)

func main() {
	// Initialize structured logger
	logLevel := slog.LevelInfo
	if os.Getenv("DEBUG") == "true" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	slog.Info("starting service",
		"service", serviceName,
		"port", cfg.Port,
		"environment", cfg.Environment,
	)

	// Initialize Redis client for caching
	redisClient, err := client.NewRedisClient(cfg.RedisURL)
	if err != nil {
		slog.Warn("redis connection failed, caching disabled", "error", err)
		redisClient = nil
	}

	// Initialize model service clients
	modelClients := &handler.ModelClients{
		ClassifyClient: client.NewHTTPClient(cfg.ClassifyServiceURL, 30*time.Second),
		DGAClient:      client.NewHTTPClient(cfg.DGAServiceURL, 10*time.Second),
		PriorityClient: client.NewHTTPClient(cfg.PriorityServiceURL, 15*time.Second),
	}

	// Initialize handlers
	predictHandler := handler.NewPredictHandler(modelClients, redisClient, cfg)
	modelHandler := handler.NewModelHandler(modelClients, cfg)
	healthHandler := handler.NewHealthHandler(modelClients)

	// Setup router
	r := router.New(predictHandler, modelHandler, healthHandler, cfg)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second, // Longer for ML inference
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		slog.Info("server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	// Close Redis connection
	if redisClient != nil {
		if err := redisClient.Close(); err != nil {
			slog.Error("redis close error", "error", err)
		}
	}

	slog.Info("server exited")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"ml-gateway"}`)
}
