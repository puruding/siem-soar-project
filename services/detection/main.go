package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siem-soar-platform/services/detection/internal/config"
	"github.com/siem-soar-platform/services/detection/internal/consumer"
	"github.com/siem-soar-platform/services/detection/internal/engine"
	"github.com/siem-soar-platform/services/detection/internal/rule"
)

const serviceName = "detection"

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("starting detection service",
		"service", serviceName,
		"http_port", cfg.HTTPPort,
		"kafka_brokers", cfg.Kafka.Brokers,
		"kafka_input_topic", cfg.Kafka.InputTopic,
		"kafka_output_topic", cfg.Kafka.OutputTopic,
		"workers", cfg.Workers)

	// Initialize rule loader (without database for now)
	loaderCfg := rule.LoaderConfig{
		RulesDirectory: cfg.RulesDirectory,
		FileExtensions: []string{".yml", ".yaml", ".json"},
	}
	ruleLoader := rule.NewLoader(loaderCfg, nil, logger)

	// Initialize detection engine
	engineCfg := engine.DefaultEngineConfig()
	engineCfg.NumWorkers = cfg.Workers
	engineCfg.BatchSize = cfg.BatchSize
	engineCfg.BatchTimeout = cfg.BatchTimeout
	engineCfg.RuleReloadInterval = cfg.RuleReloadInterval

	detectionEngine := engine.NewEngine(engineCfg, ruleLoader, logger)

	// Start detection engine
	if err := detectionEngine.Start(); err != nil {
		slog.Warn("detection engine start failed (continuing without engine)", "error", err)
		// Continue without engine - consumer will use simple rules
	}

	// Initialize Kafka consumer
	kafkaConsumer, err := consumer.NewConsumer(cfg, detectionEngine, logger)
	if err != nil {
		slog.Error("failed to create kafka consumer", "error", err)
		os.Exit(1)
	}

	// Start Kafka consumer
	if err := kafkaConsumer.Start(); err != nil {
		slog.Error("failed to start kafka consumer", "error", err)
		os.Exit(1)
	}

	// Setup HTTP server for health checks and metrics
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		readyHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		metricsHandler(w, r, kafkaConsumer, detectionEngine)
	})
	mux.HandleFunc("POST /api/v1/rules", createRuleHandler)
	mux.HandleFunc("GET /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		listRulesHandler(w, r, detectionEngine)
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server
	go func() {
		slog.Info("starting HTTP server", "port", cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down detection service")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop Kafka consumer
	if err := kafkaConsumer.Stop(); err != nil {
		slog.Error("failed to stop kafka consumer", "error", err)
	}

	// Stop detection engine
	if err := detectionEngine.Stop(); err != nil {
		slog.Error("failed to stop detection engine", "error", err)
	}

	// Stop HTTP server
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("HTTP server forced to shutdown", "error", err)
	}

	slog.Info("detection service stopped")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"detection"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	w.Header().Set("Content-Type", "application/json")

	ready := true
	status := "ready"

	if eng != nil && eng.State() != engine.StateRunning {
		// Engine not running, but consumer might still work with simple rules
		status = "degraded"
	}

	if ready {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		status = "not_ready"
	}

	fmt.Fprintf(w, `{"status":"%s","service":"detection"}`, status)
}

func metricsHandler(w http.ResponseWriter, r *http.Request, c *consumer.Consumer, eng *engine.Engine) {
	w.Header().Set("Content-Type", "application/json")

	metrics := make(map[string]interface{})
	metrics["service"] = serviceName

	// Consumer metrics
	if c != nil {
		consumerStats := c.Stats()
		metrics["consumer"] = map[string]interface{}{
			"events_consumed":  consumerStats.EventsConsumed,
			"events_processed": consumerStats.EventsProcessed,
			"alerts_generated": consumerStats.AlertsGenerated,
			"errors":           consumerStats.Errors,
			"parse_errors":     consumerStats.ParseErrors,
		}
	}

	// Engine metrics
	if eng != nil {
		metrics["engine"] = eng.Stats()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}

func createRuleHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement rule creation
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprint(w, `{"message":"rule created"}`)
}

func listRulesHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	w.Header().Set("Content-Type", "application/json")

	rules := make([]map[string]interface{}, 0)

	if eng != nil {
		for _, ru := range eng.GetRules() {
			rules = append(rules, map[string]interface{}{
				"id":        ru.ID,
				"name":      ru.Name,
				"type":      ru.Type,
				"status":    ru.Status,
				"severity":  ru.Severity,
				"enabled":   ru.IsEnabled,
			})
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"rules": rules})
}
