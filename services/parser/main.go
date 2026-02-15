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

	"github.com/siem-soar-platform/services/parser/internal/config"
	"github.com/siem-soar-platform/services/parser/internal/consumer"
	"github.com/siem-soar-platform/services/parser/internal/engine"
	"github.com/siem-soar-platform/services/parser/internal/hotreload"
)

type App struct {
	cfg      *config.Config
	engine   *engine.Engine
	consumer *consumer.Consumer
	hotreload *hotreload.Manager
	logger   *slog.Logger
}

func main() {
	// Initialize logger
	logLevel := slog.LevelInfo
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.Load()

	// Create parser engine
	parserCfg := engine.ParserConfig{
		Workers:          cfg.Workers,
		BatchSize:        cfg.BatchSize,
		MaxFieldSize:     cfg.MaxFieldSize,
		MaxFields:        cfg.MaxFields,
		ParseTimeout:     cfg.ParseTimeout,
		EnableAutoDetect: cfg.EnableAutoDetect,
		EnableGrokCache:  cfg.EnableGrokCache,
		GrokCacheSize:    cfg.GrokCacheSize,
	}
	eng := engine.NewEngine(parserCfg, logger)

	// Create hot reload manager
	hrManager := hotreload.NewManager(cfg, eng, logger)

	// Load patterns from Redis if available
	if err := hrManager.LoadPatternsFromRedis(); err != nil {
		logger.Warn("failed to load patterns from Redis", "error", err)
	}

	// Create Kafka consumer
	kafkaConsumer, err := consumer.NewConsumer(cfg, eng, logger)
	if err != nil {
		logger.Error("failed to create Kafka consumer", "error", err)
		// Continue without Kafka - service can still work via HTTP
		kafkaConsumer = nil
	}

	app := &App{
		cfg:       cfg,
		engine:    eng,
		consumer:  kafkaConsumer,
		hotreload: hrManager,
		logger:    logger,
	}

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", app.healthHandler)
	mux.HandleFunc("GET /ready", app.readyHandler)
	mux.HandleFunc("POST /api/v1/parse", app.parseHandler)
	mux.HandleFunc("POST /api/v1/parse/batch", app.batchParseHandler)
	mux.HandleFunc("GET /api/v1/patterns", app.listPatternsHandler)
	mux.HandleFunc("POST /api/v1/patterns", app.createPatternHandler)
	mux.HandleFunc("GET /api/v1/patterns/{id}", app.getPatternHandler)
	mux.HandleFunc("PUT /api/v1/patterns/{id}", app.updatePatternHandler)
	mux.HandleFunc("DELETE /api/v1/patterns/{id}", app.deletePatternHandler)
	mux.HandleFunc("POST /api/v1/detect-format", app.detectFormatHandler)
	mux.HandleFunc("GET /api/v1/stats", app.statsHandler)
	mux.HandleFunc("POST /api/v1/reload", app.reloadHandler)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start services
	if err := hrManager.Start(); err != nil {
		logger.Warn("hot reload disabled", "error", err)
	}

	if kafkaConsumer != nil {
		kafkaConsumer.Start()
	}

	go func() {
		logger.Info("starting server", "service", cfg.ServiceName, "port", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if kafkaConsumer != nil {
		kafkaConsumer.Stop()
	}
	hrManager.Stop()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
	}

	logger.Info("server exited")
}

func (a *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": a.cfg.ServiceName,
	})
}

func (a *App) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ready",
		"service": a.cfg.ServiceName,
	})
}

func (a *App) parseHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventID    string            `json:"event_id"`
		TenantID   string            `json:"tenant_id"`
		SourceType string            `json:"source_type"`
		Data       string            `json:"data"`
		Metadata   map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	rawEvent := &engine.RawEvent{
		EventID:    req.EventID,
		TenantID:   req.TenantID,
		SourceType: req.SourceType,
		Timestamp:  time.Now(),
		Data:       []byte(req.Data),
		Metadata:   req.Metadata,
	}

	parsed := a.engine.Parse(r.Context(), rawEvent)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(parsed)
}

func (a *App) batchParseHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Events []struct {
			EventID    string            `json:"event_id"`
			TenantID   string            `json:"tenant_id"`
			SourceType string            `json:"source_type"`
			Data       string            `json:"data"`
			Metadata   map[string]string `json:"metadata"`
		} `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	rawEvents := make([]*engine.RawEvent, len(req.Events))
	for i, e := range req.Events {
		rawEvents[i] = &engine.RawEvent{
			EventID:    e.EventID,
			TenantID:   e.TenantID,
			SourceType: e.SourceType,
			Timestamp:  time.Now(),
			Data:       []byte(e.Data),
			Metadata:   e.Metadata,
		}
	}

	parsed := a.engine.ParseBatch(r.Context(), rawEvents)

	successCount := 0
	for _, p := range parsed {
		if p != nil && p.ParseSuccess {
			successCount++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "batch parsed",
		"count":   len(parsed),
		"success": successCount,
		"failed":  len(parsed) - successCount,
		"results": parsed,
	})
}

func (a *App) listPatternsHandler(w http.ResponseWriter, r *http.Request) {
	grokPatterns := a.engine.GetGrokParser().List()
	regexPatterns := a.engine.GetRegexParser().GetPatterns()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"grok":  grokPatterns,
		"regex": regexPatterns,
	})
}

func (a *App) createPatternHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string `json:"type"` // grok or regex
		Name     string `json:"name"`
		Pattern  string `json:"pattern"`
		Priority int    `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	var err error
	switch req.Type {
	case "grok":
		err = a.engine.GetGrokParser().AddPattern(req.Name, req.Pattern)
	case "regex":
		err = a.engine.GetRegexParser().AddPattern(req.Name, req.Pattern, req.Priority, nil)
	default:
		http.Error(w, `{"error":"invalid pattern type"}`, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Persist to Redis
	if err := a.hotreload.SavePatternToRedis(req.Type, req.Name, req.Pattern); err != nil {
		a.logger.Warn("failed to save pattern to Redis", "error", err)
	}

	// Broadcast update
	a.hotreload.PublishUpdate(&hotreload.PatternUpdate{
		Action:  "add",
		Type:    req.Type,
		Name:    req.Name,
		Pattern: req.Pattern,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "pattern created",
		"id":      req.Name,
	})
}

func (a *App) getPatternHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	patternType := r.URL.Query().Get("type")

	var pattern string
	var found bool

	switch patternType {
	case "grok":
		pattern, found = a.engine.GetGrokParser().Get(id)
	default:
		// Return pattern info
		patterns := a.engine.GetRegexParser().GetPatterns()
		for _, p := range patterns {
			if p == id {
				found = true
				break
			}
		}
	}

	if !found {
		http.Error(w, `{"error":"pattern not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"type":    patternType,
		"pattern": pattern,
	})
}

func (a *App) updatePatternHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	var err error
	switch req.Type {
	case "grok":
		err = a.engine.GetGrokParser().AddPattern(id, req.Pattern)
	case "regex":
		err = a.engine.GetRegexParser().AddPattern(id, req.Pattern)
	default:
		http.Error(w, `{"error":"invalid pattern type"}`, http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	// Persist and broadcast
	a.hotreload.SavePatternToRedis(req.Type, id, req.Pattern)
	a.hotreload.PublishUpdate(&hotreload.PatternUpdate{
		Action:  "update",
		Type:    req.Type,
		Name:    id,
		Pattern: req.Pattern,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "pattern updated",
	})
}

func (a *App) deletePatternHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	patternType := r.URL.Query().Get("type")

	switch patternType {
	case "grok":
		a.engine.GetGrokParser().RemovePattern(id)
	case "regex":
		a.engine.GetRegexParser().RemovePattern(id)
	default:
		http.Error(w, `{"error":"invalid pattern type"}`, http.StatusBadRequest)
		return
	}

	// Persist and broadcast
	a.hotreload.DeletePatternFromRedis(patternType, id)
	a.hotreload.PublishUpdate(&hotreload.PatternUpdate{
		Action: "delete",
		Type:   patternType,
		Name:   id,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "pattern deleted",
	})
}

func (a *App) detectFormatHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	detector := engine.NewFormatDetector()
	format := detector.Detect([]byte(req.Data))

	confidence := 0.8 // Default confidence
	if format == "unknown" || format == "raw" {
		confidence = 0.2
	} else if format == "json" || format == "cef" || format == "leef" {
		confidence = 0.95
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"format":     format,
		"confidence": confidence,
	})
}

func (a *App) statsHandler(w http.ResponseWriter, r *http.Request) {
	stats := a.engine.Stats()

	if a.consumer != nil {
		consumerStats := a.consumer.Stats()
		for k, v := range consumerStats {
			stats["consumer_"+k] = v
		}
	}

	if a.hotreload != nil {
		hrStats := a.hotreload.Stats()
		for k, v := range hrStats {
			stats["hotreload_"+k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (a *App) reloadHandler(w http.ResponseWriter, r *http.Request) {
	if err := a.hotreload.LoadPatternsFromRedis(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "patterns reloaded",
	})
}
