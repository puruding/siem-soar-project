package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/siem-soar-platform/services/router/internal/config"
	"github.com/siem-soar-platform/services/router/internal/consumer"
	"github.com/siem-soar-platform/services/router/internal/destination"
	"github.com/siem-soar-platform/services/router/internal/routing"
)

const (
	serviceName = "router"
)

// Server holds all service dependencies.
type Server struct {
	config   *config.Config
	router   *routing.Router
	consumer *consumer.Consumer
	logger   *slog.Logger

	// Dynamic rules and destinations (for API management)
	rulesMu        sync.RWMutex
	rules          map[string]*routing.RoutingRule
	destinationsMu sync.RWMutex
	destinations   map[string]routing.Destination

	// Status flags
	kafkaConnected atomic.Bool
	ready          atomic.Bool
}

// RouteRequest represents a single event routing request.
type RouteRequest struct {
	Event *routing.Event `json:"event"`
}

// RouteResponse represents a single event routing response.
type RouteResponse struct {
	Success      bool     `json:"success"`
	EventID      string   `json:"event_id"`
	Destinations []string `json:"destinations"`
	Filtered     bool     `json:"filtered"`
	Sampled      bool     `json:"sampled"`
	Error        string   `json:"error,omitempty"`
}

// BatchRouteRequest represents a batch routing request.
type BatchRouteRequest struct {
	Events []*routing.Event `json:"events"`
}

// BatchRouteResponse represents a batch routing response.
type BatchRouteResponse struct {
	TotalCount   int               `json:"total_count"`
	SuccessCount int               `json:"success_count"`
	FailedCount  int               `json:"failed_count"`
	Results      []*RouteResponse  `json:"results"`
	TotalTimeMs  int64             `json:"total_time_ms"`
}

// RuleRequest represents a rule create/update request.
type RuleRequest struct {
	ID           string             `json:"id,omitempty"`
	Name         string             `json:"name"`
	Description  string             `json:"description,omitempty"`
	Priority     int                `json:"priority"`
	Enabled      bool               `json:"enabled"`
	Conditions   []routing.Condition `json:"conditions"`
	Destinations []string           `json:"destinations"`
	Actions      []routing.Action   `json:"actions,omitempty"`
	StopOnMatch  bool               `json:"stop_on_match"`
	SampleRate   float64            `json:"sample_rate"`
}

// DestinationRequest represents a destination create/update request.
type DestinationRequest struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"` // clickhouse, kafka, s3
	Config map[string]interface{} `json:"config"`
}

// DestinationResponse represents destination info.
type DestinationResponse struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Healthy bool   `json:"healthy"`
}

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := config.Load()

	// Create router engine
	routerCfg := routing.RouterConfig{
		DefaultDestination: cfg.DefaultDestination,
		MaxConcurrent:      cfg.MaxConcurrent,
		EnableMetrics:      cfg.MetricsEnabled,
	}
	router := routing.NewRouter(routerCfg, logger)

	// Create server
	server := &Server{
		config:       cfg,
		router:       router,
		logger:       logger,
		rules:        make(map[string]*routing.RoutingRule),
		destinations: make(map[string]routing.Destination),
	}

	// Initialize destinations
	if err := server.initDestinations(); err != nil {
		logger.Error("failed to initialize destinations", "error", err)
		// Continue - some destinations may fail but others work
	}

	// Initialize default routing rules
	server.initDefaultRules()

	// Initialize Kafka consumer (if configured)
	if len(cfg.KafkaBrokers) > 0 && cfg.KafkaBrokers[0] != "" {
		cons, err := consumer.NewConsumer(cfg, router, logger)
		if err != nil {
			logger.Warn("failed to create Kafka consumer, running in API-only mode", "error", err)
		} else {
			server.consumer = cons
			server.kafkaConnected.Store(true)
		}
	}

	server.ready.Store(true)

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", server.healthHandler)
	mux.HandleFunc("GET /ready", server.readyHandler)
	mux.HandleFunc("POST /api/v1/route", server.routeHandler)
	mux.HandleFunc("POST /api/v1/route/batch", server.batchRouteHandler)
	mux.HandleFunc("GET /api/v1/rules", server.listRulesHandler)
	mux.HandleFunc("POST /api/v1/rules", server.createRuleHandler)
	mux.HandleFunc("GET /api/v1/rules/{id}", server.getRuleHandler)
	mux.HandleFunc("PUT /api/v1/rules/{id}", server.updateRuleHandler)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", server.deleteRuleHandler)
	mux.HandleFunc("GET /api/v1/destinations", server.listDestinationsHandler)
	mux.HandleFunc("POST /api/v1/destinations", server.createDestinationHandler)
	mux.HandleFunc("GET /api/v1/destinations/{id}", server.getDestinationHandler)
	mux.HandleFunc("PUT /api/v1/destinations/{id}", server.updateDestinationHandler)
	mux.HandleFunc("DELETE /api/v1/destinations/{id}", server.deleteDestinationHandler)
	mux.HandleFunc("GET /api/v1/stats", server.statsHandler)

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start Kafka consumer in background
	if server.consumer != nil {
		server.consumer.Start()
		logger.Info("kafka consumer started")
	}

	// Start HTTP server
	go func() {
		slog.Info("starting server", "service", serviceName, "port", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop Kafka consumer first
	if server.consumer != nil {
		server.consumer.Stop()
		logger.Info("kafka consumer stopped")
	}

	// Close router (and all destinations)
	if err := server.router.Close(); err != nil {
		logger.Error("failed to close router", "error", err)
	}

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
}

// initDestinations initializes all destinations based on configuration.
func (s *Server) initDestinations() error {
	cfg := s.config
	var lastErr error

	// Initialize ClickHouse destination
	if len(cfg.ClickHouseHosts) > 0 && cfg.ClickHouseHosts[0] != "" {
		chCfg := destination.ClickHouseConfig{
			Name:          "clickhouse-main",
			Hosts:         cfg.ClickHouseHosts,
			Database:      cfg.ClickHouseDatabase,
			Table:         cfg.ClickHouseTable,
			Username:      cfg.ClickHouseUsername,
			Password:      cfg.ClickHousePassword,
			BatchSize:     cfg.ClickHouseBatchSize,
			FlushInterval: cfg.ClickHouseFlushInterval,
			Compression:   "lz4",
			AsyncInsert:   true,
		}
		chDest, err := destination.NewClickHouseDestination(chCfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to create ClickHouse destination", "error", err)
			lastErr = err
		} else {
			s.registerDestination(chDest)
			s.logger.Info("ClickHouse destination initialized", "name", chDest.Name())
		}
	}

	// Initialize Kafka destinations (output, detection, alerts)
	if len(cfg.KafkaBrokers) > 0 && cfg.KafkaBrokers[0] != "" {
		// Main output topic
		kafkaRoutedCfg := destination.KafkaConfig{
			Name:        "kafka-routed",
			Brokers:     cfg.KafkaBrokers,
			Topic:       cfg.KafkaOutputTopic,
			Compression: "lz4",
		}
		kafkaRoutedDest, err := destination.NewKafkaDestination(kafkaRoutedCfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to create Kafka routed destination", "error", err)
			lastErr = err
		} else {
			s.registerDestination(kafkaRoutedDest)
			s.logger.Info("Kafka routed destination initialized", "name", kafkaRoutedDest.Name())
		}

		// Detection topic
		kafkaDetectionCfg := destination.KafkaConfig{
			Name:        "kafka-detection",
			Brokers:     cfg.KafkaBrokers,
			Topic:       cfg.KafkaDetectionTopic,
			Compression: "lz4",
		}
		kafkaDetectionDest, err := destination.NewKafkaDestination(kafkaDetectionCfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to create Kafka detection destination", "error", err)
			lastErr = err
		} else {
			s.registerDestination(kafkaDetectionDest)
			s.logger.Info("Kafka detection destination initialized", "name", kafkaDetectionDest.Name())
		}

		// Alerts topic
		kafkaAlertCfg := destination.KafkaConfig{
			Name:        "kafka-alerts",
			Brokers:     cfg.KafkaBrokers,
			Topic:       cfg.KafkaAlertTopic,
			Compression: "lz4",
		}
		kafkaAlertDest, err := destination.NewKafkaDestination(kafkaAlertCfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to create Kafka alerts destination", "error", err)
			lastErr = err
		} else {
			s.registerDestination(kafkaAlertDest)
			s.logger.Info("Kafka alerts destination initialized", "name", kafkaAlertDest.Name())
		}
	}

	// Initialize S3 destination
	if cfg.S3Bucket != "" && (cfg.S3AccessKey != "" || cfg.S3Endpoint != "") {
		s3Cfg := destination.S3Config{
			Name:          "s3-archive",
			Region:        cfg.S3Region,
			Bucket:        cfg.S3Bucket,
			Prefix:        cfg.S3Prefix,
			Endpoint:      cfg.S3Endpoint,
			AccessKey:     cfg.S3AccessKey,
			SecretKey:     cfg.S3SecretKey,
			Compression:   cfg.S3Compression,
			BatchSize:     cfg.S3BatchSize,
			FlushInterval: cfg.S3FlushInterval,
			FileFormat:    "ndjson",
			PartitionBy:   "hour",
		}
		s3Dest, err := destination.NewS3Destination(s3Cfg, s.logger)
		if err != nil {
			s.logger.Warn("failed to create S3 destination", "error", err)
			lastErr = err
		} else {
			s.registerDestination(s3Dest)
			s.logger.Info("S3 destination initialized", "name", s3Dest.Name())
		}
	}

	return lastErr
}

// registerDestination registers a destination with both the server and router.
func (s *Server) registerDestination(dest routing.Destination) {
	s.destinationsMu.Lock()
	s.destinations[dest.Name()] = dest
	s.destinationsMu.Unlock()
	s.router.RegisterDestination(dest)
}

// initDefaultRules initializes default routing rules.
func (s *Server) initDefaultRules() {
	// Rule 1: Security events to Detection topic
	securityRule := &routing.RoutingRule{
		ID:          "security-events",
		Name:        "Route Security Events to Detection",
		Description: "Routes security-related events to the detection engine",
		Priority:    10,
		Enabled:     true,
		Conditions: []routing.Condition{
			{
				Field:    "event_type",
				Operator: "in",
				Value:    []interface{}{"USER_LOGIN", "PROCESS_LAUNCH", "NETWORK_CONNECTION", "FILE_MODIFICATION", "REGISTRY_MODIFICATION"},
			},
		},
		Destinations: []string{"kafka-detection"},
		StopOnMatch:  false,
		SampleRate:   1.0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.addRule(securityRule)

	// Rule 2: High severity to Alert topic
	highSeverityRule := &routing.RoutingRule{
		ID:          "high-severity",
		Name:        "Route High Severity to Alerts",
		Description: "Routes high and critical severity events to the alerts topic",
		Priority:    5,
		Enabled:     true,
		Conditions: []routing.Condition{
			{
				Field:    "severity",
				Operator: "in",
				Value:    []interface{}{"CRITICAL", "HIGH"},
			},
		},
		Destinations: []string{"kafka-alerts"},
		StopOnMatch:  false,
		SampleRate:   1.0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.addRule(highSeverityRule)

	// Rule 3: All events to ClickHouse for storage
	storageRule := &routing.RoutingRule{
		ID:           "all-to-storage",
		Name:         "Store All Events",
		Description:  "Stores all events in ClickHouse for long-term retention",
		Priority:     100,
		Enabled:      true,
		Conditions:   []routing.Condition{}, // No conditions = match all
		Destinations: []string{"clickhouse-main"},
		StopOnMatch:  false,
		SampleRate:   1.0,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.addRule(storageRule)

	// Rule 4: Archive to S3
	archiveRule := &routing.RoutingRule{
		ID:           "archive-to-s3",
		Name:         "Archive to S3",
		Description:  "Archives events to S3 for compliance and long-term storage",
		Priority:     200,
		Enabled:      true,
		Conditions:   []routing.Condition{},
		Destinations: []string{"s3-archive"},
		StopOnMatch:  false,
		SampleRate:   1.0, // Can be set to 0.1 for 10% sampling
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	s.addRule(archiveRule)

	s.logger.Info("initialized default routing rules", "count", 4)
}

// addRule adds a rule to both the server and router.
func (s *Server) addRule(rule *routing.RoutingRule) {
	s.rulesMu.Lock()
	s.rules[rule.ID] = rule
	s.rulesMu.Unlock()
	s.router.AddRule(rule)
}

// healthHandler returns service health status.
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": serviceName,
	})
}

// readyHandler returns service readiness status.
func (s *Server) readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "ready"
	httpStatus := http.StatusOK

	if !s.ready.Load() {
		status = "not_ready"
		httpStatus = http.StatusServiceUnavailable
	}

	// Check Kafka
	dependencies := map[string]string{}
	if s.consumer != nil {
		if s.kafkaConnected.Load() {
			dependencies["kafka"] = "connected"
		} else {
			dependencies["kafka"] = "disconnected"
		}
	}

	// Check destinations health
	s.destinationsMu.RLock()
	destHealth := make(map[string]bool)
	for name, dest := range s.destinations {
		destHealth[name] = dest.IsHealthy()
	}
	s.destinationsMu.RUnlock()

	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             status,
		"service":            serviceName,
		"dependencies":       dependencies,
		"destination_health": destHealth,
	})
}

// routeHandler routes a single event.
func (s *Server) routeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RouteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if req.Event == nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(RouteResponse{
			Success: false,
			Error:   "event is required",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result := s.router.Route(ctx, req.Event)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(RouteResponse{
		Success:      result.Error == "",
		EventID:      result.EventID,
		Destinations: result.Destinations,
		Filtered:     result.Filtered,
		Sampled:      result.Sampled,
		Error:        result.Error,
	})
}

// batchRouteHandler routes a batch of events.
func (s *Server) batchRouteHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req BatchRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	start := time.Now()
	results := s.router.RouteBatch(r.Context(), req.Events)

	responses := make([]*RouteResponse, len(results))
	successCount := 0
	failedCount := 0

	for i, result := range results {
		if result.Error == "" {
			successCount++
		} else {
			failedCount++
		}
		responses[i] = &RouteResponse{
			Success:      result.Error == "",
			EventID:      result.EventID,
			Destinations: result.Destinations,
			Filtered:     result.Filtered,
			Sampled:      result.Sampled,
			Error:        result.Error,
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(BatchRouteResponse{
		TotalCount:   len(req.Events),
		SuccessCount: successCount,
		FailedCount:  failedCount,
		Results:      responses,
		TotalTimeMs:  time.Since(start).Milliseconds(),
	})
}

// listRulesHandler lists all routing rules.
func (s *Server) listRulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rules := s.router.GetRules()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": rules,
		"count": len(rules),
	})
}

// createRuleHandler creates a new routing rule.
func (s *Server) createRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	if req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "name is required"})
		return
	}

	// Generate ID if not provided
	id := req.ID
	if id == "" {
		id = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}

	// Check if rule already exists
	s.rulesMu.RLock()
	_, exists := s.rules[id]
	s.rulesMu.RUnlock()

	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule with this ID already exists"})
		return
	}

	rule := &routing.RoutingRule{
		ID:           id,
		Name:         req.Name,
		Description:  req.Description,
		Priority:     req.Priority,
		Enabled:      req.Enabled,
		Conditions:   req.Conditions,
		Destinations: req.Destinations,
		Actions:      req.Actions,
		StopOnMatch:  req.StopOnMatch,
		SampleRate:   req.SampleRate,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if rule.SampleRate == 0 {
		rule.SampleRate = 1.0
	}

	s.addRule(rule)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "rule created",
		"rule":    rule,
	})
}

// getRuleHandler gets a specific routing rule.
func (s *Server) getRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}

	s.rulesMu.RLock()
	rule, exists := s.rules[id]
	s.rulesMu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(rule)
}

// updateRuleHandler updates an existing routing rule.
func (s *Server) updateRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}

	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	s.rulesMu.Lock()
	existingRule, exists := s.rules[id]
	if !exists {
		s.rulesMu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}

	// Remove old rule from router
	s.router.RemoveRule(id)

	// Update rule
	updatedRule := &routing.RoutingRule{
		ID:           id,
		Name:         req.Name,
		Description:  req.Description,
		Priority:     req.Priority,
		Enabled:      req.Enabled,
		Conditions:   req.Conditions,
		Destinations: req.Destinations,
		Actions:      req.Actions,
		StopOnMatch:  req.StopOnMatch,
		SampleRate:   req.SampleRate,
		CreatedAt:    existingRule.CreatedAt,
		UpdatedAt:    time.Now(),
	}

	if updatedRule.SampleRate == 0 {
		updatedRule.SampleRate = 1.0
	}

	s.rules[id] = updatedRule
	s.rulesMu.Unlock()

	// Add updated rule to router
	s.router.AddRule(updatedRule)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "rule updated",
		"rule":    updatedRule,
	})
}

// deleteRuleHandler deletes a routing rule.
func (s *Server) deleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}

	s.rulesMu.Lock()
	_, exists := s.rules[id]
	if !exists {
		s.rulesMu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "rule not found"})
		return
	}
	delete(s.rules, id)
	s.rulesMu.Unlock()

	s.router.RemoveRule(id)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "rule deleted"})
}

// listDestinationsHandler lists all destinations.
func (s *Server) listDestinationsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	s.destinationsMu.RLock()
	destinations := make([]*DestinationResponse, 0, len(s.destinations))
	for _, dest := range s.destinations {
		destinations = append(destinations, &DestinationResponse{
			Name:    dest.Name(),
			Type:    dest.Type(),
			Healthy: dest.IsHealthy(),
		})
	}
	s.destinationsMu.RUnlock()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"destinations": destinations,
		"count":        len(destinations),
	})
}

// createDestinationHandler creates a new destination.
func (s *Server) createDestinationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req DestinationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}

	if req.Name == "" || req.Type == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "name and type are required"})
		return
	}

	// Check if destination already exists
	s.destinationsMu.RLock()
	_, exists := s.destinations[req.Name]
	s.destinationsMu.RUnlock()

	if exists {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "destination with this name already exists"})
		return
	}

	var dest routing.Destination
	var err error

	switch req.Type {
	case "clickhouse":
		chCfg := destination.ClickHouseConfig{
			Name: req.Name,
		}
		// Parse config
		if hosts, ok := req.Config["hosts"].([]interface{}); ok {
			for _, h := range hosts {
				if hs, ok := h.(string); ok {
					chCfg.Hosts = append(chCfg.Hosts, hs)
				}
			}
		}
		if db, ok := req.Config["database"].(string); ok {
			chCfg.Database = db
		}
		if table, ok := req.Config["table"].(string); ok {
			chCfg.Table = table
		}
		if user, ok := req.Config["username"].(string); ok {
			chCfg.Username = user
		}
		if pass, ok := req.Config["password"].(string); ok {
			chCfg.Password = pass
		}
		dest, err = destination.NewClickHouseDestination(chCfg, s.logger)

	case "kafka":
		kafkaCfg := destination.KafkaConfig{
			Name: req.Name,
		}
		if brokers, ok := req.Config["brokers"].([]interface{}); ok {
			for _, b := range brokers {
				if bs, ok := b.(string); ok {
					kafkaCfg.Brokers = append(kafkaCfg.Brokers, bs)
				}
			}
		}
		if topic, ok := req.Config["topic"].(string); ok {
			kafkaCfg.Topic = topic
		}
		dest, err = destination.NewKafkaDestination(kafkaCfg, s.logger)

	case "s3":
		s3Cfg := destination.S3Config{
			Name: req.Name,
		}
		if region, ok := req.Config["region"].(string); ok {
			s3Cfg.Region = region
		}
		if bucket, ok := req.Config["bucket"].(string); ok {
			s3Cfg.Bucket = bucket
		}
		if prefix, ok := req.Config["prefix"].(string); ok {
			s3Cfg.Prefix = prefix
		}
		if endpoint, ok := req.Config["endpoint"].(string); ok {
			s3Cfg.Endpoint = endpoint
		}
		if accessKey, ok := req.Config["access_key"].(string); ok {
			s3Cfg.AccessKey = accessKey
		}
		if secretKey, ok := req.Config["secret_key"].(string); ok {
			s3Cfg.SecretKey = secretKey
		}
		dest, err = destination.NewS3Destination(s3Cfg, s.logger)

	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported destination type"})
		return
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("failed to create destination: %v", err)})
		return
	}

	s.registerDestination(dest)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "destination created",
		"destination": DestinationResponse{
			Name:    dest.Name(),
			Type:    dest.Type(),
			Healthy: dest.IsHealthy(),
		},
	})
}

// getDestinationHandler gets a specific destination.
func (s *Server) getDestinationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}

	s.destinationsMu.RLock()
	dest, exists := s.destinations[id]
	s.destinationsMu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "destination not found"})
		return
	}

	// Get stats if available
	var stats map[string]interface{}
	switch d := dest.(type) {
	case *destination.ClickHouseDestination:
		stats = d.Stats()
	case *destination.KafkaDestination:
		stats = d.Stats()
	case *destination.S3Destination:
		stats = d.Stats()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":    dest.Name(),
		"type":    dest.Type(),
		"healthy": dest.IsHealthy(),
		"stats":   stats,
	})
}

// updateDestinationHandler updates a destination (limited to config changes).
func (s *Server) updateDestinationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// For now, we don't support live destination updates
	// Users should delete and recreate destinations
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "destination updates not yet implemented - delete and recreate instead",
	})
}

// deleteDestinationHandler deletes a destination.
func (s *Server) deleteDestinationHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "id is required"})
		return
	}

	s.destinationsMu.Lock()
	dest, exists := s.destinations[id]
	if !exists {
		s.destinationsMu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "destination not found"})
		return
	}
	delete(s.destinations, id)
	s.destinationsMu.Unlock()

	// Unregister from router (this also closes the destination)
	if err := s.router.UnregisterDestination(id); err != nil {
		s.logger.Warn("failed to close destination", "name", id, "error", err)
	} else {
		dest.Close()
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "destination deleted"})
}

// statsHandler returns combined statistics.
func (s *Server) statsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	stats := s.router.Stats()
	stats["service"] = serviceName

	// Consumer stats
	if s.consumer != nil {
		stats["kafka_consumer"] = s.consumer.Stats()
	}

	// Destination stats
	destStats := make(map[string]interface{})
	s.destinationsMu.RLock()
	for name, dest := range s.destinations {
		switch d := dest.(type) {
		case *destination.ClickHouseDestination:
			destStats[name] = d.Stats()
		case *destination.KafkaDestination:
			destStats[name] = d.Stats()
		case *destination.S3Destination:
			destStats[name] = d.Stats()
		default:
			destStats[name] = map[string]bool{"healthy": dest.IsHealthy()}
		}
	}
	s.destinationsMu.RUnlock()
	stats["destinations"] = destStats

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}
