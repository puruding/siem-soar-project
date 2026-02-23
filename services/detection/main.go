package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/services/detection/internal/config"
	"github.com/siem-soar-platform/services/detection/internal/consumer"
	"github.com/siem-soar-platform/services/detection/internal/engine"
	"github.com/siem-soar-platform/services/detection/internal/rule"
	"github.com/siem-soar-platform/services/detection/internal/sigma"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const serviceName = "detection"

// APIRule represents a detection rule for the API.
type APIRule struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Severity        string    `json:"severity"` // low, medium, high, critical
	Status          string    `json:"status"`   // enabled, disabled
	Content         string    `json:"content"`  // Sigma YAML
	Author          string    `json:"author"`
	Tags            []string  `json:"tags"`
	MitreTactics    []string  `json:"mitre_tactics"`
	MitreTechniques []string  `json:"mitre_techniques"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	HitCount        int64     `json:"hit_count"`
	LastHitAt       time.Time `json:"last_hit_at,omitempty"`
}

// APIResponse is a standard API response wrapper.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// CreateRuleRequest represents the request body for creating a rule.
type CreateRuleRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"` // Sigma YAML
	Author  string `json:"author,omitempty"`
}

// UpdateRuleRequest represents the request body for updating a rule.
type UpdateRuleRequest struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Content     string   `json:"content,omitempty"`
	Author      string   `json:"author,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// TestRuleRequest represents the request body for testing a rule.
type TestRuleRequest struct {
	Content string                 `json:"content,omitempty"` // Sigma YAML (if testing new rule)
	Event   map[string]interface{} `json:"event"`             // Sample event to test against
}

// TestRuleResponse represents the response from testing a rule.
type TestRuleResponse struct {
	Matched       bool                   `json:"matched"`
	MatchedFields map[string]interface{} `json:"matched_fields,omitempty"`
	Score         float64                `json:"score,omitempty"`
	Errors        []string               `json:"errors,omitempty"`
}

// RuleStats represents statistics for a rule.
type RuleStats struct {
	RuleID         string    `json:"rule_id"`
	HitCount       int64     `json:"hit_count"`
	LastHitAt      time.Time `json:"last_hit_at,omitempty"`
	AvgMatchTimeNs int64     `json:"avg_match_time_ns"`
	FalsePositives int64     `json:"false_positives"`
	TruePositives  int64     `json:"true_positives"`
}

// RuleStore provides rule storage and management.
type RuleStore struct {
	db     *sql.DB
	mu     sync.RWMutex
	rules  map[string]*APIRule // In-memory cache
	logger *slog.Logger
}

// NewRuleStore creates a new rule store.
func NewRuleStore(db *sql.DB, logger *slog.Logger) *RuleStore {
	return &RuleStore{
		db:     db,
		rules:  make(map[string]*APIRule),
		logger: logger.With("component", "rule-store"),
	}
}

// Initialize loads rules from database into cache.
func (s *RuleStore) Initialize(ctx context.Context) error {
	if s.db == nil {
		s.logger.Warn("no database connection, using in-memory only")
		return nil
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, severity, status, content, author,
			tags, mitre_tactics, mitre_techniques, created_at, updated_at,
			hit_count, last_hit_at
		FROM detection_rules
		WHERE status != 'deleted'
		ORDER BY created_at DESC
	`)
	if err != nil {
		return fmt.Errorf("failed to query rules: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		rule := &APIRule{}
		var tagsStr, tacticsStr, techniquesStr sql.NullString
		var lastHitAt sql.NullTime

		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Description, &rule.Severity, &rule.Status,
			&rule.Content, &rule.Author, &tagsStr, &tacticsStr, &techniquesStr,
			&rule.CreatedAt, &rule.UpdatedAt, &rule.HitCount, &lastHitAt,
		)
		if err != nil {
			s.logger.Warn("failed to scan rule", "error", err)
			continue
		}

		if tagsStr.Valid {
			rule.Tags = parseStringArray(tagsStr.String)
		}
		if tacticsStr.Valid {
			rule.MitreTactics = parseStringArray(tacticsStr.String)
		}
		if techniquesStr.Valid {
			rule.MitreTechniques = parseStringArray(techniquesStr.String)
		}
		if lastHitAt.Valid {
			rule.LastHitAt = lastHitAt.Time
		}

		s.rules[rule.ID] = rule
	}

	s.logger.Info("rules loaded from database", "count", len(s.rules))
	return nil
}

// List returns all rules.
func (s *RuleStore) List() []*APIRule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rules := make([]*APIRule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.Status != "deleted" {
			rules = append(rules, r)
		}
	}
	return rules
}

// GetByID returns a rule by ID.
func (s *RuleStore) GetByID(id string) (*APIRule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok || r.Status == "deleted" {
		return nil, false
	}
	return r, true
}

// Create creates a new rule.
func (s *RuleStore) Create(ctx context.Context, r *APIRule) error {
	now := time.Now()
	r.ID = uuid.New().String()
	r.CreatedAt = now
	r.UpdatedAt = now
	if r.Status == "" {
		r.Status = "disabled"
	}

	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			INSERT INTO detection_rules (
				id, name, description, severity, status, content, author,
				tags, mitre_tactics, mitre_techniques, created_at, updated_at, hit_count
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`,
			r.ID, r.Name, r.Description, r.Severity, r.Status, r.Content, r.Author,
			formatStringArray(r.Tags), formatStringArray(r.MitreTactics),
			formatStringArray(r.MitreTechniques), r.CreatedAt, r.UpdatedAt, r.HitCount,
		)
		if err != nil {
			return fmt.Errorf("failed to insert rule: %w", err)
		}
	}

	s.mu.Lock()
	s.rules[r.ID] = r
	s.mu.Unlock()

	return nil
}

// Update updates an existing rule.
func (s *RuleStore) Update(ctx context.Context, r *APIRule) error {
	r.UpdatedAt = time.Now()

	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			UPDATE detection_rules SET
				name = $2, description = $3, severity = $4, status = $5,
				content = $6, author = $7, tags = $8, mitre_tactics = $9,
				mitre_techniques = $10, updated_at = $11
			WHERE id = $1
		`,
			r.ID, r.Name, r.Description, r.Severity, r.Status, r.Content, r.Author,
			formatStringArray(r.Tags), formatStringArray(r.MitreTactics),
			formatStringArray(r.MitreTechniques), r.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}
	}

	s.mu.Lock()
	s.rules[r.ID] = r
	s.mu.Unlock()

	return nil
}

// Delete soft-deletes a rule.
func (s *RuleStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	r, ok := s.rules[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("rule not found: %s", id)
	}
	r.Status = "deleted"
	r.UpdatedAt = time.Now()
	s.mu.Unlock()

	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			UPDATE detection_rules SET status = 'deleted', updated_at = $2 WHERE id = $1
		`, id, r.UpdatedAt)
		if err != nil {
			return fmt.Errorf("failed to delete rule: %w", err)
		}
	}

	return nil
}

// UpdateStatus updates the status of a rule.
func (s *RuleStore) UpdateStatus(ctx context.Context, id, status string) error {
	s.mu.Lock()
	r, ok := s.rules[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("rule not found: %s", id)
	}
	r.Status = status
	r.UpdatedAt = time.Now()
	s.mu.Unlock()

	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			UPDATE detection_rules SET status = $2, updated_at = $3 WHERE id = $1
		`, id, status, r.UpdatedAt)
		if err != nil {
			return fmt.Errorf("failed to update rule status: %w", err)
		}
	}

	return nil
}

// IncrementHitCount increments the hit count for a rule.
func (s *RuleStore) IncrementHitCount(ctx context.Context, id string) error {
	s.mu.Lock()
	r, ok := s.rules[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("rule not found: %s", id)
	}
	r.HitCount++
	r.LastHitAt = time.Now()
	s.mu.Unlock()

	if s.db != nil {
		_, err := s.db.ExecContext(ctx, `
			UPDATE detection_rules SET hit_count = hit_count + 1, last_hit_at = $2 WHERE id = $1
		`, id, r.LastHitAt)
		if err != nil {
			return fmt.Errorf("failed to update hit count: %w", err)
		}
	}

	return nil
}

// GetStats returns statistics for a rule.
func (s *RuleStore) GetStats(id string) (*RuleStats, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok || r.Status == "deleted" {
		return nil, false
	}

	return &RuleStats{
		RuleID:    r.ID,
		HitCount:  r.HitCount,
		LastHitAt: r.LastHitAt,
	}, true
}

// Helper functions
func parseStringArray(s string) []string {
	if s == "" || s == "{}" {
		return nil
	}
	s = strings.Trim(s, "{}")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.Trim(p, "\"' ")
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func formatStringArray(arr []string) string {
	if len(arr) == 0 {
		return "{}"
	}
	return "{" + strings.Join(arr, ",") + "}"
}

// Global rule store and sigma engine for handlers
var (
	ruleStore   *RuleStore
	sigmaEngine *sigma.Engine
)

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
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

	// Initialize PostgreSQL connection (optional)
	var db *sql.DB
	pgDSN := os.Getenv("POSTGRES_DSN")
	if pgDSN == "" {
		pgDSN = os.Getenv("DATABASE_URL")
	}
	if pgDSN != "" {
		var err error
		db, err = sql.Open("postgres", pgDSN)
		if err != nil {
			slog.Warn("failed to connect to PostgreSQL", "error", err)
		} else {
			if err := db.Ping(); err != nil {
				slog.Warn("PostgreSQL ping failed", "error", err)
				db = nil
			} else {
				slog.Info("connected to PostgreSQL")
				// Ensure schema exists
				ensureSchema(db)
			}
		}
	}

	// Initialize rule store
	ruleStore = NewRuleStore(db, logger)
	if err := ruleStore.Initialize(context.Background()); err != nil {
		slog.Warn("failed to initialize rule store", "error", err)
	}

	// Initialize Sigma engine
	sigmaEngineCfg := sigma.DefaultEngineConfig()
	sigmaEngineCfg.RulesDirectory = cfg.RulesDirectory
	sigmaEngine = sigma.NewEngine(sigmaEngineCfg, logger)

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

	// Sync rules from store to engine
	syncRulesToEngine(detectionEngine)

	// Setup HTTP server for health checks and metrics
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, r *http.Request) {
		readyHandler(w, r, detectionEngine)
	})
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// Rule management API endpoints
	mux.HandleFunc("GET /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		listRulesHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("GET /api/v1/rules/{id}", getRuleHandler)
	mux.HandleFunc("POST /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		createRuleHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("PUT /api/v1/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		updateRuleHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("DELETE /api/v1/rules/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleteRuleHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("POST /api/v1/rules/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		enableRuleHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("POST /api/v1/rules/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		disableRuleHandler(w, r, detectionEngine)
	})
	mux.HandleFunc("POST /api/v1/rules/test", testRuleHandler)
	mux.HandleFunc("GET /api/v1/rules/{id}/stats", getRuleStatsHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      otelhttp.NewHandler(mux, serviceName),
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

// ensureSchema creates the detection_rules table if it doesn't exist.
func ensureSchema(db *sql.DB) {
	schema := `
	CREATE TABLE IF NOT EXISTS detection_rules (
		id VARCHAR(36) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		severity VARCHAR(20) DEFAULT 'medium',
		status VARCHAR(20) DEFAULT 'disabled',
		content TEXT NOT NULL,
		author VARCHAR(255),
		tags TEXT DEFAULT '{}',
		mitre_tactics TEXT DEFAULT '{}',
		mitre_techniques TEXT DEFAULT '{}',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		hit_count BIGINT DEFAULT 0,
		last_hit_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_detection_rules_status ON detection_rules(status);
	CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
	`
	_, err := db.Exec(schema)
	if err != nil {
		slog.Warn("failed to ensure schema", "error", err)
	}
}

// syncRulesToEngine syncs rules from the store to the detection engine.
func syncRulesToEngine(eng *engine.Engine) {
	if ruleStore == nil || sigmaEngine == nil {
		return
	}

	for _, r := range ruleStore.List() {
		if r.Status == "enabled" && r.Content != "" {
			if err := sigmaEngine.LoadRuleYAML(r.Content); err != nil {
				slog.Warn("failed to load rule into sigma engine", "rule_id", r.ID, "error", err)
			}
		}
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, APIResponse{Success: false, Error: msg})
}

// writeSuccess writes a success response.
func writeSuccess(w http.ResponseWriter, status int, data interface{}) {
	writeJSON(w, status, APIResponse{Success: true, Data: data})
}

// parseSigmaRule parses a Sigma YAML and extracts metadata.
func parseSigmaRule(content string) (*APIRule, error) {
	converter := sigma.NewConverter()
	sigmaRule, err := converter.Parse(content)
	if err != nil {
		return nil, fmt.Errorf("invalid Sigma YAML: %w", err)
	}

	// Extract MITRE information from tags
	tactics, techniques := sigma.ExtractMITRETags(sigmaRule.Tags)

	rule := &APIRule{
		Name:            sigmaRule.Title,
		Description:     sigmaRule.Description,
		Severity:        normalizeSeverity(sigmaRule.Level),
		Content:         content,
		Author:          sigmaRule.Author,
		Tags:            sigmaRule.Tags,
		MitreTactics:    tactics,
		MitreTechniques: techniques,
	}

	// Use Sigma rule ID if provided
	if sigmaRule.ID != "" {
		rule.ID = sigmaRule.ID
	}

	return rule, nil
}

// normalizeSeverity normalizes severity level.
func normalizeSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "low"
	default:
		return "medium"
	}
}

// listRulesHandler handles GET /api/v1/rules
func listRulesHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	rules := ruleStore.List()

	// Convert to API format
	result := make([]map[string]interface{}, 0, len(rules))
	for _, ru := range rules {
		result = append(result, map[string]interface{}{
			"id":               ru.ID,
			"name":             ru.Name,
			"description":      ru.Description,
			"severity":         ru.Severity,
			"status":           ru.Status,
			"author":           ru.Author,
			"tags":             ru.Tags,
			"mitre_tactics":    ru.MitreTactics,
			"mitre_techniques": ru.MitreTechniques,
			"created_at":       ru.CreatedAt,
			"updated_at":       ru.UpdatedAt,
			"hit_count":        ru.HitCount,
		})
	}

	writeSuccess(w, http.StatusOK, map[string]interface{}{
		"rules": result,
		"total": len(result),
	})
}

// getRuleHandler handles GET /api/v1/rules/{id}
func getRuleHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	rule, ok := ruleStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	writeSuccess(w, http.StatusOK, rule)
}

// createRuleHandler handles POST /api/v1/rules
func createRuleHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req CreateRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content (Sigma YAML) is required")
		return
	}

	// Parse and validate Sigma rule
	rule, err := parseSigmaRule(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Override with request values if provided
	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Author != "" {
		rule.Author = req.Author
	}

	// Validate required fields
	if rule.Name == "" {
		writeError(w, http.StatusBadRequest, "rule name is required (from title in YAML or name in request)")
		return
	}

	// Create the rule
	if err := ruleStore.Create(r.Context(), rule); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create rule: "+err.Error())
		return
	}

	slog.Info("rule created", "rule_id", rule.ID, "name", rule.Name)
	writeSuccess(w, http.StatusCreated, rule)
}

// updateRuleHandler handles PUT /api/v1/rules/{id}
func updateRuleHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	existing, ok := ruleStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req UpdateRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	// Update fields if provided
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Severity != "" {
		existing.Severity = normalizeSeverity(req.Severity)
	}
	if req.Author != "" {
		existing.Author = req.Author
	}
	if req.Tags != nil {
		existing.Tags = req.Tags
	}

	// If content is updated, re-parse the Sigma rule
	if req.Content != "" {
		parsed, err := parseSigmaRule(req.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		existing.Content = req.Content
		existing.MitreTactics = parsed.MitreTactics
		existing.MitreTechniques = parsed.MitreTechniques
		// Update description from Sigma if not explicitly provided
		if req.Description == "" && parsed.Description != "" {
			existing.Description = parsed.Description
		}

		// Reload rule in sigma engine if enabled
		if existing.Status == "enabled" && sigmaEngine != nil {
			sigmaEngine.RemoveRule(id)
			if err := sigmaEngine.LoadRuleYAML(req.Content); err != nil {
				slog.Warn("failed to reload rule in sigma engine", "rule_id", id, "error", err)
			}
		}
	}

	if err := ruleStore.Update(r.Context(), existing); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update rule: "+err.Error())
		return
	}

	slog.Info("rule updated", "rule_id", id)
	writeSuccess(w, http.StatusOK, existing)
}

// deleteRuleHandler handles DELETE /api/v1/rules/{id}
func deleteRuleHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	_, ok := ruleStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	if err := ruleStore.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete rule: "+err.Error())
		return
	}

	// Remove from sigma engine
	if sigmaEngine != nil {
		sigmaEngine.RemoveRule(id)
	}

	slog.Info("rule deleted", "rule_id", id)
	writeSuccess(w, http.StatusOK, map[string]string{"message": "rule deleted"})
}

// enableRuleHandler handles POST /api/v1/rules/{id}/enable
func enableRuleHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	rule, ok := ruleStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	if err := ruleStore.UpdateStatus(r.Context(), id, "enabled"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable rule: "+err.Error())
		return
	}

	// Load rule into sigma engine
	if sigmaEngine != nil && rule.Content != "" {
		if err := sigmaEngine.LoadRuleYAML(rule.Content); err != nil {
			slog.Warn("failed to load rule into sigma engine", "rule_id", id, "error", err)
		}
	}

	rule.Status = "enabled"
	slog.Info("rule enabled", "rule_id", id)
	writeSuccess(w, http.StatusOK, rule)
}

// disableRuleHandler handles POST /api/v1/rules/{id}/disable
func disableRuleHandler(w http.ResponseWriter, r *http.Request, eng *engine.Engine) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	rule, ok := ruleStore.GetByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	if err := ruleStore.UpdateStatus(r.Context(), id, "disabled"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to disable rule: "+err.Error())
		return
	}

	// Remove from sigma engine
	if sigmaEngine != nil {
		sigmaEngine.RemoveRule(id)
	}

	rule.Status = "disabled"
	slog.Info("rule disabled", "rule_id", id)
	writeSuccess(w, http.StatusOK, rule)
}

// testRuleHandler handles POST /api/v1/rules/test
func testRuleHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req TestRuleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	if req.Event == nil {
		writeError(w, http.StatusBadRequest, "event is required")
		return
	}

	response := TestRuleResponse{
		Matched: false,
		Errors:  make([]string, 0),
	}

	// If content is provided, parse and test against it
	if req.Content != "" {
		converter := sigma.NewConverter()
		internal, err := converter.ConvertYAML(req.Content)
		if err != nil {
			response.Errors = append(response.Errors, "failed to parse rule: "+err.Error())
			writeSuccess(w, http.StatusOK, response)
			return
		}

		// Create a temporary evaluator to test
		evaluator := sigma.NewEvaluator()
		result := evaluator.Evaluate(internal, req.Event)

		response.Matched = result.Matched
		response.MatchedFields = result.MatchedFields
		response.Score = result.Score
	} else {
		// Test against all enabled rules
		if sigmaEngine != nil {
			matches, err := sigmaEngine.Match(req.Event)
			if err != nil {
				response.Errors = append(response.Errors, "matching failed: "+err.Error())
			} else if len(matches) > 0 {
				response.Matched = true
				response.MatchedFields = matches[0].MatchedFields
				response.Score = matches[0].Score
			}
		} else {
			response.Errors = append(response.Errors, "sigma engine not initialized")
		}
	}

	writeSuccess(w, http.StatusOK, response)
}

// getRuleStatsHandler handles GET /api/v1/rules/{id}/stats
func getRuleStatsHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	stats, ok := ruleStore.GetStats(id)
	if !ok {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}

	writeSuccess(w, http.StatusOK, stats)
}
