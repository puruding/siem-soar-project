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
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/services/soar/internal/config"
	"github.com/siem-soar-platform/services/soar/internal/consumer"
	"github.com/siem-soar-platform/services/soar/internal/playbook"
	"github.com/siem-soar-platform/services/soar/internal/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const serviceName = "soar"

var (
	store          *playbook.PostgresStore
	executionStore playbook.ExecutionStore
	db             *sql.DB
	cfg            *config.Config
	wsHub          *websocket.Hub
	alertConsumer  *consumer.AlertConsumer
	redisClient    *redis.Client
)

func main() {
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
	cfg = config.Load()

	// Initialize database connection
	var dbErr error
	db, dbErr = sql.Open("postgres", cfg.Database.ConnectionString())
	if dbErr != nil {
		slog.Error("failed to connect to database", "error", dbErr)
		// Continue without DB - will use memory store fallback
		executionStore = playbook.NewMemoryExecutionStore()
		slog.Info("Using in-memory execution store (data will not persist)")
	} else {
		if err := db.Ping(); err != nil {
			slog.Warn("database ping failed, will retry on requests", "error", err)
			executionStore = playbook.NewMemoryExecutionStore()
		} else {
			slog.Info("connected to database")
			executionStore = playbook.NewPostgresExecutionStore(db)
			slog.Info("Using PostgreSQL execution store (data will persist)")
		}
		store = playbook.NewPostgresStore(db)
	}

	// Setup WebSocket hub if enabled
	if cfg.WebSocket.Enabled {
		wsHub = websocket.NewHub(logger)
		go wsHub.Run()
		slog.Info("WebSocket hub started")
	}

	// Setup Redis client for idempotency
	if cfg.Redis.Addr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})

		// Test Redis connection
		ctx := context.Background()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			slog.Warn("Redis connection failed, idempotency checking disabled", "error", err)
			redisClient = nil
		} else {
			slog.Info("Connected to Redis", "addr", cfg.Redis.Addr)
		}
	}

	// Setup Kafka consumer for ML-enriched alerts
	if cfg.KafkaConsumer.Enabled {
		slog.Info("Initializing Kafka consumer for ML-enriched alerts",
			"topic", cfg.KafkaConsumer.Topic,
			"consumer_group", cfg.KafkaConsumer.ConsumerGroup,
		)

		// Create idempotency checker
		var idempotency *consumer.IdempotencyChecker
		if redisClient != nil {
			idempotency = consumer.NewIdempotencyCheckerWithClient(redisClient, cfg.Redis.IdempotencyTTL)
		}

		// Create playbook rule store
		ruleStore := consumer.NewPlaybookRuleStore(db, redisClient, logger)

		// Note: In production, we need to create SOAREngine here
		// For now, consumer is created but engine integration requires full Temporal setup
		consumerCfg := consumer.Config{
			Brokers:        cfg.KafkaConsumer.Brokers,
			Topic:          cfg.KafkaConsumer.Topic,
			ConsumerGroup:  cfg.KafkaConsumer.ConsumerGroup,
			DLQTopic:       cfg.KafkaConsumer.DLQTopic,
			MaxRetries:     cfg.KafkaConsumer.MaxRetries,
			RetryBackoff:   cfg.KafkaConsumer.RetryBackoff,
			CommitInterval: cfg.KafkaConsumer.CommitInterval,
			BatchSize:      cfg.KafkaConsumer.BatchSize,
			Enabled:        true,
		}

		// Create consumer (requires SOAREngine - will be integrated when Temporal is configured)
		var consumerErr error
		alertConsumer, consumerErr = consumer.NewAlertConsumer(consumerCfg, nil, ruleStore, idempotency, logger)
		if consumerErr != nil {
			slog.Error("Failed to create Kafka consumer", "error", consumerErr)
		} else {
			if err := alertConsumer.Start(); err != nil {
				slog.Error("Failed to start Kafka consumer", "error", err)
			} else {
				slog.Info("Kafka consumer started successfully")
			}
		}
	}

	// Setup HTTP router with CORS
	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", readyHandler)
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// WebSocket endpoint (if enabled)
	if cfg.WebSocket.Enabled && wsHub != nil {
		wsHandler := websocket.NewHandler(wsHub, logger)
		mux.HandleFunc("/ws/soar", wsHandler.ServeWS)
		slog.Info("WebSocket endpoint registered at /ws/soar")
	}

	// Playbook CRUD endpoints
	mux.HandleFunc("POST /api/v1/playbooks", corsMiddleware(createPlaybookHandler))
	mux.HandleFunc("GET /api/v1/playbooks", corsMiddleware(listPlaybooksHandler))
	mux.HandleFunc("GET /api/v1/playbooks/{id}", corsMiddleware(getPlaybookHandler))
	mux.HandleFunc("PUT /api/v1/playbooks/{id}", corsMiddleware(updatePlaybookHandler))
	mux.HandleFunc("DELETE /api/v1/playbooks/{id}", corsMiddleware(deletePlaybookHandler))

	// Playbook execution endpoints
	mux.HandleFunc("POST /api/v1/playbooks/{id}/execute", corsMiddleware(executePlaybookHandler))
	mux.HandleFunc("POST /api/v1/playbooks/{id}/enable", corsMiddleware(enablePlaybookHandler))
	mux.HandleFunc("POST /api/v1/playbooks/{id}/disable", corsMiddleware(disablePlaybookHandler))

	// Execution history endpoints
	mux.HandleFunc("GET /api/v1/executions", corsMiddleware(listExecutionsHandler))
	mux.HandleFunc("GET /api/v1/executions/{id}", corsMiddleware(getExecutionHandler))
	mux.HandleFunc("GET /api/v1/alerts/{alertId}/executions", corsMiddleware(getAlertExecutionsHandler))

	// CORS preflight
	mux.HandleFunc("OPTIONS /api/v1/playbooks", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/playbooks/{id}", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/playbooks/{id}/execute", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/executions", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/executions/{id}", corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/alerts/{alertId}/executions", corsPreflightHandler)

	server := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      otelhttp.NewHandler(mux, serviceName),
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("starting server", "service", serviceName, "port", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop Kafka consumer
	if alertConsumer != nil {
		alertConsumer.Stop()
		slog.Info("Kafka consumer stopped")
	}

	// Stop WebSocket hub
	if wsHub != nil {
		wsHub.Stop()
		slog.Info("WebSocket hub stopped")
	}

	// Close Redis client
	if redisClient != nil {
		redisClient.Close()
		slog.Info("Redis connection closed")
	}

	if db != nil {
		db.Close()
	}

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
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
	fmt.Fprint(w, `{"status":"healthy","service":"soar"}`)
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
	fmt.Fprintf(w, `{"status":"%s","service":"soar"}`, status)
}

// PlaybookRequest represents the request body for creating/updating a playbook
type PlaybookRequest struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name"`
	DisplayName string                 `json:"display_name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Status      string                 `json:"status"`
	TriggerType string                 `json:"trigger_type"`
	Enabled     bool                   `json:"enabled"`
	Version     int                    `json:"version"`
	Tags        []string               `json:"tags"`
	Nodes       json.RawMessage        `json:"nodes"`
	Edges       json.RawMessage        `json:"edges"`
	Variables   json.RawMessage        `json:"variables"`
	Trigger     map[string]interface{} `json:"trigger"`
}

func createPlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to read request body"})
		return
	}

	var req PlaybookRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	// Generate ID if not provided
	id := req.ID
	if id == "" || id == "new" {
		id = playbook.GeneratePlaybookID()
	}

	// Build definition JSONB
	definition := map[string]interface{}{
		"nodes":     json.RawMessage(req.Nodes),
		"edges":     json.RawMessage(req.Edges),
		"variables": json.RawMessage(req.Variables),
	}
	definitionBytes, _ := json.Marshal(definition)

	triggerType := req.TriggerType
	if triggerType == "" {
		triggerType = "manual"
	}

	category := req.Category
	if category == "" {
		category = "custom"
	}

	err = store.SaveWithDefinition(
		r.Context(),
		id,
		req.Name,
		req.DisplayName,
		req.Description,
		category,
		definitionBytes,
		triggerType,
		req.Enabled,
		req.Tags,
	)

	if err != nil {
		slog.Error("failed to create playbook", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "playbook created successfully",
		"version": 1,
	})
}

func listPlaybooksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	playbooks, err := store.ListWithDefinitions(r.Context())
	if err != nil {
		slog.Error("failed to list playbooks", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if playbooks == nil {
		playbooks = []map[string]interface{}{}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"playbooks": playbooks,
		"total":     len(playbooks),
	})
}

func getPlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook ID required"})
		return
	}

	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	pb, err := store.GetWithDefinition(r.Context(), id)
	if err != nil {
		slog.Error("failed to get playbook", "id", id, "error", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(pb)
}

func updatePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook ID required"})
		return
	}

	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to read request body"})
		return
	}

	var req PlaybookRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
		return
	}

	// Build definition JSONB
	definition := map[string]interface{}{
		"nodes":     json.RawMessage(req.Nodes),
		"edges":     json.RawMessage(req.Edges),
		"variables": json.RawMessage(req.Variables),
	}
	definitionBytes, _ := json.Marshal(definition)

	triggerType := req.TriggerType
	if triggerType == "" {
		triggerType = "manual"
	}

	category := req.Category
	if category == "" {
		category = "custom"
	}

	err = store.SaveWithDefinition(
		r.Context(),
		id,
		req.Name,
		req.DisplayName,
		req.Description,
		category,
		definitionBytes,
		triggerType,
		req.Enabled,
		req.Tags,
	)

	if err != nil {
		slog.Error("failed to update playbook", "id", id, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "playbook updated successfully",
	})
}

func deletePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook ID required"})
		return
	}

	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	err := store.Delete(r.Context(), id)
	if err != nil {
		slog.Error("failed to delete playbook", "id", id, "error", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "playbook deleted successfully",
	})
}

func executePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "playbook ID required"})
		return
	}

	// TODO: Integrate with Temporal for actual execution
	executionID := fmt.Sprintf("EXEC-%d", time.Now().UnixMilli())

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"execution_id": executionID,
		"playbook_id":  id,
		"status":       "PENDING",
		"message":      "playbook execution started",
	})
}

func enablePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	if err := store.Enable(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "playbook enabled",
	})
}

func disablePlaybookHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if store == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "database not available"})
		return
	}

	if err := store.Disable(r.Context(), id); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      id,
		"message": "playbook disabled",
	})
}

// listExecutionsHandler lists all executions with optional filters.
func listExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if executionStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "execution store not available"})
		return
	}

	// Parse query parameters for filtering
	filter := &playbook.ExecutionFilter{
		PlaybookID: r.URL.Query().Get("playbook_id"),
		AlertID:    r.URL.Query().Get("alert_id"),
		CaseID:     r.URL.Query().Get("case_id"),
		TenantID:   r.URL.Query().Get("tenant_id"),
		Limit:      100,
		Offset:     0,
	}

	// Parse status filter
	if statusParam := r.URL.Query().Get("status"); statusParam != "" {
		filter.Status = []playbook.ExecutionStatus{playbook.ExecutionStatus(statusParam)}
	}

	result, err := executionStore.List(r.Context(), filter)
	if err != nil {
		slog.Error("failed to list executions", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// getExecutionHandler retrieves a specific execution by ID.
func getExecutionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "execution ID required"})
		return
	}

	if executionStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "execution store not available"})
		return
	}

	execution, err := executionStore.Get(r.Context(), id)
	if err != nil {
		slog.Error("failed to get execution", "id", id, "error", err)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "execution not found"})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(execution)
}

// getAlertExecutionsHandler retrieves executions for a specific alert.
func getAlertExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	alertID := r.PathValue("alertId")
	if alertID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "alert ID required"})
		return
	}

	if executionStore == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"error": "execution store not available"})
		return
	}

	executions, err := executionStore.GetByAlertID(r.Context(), alertID)
	if err != nil {
		slog.Error("failed to get alert executions", "alert_id", alertID, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Return empty array if no executions found
	if executions == nil {
		executions = []*playbook.Execution{}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"executions": executions,
		"total":      len(executions),
		"alert_id":   alertID,
	})
}
