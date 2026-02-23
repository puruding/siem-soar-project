package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/services/query/internal/executor"
	"github.com/siem-soar-platform/services/query/internal/models"
	"github.com/siem-soar-platform/services/query/internal/parser"
	"github.com/siem-soar-platform/services/query/internal/storage"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	serviceName = "query"
	defaultPort = "8084"
)

// QueryService handles query operations.
type QueryService struct {
	executor  *executor.Executor
	backend   *executor.ClickHouseBackend
	parser    *parser.Parser
	validator *parser.Validator
	storage   storage.Storage
	logger    *slog.Logger
}

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

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	// Initialize service
	svc, err := newQueryService(logger)
	if err != nil {
		slog.Error("failed to initialize query service", "error", err)
		os.Exit(1)
	}
	defer svc.Close()

	mux := http.NewServeMux()

	// Health endpoints
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /ready", svc.readyHandler)
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// Query execution endpoints
	mux.HandleFunc("POST /api/v1/query", svc.executeQueryHandler)
	mux.HandleFunc("POST /api/v1/query/async", svc.asyncQueryHandler)
	mux.HandleFunc("GET /api/v1/query/status/{id}", svc.queryStatusHandler)
	mux.HandleFunc("GET /api/v1/query/results/{id}", svc.queryResultsHandler)

	// Query history endpoints
	mux.HandleFunc("GET /api/v1/query/history", svc.queryHistoryHandler)
	mux.HandleFunc("GET /api/v1/query/history/{id}", svc.getQueryHistoryHandler)
	mux.HandleFunc("DELETE /api/v1/query/history/{id}", svc.deleteQueryHistoryHandler)

	// Saved query endpoints
	mux.HandleFunc("POST /api/v1/query/save", svc.saveQueryHandler)
	mux.HandleFunc("GET /api/v1/query/saved", svc.listSavedQueriesHandler)
	mux.HandleFunc("GET /api/v1/query/saved/{id}", svc.getSavedQueryHandler)
	mux.HandleFunc("PUT /api/v1/query/saved/{id}", svc.updateSavedQueryHandler)
	mux.HandleFunc("DELETE /api/v1/query/saved/{id}", svc.deleteSavedQueryHandler)

	// Schema endpoints
	mux.HandleFunc("GET /api/v1/schema/databases", svc.getDatabasesHandler)
	mux.HandleFunc("GET /api/v1/schema/tables", svc.getTablesHandler)
	mux.HandleFunc("GET /api/v1/schema/columns", svc.getColumnsHandler)

	// Query validation endpoint
	mux.HandleFunc("POST /api/v1/query/validate", svc.validateQueryHandler)
	mux.HandleFunc("POST /api/v1/query/explain", svc.explainQueryHandler)

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      otelhttp.NewHandler(mux, serviceName),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("starting server", "service", serviceName, "port", port)
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

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
	}

	slog.Info("server exited")
}

func newQueryService(logger *slog.Logger) (*QueryService, error) {
	// Load ClickHouse configuration from environment
	chConfig := executor.LoadClickHouseConfigFromEnv()

	// Initialize ClickHouse backend
	backend, err := executor.NewClickHouseBackend(chConfig, logger)
	if err != nil {
		logger.Warn("ClickHouse not available, running in mock mode", "error", err)
		backend = nil
	}

	// Initialize executor
	execConfig := executor.DefaultExecutorConfig()
	exec := executor.NewExecutor(execConfig, logger)

	// Register backend if available
	if backend != nil {
		exec.RegisterBackend("siem", backend)
		exec.RegisterBackend("clickhouse", backend)
	}

	// Initialize parser and validator
	p := parser.NewParser("clickhouse")
	validatorConfig := parser.DefaultValidatorConfig()
	validatorConfig.AllowedTables = []string{
		"events", "events_distributed",
		"alerts", "alerts_distributed",
		"alerts_hourly",
	}
	v := parser.NewValidator(validatorConfig)

	// Initialize storage
	store := storage.NewInMemoryStorage()

	return &QueryService{
		executor:  exec,
		backend:   backend,
		parser:    p,
		validator: v,
		storage:   store,
		logger:    logger.With("component", "query-service"),
	}, nil
}

// Close closes all resources.
func (s *QueryService) Close() {
	if s.executor != nil {
		s.executor.Close()
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": serviceName,
	})
}

func (s *QueryService) readyHandler(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	httpStatus := http.StatusOK

	if s.backend != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := s.backend.Health(ctx); err != nil {
			status = "not_ready"
			httpStatus = http.StatusServiceUnavailable
		}
	}

	writeJSON(w, httpStatus, map[string]string{
		"status":  status,
		"service": serviceName,
	})
}

// executeQueryHandler handles POST /api/v1/query
func (s *QueryService) executeQueryHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request
	var req models.QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY", "Query is required", "")
		return
	}

	// Get tenant and user from headers (in production, from JWT)
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	// Set defaults
	database := req.Database
	if database == "" {
		database = "siem"
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}

	// Validate query
	validationResult := s.validator.Validate(req.Query, tenantID)
	if !validationResult.Valid {
		errMsg := "Query validation failed"
		if len(validationResult.Errors) > 0 {
			errMsg = validationResult.Errors[0].Message
		}
		writeError(w, http.StatusBadRequest, "QUERY_VALIDATION_FAILED", errMsg, "")
		return
	}

	// Add tenant filter if not present
	query := req.Query
	if !hasTenantFilter(query) {
		query = addTenantFilter(query, tenantID)
	}

	// Add LIMIT if not present
	if !hasLimit(query) {
		query = fmt.Sprintf("%s LIMIT %d", query, limit)
	}

	// Add OFFSET if specified
	if req.Offset > 0 && !hasOffset(query) {
		query = fmt.Sprintf("%s OFFSET %d", query, req.Offset)
	}

	// Execute query
	queryID := uuid.New().String()
	execReq := &executor.QueryRequest{
		ID:         queryID,
		Query:      query,
		Type:       executor.QueryTypeSelect,
		Database:   database,
		TenantID:   tenantID,
		UserID:     userID,
		MaxResults: int64(limit),
	}

	if req.Timeout > 0 {
		execReq.Timeout = time.Duration(req.Timeout) * time.Second
	}

	startTime := time.Now()
	result, err := s.executor.Execute(ctx, execReq)

	// Record execution history
	execution := &models.QueryExecution{
		ID:          queryID,
		TenantID:    tenantID,
		UserID:      userID,
		Query:       req.Query,
		Database:    database,
		Status:      string(result.Status),
		RowCount:    result.RowCount,
		TotalCount:  result.TotalCount,
		ExecutionMS: result.ExecutionMS,
		BytesRead:   result.BytesRead,
		ExecutedAt:  startTime,
		Parameters:  req.Parameters,
	}
	if err != nil {
		execution.Error = err.Error()
	}
	_ = s.storage.SaveExecution(ctx, execution)

	if err != nil {
		s.logger.Error("query execution failed", "error", err, "query_id", queryID)
		writeError(w, http.StatusInternalServerError, "QUERY_EXECUTION_FAILED", "Failed to execute query", err.Error())
		return
	}

	// Convert result to response format
	response := models.QueryResponse{
		Success: true,
		Data: &models.QueryData{
			Columns:         convertColumns(result.Columns),
			Rows:            convertRows(result.Rows, result.Columns),
			Total:           result.TotalCount,
			ExecutionTimeMS: result.ExecutionMS,
			QueryID:         queryID,
		},
	}

	if len(validationResult.Warnings) > 0 {
		warnings := make([]string, len(validationResult.Warnings))
		for i, w := range validationResult.Warnings {
			warnings[i] = w.Message
		}
		response.Data.Warnings = warnings
	}

	writeJSON(w, http.StatusOK, response)
}

// asyncQueryHandler handles POST /api/v1/query/async
func (s *QueryService) asyncQueryHandler(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var req models.QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY", "Query is required", "")
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	database := req.Database
	if database == "" {
		database = "siem"
	}

	// Create async query
	queryID := uuid.New().String()
	execReq := &executor.QueryRequest{
		ID:       queryID,
		Query:    req.Query,
		Type:     executor.QueryTypeSelect,
		Database: database,
		TenantID: tenantID,
		UserID:   userID,
	}

	// Start async execution
	_, err := s.executor.ExecuteAsync(r.Context(), execReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ASYNC_QUERY_FAILED", "Failed to start async query", err.Error())
		return
	}

	response := models.AsyncQueryResponse{
		QueryID: queryID,
		Status:  "pending",
		Message: "Query submitted successfully",
	}

	writeJSON(w, http.StatusAccepted, response)
}

// queryStatusHandler handles GET /api/v1/query/{id}/status
func (s *QueryService) queryStatusHandler(w http.ResponseWriter, r *http.Request) {
	queryID := r.PathValue("id")
	if queryID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY_ID", "Query ID is required", "")
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	// Get execution from storage
	exec, err := s.storage.GetExecution(r.Context(), tenantID, queryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "QUERY_NOT_FOUND", "Query not found", "")
		return
	}

	response := models.QueryStatusResponse{
		QueryID:   exec.ID,
		Status:    exec.Status,
		Progress:  100,
		RowsRead:  exec.RowCount,
		BytesRead: exec.BytesRead,
		ElapsedMS: exec.ExecutionMS,
		Error:     exec.Error,
	}

	writeJSON(w, http.StatusOK, response)
}

// queryResultsHandler handles GET /api/v1/query/{id}/results
func (s *QueryService) queryResultsHandler(w http.ResponseWriter, r *http.Request) {
	queryID := r.PathValue("id")
	if queryID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY_ID", "Query ID is required", "")
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	exec, err := s.storage.GetExecution(r.Context(), tenantID, queryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "QUERY_NOT_FOUND", "Query not found", "")
		return
	}

	// For async queries, results would be stored separately
	// Here we return the execution metadata
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"query_id":      exec.ID,
		"status":        exec.Status,
		"row_count":     exec.RowCount,
		"total_count":   exec.TotalCount,
		"execution_ms":  exec.ExecutionMS,
		"executed_at":   exec.ExecutedAt,
	})
}

// queryHistoryHandler handles GET /api/v1/query/history
func (s *QueryService) queryHistoryHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	// Parse query parameters
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	filter := models.QueryHistoryFilter{
		UserID:   r.URL.Query().Get("user_id"),
		Database: r.URL.Query().Get("database"),
		Status:   r.URL.Query().Get("status"),
		Limit:    limit,
		Offset:   offset,
	}

	if start := r.URL.Query().Get("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			filter.StartTime = t
		}
	}
	if end := r.URL.Query().Get("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			filter.EndTime = t
		}
	}

	executions, total, err := s.storage.ListExecutions(r.Context(), tenantID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "HISTORY_FETCH_FAILED", "Failed to fetch query history", err.Error())
		return
	}

	response := models.PaginatedResponse{
		Data:       executions,
		Total:      total,
		Page:       (offset / limit) + 1,
		PageSize:   limit,
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	writeJSON(w, http.StatusOK, response)
}

// getQueryHistoryHandler handles GET /api/v1/query/history/{id}
func (s *QueryService) getQueryHistoryHandler(w http.ResponseWriter, r *http.Request) {
	execID := r.PathValue("id")
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	exec, err := s.storage.GetExecution(r.Context(), tenantID, execID)
	if err != nil {
		writeError(w, http.StatusNotFound, "EXECUTION_NOT_FOUND", "Execution not found", "")
		return
	}

	writeJSON(w, http.StatusOK, exec)
}

// deleteQueryHistoryHandler handles DELETE /api/v1/query/history/{id}
func (s *QueryService) deleteQueryHistoryHandler(w http.ResponseWriter, r *http.Request) {
	execID := r.PathValue("id")
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	if err := s.storage.DeleteExecution(r.Context(), tenantID, execID); err != nil {
		writeError(w, http.StatusInternalServerError, "DELETE_FAILED", "Failed to delete execution", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// saveQueryHandler handles POST /api/v1/query/save
func (s *QueryService) saveQueryHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	var req models.SaveQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "MISSING_NAME", "Query name is required", "")
		return
	}
	if req.Query == "" {
		writeError(w, http.StatusBadRequest, "MISSING_QUERY", "Query is required", "")
		return
	}

	database := req.Database
	if database == "" {
		database = "siem"
	}

	savedQuery := &models.SavedQuery{
		TenantID:    tenantID,
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
		Query:       req.Query,
		Database:    database,
		Tags:        req.Tags,
		IsPublic:    req.IsPublic,
	}

	if err := s.storage.SaveQuery(r.Context(), savedQuery); err != nil {
		writeError(w, http.StatusInternalServerError, "SAVE_FAILED", "Failed to save query", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, savedQuery)
}

// listSavedQueriesHandler handles GET /api/v1/query/saved
func (s *QueryService) listSavedQueriesHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	filter := models.SavedQueryFilter{
		UserID:      r.URL.Query().Get("user_id"),
		SearchQuery: r.URL.Query().Get("search"),
		Limit:       limit,
		Offset:      offset,
	}

	if tags := r.URL.Query().Get("tags"); tags != "" {
		filter.Tags = strings.Split(tags, ",")
	}

	if isPublic := r.URL.Query().Get("is_public"); isPublic != "" {
		b := isPublic == "true"
		filter.IsPublic = &b
	}

	queries, total, err := s.storage.ListSavedQueries(r.Context(), tenantID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "LIST_FAILED", "Failed to list saved queries", err.Error())
		return
	}

	response := models.PaginatedResponse{
		Data:       queries,
		Total:      total,
		Page:       (offset / limit) + 1,
		PageSize:   limit,
		TotalPages: int((total + int64(limit) - 1) / int64(limit)),
	}

	writeJSON(w, http.StatusOK, response)
}

// getSavedQueryHandler handles GET /api/v1/query/saved/{id}
func (s *QueryService) getSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	queryID := r.PathValue("id")
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	query, err := s.storage.GetSavedQuery(r.Context(), tenantID, queryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "QUERY_NOT_FOUND", "Saved query not found", "")
		return
	}

	writeJSON(w, http.StatusOK, query)
}

// updateSavedQueryHandler handles PUT /api/v1/query/saved/{id}
func (s *QueryService) updateSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	queryID := r.PathValue("id")
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	// Check if query exists
	existing, err := s.storage.GetSavedQuery(r.Context(), tenantID, queryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "QUERY_NOT_FOUND", "Saved query not found", "")
		return
	}

	// Check ownership
	if existing.UserID != userID {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "You can only update your own queries", "")
		return
	}

	var req models.SaveQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	database := req.Database
	if database == "" {
		database = existing.Database
	}

	updated := &models.SavedQuery{
		ID:          queryID,
		TenantID:    tenantID,
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
		Query:       req.Query,
		Database:    database,
		Tags:        req.Tags,
		IsPublic:    req.IsPublic,
	}

	if updated.Name == "" {
		updated.Name = existing.Name
	}
	if updated.Query == "" {
		updated.Query = existing.Query
	}

	if err := s.storage.UpdateSavedQuery(r.Context(), updated); err != nil {
		writeError(w, http.StatusInternalServerError, "UPDATE_FAILED", "Failed to update query", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

// deleteSavedQueryHandler handles DELETE /api/v1/query/saved/{id}
func (s *QueryService) deleteSavedQueryHandler(w http.ResponseWriter, r *http.Request) {
	queryID := r.PathValue("id")
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}

	// Check if query exists and ownership
	existing, err := s.storage.GetSavedQuery(r.Context(), tenantID, queryID)
	if err != nil {
		writeError(w, http.StatusNotFound, "QUERY_NOT_FOUND", "Saved query not found", "")
		return
	}

	if existing.UserID != userID {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "You can only delete your own queries", "")
		return
	}

	if err := s.storage.DeleteSavedQuery(r.Context(), tenantID, queryID); err != nil {
		writeError(w, http.StatusInternalServerError, "DELETE_FAILED", "Failed to delete query", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// validateQueryHandler handles POST /api/v1/query/validate
func (s *QueryService) validateQueryHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Failed to read request body", err.Error())
		return
	}

	var req struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		tenantID = "default"
	}

	result := s.validator.Validate(req.Query, tenantID)
	writeJSON(w, http.StatusOK, result)
}

// explainQueryHandler handles POST /api/v1/query/explain
func (s *QueryService) explainQueryHandler(w http.ResponseWriter, r *http.Request) {
	if s.backend == nil {
		writeError(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "ClickHouse backend not available", "")
		return
	}

	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body", err.Error())
		return
	}

	plan, err := s.backend.ExplainQuery(r.Context(), req.Query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "EXPLAIN_FAILED", "Failed to explain query", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"plan": plan})
}

// getDatabasesHandler handles GET /api/v1/schema/databases
func (s *QueryService) getDatabasesHandler(w http.ResponseWriter, r *http.Request) {
	if s.backend == nil {
		writeError(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "ClickHouse backend not available", "")
		return
	}

	databases, err := s.backend.GetDatabases(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "FETCH_FAILED", "Failed to fetch databases", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"databases": databases})
}

// getTablesHandler handles GET /api/v1/schema/tables
func (s *QueryService) getTablesHandler(w http.ResponseWriter, r *http.Request) {
	if s.backend == nil {
		writeError(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "ClickHouse backend not available", "")
		return
	}

	database := r.URL.Query().Get("database")
	if database == "" {
		database = "siem"
	}

	tables, err := s.backend.GetTables(r.Context(), database)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "FETCH_FAILED", "Failed to fetch tables", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"tables": tables})
}

// getColumnsHandler handles GET /api/v1/schema/columns
func (s *QueryService) getColumnsHandler(w http.ResponseWriter, r *http.Request) {
	if s.backend == nil {
		writeError(w, http.StatusServiceUnavailable, "BACKEND_UNAVAILABLE", "ClickHouse backend not available", "")
		return
	}

	database := r.URL.Query().Get("database")
	if database == "" {
		database = "siem"
	}
	table := r.URL.Query().Get("table")
	if table == "" {
		writeError(w, http.StatusBadRequest, "MISSING_TABLE", "Table parameter is required", "")
		return
	}

	columns, err := s.backend.GetTableSchema(r.Context(), database, table)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "FETCH_FAILED", "Failed to fetch columns", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"columns": columns})
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message, details string) {
	response := models.QueryResponse{
		Success: false,
		Error: &models.ErrorResponse{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
	writeJSON(w, status, response)
}

func convertColumns(cols []executor.ColumnInfo) []models.ColumnInfo {
	result := make([]models.ColumnInfo, len(cols))
	for i, c := range cols {
		result[i] = models.ColumnInfo{
			Name:     c.Name,
			Type:     c.Type,
			Nullable: c.Nullable,
		}
	}
	return result
}

func convertRows(rows []map[string]interface{}, columns []executor.ColumnInfo) [][]interface{} {
	result := make([][]interface{}, len(rows))
	for i, row := range rows {
		rowData := make([]interface{}, len(columns))
		for j, col := range columns {
			rowData[j] = row[col.Name]
		}
		result[i] = rowData
	}
	return result
}

func hasTenantFilter(query string) bool {
	upper := strings.ToUpper(query)
	return strings.Contains(upper, "TENANT_ID")
}

func addTenantFilter(query, tenantID string) string {
	upper := strings.ToUpper(query)
	whereIdx := strings.Index(upper, "WHERE")

	if whereIdx == -1 {
		// No WHERE clause, need to add one
		fromIdx := strings.Index(upper, "FROM")
		if fromIdx == -1 {
			return query
		}

		// Find position after FROM table
		afterFrom := fromIdx + 4
		for afterFrom < len(query) && (query[afterFrom] == ' ' || query[afterFrom] == '\t') {
			afterFrom++
		}
		// Skip table name
		for afterFrom < len(query) && query[afterFrom] != ' ' && query[afterFrom] != '\t' && query[afterFrom] != '\n' {
			afterFrom++
		}

		// Find next keyword
		rest := strings.ToUpper(query[afterFrom:])
		insertPos := afterFrom

		keywords := []string{"GROUP BY", "ORDER BY", "LIMIT", "HAVING", "JOIN"}
		for _, kw := range keywords {
			if idx := strings.Index(rest, kw); idx >= 0 && (insertPos == afterFrom || afterFrom+idx < insertPos) {
				insertPos = afterFrom + idx
			}
		}

		tenantFilter := fmt.Sprintf(" WHERE tenant_id = '%s' ", tenantID)
		return query[:insertPos] + tenantFilter + query[insertPos:]
	}

	// WHERE clause exists, add AND condition
	insertPos := whereIdx + 5
	for insertPos < len(query) && (query[insertPos] == ' ' || query[insertPos] == '\t') {
		insertPos++
	}

	tenantFilter := fmt.Sprintf("tenant_id = '%s' AND ", tenantID)
	return query[:insertPos] + tenantFilter + query[insertPos:]
}

func hasLimit(query string) bool {
	return strings.Contains(strings.ToUpper(query), "LIMIT")
}

func hasOffset(query string) bool {
	return strings.Contains(strings.ToUpper(query), "OFFSET")
}
