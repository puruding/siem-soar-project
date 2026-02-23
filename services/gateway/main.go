package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/pkg/repository"
	"github.com/siem-soar-platform/services/gateway/internal/auth"
	"github.com/siem-soar-platform/services/gateway/internal/handler"
	"github.com/siem-soar-platform/services/gateway/internal/middleware"
	"github.com/siem-soar-platform/services/gateway/internal/ratelimit"
	"github.com/siem-soar-platform/services/gateway/internal/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	serviceName = "gateway"
	defaultPort = "8080"
)

func main() {
	// Initialize structured logger
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

	// Load authentication configuration from environment
	authEnabled := getEnvBool("AUTH_ENABLED", true)
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	keycloakRealm := os.Getenv("KEYCLOAK_REALM")
	keycloakClientID := os.Getenv("KEYCLOAK_CLIENT_ID")

	// Load rate limiting configuration from environment
	rateLimitRPS := getEnvInt("RATE_LIMIT_RPS", 100)
	rateLimitBurst := getEnvInt("RATE_LIMIT_BURST", 200)

	// Initialize ClickHouse connection for Events
	var eventRepo repository.EventRepository
	chConfig := repository.DefaultClickHouseConfig()

	// Override with environment variables
	if host := os.Getenv("CLICKHOUSE_HOST"); host != "" {
		chConfig.Hosts = []string{host}
	}
	if db := os.Getenv("CLICKHOUSE_DATABASE"); db != "" {
		chConfig.Database = db
	}
	if user := os.Getenv("CLICKHOUSE_USER"); user != "" {
		chConfig.Username = user
	}
	if pass := os.Getenv("CLICKHOUSE_PASSWORD"); pass != "" {
		chConfig.Password = pass
	}

	// Try to connect to ClickHouse
	chConn, err := repository.NewClickHouseConn(chConfig)
	if err != nil {
		logger.Warn("Failed to connect to ClickHouse, events API will use fallback",
			"error", err,
			"hosts", chConfig.Hosts,
			"database", chConfig.Database,
		)
		eventRepo = nil // Will fall back to mock data in handler
	} else {
		eventRepo = repository.NewClickHouseEventRepository(chConn)
		logger.Info("ClickHouse connection established",
			"hosts", chConfig.Hosts,
			"database", chConfig.Database,
		)
		defer chConn.Close()
	}

	// Initialize JWT authenticator
	var jwtAuth *auth.JWTAuthenticator
	if keycloakURL != "" && keycloakRealm != "" {
		jwtConfig := auth.NewKeycloakConfig(keycloakURL, keycloakRealm, keycloakClientID)
		jwtAuth = auth.NewJWTAuthenticator(jwtConfig, logger)
		logger.Info("Keycloak JWT authentication configured",
			"keycloak_url", keycloakURL,
			"realm", keycloakRealm,
			"client_id", keycloakClientID,
		)
	} else {
		// Use default config if Keycloak not configured
		jwtAuth = auth.NewJWTAuthenticator(auth.DefaultJWTConfig(), logger)
		logger.Warn("Keycloak not configured, using default JWT config")
	}
	defer jwtAuth.Stop()

	// Initialize API key authenticator (with in-memory store for dev)
	apiKeyStore := auth.NewInMemoryAPIKeyStore()
	apiKeyAuth := auth.NewAPIKeyAuthenticator(auth.DefaultAPIKeyConfig(), apiKeyStore, logger)

	// Initialize rate limiter
	rateLimitConfig := ratelimit.DefaultRateLimitConfig()
	rateLimitConfig.IPRPS = rateLimitRPS
	rateLimitConfig.IPBurst = rateLimitBurst
	rateLimiter := ratelimit.NewRateLimiter(rateLimitConfig, logger)
	defer rateLimiter.Stop()

	// Initialize WebSocket hub
	wsHub := websocket.NewHub(logger)
	ctx, cancelHub := context.WithCancel(context.Background())
	go wsHub.Run(ctx)
	defer func() {
		cancelHub()
		wsHub.Stop()
	}()

	// Make hub available globally for alert broadcasts
	handler.SetWebSocketHub(wsHub)

	// Set EventRepository for events handler
	handler.SetEventRepository(eventRepo)

	// Configure authentication middleware
	authConfig := middleware.DefaultAuthConfig()
	authConfig.Enabled = authEnabled
	authConfig.ExcludedPaths = []string{"/health", "/ready"}

	logger.Info("Authentication configuration",
		"enabled", authEnabled,
		"excluded_paths", authConfig.ExcludedPaths,
	)

	// Build middleware stack for API routes
	apiMiddleware := middleware.Chain(
		middleware.RequestID(),
		middleware.Logger(logger),
		middleware.Recovery(logger),
		middleware.CORS(middleware.DefaultCORSConfig()),
		middleware.SecurityHeaders(),
		middleware.RateLimit(rateLimiter, logger),
		middleware.ConditionalAuth(jwtAuth, apiKeyAuth, authConfig, logger),
	)

	// Build middleware stack for public routes (no auth)
	publicMiddleware := middleware.Chain(
		middleware.RequestID(),
		middleware.Logger(logger),
		middleware.Recovery(logger),
	)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.Handle("GET /health", publicMiddleware(http.HandlerFunc(healthHandler)))
	mux.Handle("GET /ready", publicMiddleware(http.HandlerFunc(readyHandler)))
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// WebSocket routes (no auth middleware - handled internally)
	wsHandlerConfig := websocket.HandlerConfig{
		Hub:              wsHub,
		JWTAuthenticator: jwtAuth,
		AuthEnabled:      authEnabled,
		Logger:           logger,
	}
	mux.HandleFunc("GET /ws", websocket.NewHandler(wsHandlerConfig))
	mux.HandleFunc("GET /ws/alerts", websocket.NewAlertHandler(wsHandlerConfig))
	mux.HandleFunc("GET /ws/pipeline", websocket.NewPipelineHandler(wsHandlerConfig))
	mux.HandleFunc("GET /ws/stats", websocket.StatsHandler(wsHub))
	mux.HandleFunc("GET /ws/health", websocket.HealthHandler(wsHub))

	// Alert API routes (protected by middleware)
	mux.Handle("GET /api/v1/alerts", apiMiddleware(http.HandlerFunc(handler.ListAlertsHandler)))
	mux.Handle("POST /api/v1/alerts", apiMiddleware(http.HandlerFunc(handler.CreateAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts", apiMiddleware(http.HandlerFunc(handler.CreateAlertHandler))) // CORS preflight

	// Single alert operations
	mux.Handle("GET /api/v1/alerts/{id}", apiMiddleware(http.HandlerFunc(handler.GetAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}", apiMiddleware(http.HandlerFunc(handler.GetAlertHandler)))
	mux.Handle("PUT /api/v1/alerts/{id}/status", apiMiddleware(http.HandlerFunc(handler.UpdateAlertStatusHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/status", apiMiddleware(http.HandlerFunc(handler.UpdateAlertStatusHandler)))
	mux.Handle("GET /api/v1/alerts/{id}/related", apiMiddleware(http.HandlerFunc(handler.GetRelatedAlertsHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/related", apiMiddleware(http.HandlerFunc(handler.GetRelatedAlertsHandler)))

	// Quick Action endpoints for alerts
	mux.Handle("POST /api/v1/alerts/{id}/acknowledge", apiMiddleware(http.HandlerFunc(handler.AcknowledgeAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/acknowledge", apiMiddleware(http.HandlerFunc(handler.AcknowledgeAlertHandler)))
	mux.Handle("POST /api/v1/alerts/{id}/close", apiMiddleware(http.HandlerFunc(handler.CloseAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/close", apiMiddleware(http.HandlerFunc(handler.CloseAlertHandler)))
	mux.Handle("POST /api/v1/alerts/{id}/create-case", apiMiddleware(http.HandlerFunc(handler.CreateCaseFromAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/create-case", apiMiddleware(http.HandlerFunc(handler.CreateCaseFromAlertHandler)))
	mux.Handle("POST /api/v1/alerts/{id}/run-playbook", apiMiddleware(http.HandlerFunc(handler.RunPlaybookOnAlertHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/run-playbook", apiMiddleware(http.HandlerFunc(handler.RunPlaybookOnAlertHandler)))

	// Alert comments
	mux.Handle("GET /api/v1/alerts/{id}/comments", apiMiddleware(http.HandlerFunc(handler.GetAlertCommentsHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/comments", apiMiddleware(http.HandlerFunc(handler.GetAlertCommentsHandler)))
	mux.Handle("POST /api/v1/alerts/{id}/comments", apiMiddleware(http.HandlerFunc(handler.AddAlertCommentHandler)))

	// Case API routes
	mux.Handle("GET /api/v1/cases", apiMiddleware(http.HandlerFunc(handler.ListCasesHandler)))
	mux.Handle("POST /api/v1/cases", apiMiddleware(http.HandlerFunc(handler.CreateCaseHandler)))
	mux.Handle("OPTIONS /api/v1/cases", apiMiddleware(http.HandlerFunc(handler.CreateCaseHandler)))
	mux.Handle("GET /api/v1/cases/stats", apiMiddleware(http.HandlerFunc(handler.GetCaseStatsHandler)))
	mux.Handle("OPTIONS /api/v1/cases/stats", apiMiddleware(http.HandlerFunc(handler.GetCaseStatsHandler)))
	mux.Handle("GET /api/v1/cases/{id}", apiMiddleware(http.HandlerFunc(handler.GetCaseHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}", apiMiddleware(http.HandlerFunc(handler.GetCaseHandler)))
	mux.Handle("PUT /api/v1/cases/{id}", apiMiddleware(http.HandlerFunc(handler.UpdateCaseHandler)))
	mux.Handle("PATCH /api/v1/cases/{id}", apiMiddleware(http.HandlerFunc(handler.UpdateCaseHandler)))
	mux.Handle("DELETE /api/v1/cases/{id}", apiMiddleware(http.HandlerFunc(handler.DeleteCaseHandler)))
	mux.Handle("POST /api/v1/cases/{id}/assign", apiMiddleware(http.HandlerFunc(handler.AssignCaseHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}/assign", apiMiddleware(http.HandlerFunc(handler.AssignCaseHandler)))
	mux.Handle("POST /api/v1/cases/{id}/status", apiMiddleware(http.HandlerFunc(handler.ChangeStatusHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}/status", apiMiddleware(http.HandlerFunc(handler.ChangeStatusHandler)))
	mux.Handle("POST /api/v1/cases/{id}/alerts", apiMiddleware(http.HandlerFunc(handler.AddAlertToCaseHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}/alerts", apiMiddleware(http.HandlerFunc(handler.AddAlertToCaseHandler)))
	mux.Handle("DELETE /api/v1/cases/{id}/alerts/{alertId}", apiMiddleware(http.HandlerFunc(handler.RemoveAlertFromCaseHandler)))
	mux.Handle("GET /api/v1/cases/{id}/timeline", apiMiddleware(http.HandlerFunc(handler.GetCaseTimelineHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}/timeline", apiMiddleware(http.HandlerFunc(handler.GetCaseTimelineHandler)))
	mux.Handle("POST /api/v1/cases/{id}/comments", apiMiddleware(http.HandlerFunc(handler.AddCommentHandler)))
	mux.Handle("OPTIONS /api/v1/cases/{id}/comments", apiMiddleware(http.HandlerFunc(handler.AddCommentHandler)))

	// Playbook API routes
	mux.Handle("GET /api/v1/playbooks", apiMiddleware(http.HandlerFunc(handler.ListPlaybooksHandler)))
	mux.Handle("OPTIONS /api/v1/playbooks", apiMiddleware(http.HandlerFunc(handler.ListPlaybooksHandler)))
	mux.Handle("POST /api/v1/playbooks/run/{id}", apiMiddleware(http.HandlerFunc(handler.ExecutePlaybookHandler)))
	mux.Handle("OPTIONS /api/v1/playbooks/run/{id}", apiMiddleware(http.HandlerFunc(handler.ExecutePlaybookHandler)))
	mux.Handle("GET /api/v1/playbooks/{id}", apiMiddleware(http.HandlerFunc(handler.GetPlaybookHandler)))
	mux.Handle("OPTIONS /api/v1/playbooks/{id}", apiMiddleware(http.HandlerFunc(handler.GetPlaybookHandler)))

	// Playbook execution routes (separate path to avoid conflict)
	mux.Handle("GET /api/v1/executions", apiMiddleware(http.HandlerFunc(handler.ListExecutionsHandler)))
	mux.Handle("OPTIONS /api/v1/executions", apiMiddleware(http.HandlerFunc(handler.ListExecutionsHandler)))
	mux.Handle("GET /api/v1/executions/{id}", apiMiddleware(http.HandlerFunc(handler.GetExecutionStatusHandler)))
	mux.Handle("OPTIONS /api/v1/executions/{id}", apiMiddleware(http.HandlerFunc(handler.GetExecutionStatusHandler)))

	// User info endpoint (returns current user from JWT)
	mux.Handle("GET /api/v1/me", apiMiddleware(http.HandlerFunc(userInfoHandler)))

	// Query API routes
	mux.Handle("POST /api/v1/query", apiMiddleware(http.HandlerFunc(handler.ExecuteQueryHandler)))
	mux.Handle("OPTIONS /api/v1/query", apiMiddleware(http.HandlerFunc(handler.ExecuteQueryHandler)))
	mux.Handle("POST /api/v1/query/execute", apiMiddleware(http.HandlerFunc(handler.ExecuteQueryHandler)))
	mux.Handle("OPTIONS /api/v1/query/execute", apiMiddleware(http.HandlerFunc(handler.ExecuteQueryHandler)))
	mux.Handle("GET /api/v1/query/schema", apiMiddleware(http.HandlerFunc(handler.GetSchemaHandler)))
	mux.Handle("OPTIONS /api/v1/query/schema", apiMiddleware(http.HandlerFunc(handler.GetSchemaHandler)))
	mux.Handle("GET /api/v1/query/saved", apiMiddleware(http.HandlerFunc(handler.ListSavedQueriesHandler)))
	mux.Handle("OPTIONS /api/v1/query/saved", apiMiddleware(http.HandlerFunc(handler.ListSavedQueriesHandler)))
	mux.Handle("POST /api/v1/query/saved", apiMiddleware(http.HandlerFunc(handler.CreateSavedQueryHandler)))
	mux.Handle("GET /api/v1/query/saved/{id}", apiMiddleware(http.HandlerFunc(handler.GetSavedQueryHandler)))
	mux.Handle("OPTIONS /api/v1/query/saved/{id}", apiMiddleware(http.HandlerFunc(handler.GetSavedQueryHandler)))
	mux.Handle("DELETE /api/v1/query/saved/{id}", apiMiddleware(http.HandlerFunc(handler.DeleteSavedQueryHandler)))
	mux.Handle("GET /api/v1/query/history", apiMiddleware(http.HandlerFunc(handler.GetQueryHistoryHandler)))
	mux.Handle("OPTIONS /api/v1/query/history", apiMiddleware(http.HandlerFunc(handler.GetQueryHistoryHandler)))
	mux.Handle("POST /api/v1/query/validate", apiMiddleware(http.HandlerFunc(handler.ValidateQueryHandler)))
	mux.Handle("OPTIONS /api/v1/query/validate", apiMiddleware(http.HandlerFunc(handler.ValidateQueryHandler)))

	// Assets API routes
	mux.Handle("GET /api/v1/assets", apiMiddleware(http.HandlerFunc(handler.ListAssetsHandler)))
	mux.Handle("OPTIONS /api/v1/assets", apiMiddleware(http.HandlerFunc(handler.ListAssetsHandler)))
	mux.Handle("POST /api/v1/assets", apiMiddleware(http.HandlerFunc(handler.CreateAssetHandler)))
	mux.Handle("GET /api/v1/assets/{id}", apiMiddleware(http.HandlerFunc(handler.GetAssetHandler)))
	mux.Handle("OPTIONS /api/v1/assets/{id}", apiMiddleware(http.HandlerFunc(handler.GetAssetHandler)))
	mux.Handle("PUT /api/v1/assets/{id}", apiMiddleware(http.HandlerFunc(handler.UpdateAssetHandler)))
	mux.Handle("DELETE /api/v1/assets/{id}", apiMiddleware(http.HandlerFunc(handler.DeleteAssetHandler)))

	// Products API routes
	mux.Handle("GET /api/v1/products", apiMiddleware(http.HandlerFunc(handler.ListProductsHandler)))
	mux.Handle("OPTIONS /api/v1/products", apiMiddleware(http.HandlerFunc(handler.ListProductsHandler)))
	mux.Handle("POST /api/v1/products", apiMiddleware(http.HandlerFunc(handler.CreateProductHandler)))
	mux.Handle("GET /api/v1/products/{id}", apiMiddleware(http.HandlerFunc(handler.GetProductHandler)))
	mux.Handle("OPTIONS /api/v1/products/{id}", apiMiddleware(http.HandlerFunc(handler.GetProductHandler)))

	// Parsers API routes
	mux.Handle("GET /api/v1/parsers", apiMiddleware(http.HandlerFunc(handler.ListParsersHandler)))
	mux.Handle("OPTIONS /api/v1/parsers", apiMiddleware(http.HandlerFunc(handler.ListParsersHandler)))
	mux.Handle("POST /api/v1/parsers", apiMiddleware(http.HandlerFunc(handler.CreateParserHandler)))
	mux.Handle("GET /api/v1/parsers/{id}", apiMiddleware(http.HandlerFunc(handler.GetParserHandler)))
	mux.Handle("OPTIONS /api/v1/parsers/{id}", apiMiddleware(http.HandlerFunc(handler.GetParserHandler)))
	mux.Handle("PUT /api/v1/parsers/{id}", apiMiddleware(http.HandlerFunc(handler.UpdateParserHandler)))
	mux.Handle("DELETE /api/v1/parsers/{id}", apiMiddleware(http.HandlerFunc(handler.DeleteParserHandler)))
	mux.Handle("POST /api/v1/parsers/test", apiMiddleware(http.HandlerFunc(handler.TestParserHandler)))
	mux.Handle("OPTIONS /api/v1/parsers/test", apiMiddleware(http.HandlerFunc(handler.TestParserHandler)))

	// Events API routes
	mux.Handle("GET /api/v1/events", apiMiddleware(http.HandlerFunc(handler.ListEventsHandler)))
	mux.Handle("OPTIONS /api/v1/events", apiMiddleware(http.HandlerFunc(handler.ListEventsHandler)))
	mux.Handle("POST /api/v1/events", apiMiddleware(http.HandlerFunc(handler.CreateEventHandler)))
	mux.Handle("GET /api/v1/events/{id}", apiMiddleware(http.HandlerFunc(handler.GetEventHandler)))
	mux.Handle("OPTIONS /api/v1/events/{id}", apiMiddleware(http.HandlerFunc(handler.GetEventHandler)))
	mux.Handle("GET /api/v1/events/stats", apiMiddleware(http.HandlerFunc(handler.GetEventStatsHandler)))
	mux.Handle("OPTIONS /api/v1/events/stats", apiMiddleware(http.HandlerFunc(handler.GetEventStatsHandler)))

	// Dashboard API routes
	mux.Handle("GET /api/v1/dashboard/stats", apiMiddleware(http.HandlerFunc(handler.GetDashboardStatsHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/stats", apiMiddleware(http.HandlerFunc(handler.GetDashboardStatsHandler)))
	mux.Handle("GET /api/v1/dashboard/alerts/trend", apiMiddleware(http.HandlerFunc(handler.GetAlertTrendHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/alerts/trend", apiMiddleware(http.HandlerFunc(handler.GetAlertTrendHandler)))
	mux.Handle("GET /api/v1/dashboard/alerts/top", apiMiddleware(http.HandlerFunc(handler.GetTopAlertsHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/alerts/top", apiMiddleware(http.HandlerFunc(handler.GetTopAlertsHandler)))
	mux.Handle("GET /api/v1/dashboard/cases/recent", apiMiddleware(http.HandlerFunc(handler.GetRecentCasesHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/cases/recent", apiMiddleware(http.HandlerFunc(handler.GetRecentCasesHandler)))
	mux.Handle("GET /api/v1/dashboard/threats/summary", apiMiddleware(http.HandlerFunc(handler.GetThreatSummaryHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/threats/summary", apiMiddleware(http.HandlerFunc(handler.GetThreatSummaryHandler)))
	mux.Handle("GET /api/v1/dashboard/metrics/eps", apiMiddleware(http.HandlerFunc(handler.GetEPSMetricsHandler)))
	mux.Handle("OPTIONS /api/v1/dashboard/metrics/eps", apiMiddleware(http.HandlerFunc(handler.GetEPSMetricsHandler)))

	// Threat Intelligence (TI) API routes
	mux.Handle("GET /api/v1/ti/iocs", apiMiddleware(http.HandlerFunc(handler.ListIOCsHandler)))
	mux.Handle("OPTIONS /api/v1/ti/iocs", apiMiddleware(http.HandlerFunc(handler.ListIOCsHandler)))
	mux.Handle("POST /api/v1/ti/iocs", apiMiddleware(http.HandlerFunc(handler.AddIOCHandler)))
	mux.Handle("GET /api/v1/ti/iocs/{id}", apiMiddleware(http.HandlerFunc(handler.GetIOCHandler)))
	mux.Handle("OPTIONS /api/v1/ti/iocs/{id}", apiMiddleware(http.HandlerFunc(handler.GetIOCHandler)))
	mux.Handle("POST /api/v1/ti/lookup", apiMiddleware(http.HandlerFunc(handler.LookupIOCHandler)))
	mux.Handle("OPTIONS /api/v1/ti/lookup", apiMiddleware(http.HandlerFunc(handler.LookupIOCHandler)))
	mux.Handle("GET /api/v1/ti/stats", apiMiddleware(http.HandlerFunc(handler.GetTIStatsHandler)))
	mux.Handle("OPTIONS /api/v1/ti/stats", apiMiddleware(http.HandlerFunc(handler.GetTIStatsHandler)))

	// Alert TI enrichment endpoint
	mux.Handle("GET /api/v1/alerts/{id}/ti", apiMiddleware(http.HandlerFunc(handler.GetAlertTIHandler)))
	mux.Handle("OPTIONS /api/v1/alerts/{id}/ti", apiMiddleware(http.HandlerFunc(handler.GetAlertTIHandler)))

	// Rules API routes (Sigma detection rules)
	mux.Handle("GET /api/v1/rules", apiMiddleware(http.HandlerFunc(handler.ListRulesHandler)))
	mux.Handle("OPTIONS /api/v1/rules", apiMiddleware(http.HandlerFunc(handler.ListRulesHandler)))
	mux.Handle("POST /api/v1/rules", apiMiddleware(http.HandlerFunc(handler.CreateRuleHandler)))
	mux.Handle("GET /api/v1/rules/{id}", apiMiddleware(http.HandlerFunc(handler.GetRuleHandler)))
	mux.Handle("OPTIONS /api/v1/rules/{id}", apiMiddleware(http.HandlerFunc(handler.GetRuleHandler)))
	mux.Handle("PUT /api/v1/rules/{id}", apiMiddleware(http.HandlerFunc(handler.UpdateRuleHandler)))
	mux.Handle("DELETE /api/v1/rules/{id}", apiMiddleware(http.HandlerFunc(handler.DeleteRuleHandler)))
	mux.Handle("POST /api/v1/rules/{id}/enable", apiMiddleware(http.HandlerFunc(handler.EnableRuleHandler)))
	mux.Handle("OPTIONS /api/v1/rules/{id}/enable", apiMiddleware(http.HandlerFunc(handler.EnableRuleHandler)))
	mux.Handle("POST /api/v1/rules/{id}/disable", apiMiddleware(http.HandlerFunc(handler.DisableRuleHandler)))
	mux.Handle("OPTIONS /api/v1/rules/{id}/disable", apiMiddleware(http.HandlerFunc(handler.DisableRuleHandler)))
	mux.Handle("POST /api/v1/rules/test", apiMiddleware(http.HandlerFunc(handler.TestRuleHandler)))
	mux.Handle("OPTIONS /api/v1/rules/test", apiMiddleware(http.HandlerFunc(handler.TestRuleHandler)))

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      otelhttp.NewHandler(mux, serviceName),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"gateway"}`)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready","service":"gateway"}`)
}

// userInfoHandler returns the current user info from the JWT token.
func userInfoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	claims := auth.GetClaims(r.Context())
	if claims == nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"Not authenticated"}`)
		return
	}

	// Build user info response
	userInfo := map[string]interface{}{
		"sub":      claims.Subject,
		"user_id":  claims.UserID,
		"username": claims.GetEffectiveUsername(),
		"email":    claims.Email,
		"roles":    claims.GetAllRoles(),
		"groups":   claims.Groups,
	}

	if claims.TenantID != "" {
		userInfo["tenant_id"] = claims.TenantID
	}

	w.WriteHeader(http.StatusOK)
	jsonBytes, _ := json.Marshal(userInfo)
	w.Write(jsonBytes)
}

// getEnvBool returns a boolean environment variable or a default value.
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	val = strings.ToLower(val)
	return val == "true" || val == "1" || val == "yes"
}

// getEnvInt returns an integer environment variable or a default value.
func getEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return intVal
}
