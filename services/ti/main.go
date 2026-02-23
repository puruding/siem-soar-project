package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/siem-soar-platform/pkg/observability"
	"github.com/siem-soar-platform/services/ti/internal/cache"
	"github.com/siem-soar-platform/services/ti/internal/feed"
	"github.com/siem-soar-platform/services/ti/internal/handler"
	"github.com/siem-soar-platform/services/ti/internal/ioc"
	"github.com/siem-soar-platform/services/ti/internal/matcher"
	"github.com/siem-soar-platform/services/ti/internal/repository"
	"github.com/siem-soar-platform/services/ti/internal/service"
)

const (
	serviceName = "ti" // Threat Intelligence
	defaultPort = "8083"
)

// Config holds service configuration.
type Config struct {
	Port        string
	PostgresDSN string
	RedisAddr   string
}

// loadConfig loads configuration from environment variables.
func loadConfig() *Config {
	cfg := &Config{
		Port:        os.Getenv("PORT"),
		PostgresDSN: os.Getenv("POSTGRES_DSN"),
		RedisAddr:   os.Getenv("REDIS_ADDR"),
	}

	if cfg.Port == "" {
		cfg.Port = defaultPort
	}
	if cfg.PostgresDSN == "" {
		cfg.PostgresDSN = "postgres://postgres:postgres@localhost:5432/ti?sslmode=disable"
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = "localhost:6379"
	}

	return cfg
}

// App holds application dependencies.
type App struct {
	config       *Config
	logger       *slog.Logger
	db           *sql.DB
	redisClient  *redis.Client
	iocRepo      *repository.PostgresIOCRepository
	iocCache     *cache.IOCCache
	iocStore     *ioc.Store
	iocMatcher   *matcher.Matcher
	feedManager  *feed.Manager
	iocService   *service.IOCService
	feedService  *service.FeedService
	iocHandler   *handler.IOCHandler
	feedHandler  *handler.FeedHandler
}

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
	cfg := loadConfig()

	// Create app
	app := &App{
		config: cfg,
		logger: logger,
	}

	// Initialize dependencies
	if err := app.initDependencies(); err != nil {
		logger.Error("failed to initialize dependencies", "error", err)
		os.Exit(1)
	}
	defer app.cleanup()

	// Create router
	mux := app.setupRoutes()

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      loggingMiddleware(logger)(otelhttp.NewHandler(mux, serviceName)),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start background services
	if err := app.startBackgroundServices(); err != nil {
		logger.Error("failed to start background services", "error", err)
		os.Exit(1)
	}

	// Start server
	go func() {
		logger.Info("starting server", "service", serviceName, "port", cfg.Port)
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

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
	}

	logger.Info("server exited")
}

// initDependencies initializes all application dependencies.
func (app *App) initDependencies() error {
	ctx := context.Background()

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", app.config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}
	app.db = db
	app.logger.Info("connected to PostgreSQL")

	// Initialize repository
	app.iocRepo = repository.NewPostgresIOCRepository(db)
	if err := app.iocRepo.InitSchema(ctx); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Connect to Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:         app.config.RedisAddr,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     50,
	})

	if err := redisClient.Ping(ctx).Err(); err != nil {
		app.logger.Warn("failed to connect to Redis, cache will be disabled", "error", err)
		redisClient = nil
	} else {
		app.redisClient = redisClient
		app.logger.Info("connected to Redis")
	}

	// Initialize cache with 100M IOC capacity Bloom filter
	if redisClient != nil {
		cacheConfig := cache.DefaultCacheConfig()
		cacheConfig.BloomCapacity = 100_000_000 // 100M IOCs
		cacheConfig.BloomFPRate = 0.001         // 0.1% false positive rate
		app.iocCache = cache.NewIOCCache(redisClient, cacheConfig, app.logger)
	}

	// Initialize in-memory IOC store
	storeConfig := ioc.DefaultStoreConfig()
	app.iocStore = ioc.NewStore(storeConfig, app.iocRepo, app.logger)

	// Initialize matcher
	matcherConfig := matcher.DefaultMatcherConfig()
	matcherConfig.BloomSize = 100_000_000 // 100M IOCs
	app.iocMatcher = matcher.NewMatcher(matcherConfig, app.iocStore, app.logger)

	// Initialize IOC service
	app.iocService = service.NewIOCService(
		app.iocRepo,
		app.iocCache,
		app.iocMatcher,
		app.iocStore,
		app.logger,
	)

	// Initialize feed handler for processing IOCs
	feedIOCHandler := service.NewFeedIOCHandler(app.iocService, app.logger)

	// Initialize feed manager
	feedConfig := feed.DefaultManagerConfig()
	app.feedManager = feed.NewManager(feedConfig, feedIOCHandler, app.logger)

	// Initialize feed service
	app.feedService = service.NewFeedService(app.feedManager, app.iocService, app.logger)

	// Initialize HTTP handlers
	app.iocHandler = handler.NewIOCHandler(app.iocService, app.logger)
	app.feedHandler = handler.NewFeedHandler(app.feedService, app.logger)

	app.logger.Info("dependencies initialized")
	return nil
}

// startBackgroundServices starts background services.
func (app *App) startBackgroundServices() error {
	// Start IOC store
	if err := app.iocStore.Start(); err != nil {
		return fmt.Errorf("failed to start IOC store: %w", err)
	}

	// Start matcher
	if err := app.iocMatcher.Start(); err != nil {
		return fmt.Errorf("failed to start matcher: %w", err)
	}

	// Start feed manager
	if err := app.feedManager.Start(); err != nil {
		return fmt.Errorf("failed to start feed manager: %w", err)
	}

	// Warm up cache asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		if err := app.iocService.WarmupCache(ctx); err != nil {
			app.logger.Error("cache warmup failed", "error", err)
		}
	}()

	app.logger.Info("background services started")
	return nil
}

// setupRoutes sets up HTTP routes.
func (app *App) setupRoutes() *http.ServeMux {
	mux := http.NewServeMux()

	// Health and readiness endpoints
	mux.HandleFunc("GET /health", app.healthHandler)
	mux.HandleFunc("GET /ready", app.readyHandler)

	// Metrics endpoint
	mux.Handle("GET /metrics", observability.MetricsHandler())

	// IOC endpoints
	mux.HandleFunc("GET /api/v1/iocs", app.iocHandler.ListIOCs)
	mux.HandleFunc("POST /api/v1/iocs", app.iocHandler.CreateIOC)
	mux.HandleFunc("POST /api/v1/iocs/batch", app.iocHandler.CreateIOCBatch)
	mux.HandleFunc("GET /api/v1/iocs/lookup", app.iocHandler.LookupIOC)
	mux.HandleFunc("POST /api/v1/iocs/batch-lookup", app.iocHandler.BatchLookup)
	mux.HandleFunc("GET /api/v1/iocs/stats", app.iocHandler.GetStats)
	mux.HandleFunc("GET /api/v1/iocs/export", app.iocHandler.ExportIOCs)
	mux.HandleFunc("GET /api/v1/iocs/{id}", app.iocHandler.GetIOC)
	mux.HandleFunc("PUT /api/v1/iocs/{id}", app.iocHandler.UpdateIOC)
	mux.HandleFunc("DELETE /api/v1/iocs/{id}", app.iocHandler.DeleteIOC)

	// Feed endpoints
	mux.HandleFunc("GET /api/v1/feeds", app.feedHandler.ListFeeds)
	mux.HandleFunc("POST /api/v1/feeds", app.feedHandler.CreateFeed)
	mux.HandleFunc("POST /api/v1/feeds/sync", app.feedHandler.SyncAllFeeds)
	mux.HandleFunc("POST /api/v1/feeds/test", app.feedHandler.TestFeed)
	mux.HandleFunc("GET /api/v1/feeds/stats", app.feedHandler.GetFeedStats)
	mux.HandleFunc("GET /api/v1/feeds/{id}", app.feedHandler.GetFeed)
	mux.HandleFunc("PUT /api/v1/feeds/{id}", app.feedHandler.UpdateFeed)
	mux.HandleFunc("DELETE /api/v1/feeds/{id}", app.feedHandler.DeleteFeed)
	mux.HandleFunc("POST /api/v1/feeds/{id}/sync", app.feedHandler.SyncFeed)
	mux.HandleFunc("POST /api/v1/feeds/{id}/enable", app.feedHandler.EnableFeed)
	mux.HandleFunc("POST /api/v1/feeds/{id}/disable", app.feedHandler.DisableFeed)

	// Stats endpoint
	mux.HandleFunc("GET /api/v1/stats", app.statsHandler)

	return mux
}

// cleanup cleans up resources.
func (app *App) cleanup() {
	if app.feedManager != nil {
		app.feedManager.Stop()
	}
	if app.iocMatcher != nil {
		app.iocMatcher.Stop()
	}
	if app.iocStore != nil {
		app.iocStore.Stop()
	}
	if app.iocCache != nil {
		app.iocCache.Close()
	}
	if app.redisClient != nil {
		app.redisClient.Close()
	}
	if app.db != nil {
		app.db.Close()
	}
	app.logger.Info("cleanup complete")
}

// healthHandler handles GET /health
func (app *App) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy","service":"ti"}`)
}

// readyHandler handles GET /ready
func (app *App) readyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check PostgreSQL
	if err := app.db.PingContext(ctx); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"status":"not_ready","service":"ti","error":"database unavailable"}`)
		return
	}

	// Check Redis (optional)
	if app.iocCache != nil {
		if err := app.iocCache.Ping(ctx); err != nil {
			app.logger.Warn("redis not ready", "error", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ready","service":"ti"}`)
}

// statsHandler handles GET /api/v1/stats
func (app *App) statsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats := map[string]interface{}{
		"service": serviceName,
	}

	// IOC store stats
	if app.iocStore != nil {
		stats["store"] = app.iocStore.Stats()
	}

	// Cache stats
	if app.iocCache != nil {
		stats["cache"] = app.iocCache.Stats()
	}

	// Matcher stats
	if app.iocMatcher != nil {
		stats["matcher"] = app.iocMatcher.Stats()
	}

	// Feed stats
	if app.feedManager != nil {
		stats["feeds"] = app.feedManager.Stats()
	}

	// IOC stats from database
	if iocStats, err := app.iocRepo.GetStats(ctx, ""); err == nil {
		stats["iocs"] = iocStats
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(stats)
}

// loggingMiddleware returns a middleware that logs HTTP requests.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			// Skip logging for health/ready checks
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				return
			}

			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration", duration,
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
