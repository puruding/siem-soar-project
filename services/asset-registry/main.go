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

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/siem-soar-platform/services/asset-registry/api"
	"github.com/siem-soar-platform/services/asset-registry/internal/repository"
	"github.com/siem-soar-platform/services/asset-registry/internal/service"
)

const (
	serviceName = "asset-registry"
	defaultPort = "8090"
)

// Config holds service configuration.
type Config struct {
	Port        string
	PostgresDSN string
	RedisAddr   string
	RedisDB     int
	LogLevel    string
}

func main() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg := loadConfig()

	// Initialize database
	db, err := initDatabase(cfg.PostgresDSN)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize Redis
	redisClient := initRedis(cfg.RedisAddr, cfg.RedisDB)
	defer redisClient.Close()

	// Create repositories
	baseRepo := repository.NewPostgresAssetRepository(db)
	cache := repository.NewAssetCache(redisClient, repository.DefaultCacheConfig())
	cachedRepo := repository.NewCachedAssetRepository(baseRepo, cache)

	// Create service
	assetService := service.NewAssetService(cachedRepo, logger)

	// Create router
	router := api.NewRouter(assetService, logger)

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server
	go func() {
		logger.Info("starting server",
			"service", serviceName,
			"port", cfg.Port,
		)
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

func loadConfig() Config {
	cfg := Config{
		Port:        getEnv("PORT", defaultPort),
		PostgresDSN: getEnv("POSTGRES_DSN", "host=localhost port=5432 dbname=siem user=siem_app password=siem_password sslmode=disable"),
		RedisAddr:   getEnv("REDIS_ADDR", "localhost:6379"),
		RedisDB:     0,
		LogLevel:    getEnv("LOG_LEVEL", "info"),
	}
	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func initDatabase(dsn string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func initRedis(addr string, db int) redis.UniversalClient {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DB:           db,
		MaxRetries:   3,
		PoolSize:     10,
		MinIdleConns: 2,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	return client
}
