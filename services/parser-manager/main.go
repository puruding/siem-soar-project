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

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/siem-soar-platform/services/parser-manager/internal/api"
	"github.com/siem-soar-platform/services/parser-manager/internal/hotreload"
	"github.com/siem-soar-platform/services/parser-manager/internal/repository"
	"github.com/siem-soar-platform/services/parser-manager/internal/service"
)

const (
	serviceName = "parser-manager"
	defaultPort = "8092"
)

// Config holds service configuration.
type Config struct {
	Port          string
	PostgresDSN   string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	ReloadChannel string
	InstanceID    string
	LogLevel      string
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

	// Create repositories
	parserRepo := repository.NewPostgresParserRepository(db)

	// Create hot reload manager
	hrConfig := &hotreload.Config{
		RedisAddr:     cfg.RedisAddr,
		RedisPassword: cfg.RedisPassword,
		RedisDB:       cfg.RedisDB,
		Channel:       cfg.ReloadChannel,
		InstanceID:    cfg.InstanceID,
	}
	hrManager := hotreload.NewManager(hrConfig, parserRepo, logger)

	// Create service
	parserService := service.NewParserService(parserRepo, hrManager, logger)

	// Create router
	router := api.NewRouter(parserService, logger)

	// Create server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start hot reload manager
	if err := hrManager.Start(); err != nil {
		logger.Warn("hot reload disabled", "error", err)
	}

	// Start server
	go func() {
		logger.Info("starting server",
			"service", serviceName,
			"port", cfg.Port,
			"instance_id", cfg.InstanceID,
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

	// Stop hot reload manager
	hrManager.Stop()

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
	}

	logger.Info("server exited")
}

func loadConfig() Config {
	instanceID := os.Getenv("INSTANCE_ID")
	if instanceID == "" {
		instanceID = "parser-manager-" + uuid.New().String()[:8]
	}

	cfg := Config{
		Port:          getEnv("PORT", defaultPort),
		PostgresDSN:   getEnv("POSTGRES_DSN", "host=localhost port=5432 dbname=siem user=siem_app password=siem_password sslmode=disable"),
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       0,
		ReloadChannel: getEnv("RELOAD_CHANNEL", "parser:reload"),
		InstanceID:    instanceID,
		LogLevel:      getEnv("LOG_LEVEL", "info"),
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
