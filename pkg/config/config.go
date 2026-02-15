// Package config provides configuration loading and management for all services.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config represents the base configuration for all services.
type Config struct {
	// Service identification
	ServiceName string
	Environment string
	Version     string

	// Server settings
	HTTPPort     int
	GRPCPort     int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// Database connections
	PostgresDSN   string
	ClickHouseDSN string
	RedisDSN      string

	// Kafka settings
	KafkaBrokers []string
	KafkaGroupID string

	// Observability
	LogLevel    string
	LogFormat   string
	MetricsPort int
	TracingURL  string

	// Security
	JWTSecret      string
	APIKeyHeader   string
	CORSOrigins    []string
	TLSEnabled     bool
	TLSCertPath    string
	TLSKeyPath     string
}

// Load creates a new Config from environment variables with defaults.
func Load() (*Config, error) {
	cfg := &Config{
		ServiceName:   getEnv("SERVICE_NAME", "unknown"),
		Environment:   getEnv("ENVIRONMENT", "development"),
		Version:       getEnv("VERSION", "0.0.0"),
		HTTPPort:      getEnvAsInt("HTTP_PORT", 8080),
		GRPCPort:      getEnvAsInt("GRPC_PORT", 9090),
		ReadTimeout:   getEnvAsDuration("READ_TIMEOUT", 15*time.Second),
		WriteTimeout:  getEnvAsDuration("WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:   getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),
		PostgresDSN:   getEnv("POSTGRES_DSN", ""),
		ClickHouseDSN: getEnv("CLICKHOUSE_DSN", ""),
		RedisDSN:      getEnv("REDIS_DSN", ""),
		KafkaBrokers:  getEnvAsSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
		KafkaGroupID:  getEnv("KAFKA_GROUP_ID", ""),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		LogFormat:     getEnv("LOG_FORMAT", "json"),
		MetricsPort:   getEnvAsInt("METRICS_PORT", 9091),
		TracingURL:    getEnv("TRACING_URL", ""),
		JWTSecret:     getEnv("JWT_SECRET", ""),
		APIKeyHeader:  getEnv("API_KEY_HEADER", "X-API-Key"),
		CORSOrigins:   getEnvAsSlice("CORS_ORIGINS", []string{"*"}),
		TLSEnabled:    getEnvAsBool("TLS_ENABLED", false),
		TLSCertPath:   getEnv("TLS_CERT_PATH", ""),
		TLSKeyPath:    getEnv("TLS_KEY_PATH", ""),
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// validate checks that required fields are set based on environment.
func (c *Config) validate() error {
	if c.Environment == "production" {
		if c.JWTSecret == "" {
			return fmt.Errorf("JWT_SECRET is required in production")
		}
		if c.PostgresDSN == "" {
			return fmt.Errorf("POSTGRES_DSN is required in production")
		}
	}
	return nil
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsProduction returns true if running in production mode.
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// Helper functions for environment variable parsing

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Simple comma-separated parsing
		var result []string
		start := 0
		for i := 0; i <= len(value); i++ {
			if i == len(value) || value[i] == ',' {
				if start < i {
					result = append(result, value[start:i])
				}
				start = i + 1
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}
