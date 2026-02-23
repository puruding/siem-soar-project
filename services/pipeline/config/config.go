// Package config provides configuration for the pipeline service.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the pipeline service.
type Config struct {
	// Service identification
	ServiceName string
	Environment string
	Version     string

	// Server settings
	Server ServerConfig

	// Database connections
	Redis      RedisConfig
	ClickHouse ClickHouseConfig
	Postgres   PostgresConfig

	// Kafka settings
	Kafka KafkaConfig

	// Pipeline settings
	Pipeline PipelineConfig

	// CORS settings
	CORS CORSConfig
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	URL      string
	Password string
	DB       int
	PoolSize int
}

// ClickHouseConfig holds ClickHouse connection configuration.
type ClickHouseConfig struct {
	DSN      string
	Database string
	Username string
	Password string
}

// PostgresConfig holds PostgreSQL connection configuration.
type PostgresConfig struct {
	DSN      string
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// ConnectionString returns PostgreSQL connection string.
func (c *PostgresConfig) ConnectionString() string {
	if c.DSN != "" {
		return c.DSN
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}

// KafkaConfig holds Kafka connection configuration.
type KafkaConfig struct {
	Brokers       []string
	ConsumerGroup string
	InputTopic    string
	OutputTopic   string
	AlertTopic    string
}

// PipelineConfig holds pipeline-specific settings.
type PipelineConfig struct {
	Workers            int
	BatchSize          int
	BatchTimeout       time.Duration
	ClassifyTimeout    time.Duration
	PlaybookMatchLimit int
	EnableAutoResponse bool
}

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods []string
	AllowedHeaders []string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		ServiceName: getEnv("SERVICE_NAME", "pipeline"),
		Environment: getEnv("ENVIRONMENT", "development"),
		Version:     getEnv("VERSION", "1.0.0"),

		Server: ServerConfig{
			Port:         getEnv("PORT", "8087"),
			ReadTimeout:  getEnvAsDuration("READ_TIMEOUT", 15*time.Second),
			WriteTimeout: getEnvAsDuration("WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:  getEnvAsDuration("IDLE_TIMEOUT", 60*time.Second),
		},

		Redis: RedisConfig{
			URL:      getEnv("REDIS_URL", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
			PoolSize: getEnvAsInt("REDIS_POOL_SIZE", 10),
		},

		ClickHouse: ClickHouseConfig{
			DSN:      getEnv("CLICKHOUSE_DSN", ""),
			Database: getEnv("CLICKHOUSE_DATABASE", "siem"),
			Username: getEnv("CLICKHOUSE_USERNAME", "default"),
			Password: getEnv("CLICKHOUSE_PASSWORD", ""),
		},

		Postgres: PostgresConfig{
			DSN:      getEnv("POSTGRES_DSN", ""),
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvAsInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "siem"),
			Password: getEnv("DB_PASSWORD", "siem_password"),
			DBName:   getEnv("DB_NAME", "siem_soar"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},

		Kafka: KafkaConfig{
			Brokers:       getEnvAsSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
			ConsumerGroup: getEnv("KAFKA_CONSUMER_GROUP", "pipeline-service"),
			InputTopic:    getEnv("KAFKA_INPUT_TOPIC", "logs.normalized"),
			OutputTopic:   getEnv("KAFKA_OUTPUT_TOPIC", "pipeline.events"),
			AlertTopic:    getEnv("KAFKA_ALERT_TOPIC", "alerts"),
		},

		Pipeline: PipelineConfig{
			Workers:            getEnvAsInt("PIPELINE_WORKERS", 8),
			BatchSize:          getEnvAsInt("PIPELINE_BATCH_SIZE", 100),
			BatchTimeout:       getEnvAsDuration("PIPELINE_BATCH_TIMEOUT", time.Second),
			ClassifyTimeout:    getEnvAsDuration("PIPELINE_CLASSIFY_TIMEOUT", 5*time.Second),
			PlaybookMatchLimit: getEnvAsInt("PIPELINE_PLAYBOOK_MATCH_LIMIT", 5),
			EnableAutoResponse: getEnvAsBool("PIPELINE_ENABLE_AUTO_RESPONSE", false),
		},

		CORS: CORSConfig{
			AllowedOrigins: getEnvAsSlice("CORS_ORIGINS", []string{"http://localhost:5173", "http://localhost:3000", "*"}),
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization", "X-Tenant-ID"},
		},
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Port == "" {
		return fmt.Errorf("PORT is required")
	}
	if c.Pipeline.Workers <= 0 {
		c.Pipeline.Workers = 8
	}
	if c.Pipeline.BatchSize <= 0 {
		c.Pipeline.BatchSize = 100
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

// Helper functions

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
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}
