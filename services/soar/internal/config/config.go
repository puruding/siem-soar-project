// Package config provides configuration for the SOAR service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the SOAR service.
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig
	CORS          CORSConfig
	WebSocket     WebSocketConfig
	KafkaConsumer KafkaConsumerConfig
	Redis         RedisConfig
	FeatureFlags  FeatureFlagsConfig
}

// KafkaConsumerConfig holds Kafka consumer settings.
type KafkaConsumerConfig struct {
	Enabled        bool          `json:"enabled"`
	Brokers        []string      `json:"brokers"`
	Topic          string        `json:"topic"`           // alerts.ml_enriched
	ConsumerGroup  string        `json:"consumer_group"`  // soar-consumer
	DLQTopic       string        `json:"dlq_topic"`       // alerts.ml_enriched.dlq
	MaxRetries     int           `json:"max_retries"`
	RetryBackoff   time.Duration `json:"retry_backoff"`
	CommitInterval time.Duration `json:"commit_interval"`
	BatchSize      int           `json:"batch_size"`
}

// RedisConfig holds Redis configuration for idempotency checking.
type RedisConfig struct {
	Addr           string        `json:"addr"`
	Password       string        `json:"password"`
	DB             int           `json:"db"`
	IdempotencyTTL time.Duration `json:"idempotency_ttl"` // default 30m
}

// FeatureFlagsConfig holds feature flag settings.
type FeatureFlagsConfig struct {
	SOARAutoTrigger         bool `json:"soar_auto_trigger"`          // Auto playbook execution
	HumanApprovalRequired   bool `json:"human_approval_required"`    // Default approval requirement
	MLEnrichedProcessing    bool `json:"ml_enriched_processing"`     // Process ML-enriched alerts
}

// WebSocketConfig holds WebSocket configuration.
type WebSocketConfig struct {
	Enabled           bool
	HeartbeatInterval int // seconds
	ReadBufferSize    int
	WriteBufferSize   int
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Port         string
	ReadTimeout  int
	WriteTimeout int
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
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
		Server: ServerConfig{
			Port:         getEnv("PORT", "8082"),
			ReadTimeout:  getEnvInt("READ_TIMEOUT", 15),
			WriteTimeout: getEnvInt("WRITE_TIMEOUT", 15),
		},
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnvInt("DB_PORT", 5432),
			User:     getEnv("DB_USER", "siem"),
			Password: getEnv("DB_PASSWORD", "siem_password"),
			DBName:   getEnv("DB_NAME", "siem_soar"),
			SSLMode:  getEnv("DB_SSLMODE", "disable"),
		},
		CORS: CORSConfig{
			AllowedOrigins: []string{"http://localhost:5173", "http://localhost:3000", "*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders: []string{"Content-Type", "Authorization", "X-Tenant-ID"},
		},
		WebSocket: WebSocketConfig{
			Enabled:           getEnvBool("SOAR_WEBSOCKET_ENABLED", true),
			HeartbeatInterval: getEnvInt("SOAR_WEBSOCKET_HEARTBEAT_INTERVAL", 30),
			ReadBufferSize:    getEnvInt("SOAR_WEBSOCKET_READ_BUFFER_SIZE", 1024),
			WriteBufferSize:   getEnvInt("SOAR_WEBSOCKET_WRITE_BUFFER_SIZE", 1024),
		},
		KafkaConsumer: KafkaConsumerConfig{
			Enabled:        getEnvBool("SOAR_KAFKA_CONSUMER_ENABLED", false),
			Brokers:        getEnvList("KAFKA_BROKERS", "localhost:9092"),
			Topic:          getEnv("SOAR_KAFKA_TOPIC", "alerts.ml_enriched"),
			ConsumerGroup:  getEnv("SOAR_KAFKA_CONSUMER_GROUP", "soar-consumer"),
			DLQTopic:       getEnv("SOAR_KAFKA_DLQ_TOPIC", "alerts.ml_enriched.dlq"),
			MaxRetries:     getEnvInt("SOAR_KAFKA_MAX_RETRIES", 3),
			RetryBackoff:   getEnvDuration("SOAR_KAFKA_RETRY_BACKOFF", time.Second),
			CommitInterval: getEnvDuration("SOAR_KAFKA_COMMIT_INTERVAL", 5*time.Second),
			BatchSize:      getEnvInt("SOAR_KAFKA_BATCH_SIZE", 100),
		},
		Redis: RedisConfig{
			Addr:           getEnv("REDIS_ADDR", "localhost:6379"),
			Password:       getEnv("REDIS_PASSWORD", ""),
			DB:             getEnvInt("REDIS_DB", 0),
			IdempotencyTTL: getEnvDuration("SOAR_IDEMPOTENCY_TTL", 30*time.Minute),
		},
		FeatureFlags: FeatureFlagsConfig{
			SOARAutoTrigger:       getEnvBool("SOAR_AUTO_TRIGGER_ENABLED", true),
			HumanApprovalRequired: getEnvBool("SOAR_REQUIRE_APPROVAL", false),
			MLEnrichedProcessing:  getEnvBool("SOAR_ML_ENRICHED_PROCESSING", true),
		},
	}
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// ConnectionString returns PostgreSQL connection string.
func (c *DatabaseConfig) ConnectionString() string {
	return "host=" + c.Host +
		" port=" + strconv.Itoa(c.Port) +
		" user=" + c.User +
		" password=" + c.Password +
		" dbname=" + c.DBName +
		" sslmode=" + c.SSLMode
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvList(key string, defaultValue string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return strings.Split(defaultValue, ",")
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}
