// Package config provides configuration for the detection service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the detection service configuration.
type Config struct {
	// Service settings
	ServiceName string
	HTTPPort    int
	MetricsPort int

	// Kafka settings
	Kafka KafkaConfig

	// ClickHouse settings
	ClickHouse ClickHouseConfig

	// Engine settings
	Workers      int
	BatchSize    int
	BatchTimeout time.Duration

	// Rules settings
	RulesDirectory     string
	RuleReloadInterval time.Duration
}

// KafkaConfig holds Kafka connection settings.
type KafkaConfig struct {
	Brokers       []string
	ConsumerGroup string
	InputTopic    string
	OutputTopic   string

	// Consumer settings
	MaxPollRecords    int
	SessionTimeout    time.Duration
	HeartbeatInterval time.Duration
	AutoCommit        bool
	OffsetReset       string // "earliest" or "latest"

	// Security
	TLSEnabled    bool
	TLSCertPath   string
	TLSKeyPath    string
	TLSCAPath     string
	SASLEnabled   bool
	SASLMechanism string
	SASLUsername  string
	SASLPassword  string
}

// ClickHouseConfig holds ClickHouse connection settings.
type ClickHouseConfig struct {
	Addr     string
	User     string
	Password string
	Database string
	Debug    bool
}

// Load creates a new Config from environment variables.
func Load() *Config {
	return &Config{
		ServiceName: getEnv("SERVICE_NAME", "detection"),
		HTTPPort:    getEnvAsInt("HTTP_PORT", 8081),
		MetricsPort: getEnvAsInt("METRICS_PORT", 9081),

		Kafka: KafkaConfig{
			Brokers:           getEnvAsSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
			ConsumerGroup:     getEnv("KAFKA_CONSUMER_GROUP", "detection-service"),
			InputTopic:        getEnv("KAFKA_INPUT_TOPIC", "logs.parsed"),
			OutputTopic:       getEnv("KAFKA_OUTPUT_TOPIC", "alerts"),
			MaxPollRecords:    getEnvAsInt("KAFKA_MAX_POLL_RECORDS", 500),
			SessionTimeout:    getEnvAsDuration("KAFKA_SESSION_TIMEOUT", 30*time.Second),
			HeartbeatInterval: getEnvAsDuration("KAFKA_HEARTBEAT_INTERVAL", 3*time.Second),
			AutoCommit:        getEnvAsBool("KAFKA_AUTO_COMMIT", true),
			OffsetReset:       getEnv("KAFKA_OFFSET_RESET", "latest"),
			TLSEnabled:        getEnvAsBool("KAFKA_TLS_ENABLED", false),
			TLSCertPath:       getEnv("KAFKA_TLS_CERT_PATH", ""),
			TLSKeyPath:        getEnv("KAFKA_TLS_KEY_PATH", ""),
			TLSCAPath:         getEnv("KAFKA_TLS_CA_PATH", ""),
			SASLEnabled:       getEnvAsBool("KAFKA_SASL_ENABLED", false),
			SASLMechanism:     getEnv("KAFKA_SASL_MECHANISM", "PLAIN"),
			SASLUsername:      getEnv("KAFKA_SASL_USERNAME", ""),
			SASLPassword:      getEnv("KAFKA_SASL_PASSWORD", ""),
		},

		ClickHouse: ClickHouseConfig{
			Addr:     getEnv("CLICKHOUSE_ADDR", "localhost:9000"),
			User:     getEnv("CLICKHOUSE_USER", "default"),
			Password: getEnv("CLICKHOUSE_PASSWORD", ""),
			Database: getEnv("CLICKHOUSE_DATABASE", "siem"),
			Debug:    getEnvAsBool("CLICKHOUSE_DEBUG", false),
		},

		Workers:            getEnvAsInt("WORKERS", 8),
		BatchSize:          getEnvAsInt("BATCH_SIZE", 100),
		BatchTimeout:       getEnvAsDuration("BATCH_TIMEOUT", time.Second),
		RulesDirectory:     getEnv("RULES_DIRECTORY", "./rules"),
		RuleReloadInterval: getEnvAsDuration("RULE_RELOAD_INTERVAL", time.Minute),
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Kafka.Brokers) == 0 {
		return ErrNoBrokers
	}
	if c.Kafka.InputTopic == "" {
		return ErrNoInputTopic
	}
	if c.Kafka.OutputTopic == "" {
		return ErrNoOutputTopic
	}
	if c.Workers <= 0 {
		c.Workers = 8
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	return nil
}

// Configuration errors
var (
	ErrNoBrokers     = configError("KAFKA_BROKERS is required")
	ErrNoInputTopic  = configError("KAFKA_INPUT_TOPIC is required")
	ErrNoOutputTopic = configError("KAFKA_OUTPUT_TOPIC is required")
)

type configError string

func (e configError) Error() string {
	return string(e)
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
