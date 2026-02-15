// Package config provides configuration management for the normalizer service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds normalizer service configuration.
type Config struct {
	// Service
	ServiceName string
	Port        string
	LogLevel    string

	// Kafka
	KafkaBrokers       []string
	KafkaInputTopic    string
	KafkaOutputTopic   string
	KafkaDLQTopic      string
	KafkaConsumerGroup string

	// Normalizer
	Workers               int
	BatchSize             int
	BatchTimeout          time.Duration
	StrictValidation      bool
	RequiredFields        []string
	DropInvalidEvents     bool
	PreserveUnmappedFields bool

	// Mapping Hot Reload
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	ReloadChannel   string
	MappingsKey     string

	// Metrics
	MetricsEnabled bool
	MetricsPort    string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		// Service
		ServiceName: getEnv("SERVICE_NAME", "normalizer"),
		Port:        getEnv("PORT", "8089"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),

		// Kafka
		KafkaBrokers:       strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		KafkaInputTopic:    getEnv("KAFKA_INPUT_TOPIC", "logs.parsed"),
		KafkaOutputTopic:   getEnv("KAFKA_OUTPUT_TOPIC", "logs.normalized"),
		KafkaDLQTopic:      getEnv("KAFKA_DLQ_TOPIC", "logs.dlq.normalizer"),
		KafkaConsumerGroup: getEnv("KAFKA_CONSUMER_GROUP", "normalizer-service"),

		// Normalizer
		Workers:                getEnvInt("NORMALIZER_WORKERS", 8),
		BatchSize:              getEnvInt("NORMALIZER_BATCH_SIZE", 1000),
		BatchTimeout:           getEnvDuration("NORMALIZER_BATCH_TIMEOUT", "100ms"),
		StrictValidation:       getEnvBool("NORMALIZER_STRICT_VALIDATION", false),
		RequiredFields:         strings.Split(getEnv("NORMALIZER_REQUIRED_FIELDS", "metadata.event_type,metadata.event_timestamp"), ","),
		DropInvalidEvents:      getEnvBool("NORMALIZER_DROP_INVALID", false),
		PreserveUnmappedFields: getEnvBool("NORMALIZER_PRESERVE_UNMAPPED", true),

		// Hot Reload
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),
		ReloadChannel: getEnv("REDIS_RELOAD_CHANNEL", "normalizer:reload"),
		MappingsKey:   getEnv("REDIS_MAPPINGS_KEY", "normalizer:mappings"),

		// Metrics
		MetricsEnabled: getEnvBool("METRICS_ENABLED", true),
		MetricsPort:    getEnv("METRICS_PORT", "9090"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvDuration(key, defaultValue string) time.Duration {
	value := getEnv(key, defaultValue)
	d, err := time.ParseDuration(value)
	if err != nil {
		d, _ = time.ParseDuration(defaultValue)
	}
	return d
}
